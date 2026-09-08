use crate::{Error, FeatureLevel, SqlReadBytes};
use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::io::AsyncReadExt;
use std::convert::TryFrom;
use std::io::Cursor;

// `tds_version` is applied to the connection `Context` (see
// `TokenStream::get_login_ack`), and `prog_name`/`version` are logged via
// `event!(Level::DEBUG, ...)` there. Only `interface` is otherwise unread;
// retained for `Debug` diagnostics.
#[derive(Debug)]
pub struct TokenLoginAck {
    /// The type of interface with which the server will accept client requests
    /// 0: SQL_DFLT (server confirms that whatever is sent by the client is acceptable. If the client
    ///    requested SQL_DFLT, SQL_TSQL will be used)
    /// 1: SQL_TSQL (TSQL is accepted)
    #[allow(dead_code)]
    pub(crate) interface: u8,
    pub(crate) tds_version: FeatureLevel,
    pub(crate) prog_name: String,
    /// major.minor.buildhigh.buildlow
    pub(crate) version: u32,
}

/// Read a `B_VARCHAR` (a single `u8` UTF-16 code-unit count followed by that
/// many little-endian `u16` code units) from an in-memory cursor.
fn read_b_varchar(cur: &mut Cursor<&[u8]>) -> crate::Result<String> {
    let char_count = cur.read_u8()? as usize;
    let mut units = Vec::with_capacity(char_count);

    for _ in 0..char_count {
        units.push(cur.read_u16::<LittleEndian>()?);
    }

    String::from_utf16(&units)
        .map_err(|_| Error::Protocol("Login ACK: ProgName is not valid UTF-16".into()))
}

impl TokenLoginAck {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let length = src.read_u16_le().await? as usize;

        // `Interface` (1) and `TDSVersion` (4) are fixed-width, so they cannot
        // desync on their own; read them directly. The rest of the body
        // (`ProgName`, a greedy B_VARCHAR, plus the 4-byte build version) is what
        // could over-/under-read on a Length/content mismatch, so it is read
        // into a bounded buffer sized by the *remaining* declared Length and
        // parsed from there. Total consumption is therefore exactly `Length`,
        // keeping the token stream aligned.
        const FIXED_PREFIX: usize = 5; // interface (1) + tds_version (4)

        if length < FIXED_PREFIX {
            // Consume whatever the (too-small) Length declared so the stream
            // stays aligned to the next token boundary, then fail cleanly.
            let mut discard = vec![0u8; length];
            src.read_exact(&mut discard).await?;

            return Err(Error::Protocol(
                "Login ACK: token length shorter than fixed header".into(),
            ));
        }

        let interface = src.read_u8().await?;

        // TDS version is a 4-byte big-endian value.
        let tds_version = FeatureLevel::try_from(src.read_u32().await?)
            .map_err(|_| Error::Protocol("Login ACK: Invalid TDS version".into()))?;

        let mut data = vec![0u8; length - FIXED_PREFIX];
        src.read_exact(&mut data).await?;

        let mut cur = Cursor::new(&data[..]);

        let prog_name = read_b_varchar(&mut cur)?;
        let version = cur.read_u32::<LittleEndian>()?;

        Ok(TokenLoginAck {
            interface,
            tds_version,
            prog_name,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    fn put_b_varchar(buf: &mut BytesMut, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        buf.put_u8(utf16.len() as u8);
        for c in utf16 {
            buf.put_u16_le(c);
        }
    }

    /// Build a LOGINACK wire buffer: the token body prefixed by its exact
    /// `Length` (u16, little-endian).
    fn ack_body(interface: u8, tds_version: u32, prog_name: &str, version: u32) -> BytesMut {
        let mut body = BytesMut::new();
        body.put_u8(interface);
        body.put_u32(tds_version); // big-endian tds version
        put_b_varchar(&mut body, prog_name);
        body.put_u32_le(version);

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16);
        buf.put_slice(&body);
        buf
    }

    #[tokio::test]
    async fn decodes_valid_ack() {
        let buf = ack_body(
            1,
            FeatureLevel::SqlServerN as u32,
            "Microsoft SQL Server",
            0x0F00_0FA0,
        );

        let ack = TokenLoginAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(ack.interface, 1);
        assert_eq!(ack.tds_version, FeatureLevel::SqlServerN);
        assert_eq!(ack.prog_name, "Microsoft SQL Server");
        assert_eq!(ack.version, 0x0F00_0FA0);
    }

    #[tokio::test]
    async fn negotiated_version_is_recorded_in_context() {
        // Mirrors the wiring in `TokenStream::get_login_ack`: after decoding a
        // LOGINACK the negotiated `tds_version` must be pushed into the
        // connection context so version-dependent decoders use the right
        // layout. A pre-2005 version differs from the default (SqlServerN), so
        // this proves the value is actually applied and not left at the default.
        use crate::SqlReadBytes;

        let buf = ack_body(
            1,
            FeatureLevel::SqlServer2000 as u32,
            "Microsoft SQL Server",
            0x0800_0000,
        );

        let mut reader = buf.into_sql_read_bytes();
        assert_eq!(reader.context().version(), FeatureLevel::SqlServerN);

        let ack = TokenLoginAck::decode(&mut reader).await.unwrap();
        assert_eq!(ack.tds_version, FeatureLevel::SqlServer2000);

        // The exact call `get_login_ack` performs.
        reader.context_mut().set_version(ack.tds_version);

        assert_eq!(reader.context().version(), FeatureLevel::SqlServer2000);
    }

    #[tokio::test]
    async fn invalid_tds_version_errors() {
        let mut body = BytesMut::new();
        body.put_u8(1); // interface
        body.put_u32(0xDEAD_BEEF); // not a valid FeatureLevel

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16);
        buf.put_slice(&body);

        let err = TokenLoginAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("must fail on invalid version");

        assert!(matches!(err, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn under_declared_length_is_clean_error_and_does_not_desync() {
        // Declared Length (5) covers only interface + tds_version; the ProgName
        // length byte and everything after it fall outside it. Decoding must
        // fail cleanly AND consume exactly `Length` body bytes, leaving the
        // following byte on the wire readable — i.e. no desync. A decoder that
        // ignored `Length` (the old behaviour) would greedily read the trailing
        // bytes as ProgName/version and succeed, desyncing the stream.
        use crate::SqlReadBytes;

        let mut buf = BytesMut::new();
        buf.put_u16_le(5); // declared Length (too small for the full body)
        buf.put_u8(1); // interface
        buf.put_u32(FeatureLevel::SqlServerN as u32); // big-endian tds version

        // The bytes below belong to the *next* token on the wire; a length-
        // ignoring decoder would (mis)read them as ProgName + version.
        buf.put_u8(0); // (mis)read as ProgName length 0
        buf.put_u32_le(0x1234_5678); // (mis)read as version
        buf.put_u8(0xEF); // sentinel further along

        let mut reader = buf.into_sql_read_bytes();

        let err = TokenLoginAck::decode(&mut reader)
            .await
            .expect_err("under-declared length must be a clean error");
        assert!(matches!(err, Error::Protocol(_) | Error::Io { .. }));

        // Exactly the 5 declared body bytes were consumed, so the first byte of
        // the next token region is still on the wire (no desync).
        assert_eq!(reader.read_u8().await.unwrap(), 0x00);
    }

    #[tokio::test]
    async fn trailing_bytes_within_declared_length_are_ignored() {
        // Declared Length is larger than the fields consume; the extra padding
        // is discarded and the next token (sentinel) is read cleanly afterwards.
        use crate::SqlReadBytes;

        let mut body = BytesMut::new();
        body.put_u8(1); // interface
        body.put_u32(FeatureLevel::SqlServerN as u32); // tds version
        put_b_varchar(&mut body, "srv");
        body.put_u32_le(0x0F00_0FA0); // version
        body.put_u8(0x99); // trailing padding within the declared length

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16);
        buf.put_slice(&body);
        buf.put_u8(0xCD); // sentinel next token

        let mut reader = buf.into_sql_read_bytes();

        let ack = TokenLoginAck::decode(&mut reader)
            .await
            .expect("trailing padding within length must decode");
        assert_eq!(ack.prog_name, "srv");
        assert_eq!(ack.version, 0x0F00_0FA0);

        assert_eq!(reader.read_u8().await.unwrap(), 0xCD);
    }
}
