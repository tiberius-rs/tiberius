use crate::{tds::codec::FeatureLevel, Error, SqlReadBytes};
use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::io::AsyncReadExt;
use std::fmt;
use std::io::Cursor;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
/// An error token returned from the server.
pub struct TokenError {
    /// ErrorCode
    pub(crate) code: u32,
    /// ErrorState (describing code)
    pub(crate) state: u8,
    /// The class (severity) of the error
    pub(crate) class: u8,
    /// The error message
    pub(crate) message: String,
    pub(crate) server: String,
    pub(crate) procedure: String,
    pub(crate) line: u32,
}

/// The body shared by the ERROR (`0xAA`) and INFO (`0xAB`) tokens, which have
/// byte-for-byte identical layouts (MS-TDS §2.2.7.10 / §2.2.7.13).
pub(crate) struct ErrorInfoBody {
    pub(crate) code: u32,
    pub(crate) state: u8,
    pub(crate) class: u8,
    pub(crate) message: String,
    pub(crate) server: String,
    pub(crate) procedure: String,
    pub(crate) line: u32,
}

fn read_utf16(cur: &mut Cursor<&[u8]>, char_count: usize) -> crate::Result<String> {
    let mut units = Vec::with_capacity(char_count);
    for _ in 0..char_count {
        units.push(cur.read_u16::<LittleEndian>()?);
    }
    String::from_utf16(&units)
        .map_err(|_| Error::Protocol("ERROR/INFO token string is not valid UTF-16".into()))
}

fn read_us_varchar(cur: &mut Cursor<&[u8]>) -> crate::Result<String> {
    let char_count = cur.read_u16::<LittleEndian>()? as usize;
    read_utf16(cur, char_count)
}

fn read_b_varchar(cur: &mut Cursor<&[u8]>) -> crate::Result<String> {
    let char_count = cur.read_u8()? as usize;
    read_utf16(cur, char_count)
}

/// Decode the common ERROR/INFO token body.
///
/// The token's declared `Length` is honored exactly: the whole body is read
/// into a bounded buffer and parsed from there, so a `Length`/content mismatch
/// surfaces as a clean protocol error instead of over- or under-reading the
/// wire and desyncing the token stream. Any trailing bytes within `Length` that
/// the fields do not consume are discarded.
pub(crate) async fn decode_error_info_body<R>(src: &mut R) -> crate::Result<ErrorInfoBody>
where
    R: SqlReadBytes + Unpin,
{
    // MS-TDS §2.2.7.10/§2.2.7.13: LineNumber is a 4-byte LONG for TDS 7.2 (SQL
    // Server 2005) and later, and a 2-byte USHORT before that. The boundary is
    // inclusive of 7.2, so use `>=`. Capture it before consuming the body.
    let four_byte_line = src.context().version() >= FeatureLevel::SqlServer2005;

    let length = src.read_u16_le().await? as usize;

    let mut data = vec![0u8; length];
    src.read_exact(&mut data).await?;

    let mut cur = Cursor::new(&data[..]);

    let code = cur.read_u32::<LittleEndian>()?;
    let state = cur.read_u8()?;
    let class = cur.read_u8()?;
    let message = read_us_varchar(&mut cur)?;
    let server = read_b_varchar(&mut cur)?;
    let procedure = read_b_varchar(&mut cur)?;
    let line = if four_byte_line {
        cur.read_u32::<LittleEndian>()?
    } else {
        cur.read_u16::<LittleEndian>()? as u32
    };

    Ok(ErrorInfoBody {
        code,
        state,
        class,
        message,
        server,
        procedure,
        line,
    })
}

impl TokenError {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let body = decode_error_info_body(src).await?;

        Ok(TokenError {
            code: body.code,
            state: body.state,
            class: body.class,
            message: body.message,
            server: body.server,
            procedure: body.procedure,
            line: body.line,
        })
    }

    /// The error code, see descriptions from [the manual].
    ///
    /// [the manual]: https://docs.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors?view=sql-server-ver15
    pub fn code(&self) -> u32 {
        self.code
    }

    /// The error state, used as a modifier to the error number.
    pub fn state(&self) -> u8 {
        self.state
    }

    /// The class (severity) of the error. A class of less than 10 indicates an
    /// informational message.
    pub fn class(&self) -> u8 {
        self.class
    }

    /// The error message returned from the server.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The server name.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The name of the stored procedure causing the error.
    pub fn procedure(&self) -> &str {
        &self.procedure
    }

    /// The line number in the SQL batch or stored procedure that caused the
    /// error. Line numbers begin at 1. If the line number is not applicable to
    /// the message, the value is 0.
    pub fn line(&self) -> u32 {
        self.line
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' on server {} executing {} on line {} (code: {}, state: {}, class: {})",
            self.message, self.server, self.procedure, self.line, self.code, self.state, self.class
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TokenError {
        TokenError {
            code: 1205,
            state: 2,
            class: 13,
            message: "deadlocked".to_string(),
            server: "myserver".to_string(),
            procedure: "myproc".to_string(),
            line: 42,
        }
    }

    #[test]
    fn accessors() {
        let e = sample();
        assert_eq!(e.code(), 1205);
        assert_eq!(e.state(), 2);
        assert_eq!(e.class(), 13);
        assert_eq!(e.message(), "deadlocked");
        assert_eq!(e.server(), "myserver");
        assert_eq!(e.procedure(), "myproc");
        assert_eq!(e.line(), 42);
    }

    #[test]
    fn display_contains_all_fields() {
        let rendered = format!("{}", sample());
        assert_eq!(
            rendered,
            "'deadlocked' on server myserver executing myproc on line 42 (code: 1205, state: 2, class: 13)"
        );
    }

    #[tokio::test]
    async fn decode_reads_all_fields_with_four_byte_line_number() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use byteorder::{LittleEndian, WriteBytesExt};
        use bytes::{BufMut, BytesMut};

        fn write_us_varchar(buf: &mut Vec<u8>, s: &str) {
            buf.write_u16::<LittleEndian>(s.encode_utf16().count() as u16)
                .unwrap();
            for u in s.encode_utf16() {
                buf.write_u16::<LittleEndian>(u).unwrap();
            }
        }

        fn write_b_varchar(buf: &mut Vec<u8>, s: &str) {
            buf.push(s.encode_utf16().count() as u8);
            for u in s.encode_utf16() {
                buf.write_u16::<LittleEndian>(u).unwrap();
            }
        }

        let mut body = Vec::new();
        body.write_u32::<LittleEndian>(1205).unwrap(); // code
        body.push(2); // state
        body.push(13); // class
        write_us_varchar(&mut body, "deadlocked");
        write_b_varchar(&mut body, "myserver");
        write_b_varchar(&mut body, "myproc");
        body.write_u32::<LittleEndian>(42).unwrap(); // line, TDS >= 7.2 (default context)

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16); // length prefix, ignored by decode
        buf.put_slice(&body);

        let decoded = TokenError::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(decoded, sample());
    }

    #[tokio::test]
    async fn decode_reads_full_four_byte_line_number_on_tds72_plus() {
        // The default test context reports SqlServerN (>= TDS 7.2), so the
        // LineNumber must be read as a 4-byte LONG. 0x0001_0001 (65537) has
        // distinct low-16-bit and full-32-bit values, so a 2-byte read yields 1
        // while the correct 4-byte read yields 65537.
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use bytes::{BufMut, BytesMut};

        let mut body = BytesMut::new();
        body.put_u32_le(1205); // code
        body.put_u8(2); // state
        body.put_u8(13); // class
        body.put_u16_le(0); // message: us_varchar, length 0
        body.put_u8(0); // server: b_varchar, length 0
        body.put_u8(0); // procedure: b_varchar, length 0
        body.put_u32_le(0x0001_0001); // line number, 4 bytes

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16); // length prefix, ignored by decode
        buf.put_slice(&body);

        let decoded = TokenError::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(decoded.line(), 0x0001_0001);
    }

    #[tokio::test]
    async fn decode_consumes_exactly_length_and_does_not_desync() {
        // Declared Length (6) covers only code+state+class; the message length
        // prefix falls outside it. Decoding must fail with a clean error AND
        // consume exactly `Length` body bytes, so the following byte on the wire
        // (a sentinel here) is still readable — i.e. the stream is not desynced.
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use crate::SqlReadBytes;
        use bytes::{BufMut, BytesMut};

        // The trailing bytes below belong to the *next* token on the wire. A
        // decoder that ignores `Length` (the old behaviour) would greedily read
        // them as this token's message/server/procedure/line and succeed,
        // desyncing the stream. They form a valid trailing field sequence so the
        // old code returns Ok, making `expect_err` a genuine red.
        let mut buf = BytesMut::new();
        buf.put_u16_le(6); // declared Length (too small for the full body)
        buf.put_u32_le(0x1122_3344); // code
        buf.put_u8(0x55); // state
        buf.put_u8(0x66); // class
        buf.put_u16_le(0); // next token: (mis)read as message length 0
        buf.put_u8(0); // next token: (mis)read as server length 0
        buf.put_u8(0); // next token: (mis)read as procedure length 0
        buf.put_u32_le(0x2A); // next token: (mis)read as line
        buf.put_u8(0xEF); // sentinel further along

        let mut reader = buf.into_sql_read_bytes();

        let err = TokenError::decode(&mut reader)
            .await
            .expect_err("under-declared length must be a clean error");
        assert!(matches!(err, Error::Protocol(_) | Error::Io { .. }));

        // Exactly the 6 declared body bytes were consumed, so the first byte of
        // the next token region is still on the wire (no desync).
        assert_eq!(reader.read_u8().await.unwrap(), 0x00);
    }

    #[tokio::test]
    async fn decode_ignores_trailing_bytes_within_declared_length() {
        // Declared Length is larger than the fields consume; the extra bytes are
        // discarded and the next token (sentinel) is read cleanly afterwards.
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use crate::SqlReadBytes;
        use bytes::{BufMut, BytesMut};

        let mut body = BytesMut::new();
        body.put_u32_le(1205); // code
        body.put_u8(2); // state
        body.put_u8(13); // class
        body.put_u16_le(0); // message (empty)
        body.put_u8(0); // server (empty)
        body.put_u8(0); // procedure (empty)
        body.put_u32_le(42); // line
        body.put_u8(0x99); // trailing padding within the declared length

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16);
        buf.put_slice(&body);
        buf.put_u8(0xCD); // sentinel next token

        let mut reader = buf.into_sql_read_bytes();

        let decoded = TokenError::decode(&mut reader)
            .await
            .expect("trailing padding within length must decode");
        assert_eq!(decoded.code(), 1205);
        assert_eq!(decoded.line(), 42);

        assert_eq!(reader.read_u8().await.unwrap(), 0xCD);
    }
}
