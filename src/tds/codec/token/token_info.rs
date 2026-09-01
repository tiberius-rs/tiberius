use crate::{tds::codec::FeatureLevel, SqlReadBytes};

#[allow(dead_code)] // we might want to debug the values
#[derive(Debug)]
pub struct TokenInfo {
    /// info number
    pub(crate) number: u32,
    /// error state
    pub(crate) state: u8,
    /// severity (<10: Info)
    pub(crate) class: u8,
    pub(crate) message: String,
    pub(crate) server: String,
    pub(crate) procedure: String,
    pub(crate) line: u32,
}

impl TokenInfo {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let _length = src.read_u16_le().await?;

        let number = src.read_u32_le().await?;
        let state = src.read_u8().await?;
        let class = src.read_u8().await?;
        let message = src.read_us_varchar().await?;
        let server = src.read_b_varchar().await?;
        let procedure = src.read_b_varchar().await?;
        // MS-TDS 2.2.7.13: like ERROR, INFO's LineNumber is a 4-byte LONG for
        // TDS 7.2 (SQL Server 2005) and later, and a 2-byte USHORT before that.
        // Reading a fixed u32 over-reads 2 bytes against a TDS 7.1 server and
        // desyncs the token stream.
        let line = if src.context().version() >= FeatureLevel::SqlServer2005 {
            src.read_u32_le().await?
        } else {
            src.read_u16_le().await? as u32
        };

        Ok(TokenInfo {
            number,
            state,
            class,
            message,
            server,
            procedure,
            line,
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

    fn put_us_varchar(buf: &mut BytesMut, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        buf.put_u16_le(utf16.len() as u16);
        for c in utf16 {
            buf.put_u16_le(c);
        }
    }

    #[tokio::test]
    async fn decodes_all_fields() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0); // length, ignored
        buf.put_u32_le(4711);
        buf.put_u8(2);
        buf.put_u8(9);
        put_us_varchar(&mut buf, "informational");
        put_b_varchar(&mut buf, "server");
        put_b_varchar(&mut buf, "proc");
        buf.put_u32_le(123);

        let info = TokenInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(info.number, 4711);
        assert_eq!(info.state, 2);
        assert_eq!(info.class, 9);
        assert_eq!(info.message, "informational");
        assert_eq!(info.server, "server");
        assert_eq!(info.procedure, "proc");
        assert_eq!(info.line, 123);
    }

    #[tokio::test]
    async fn decode_reads_full_four_byte_line_number_on_tds72_plus() {
        // The default test context reports SqlServerN (>= TDS 7.2), so the
        // LineNumber must be read as a 4-byte LONG. A `>` mutation of the `>=`
        // boundary check would read only 2 bytes. 0x0001_0001 (65537) reads as 1
        // when truncated to 2 bytes but as 65537 when read correctly as 4 bytes.
        let mut buf = BytesMut::new();
        buf.put_u16_le(0); // length, ignored
        buf.put_u32_le(4711);
        buf.put_u8(2);
        buf.put_u8(9);
        put_us_varchar(&mut buf, "informational");
        put_b_varchar(&mut buf, "server");
        put_b_varchar(&mut buf, "proc");
        buf.put_u32_le(0x0001_0001);

        let info = TokenInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(info.line, 0x0001_0001);
    }
}
