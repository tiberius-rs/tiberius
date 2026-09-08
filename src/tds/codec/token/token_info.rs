use super::token_error::decode_error_info_body;
use crate::SqlReadBytes;

// Fields are decoded from the INFO token and logged at DEBUG on receipt, but
// are not otherwise read; retained for `Debug` diagnostics and future surfacing
// of server informational messages to callers.
#[allow(dead_code)]
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
        // INFO and ERROR share an identical body layout (MS-TDS §2.2.7.13 /
        // §2.2.7.10); reuse the shared, length-bounded decoder. `number` is the
        // INFO spelling of ERROR's `code` field.
        let body = decode_error_info_body(src).await?;

        Ok(TokenInfo {
            number: body.code,
            state: body.state,
            class: body.class,
            message: body.message,
            server: body.server,
            procedure: body.procedure,
            line: body.line,
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
        let mut body = BytesMut::new();
        body.put_u32_le(4711);
        body.put_u8(2);
        body.put_u8(9);
        put_us_varchar(&mut body, "informational");
        put_b_varchar(&mut body, "server");
        put_b_varchar(&mut body, "proc");
        body.put_u32_le(123);

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16); // declared Length
        buf.put_slice(&body);

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
        // LineNumber must be read as a 4-byte LONG. 0x0001_0001 (65537) reads as 1
        // when truncated to 2 bytes but as 65537 when read correctly as 4 bytes.
        let mut body = BytesMut::new();
        body.put_u32_le(4711);
        body.put_u8(2);
        body.put_u8(9);
        put_us_varchar(&mut body, "informational");
        put_b_varchar(&mut body, "server");
        put_b_varchar(&mut body, "proc");
        body.put_u32_le(0x0001_0001);

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16); // declared Length
        buf.put_slice(&body);

        let info = TokenInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(info.line, 0x0001_0001);
    }
}
