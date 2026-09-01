use crate::{tds::codec::FeatureLevel, SqlReadBytes};
use std::fmt;

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

impl TokenError {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let _length = src.read_u16_le().await? as usize;

        let code = src.read_u32_le().await?;
        let state = src.read_u8().await?;
        let class = src.read_u8().await?;

        let message = src.read_us_varchar().await?;
        let server = src.read_b_varchar().await?;
        let procedure = src.read_b_varchar().await?;

        // MS-TDS 2.2.7.10: LineNumber is a 4-byte LONG for TDS 7.2 (SQL Server
        // 2005) and later, and a 2-byte USHORT before that. The boundary is
        // inclusive of 7.2, so use `>=` — a strict `>` mis-reads a 2-byte value
        // against a real SQL Server 2005 and desyncs the token stream.
        let line = if src.context().version() >= FeatureLevel::SqlServer2005 {
            src.read_u32_le().await?
        } else {
            src.read_u16_le().await? as u32
        };

        let token = TokenError {
            code,
            state,
            class,
            message,
            server,
            procedure,
            line,
        };

        Ok(token)
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
        // LineNumber must be read as a 4-byte LONG. A `>` mutation of the
        // `>=` boundary check would read only 2 bytes and mis-decode the value.
        // 0x0001_0001 (65537) has distinct low-16-bit and full-32-bit values, so
        // a 2-byte read yields 1 while the correct 4-byte read yields 65537.
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
}
