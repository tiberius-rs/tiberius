use crate::{Error, SqlReadBytes};

/// A multi-part table name as sent inside a [`TokenTabName`].
///
/// Each name is composed of one or more parts, ordered from the most
/// significant to the least significant, for example
/// `[database].[schema].[table]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableName {
    parts: Vec<String>,
}

impl TableName {
    /// The individual parts of the table name, ordered from the most
    /// significant (for example the database name) to the least significant
    /// (the table name itself).
    #[allow(dead_code)]
    pub fn parts(&self) -> &[String] {
        &self.parts
    }
}

/// The `TABNAME` token (`0xA4`, MS-TDS §2.2.7.21).
///
/// Sent by the server to convey the table name(s) that back a result set. It
/// is only produced in browse mode (a `SELECT ... FOR BROWSE` query or a
/// connection with `SET NO_BROWSETABLE ON`) and is used together with the
/// [`ColInfo`](crate::tds::codec::TokenType::ColInfo) token, whose entries
/// reference tables by their one-based index in this token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTabName {
    tables: Vec<TableName>,
}

impl TokenTabName {
    /// The table names carried by this token, in the order the server sent
    /// them. `ColInfo` table indexes are one-based positions into this slice.
    #[allow(dead_code)]
    pub fn tables(&self) -> &[TableName] {
        &self.tables
    }

    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // `Length` is the number of bytes of token data that follow. Read the
        // whole payload up front and parse it in memory so that the exact
        // number of bytes is always consumed, regardless of how many table
        // names are packed into the token.
        let len = src.read_u16_le().await? as usize;

        let mut data = vec![0u8; len];
        for byte in data.iter_mut() {
            *byte = src.read_u8().await?;
        }

        Self::parse(&data)
    }

    /// Parse the `TABNAME` token payload (the bytes following the `Length`
    /// field).
    ///
    /// Each table name is encoded as a `NumParts` byte followed by that many
    /// `US_VARCHAR` parts (a `USHORT` UTF-16 code-unit count followed by the
    /// UTF-16LE characters).
    fn parse(data: &[u8]) -> crate::Result<Self> {
        let mut tables = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let num_parts = data[pos];
            pos += 1;

            let mut parts = Vec::with_capacity(num_parts as usize);

            for _ in 0..num_parts {
                if pos + 2 > data.len() {
                    return Err(Error::Protocol(
                        "TABNAME token truncated while reading part length".into(),
                    ));
                }

                let char_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;

                let byte_count = char_count * 2;

                if pos + byte_count > data.len() {
                    return Err(Error::Protocol(
                        "TABNAME token truncated while reading part name".into(),
                    ));
                }

                let mut units = Vec::with_capacity(char_count);
                for _ in 0..char_count {
                    units.push(u16::from_le_bytes([data[pos], data[pos + 1]]));
                    pos += 2;
                }

                let part = String::from_utf16(&units).map_err(|_| {
                    Error::Protocol("TABNAME token part is not valid UTF-16".into())
                })?;

                parts.push(part);
            }

            tables.push(TableName { parts });
        }

        Ok(TokenTabName { tables })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn us_varchar(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = Vec::new();
        out.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    #[test]
    fn parse_single_multipart_table() {
        let mut data = Vec::new();
        // NumParts = 3
        data.push(3u8);
        data.extend_from_slice(&us_varchar("mydb"));
        data.extend_from_slice(&us_varchar("dbo"));
        data.extend_from_slice(&us_varchar("Customers"));

        let token = TokenTabName::parse(&data).expect("must parse");

        assert_eq!(token.tables().len(), 1);
        assert_eq!(
            token.tables()[0].parts(),
            &[
                "mydb".to_string(),
                "dbo".to_string(),
                "Customers".to_string()
            ]
        );
    }

    #[test]
    fn parse_multiple_tables() {
        let mut data = Vec::new();
        // First table: single part.
        data.push(1u8);
        data.extend_from_slice(&us_varchar("Orders"));
        // Second table: two parts.
        data.push(2u8);
        data.extend_from_slice(&us_varchar("dbo"));
        data.extend_from_slice(&us_varchar("Products"));

        let token = TokenTabName::parse(&data).expect("must parse");

        assert_eq!(token.tables().len(), 2);
        assert_eq!(token.tables()[0].parts(), &["Orders".to_string()]);
        assert_eq!(
            token.tables()[1].parts(),
            &["dbo".to_string(), "Products".to_string()]
        );
    }

    #[test]
    fn parse_empty_payload() {
        let token = TokenTabName::parse(&[]).expect("must parse");
        assert!(token.tables().is_empty());
    }

    #[test]
    fn parse_truncated_length_fails() {
        // NumParts says 1 part but no length bytes follow.
        let data = vec![1u8];
        assert!(TokenTabName::parse(&data).is_err());
    }

    #[test]
    fn parse_truncated_name_fails() {
        // NumParts = 1, claims a 4-code-unit name but provides no bytes.
        let mut data = vec![1u8];
        data.extend_from_slice(&4u16.to_le_bytes());
        assert!(TokenTabName::parse(&data).is_err());
    }

    #[tokio::test]
    async fn decode_reads_length_prefixed_payload() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use bytes::BytesMut;

        let mut payload = Vec::new();
        payload.push(2u8);
        payload.extend_from_slice(&us_varchar("dbo"));
        payload.extend_from_slice(&us_varchar("Invoices"));

        let mut wire = BytesMut::new();
        wire.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        wire.extend_from_slice(&payload);

        let token = TokenTabName::decode(&mut wire.into_sql_read_bytes())
            .await
            .expect("decode must succeed");

        assert_eq!(token.tables().len(), 1);
        assert_eq!(
            token.tables()[0].parts(),
            &["dbo".to_string(), "Invoices".to_string()]
        );
    }
}
