use crate::SqlReadBytes;

/// The column is the result of an expression rather than a direct reference to
/// a base-table column (`fExpression`).
const STATUS_EXPRESSION: u8 = 0x04;
/// The column is part of a key for the associated table (`fKey`).
const STATUS_KEY: u8 = 0x08;
/// The column was not requested, but was added because it is part of a key for
/// the associated table (`fHidden`).
const STATUS_HIDDEN: u8 = 0x10;
/// The column name is different from the name of the base-table column it was
/// derived from (`fDifferentName`). When set, the entry carries a `ColName`.
const STATUS_DIFFERENT_NAME: u8 = 0x20;

/// A single column description within a [`TokenColInfo`] token.
#[allow(dead_code)] // informational: exposed for debugging/browse-mode consumers
#[derive(Debug, Clone)]
pub struct ColInfo {
    /// The column number in the result set (1-based).
    pub(crate) col_num: u8,
    /// The number of the base table the column was derived from, as an index
    /// into the table names carried by a preceding `TABNAME` token. Zero when
    /// the column is not derived from a table column.
    pub(crate) table_num: u8,
    /// The raw status bitmap for this column.
    pub(crate) status: u8,
    /// The base-table column name, present only when
    /// [`ColInfo::has_different_name`] is `true`.
    pub(crate) col_name: Option<String>,
}

#[allow(dead_code)] // informational accessors for browse-mode consumers
impl ColInfo {
    /// Whether the column is the result of an expression (`fExpression`).
    pub(crate) fn is_expression(&self) -> bool {
        self.status & STATUS_EXPRESSION != 0
    }

    /// Whether the column is part of a key (`fKey`).
    pub(crate) fn is_key(&self) -> bool {
        self.status & STATUS_KEY != 0
    }

    /// Whether the column was added implicitly because it is part of a key
    /// (`fHidden`).
    pub(crate) fn is_hidden(&self) -> bool {
        self.status & STATUS_HIDDEN != 0
    }

    /// Whether the column carries a differing base-table name (`fDifferentName`).
    pub(crate) fn has_different_name(&self) -> bool {
        self.status & STATUS_DIFFERENT_NAME != 0
    }
}

/// The `COLINFO` token (`0xA5`), sent by the server in browse mode to describe
/// the origin of each column in the result set.
///
/// See MS-TDS §2.2.7.4. This token is informational; it is decoded so the
/// token stream does not error out when browse-mode metadata is returned.
#[allow(dead_code)] // informational: consumed by the token stream, exposed for debugging
#[derive(Debug, Clone)]
pub struct TokenColInfo {
    /// One entry per column in the current result set.
    pub(crate) columns: Vec<ColInfo>,
}

impl TokenColInfo {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // Total length in bytes of the column-info entries that follow.
        let length = src.read_u16_le().await? as usize;

        let mut consumed = 0usize;
        let mut columns = Vec::new();

        while consumed < length {
            let col_num = src.read_u8().await?;
            let table_num = src.read_u8().await?;
            let status = src.read_u8().await?;
            consumed += 3;

            let col_name = if status & STATUS_DIFFERENT_NAME != 0 {
                // ColName is a B_VARCHAR: a byte length (in UCS-2 characters)
                // followed by that many little-endian UTF-16 code units.
                let char_len = src.read_u8().await? as usize;
                consumed += 1;

                let mut units = Vec::with_capacity(char_len);
                for _ in 0..char_len {
                    units.push(src.read_u16_le().await?);
                }
                consumed += char_len * 2;

                Some(String::from_utf16_lossy(&units))
            } else {
                None
            };

            columns.push(ColInfo {
                col_num,
                table_num,
                status,
                col_name,
            });
        }

        Ok(TokenColInfo { columns })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decode_col_info_with_and_without_names() {
        let mut buf = BytesMut::new();

        // Placeholder for the u16 length prefix; filled in after the body.
        let mut body = BytesMut::new();

        // Column 1: derived directly from base table 1, no different name.
        body.put_u8(1); // ColNum
        body.put_u8(1); // TableNum
        body.put_u8(STATUS_KEY); // Status: part of a key

        // Column 2: expression + different name "Id".
        body.put_u8(2); // ColNum
        body.put_u8(0); // TableNum (not from a table)
        body.put_u8(STATUS_EXPRESSION | STATUS_DIFFERENT_NAME); // Status
        body.put_u8(2); // ColName length in characters
        body.put_u16_le(u16::from(b'I'));
        body.put_u16_le(u16::from(b'd'));

        buf.put_u16_le(body.len() as u16);
        buf.extend_from_slice(&body);

        let mut reader = buf.into_sql_read_bytes();
        let token = TokenColInfo::decode(&mut reader).await.unwrap();

        assert_eq!(token.columns.len(), 2);

        let first = &token.columns[0];
        assert_eq!(first.col_num, 1);
        assert_eq!(first.table_num, 1);
        assert!(first.is_key());
        assert!(!first.has_different_name());
        assert_eq!(first.col_name, None);

        let second = &token.columns[1];
        assert_eq!(second.col_num, 2);
        assert_eq!(second.table_num, 0);
        assert!(second.is_expression());
        assert!(second.has_different_name());
        assert!(!second.is_hidden());
        assert_eq!(second.col_name.as_deref(), Some("Id"));
    }
}
