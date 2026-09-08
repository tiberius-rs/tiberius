use crate::{
    tds::codec::{ColumnData, TokenAltMetaData},
    SqlReadBytes,
};

/// A row of computed data produced by a COMPUTE (BY) clause (`ALTROW`, token
/// `0xD3`).
///
/// The row refers back, through [`id`](Self::id), to the
/// [`TokenAltMetaData`](crate::tds::codec::TokenAltMetaData) that describes the
/// type of each value. See [MS-TDS] section 2.2.7.2.
///
/// [MS-TDS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
#[derive(Debug, Clone)]
pub struct TokenAltRow<'a> {
    /// Identifies the COMPUTE clause (and thus the `ALTMETADATA`) this row
    /// belongs to.
    pub id: u16,
    data: Vec<ColumnData<'a>>,
}

impl<'a> TokenAltRow<'a> {
    /// The id of the COMPUTE clause this row belongs to.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// The number of computed columns in the row.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True if the row has no columns.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns an iterator over the computed column values.
    pub fn iter(&self) -> std::slice::Iter<'_, ColumnData<'a>> {
        self.data.iter()
    }

    /// Gets the computed value at the given index, `None` if out of bounds.
    pub fn get(&self, index: usize) -> Option<&ColumnData<'a>> {
        self.data.get(index)
    }
}

impl TokenAltRow<'static> {
    /// Decodes the column values of an `ALTROW` for the COMPUTE clause `id`,
    /// using the previously received [`TokenAltMetaData`] that describes it.
    ///
    /// The `id` is read from the wire separately (by the token stream) so that
    /// the correct metadata can be looked up before the values are parsed.
    pub(crate) async fn decode<R>(
        src: &mut R,
        id: u16,
        meta: &TokenAltMetaData<'static>,
    ) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let mut data = Vec::with_capacity(meta.columns.len());

        for column in meta.columns.iter() {
            data.push(ColumnData::decode(src, &column.base.ty).await?);
        }

        Ok(TokenAltRow { id, data })
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{
        sql_read_bytes::test_utils::IntoSqlReadBytes, AltMetaDataColumn, BaseMetaDataColumn,
        ColumnFlag, FixedLenType, TypeInfo,
    };
    use bytes::{BufMut, BytesMut};

    fn int_alt_meta() -> TokenAltMetaData<'static> {
        TokenAltMetaData {
            id: 1,
            by_columns: vec![],
            columns: vec![AltMetaDataColumn {
                op: 0x4f, // SUM
                operand: 1,
                base: BaseMetaDataColumn {
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::FixedLen(FixedLenType::Int4),
                    table_name: None,
                },
                col_name: Cow::from("sum"),
            }],
        }
    }

    #[tokio::test]
    async fn decode_alt_row_reads_values() {
        let meta = int_alt_meta();

        let mut buf = BytesMut::new();
        buf.put_i32_le(42); // the single Int4 computed value

        let mut reader = buf.into_sql_read_bytes();
        let row = TokenAltRow::decode(&mut reader, meta.id, &meta)
            .await
            .unwrap();

        assert_eq!(1, row.id());
        assert_eq!(1, row.len());
        assert!(matches!(row.get(0), Some(ColumnData::I32(Some(42)))));
    }

    #[test]
    fn accessors_reflect_id_and_columns() {
        // Empty row: id must be the stored value (not a hardcoded 1), len 0,
        // is_empty true.
        let empty = TokenAltRow {
            id: 5,
            data: vec![],
        };
        assert_eq!(empty.id(), 5);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());

        // Non-empty row with a distinct id and two columns: len 2, is_empty
        // false.
        let filled = TokenAltRow {
            id: 9,
            data: vec![ColumnData::I32(Some(10)), ColumnData::I32(Some(20))],
        };
        assert_eq!(filled.id(), 9);
        assert_eq!(filled.len(), 2);
        assert!(!filled.is_empty());
    }
}
