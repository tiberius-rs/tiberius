mod bytes_mut_with_data_columns;
mod into_row;
use crate::tds::codec::encode::Encode;
use crate::{tds::codec::ColumnData, BytesMutWithTypeInfo, SqlReadBytes, TokenType};
use bytes::BufMut;
pub(crate) use bytes_mut_with_data_columns::BytesMutWithDataColumns;
use futures_util::io::AsyncReadExt;
pub use into_row::IntoRow;

/// A row of data.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenRow<'a> {
    data: Vec<ColumnData<'a>>,
}

impl<'a> IntoIterator for TokenRow<'a> {
    type Item = ColumnData<'a>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a> Encode<BytesMutWithDataColumns<'a>> for TokenRow<'a> {
    fn encode(self, dst: &mut BytesMutWithDataColumns<'a>) -> crate::Result<()> {
        dst.put_u8(TokenType::Row as u8);

        if self.data.len() != dst.data_columns().len() {
            return Err(crate::Error::BulkInput(
                format!(
                    "Expecting {} columns but {} were given",
                    dst.data_columns().len(),
                    self.data.len()
                )
                .into(),
            ));
        }

        for (value, column) in self.data.into_iter().zip(dst.data_columns()) {
            let mut dst_ti = BytesMutWithTypeInfo::new(dst).with_type_info(&column.base.ty);
            value.encode(&mut dst_ti)?
        }

        Ok(())
    }
}

impl<'a> TokenRow<'a> {
    /// Creates a new empty row.
    pub const fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Creates a new empty row with allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Clears the row, removing all column values.
    ///
    /// Note that this method has no effect on the allocated capacity of the row.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// The number of columns.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns an iterator over column values.
    pub fn iter(&self) -> std::slice::Iter<'_, ColumnData<'a>> {
        self.data.iter()
    }

    /// True if row has no columns.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Gets the columnar data with the given index. `None` if index out of
    /// bounds.
    pub fn get(&self, index: usize) -> Option<&ColumnData<'a>> {
        self.data.get(index)
    }

    /// Adds a new value to the row.
    pub fn push(&mut self, value: ColumnData<'a>) {
        self.data.push(value);
    }
}

impl TokenRow<'static> {
    /// Normal row. We'll read the metadata what we've cached and parse columns
    /// based on that.
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let col_meta = src.context().last_meta().ok_or_else(|| {
            crate::Error::Protocol("ROW token arrived before any COLMETADATA".into())
        })?;

        let mut row = Self {
            data: Vec::with_capacity(col_meta.columns.len()),
        };

        for column in col_meta.columns.iter() {
            let data = ColumnData::decode(src, &column.base.ty).await?;
            row.data.push(data);
        }

        Ok(row)
    }

    /// SQL Server has packed nulls on this row type. We'll read what columns
    /// are null from the bitmap.
    pub(crate) async fn decode_nbc<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let col_meta = src.context().last_meta().ok_or_else(|| {
            crate::Error::Protocol("NBCROW token arrived before any COLMETADATA".into())
        })?;
        let row_bitmap = RowBitmap::decode(src, col_meta.columns.len()).await?;

        let mut row = Self {
            data: Vec::with_capacity(col_meta.columns.len()),
        };

        for (i, column) in col_meta.columns.iter().enumerate() {
            let data = if row_bitmap.is_null(i) {
                column.base.null_value()
            } else {
                ColumnData::decode(src, &column.base.ty).await?
            };

            row.data.push(data);
        }

        Ok(row)
    }
}

/// A bitmap of null values in the row. Sometimes SQL Server decides to pack the
/// null values in the row, calling it the NBCROW. In this kind of tokens the row
/// itself skips the null columns completely, but they can be found from the bitmap
/// stored in the beginning of the token.
///
/// One byte can store eight bits of information. Bits with value of one being null.
///
/// If our row has eight columns, and our byte in bits is:
///
/// ```ignore
/// 1 0 0 1 0 1 0 0
/// ```
///
/// This would mean columns 0, 3 and 5 are null and should not be parsed at all.
/// For more than eight columns, more bits need to be reserved for the bitmap
/// (see the size calculation).
struct RowBitmap {
    data: Vec<u8>,
}

impl RowBitmap {
    /// Is the given column index null or not.
    #[inline]
    fn is_null(&self, i: usize) -> bool {
        let index = i / 8;
        let bit = i % 8;

        self.data[index] & (1 << bit) > 0
    }

    /// Decode the bitmap data from the beginning of the row. Only doable if the
    /// type is `NbcRowToken`.
    async fn decode<R>(src: &mut R, columns: usize) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let size = columns.div_ceil(8);
        let mut data = vec![0; size];
        src.read_exact(&mut data[0..size]).await?;

        Ok(Self { data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BaseMetaDataColumn, ColumnFlag, FixedLenType, MetaDataColumn, TypeInfo};
    use bytes::BytesMut;

    #[tokio::test]
    async fn wrong_number_of_columns_will_fail() {
        let row = (true, 5).into_row();
        let columns = vec![MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::FixedLen(FixedLenType::Bit),
                table_name: None,
            },
            col_name: Default::default(),
        }];
        let mut buf = BytesMut::new();
        let mut buf_with_columns = BytesMutWithDataColumns::new(&mut buf, &columns);

        row.encode(&mut buf_with_columns)
            .expect_err("wrong number of columns");
    }

    // A row whose encoding fails partway (here: an out-of-range money value in
    // the second column, after the Row token byte and first column are already
    // written) must be rolled back by the caller so the bulk stream stays in
    // sync. This mirrors `BulkLoadRequest::send`'s snapshot-and-truncate logic.
    #[tokio::test]
    async fn partial_row_can_be_rolled_back_on_encode_error() {
        use crate::tds::codec::type_info::VarLenContext;
        use crate::{ColumnData, VarLenType};

        let columns = vec![
            MetaDataColumn {
                base: BaseMetaDataColumn {
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::FixedLen(FixedLenType::Int4),
                    table_name: None,
                },
                col_name: Default::default(),
            },
            MetaDataColumn {
                base: BaseMetaDataColumn {
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None)),
                    table_name: None,
                },
                col_name: Default::default(),
            },
        ];

        // Pretend some earlier, fully-encoded rows already sit in the buffer.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let snapshot = buf.to_vec();
        let start = buf.len();

        let mut row = TokenRow::new();
        row.push(ColumnData::I32(Some(1)));
        row.push(ColumnData::F64(Some(1e18))); // out of range for money

        let mut buf_with_columns = BytesMutWithDataColumns::new(&mut buf, &columns);
        let err = row.encode(&mut buf_with_columns).unwrap_err();
        assert!(matches!(err, crate::Error::BulkInput(_)), "got {err:?}");

        // Partial bytes (Row token + first column) were written...
        assert!(buf.len() > start, "expected a partial row to be present");
        // ...and truncating back to the snapshot restores the buffer exactly.
        buf.truncate(start);
        assert_eq!(buf.to_vec(), snapshot);
    }

    #[tokio::test]
    async fn row_before_colmetadata_is_protocol_error() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        // No COLMETADATA has been seen, so last_meta() is None: decoding a ROW
        // must be a protocol error rather than an unwrap() panic.
        let buf = BytesMut::new();
        let err = TokenRow::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("ROW before COLMETADATA must error");
        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    #[test]
    fn basic_container_operations() {
        let mut row = TokenRow::new();
        assert!(row.is_empty());
        assert_eq!(row.len(), 0);
        assert_eq!(row.get(0), None);

        row.push(ColumnData::I32(Some(1)));
        row.push(ColumnData::I32(Some(2)));
        assert_eq!(row.len(), 2);
        assert!(!row.is_empty());
        assert_eq!(row.get(0), Some(&ColumnData::I32(Some(1))));
        assert_eq!(row.get(5), None);

        let collected: Vec<_> = row.iter().collect();
        assert_eq!(collected.len(), 2);

        row.clear();
        assert!(row.is_empty());

        let with_cap = TokenRow::with_capacity(4);
        assert!(with_cap.is_empty());
    }

    #[test]
    fn with_capacity_preallocates() {
        // with_capacity must actually reserve room; Default::default() would
        // give a zero-capacity vec.
        let row = TokenRow::with_capacity(16);
        assert!(row.is_empty());
        assert!(row.data.capacity() >= 16);
    }

    #[test]
    fn row_bitmap_is_null_checks_correct_bit() {
        // Only bit 3 is set in the single bitmap byte; is_null must consult that
        // exact bit.
        let bitmap = RowBitmap {
            data: vec![0b0000_1000],
        };

        assert!(bitmap.is_null(3));
        assert!(!bitmap.is_null(0));
        assert!(!bitmap.is_null(1));
        assert!(!bitmap.is_null(2));
        assert!(!bitmap.is_null(4));
    }

    #[test]
    fn into_iter_yields_owned_values() {
        let mut row = TokenRow::new();
        row.push(ColumnData::I32(Some(1)));
        row.push(ColumnData::I32(Some(2)));

        let values: Vec<_> = row.into_iter().collect();
        assert_eq!(
            values,
            vec![ColumnData::I32(Some(1)), ColumnData::I32(Some(2))]
        );
    }

    #[tokio::test]
    async fn encode_matching_columns_round_trip() {
        let row = (true, 5i32).into_row();
        let columns = vec![
            MetaDataColumn {
                base: BaseMetaDataColumn {
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::FixedLen(FixedLenType::Bit),
                    table_name: None,
                },
                col_name: Default::default(),
            },
            MetaDataColumn {
                base: BaseMetaDataColumn {
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::FixedLen(FixedLenType::Int4),
                    table_name: None,
                },
                col_name: Default::default(),
            },
        ];
        let mut buf = BytesMut::new();
        let mut buf_with_columns = BytesMutWithDataColumns::new(&mut buf, &columns);

        row.encode(&mut buf_with_columns).unwrap();
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn decode_reads_columns_from_cached_meta() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use crate::tds::codec::TokenColMetaData;
        use std::sync::Arc;

        let col_meta = TokenColMetaData {
            columns: vec![MetaDataColumn {
                base: BaseMetaDataColumn {
                    flags: ColumnFlag::Nullable.into(),
                    ty: TypeInfo::FixedLen(FixedLenType::Int4),
                    table_name: None,
                },
                col_name: Default::default(),
            }],
        };

        let mut buf = BytesMut::new();
        buf.put_i32_le(42);

        let mut reader = buf.into_sql_read_bytes();
        reader.context_mut().set_last_meta(Arc::new(col_meta));

        let row = TokenRow::decode(&mut reader).await.unwrap();
        assert_eq!(row.len(), 1);
        assert_eq!(row.get(0), Some(&ColumnData::I32(Some(42))));
    }

    #[tokio::test]
    async fn decode_nbc_before_colmetadata_is_protocol_error() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

        let buf = BytesMut::new();
        let err = TokenRow::decode_nbc(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("NBCROW before COLMETADATA must error");
        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    #[tokio::test]
    async fn decode_nbc_uses_bitmap_for_nulls() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use crate::tds::codec::TokenColMetaData;
        use std::sync::Arc;

        // Two int columns: first null (bit 0 set), second present (value 7).
        let col_meta = TokenColMetaData {
            columns: vec![
                MetaDataColumn {
                    base: BaseMetaDataColumn {
                        flags: ColumnFlag::Nullable.into(),
                        ty: TypeInfo::FixedLen(FixedLenType::Int4),
                        table_name: None,
                    },
                    col_name: Default::default(),
                },
                MetaDataColumn {
                    base: BaseMetaDataColumn {
                        flags: ColumnFlag::Nullable.into(),
                        ty: TypeInfo::FixedLen(FixedLenType::Int4),
                        table_name: None,
                    },
                    col_name: Default::default(),
                },
            ],
        };

        let mut buf = BytesMut::new();
        buf.put_u8(0b0000_0001); // bitmap: column 0 is null
        buf.put_i32_le(7); // column 1's value

        let mut reader = buf.into_sql_read_bytes();
        reader.context_mut().set_last_meta(Arc::new(col_meta));

        let row = TokenRow::decode_nbc(&mut reader).await.unwrap();
        assert_eq!(row.len(), 2);
        assert_eq!(row.get(0), Some(&ColumnData::I32(None)));
        assert_eq!(row.get(1), Some(&ColumnData::I32(Some(7))));
    }
}
