use std::borrow::Cow;

use crate::{tds::codec::BaseMetaDataColumn, SqlReadBytes};

/// A column produced by a COMPUTE clause, as described by an
/// [`TokenAltMetaData`] (`ALTMETADATA`, token `0x88`) stream.
///
/// In addition to the regular column metadata, each computed column carries the
/// aggregate operator (`op`) that produced it (for example `SUM`, `AVG`,
/// `COUNT`) and the operand column number (`operand`) the operator was applied
/// to. See [MS-TDS] section 2.2.7.1.
///
/// [MS-TDS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
#[derive(Debug, Clone)]
pub struct AltMetaDataColumn<'a> {
    /// The aggregate operator that produced this column (`Op` in [MS-TDS]).
    pub op: u8,
    /// The column number in the originating result set that the aggregate
    /// operator was applied to (`Operand` in [MS-TDS]).
    pub operand: u16,
    /// The regular column metadata (flags, type information).
    pub base: BaseMetaDataColumn,
    /// The name of the computed column.
    pub col_name: Cow<'a, str>,
}

/// The token describing the layout of a COMPUTE (BY) result set
/// (`ALTMETADATA`, token `0x88`).
///
/// A single query can contain more than one COMPUTE clause; each is uniquely
/// identified by [`id`](Self::id), which the matching [`TokenAltRow`] rows refer
/// back to. See [MS-TDS] section 2.2.7.1.
///
/// [`TokenAltRow`]: crate::tds::codec::TokenAltRow
/// [MS-TDS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
#[derive(Debug, Clone)]
pub struct TokenAltMetaData<'a> {
    /// Identifies the COMPUTE clause this metadata describes. The associated
    /// [`TokenAltRow`](crate::tds::codec::TokenAltRow) rows carry the same id.
    pub id: u16,
    /// The column numbers (from the originating result set) listed in the
    /// COMPUTE `BY` clause, in order.
    pub by_columns: Vec<u16>,
    /// The computed columns, one per aggregate operator in the COMPUTE clause.
    pub columns: Vec<AltMetaDataColumn<'a>>,
}

impl TokenAltMetaData<'static> {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // Number of computed columns, e.g. `COMPUTE SUM(x), AVG(x)` -> 2.
        let column_count = src.read_u16_le().await?;

        // Identifies the COMPUTE clause; referenced by the ALTROW token.
        let id = src.read_u16_le().await?;

        // Number of grouping columns in the `BY` list.
        let by_cols = src.read_u8().await?;

        let mut by_columns = Vec::with_capacity(by_cols as usize);
        for _ in 0..by_cols {
            by_columns.push(src.read_u16_le().await?);
        }

        // `column_count` is an untrusted u16 (up to 65535); cap the up-front
        // reservation so a hostile ALTMETADATA token can't force a large
        // transient allocation before the column data has arrived. The Vec
        // still grows as real columns are decoded.
        let mut columns = Vec::with_capacity(
            (column_count as usize).min(crate::tds::codec::column_data::MAX_PREALLOC),
        );
        for _ in 0..column_count {
            let op = src.read_u8().await?;
            let operand = src.read_u16_le().await?;

            let base = BaseMetaDataColumn::decode(src).await?;
            let col_name = Cow::from(src.read_b_varchar().await?);

            columns.push(AltMetaDataColumn {
                op,
                operand,
                base,
                col_name,
            });
        }

        Ok(TokenAltMetaData {
            id,
            by_columns,
            columns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sql_read_bytes::test_utils::IntoSqlReadBytes, tds::codec::TypeInfo, FixedLenType};
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decode_alt_meta_data_single_sum_column() {
        // `SELECT ... COMPUTE SUM(x) BY y` style metadata for one Int4 column.
        let mut buf = BytesMut::new();

        buf.put_u16_le(1); // column count (one aggregate)
        buf.put_u16_le(7); // compute id
        buf.put_u8(1); // by_cols
        buf.put_u16_le(2); // BY column number

        // ComputeData for the single column:
        buf.put_u8(0x4f); // Op = SUM
        buf.put_u16_le(1); // Operand column number

        // BaseMetaDataColumn: user type (u32), flags (u16), TYPE_INFO
        buf.put_u32_le(0); // user type
        buf.put_u16_le(0x0001); // flags (Nullable)
        buf.put_u8(FixedLenType::Int4 as u8); // TYPE_INFO: INT4TYPE

        // ColName as B_VARCHAR (length in chars, then UTF-16LE)
        let name: Vec<u16> = "sum".encode_utf16().collect();
        buf.put_u8(name.len() as u8);
        for c in name {
            buf.put_u16_le(c);
        }

        let mut reader = buf.into_sql_read_bytes();
        let meta = TokenAltMetaData::decode(&mut reader).await.unwrap();

        assert_eq!(7, meta.id);
        assert_eq!(vec![2], meta.by_columns);
        assert_eq!(1, meta.columns.len());

        let col = &meta.columns[0];
        assert_eq!(0x4f, col.op);
        assert_eq!(1, col.operand);
        assert_eq!("sum", col.col_name);
        assert!(matches!(
            col.base.ty,
            TypeInfo::FixedLen(FixedLenType::Int4)
        ));
    }
}
