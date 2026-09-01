use crate::{sql_read_bytes::SqlReadBytes, ColumnData, FixedLenType};

pub(crate) async fn decode<R>(
    src: &mut R,
    r#type: &FixedLenType,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let data = match r#type {
        // Wire type 0x1F (MS-TDS 2.2.5.4.1) carries no data and represents a
        // typeless NULL. Surface it as `I32(None)` to match both the NBCROW
        // packed-null path (`BaseMetaDataColumn::null_value`) and the column's
        // own `Display` ("int"); previously this ROW path returned `Bit(None)`,
        // so the same `SELECT NULL` column decoded to a different variant
        // depending on whether the server packed the row.
        FixedLenType::Null => ColumnData::I32(None),
        FixedLenType::Bit => ColumnData::Bit(Some(src.read_u8().await? != 0)),
        FixedLenType::Int1 => ColumnData::U8(Some(src.read_u8().await?)),
        FixedLenType::Int2 => ColumnData::I16(Some(src.read_i16_le().await?)),
        FixedLenType::Int4 => ColumnData::I32(Some(src.read_i32_le().await?)),
        FixedLenType::Int8 => ColumnData::I64(Some(src.read_i64_le().await?)),
        FixedLenType::Float4 => ColumnData::F32(Some(src.read_f32_le().await?)),
        FixedLenType::Float8 => ColumnData::F64(Some(src.read_f64_le().await?)),
        FixedLenType::Datetime => super::datetimen::decode(src, 8, 8).await?,
        FixedLenType::Datetime4 => super::datetimen::decode(src, 4, 8).await?,
        FixedLenType::Money4 => super::money::decode(src, 4).await?,
        FixedLenType::Money => super::money::decode(src, 8).await?,
    };

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    #[tokio::test]
    async fn null_decodes_as_i32_none() {
        // FixedLenType::Null (0x1F) carries no bytes and must decode to
        // `I32(None)`, consistent with the NBCROW `null_value()` path and the
        // column's `Display` ("int").
        let buf = BytesMut::new();
        let data = decode(&mut buf.into_sql_read_bytes(), &FixedLenType::Null)
            .await
            .expect("null decode must succeed");
        assert!(matches!(data, ColumnData::I32(None)));
    }
}
