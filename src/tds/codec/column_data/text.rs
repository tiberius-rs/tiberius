use crate::{error::Error, sql_read_bytes::SqlReadBytes, tds::Collation, ColumnData};

pub(crate) async fn decode<R>(
    src: &mut R,
    collation: Option<Collation>,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let ptr_len = src.read_u8().await? as usize;

    if ptr_len == 0 {
        return Ok(ColumnData::String(None));
    }

    for _ in 0..ptr_len {
        src.read_u8().await?;
    }

    src.read_i32_le().await?; // days
    src.read_u32_le().await?; // second fractions

    let text = match collation {
        // TEXT
        Some(collation) => {
            let encoder = collation.encoding()?;
            let text_len = src.read_u32_le().await? as usize;
            let mut buf = Vec::with_capacity(text_len.min(super::MAX_PREALLOC));

            for _ in 0..text_len {
                buf.push(src.read_u8().await?);
            }

            encoder
                .decode_without_bom_handling_and_without_replacement(buf.as_ref())
                .ok_or_else(|| Error::Encoding("invalid sequence".into()))?
                .to_string()
        }
        // NTEXT
        None => {
            let text_len = src.read_u32_le().await? as usize / 2;
            // u16 elements; cap the reservation to MAX_PREALLOC bytes' worth.
            let mut buf = Vec::with_capacity(text_len.min(super::MAX_PREALLOC / 2));

            for _ in 0..text_len {
                buf.push(src.read_u16_le().await?);
            }

            String::from_utf16(&buf[..])?
        }
    };

    Ok(ColumnData::String(Some(text.into())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decode_null_when_ptr_len_zero() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);

        let data = decode(&mut buf.into_sql_read_bytes(), None).await.unwrap();
        assert_eq!(data, ColumnData::String(None));
    }

    #[tokio::test]
    async fn decode_ntext_reads_utf16_payload() {
        let mut buf = BytesMut::new();
        buf.put_u8(1); // ptr_len
        buf.put_u8(0xAA); // pointer byte (ignored)
        buf.put_i32_le(0); // days
        buf.put_u32_le(0); // second fractions
        buf.put_u32_le(4); // byte length of the UTF-16 text (2 chars)
        buf.put_u16_le('h' as u16);
        buf.put_u16_le('i' as u16);

        let data = decode(&mut buf.into_sql_read_bytes(), None).await.unwrap();
        assert_eq!(data, ColumnData::String(Some("hi".into())));
    }

    #[tokio::test]
    async fn decode_text_uses_collation_encoding() {
        let mut buf = BytesMut::new();
        buf.put_u8(1); // ptr_len
        buf.put_u8(0xAA);
        buf.put_i32_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(2); // 2 raw bytes in codepage encoding
        buf.put_slice(b"hi");

        let collation = crate::tds::Collation::new(0x0409, 0); // WINDOWS_1252
        let data = decode(&mut buf.into_sql_read_bytes(), Some(collation))
            .await
            .unwrap();
        assert_eq!(data, ColumnData::String(Some("hi".into())));
    }
}
