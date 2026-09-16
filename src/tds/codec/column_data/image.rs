use crate::{sql_read_bytes::SqlReadBytes, ColumnData};

pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let ptr_len = src.read_u8().await? as usize;

    if ptr_len == 0 {
        return Ok(ColumnData::Binary(None));
    }

    // Skip the text pointer (packet-aware bulk read into a throwaway buffer).
    let mut ptr = Vec::new();
    crate::sql_read_bytes::read_bytes_into(src, &mut ptr, ptr_len, super::MAX_PREALLOC).await?;

    src.read_i32_le().await?; // days
    src.read_u32_le().await?; // second fractions

    let len = src.read_u32_le().await? as usize;
    // `len` is untrusted; the bulk reader caps the up-front reservation (see
    // MAX_PREALLOC) and grows in bounded windows as bytes arrive.
    let mut buf = Vec::new();
    crate::sql_read_bytes::read_bytes_into(src, &mut buf, len, super::MAX_PREALLOC).await?;

    Ok(ColumnData::Binary(Some(buf.into())))
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

        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::Binary(None));
    }

    #[tokio::test]
    async fn decode_reads_pointer_timestamp_and_payload() {
        let mut buf = BytesMut::new();
        buf.put_u8(2); // ptr_len
        buf.put_u8(0xAA);
        buf.put_u8(0xBB); // pointer bytes (ignored)
        buf.put_i32_le(0); // days (ignored)
        buf.put_u32_le(0); // second fractions (ignored)
        buf.put_u32_le(3); // payload len
        buf.put_slice(&[1, 2, 3]);

        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::Binary(Some(vec![1, 2, 3].into())));
    }
}
