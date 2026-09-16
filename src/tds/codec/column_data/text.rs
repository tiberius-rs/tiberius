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

    // Skip the text pointer (packet-aware bulk read into a throwaway buffer).
    let mut ptr = Vec::new();
    crate::sql_read_bytes::read_bytes_into(src, &mut ptr, ptr_len, super::MAX_PREALLOC).await?;

    src.read_i32_le().await?; // days
    src.read_u32_le().await?; // second fractions

    let text = match collation {
        // TEXT
        Some(collation) => {
            let encoder = collation.encoding()?;
            let text_len = src.read_u32_le().await? as usize;
            let mut buf = Vec::new();
            crate::sql_read_bytes::read_bytes_into(src, &mut buf, text_len, super::MAX_PREALLOC)
                .await?;

            encoder
                .decode_without_bom_handling_and_without_replacement(buf.as_ref())
                .ok_or_else(|| Error::Encoding("invalid sequence".into()))?
                .to_string()
        }
        // NTEXT
        None => {
            let byte_len = src.read_u32_le().await? as usize;
            // NTEXT is UTF-16: the byte length must be even. An odd length would
            // desync the stream (the final `read_u16_le` would consume a byte
            // from the next field), so reject it as a protocol error.
            if !byte_len.is_multiple_of(2) {
                return Err(Error::Protocol(
                    format!("ntext: odd byte length {byte_len} is invalid").into(),
                ));
            }
            // Bulk-read the raw UTF-16LE bytes, then decode them as u16 code
            // units (like string.rs), instead of one packet-aware u16 per poll.
            let mut raw = Vec::new();
            crate::sql_read_bytes::read_bytes_into(src, &mut raw, byte_len, super::MAX_PREALLOC)
                .await?;

            // `byte_len` is guaranteed even (odd lengths are rejected above),
            // so every 2-byte chunk is a complete UTF-16LE code unit.
            let buf: Vec<u16> = raw
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();

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
    async fn decode_ntext_rejects_odd_byte_length() {
        // An odd UTF-16 byte length must be a protocol error, not a desync.
        let mut buf = BytesMut::new();
        buf.put_u8(1); // ptr_len
        buf.put_u8(0xAA); // pointer byte (ignored)
        buf.put_i32_le(0); // days
        buf.put_u32_le(0); // second fractions
        buf.put_u32_le(3); // odd byte length
        buf.put_u16_le('h' as u16);
        buf.put_u8(0);

        let err = decode(&mut buf.into_sql_read_bytes(), None)
            .await
            .expect_err("odd ntext length must be rejected");
        assert!(matches!(err, Error::Protocol(_)));
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
