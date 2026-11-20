use std::borrow::Cow;

use crate::{sql_read_bytes::SqlReadBytes, ColumnData};

/// Decodes a native `json` value: UTF-8 text sent as PLP data (MS-TDS JSON
/// type, SQL Server 2025+). The value is surfaced as a string.
pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    // `json` has no declared length: it is always PLP (the "MAX" form).
    let data = match super::plp::decode(src, usize::MAX).await? {
        None => return Ok(ColumnData::String(None)),
        Some(data) => data,
    };

    Ok(ColumnData::String(Some(Cow::Owned(decode_text(data)?))))
}

/// Decodes the bytes of a `json` value.
///
/// MS-TDS says the encoding "follows RFC 8259", which means UTF-8 between
/// systems, and Microsoft.Data.SqlClient reads UTF-8. SQL Server 2025
/// (17.0, CU11) was observed sending UTF-16LE without a byte order mark
/// instead, so both are accepted. The two are told apart without guessing:
/// JSON text starts with an ASCII character (`{`, `[`, `"`, a digit, a
/// literal or whitespace), so the second byte is `0x00` in UTF-16LE and never
/// `0x00` in UTF-8, where an unescaped NUL is not valid JSON.
fn decode_text(data: Vec<u8>) -> crate::Result<String> {
    if let Some(rest) = data.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return utf8(rest.to_vec());
    }

    if let Some(rest) = data.strip_prefix(&[0xFF, 0xFE]) {
        return utf16le(rest);
    }

    if data.len() >= 2 && data[1] == 0 {
        return utf16le(&data);
    }

    utf8(data)
}

fn utf8(data: Vec<u8>) -> crate::Result<String> {
    String::from_utf8(data)
        .map_err(|_| crate::Error::Protocol("json value is not valid UTF-8".into()))
}

fn utf16le(data: &[u8]) -> crate::Result<String> {
    if !data.len().is_multiple_of(2) {
        return Err(crate::Error::Protocol(
            "json value has an odd number of UTF-16 bytes".into(),
        ));
    }

    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();

    String::from_utf16(&units)
        .map_err(|_| crate::Error::Protocol("json value is not valid UTF-16".into()))
}

/// Encodes a string into the native `json` row/parameter form: a single PLP
/// chunk of UTF-8 bytes, or a PLP NULL.
pub(crate) fn encode(dst: &mut impl bytes::BufMut, value: Option<&str>) {
    match value {
        None => dst.put_u64_le(0xffffffffffffffff),
        Some(text) => {
            let bytes = text.as_bytes();
            // unknown total length, then one chunk and the terminator
            dst.put_u64_le(0xfffffffffffffffe);
            dst.put_u32_le(bytes.len() as u32);

            if !bytes.is_empty() {
                dst.put_slice(bytes);
                dst.put_u32_le(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    #[tokio::test]
    async fn round_trips_utf8_text() {
        let mut buf = BytesMut::new();
        encode(&mut buf, Some(r#"{"name":"ação"}"#));

        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(
            data,
            ColumnData::String(Some(Cow::Borrowed(r#"{"name":"ação"}"#)))
        );
    }

    #[tokio::test]
    async fn round_trips_null_and_empty() {
        let mut buf = BytesMut::new();
        encode(&mut buf, None);
        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::String(None));

        let mut buf = BytesMut::new();
        encode(&mut buf, Some(""));
        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::String(Some(Cow::Borrowed(""))));
    }

    #[tokio::test]
    async fn decodes_multiple_chunks() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&0xfffffffffffffffe_u64.to_le_bytes());
        for chunk in [&b"[1,"[..], &b"2]"[..]] {
            buf.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            buf.extend_from_slice(chunk);
        }
        buf.extend_from_slice(&0u32.to_le_bytes());

        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::String(Some(Cow::Borrowed("[1,2]"))));
    }

    fn plp(bytes: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    // SQL Server 2025 CU11 sends json as UTF-16LE without a BOM.
    #[tokio::test]
    async fn decodes_utf16le_as_sent_by_sql_server_2025() {
        let bytes: Vec<u8> = r#"{"a":"ç"}"#.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(&bytes[..4], &[0x7b, 0x00, 0x22, 0x00]);

        let data = decode(&mut plp(&bytes).into_sql_read_bytes())
            .await
            .unwrap();
        assert_eq!(
            data,
            ColumnData::String(Some(Cow::Borrowed(r#"{"a":"ç"}"#)))
        );
    }

    #[tokio::test]
    async fn decodes_boms_and_single_byte_utf8() {
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(b"[1]");
        let data = decode(&mut plp(&with_bom).into_sql_read_bytes())
            .await
            .unwrap();
        assert_eq!(data, ColumnData::String(Some(Cow::Borrowed("[1]"))));

        let mut utf16_bom = vec![0xFF, 0xFE];
        utf16_bom.extend("[1]".encode_utf16().flat_map(|u| u.to_le_bytes()));
        let data = decode(&mut plp(&utf16_bom).into_sql_read_bytes())
            .await
            .unwrap();
        assert_eq!(data, ColumnData::String(Some(Cow::Borrowed("[1]"))));

        let data = decode(&mut plp(b"7").into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::String(Some(Cow::Borrowed("7"))));
    }

    #[tokio::test]
    async fn rejects_odd_length_utf16() {
        let err = decode(&mut plp(&[0x7b, 0x00, 0x7d]).into_sql_read_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    #[tokio::test]
    async fn rejects_invalid_utf8() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&[0x7b, 0xff]); // '{' then a byte that is never valid UTF-8
        buf.extend_from_slice(&0u32.to_le_bytes());

        let err = decode(&mut buf.into_sql_read_bytes()).await.unwrap_err();
        assert!(matches!(err, crate::Error::Protocol(_)));
    }
}
