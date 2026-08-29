use std::borrow::Cow;

use crate::{sql_read_bytes::SqlReadBytes, ColumnData};

/// Decode the value of a CLR user-defined type (UDT) column.
///
/// UDT values are always transferred using the partially length-prefixed (PLP)
/// byte-stream format (MS-TDS §2.2.5.5.4). tiberius does not attempt to
/// deserialize the CLR representation; the raw serialized bytes are surfaced
/// verbatim as [`ColumnData::Binary`].
pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    // Force the PLP (u64-prefixed) code path, which is how UDT values are
    // always encoded on the wire regardless of the declared max byte size.
    let data = super::plp::decode(src, 0xffff_ffff).await?.map(Cow::Owned);

    Ok(ColumnData::Binary(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decode_udt_plp_bytes() {
        let payload: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

        let mut buf = BytesMut::new();
        // PLP: unknown total length sentinel.
        buf.put_u64_le(0xfffffffffffffffe);
        // One chunk carrying the payload.
        buf.put_u32_le(payload.len() as u32);
        buf.extend_from_slice(payload);
        // PLP terminator.
        buf.put_u32_le(0);

        let data = decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("decode must succeed");

        match data {
            ColumnData::Binary(Some(bytes)) => assert_eq!(bytes.as_ref(), payload),
            other => panic!("expected Binary, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_udt_null() {
        let mut buf = BytesMut::new();
        // PLP NULL sentinel.
        buf.put_u64_le(0xffffffffffffffff);

        let data = decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("decode must succeed");

        assert!(matches!(data, ColumnData::Binary(None)));
    }
}
