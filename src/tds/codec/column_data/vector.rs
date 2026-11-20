use std::borrow::Cow;

use crate::{sql_read_bytes::SqlReadBytes, vector::Vector, ColumnData};

/// Decodes a native `vector` value: a `u16` length prefix (`0xFFFF` = NULL)
/// followed by the vector header and elements.
pub(crate) async fn decode<R>(src: &mut R, size: u16) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    // A vector is a USHORTLEN type; `plp::decode` handles that form when the
    // declared size is below 0xFFFF.
    if size == 0xffff {
        return Err(crate::Error::Protocol(
            "vector column declares an invalid size of 0xFFFF".into(),
        ));
    }

    let value = match super::plp::decode(src, size as usize).await? {
        None => None,
        Some(bytes) => Some(Cow::Owned(Vector::decode_payload(&bytes)?)),
    };

    Ok(ColumnData::Vector(value))
}

/// Encodes a vector value with its `u16` length prefix, or a NULL.
pub(crate) fn encode(dst: &mut impl bytes::BufMut, value: Option<&Vector>) -> crate::Result<()> {
    match value {
        None => dst.put_u16_le(0xffff),
        Some(vector) => {
            let payload = vector.encode_payload()?;
            dst.put_u16_le(payload.len() as u16);
            dst.put_slice(&payload);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    #[tokio::test]
    async fn round_trips_value_and_null() {
        let v = Vector::from(vec![0.5f32, -1.25, 3.0]);

        let mut buf = BytesMut::new();
        encode(&mut buf, Some(&v)).unwrap();
        let data = decode(&mut buf.into_sql_read_bytes(), v.encoded_len() as u16)
            .await
            .unwrap();
        assert_eq!(data, ColumnData::Vector(Some(Cow::Owned(v))));

        let mut buf = BytesMut::new();
        encode(&mut buf, None).unwrap();
        let data = decode(&mut buf.into_sql_read_bytes(), 20).await.unwrap();
        assert_eq!(data, ColumnData::Vector(None));
    }

    #[tokio::test]
    async fn rejects_corrupt_payload() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 0, 0, 0]); // bad magic

        let err = decode(&mut buf.into_sql_read_bytes(), 8).await.unwrap_err();
        assert!(matches!(err, crate::Error::Protocol(_)));
    }
}
