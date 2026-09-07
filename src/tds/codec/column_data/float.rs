use crate::{error::Error, sql_read_bytes::SqlReadBytes, ColumnData};

pub(crate) async fn decode<R>(src: &mut R, type_len: usize) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let len = src.read_u8().await? as usize;

    let res = match (len, type_len) {
        (0, 4) => ColumnData::F32(None),
        (0, _) => ColumnData::F64(None),
        (4, _) => ColumnData::F32(Some(src.read_f32_le().await?)),
        (8, _) => ColumnData::F64(Some(src.read_f64_le().await?)),
        _ => {
            return Err(Error::Protocol(
                format!("floatn: length of {} is invalid", len).into(),
            ))
        }
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn invalid_floatn_length_is_protocol_error() {
        // 3 is not a valid floatn length (only 0, 4, 8 are accepted).
        let mut buf = BytesMut::new();
        buf.put_u8(3);
        buf.put_slice(&[0, 0, 0]);

        let err = decode(&mut buf.into_sql_read_bytes(), 4).await.unwrap_err();
        match err {
            Error::Protocol(msg) => assert!(msg.to_string().contains("floatn")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decode_null_dispatches_on_type_len() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 4).await.unwrap(),
            ColumnData::F32(None)
        );

        let mut buf = BytesMut::new();
        buf.put_u8(0);
        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 8).await.unwrap(),
            ColumnData::F64(None)
        );
    }

    #[tokio::test]
    async fn decode_f32_round_trip() {
        let value = 1.5f32;
        let mut buf = BytesMut::new();
        buf.put_u8(4);
        buf.put_f32_le(value);

        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 4).await.unwrap(),
            ColumnData::F32(Some(value))
        );
    }

    #[tokio::test]
    async fn decode_f64_round_trip() {
        let value = -12345.6789f64;
        let mut buf = BytesMut::new();
        buf.put_u8(8);
        buf.put_f64_le(value);

        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 8).await.unwrap(),
            ColumnData::F64(Some(value))
        );
    }
}
