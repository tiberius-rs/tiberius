use crate::{sql_read_bytes::SqlReadBytes, ColumnData, Error};

pub(crate) async fn decode<R>(src: &mut R, type_len: usize) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let recv_len = src.read_u8().await? as usize;

    let res = match (recv_len, type_len) {
        (0, 1) => ColumnData::U8(None),
        (0, 2) => ColumnData::I16(None),
        (0, 4) => ColumnData::I32(None),
        (0, _) => ColumnData::I64(None),
        (1, _) => ColumnData::U8(Some(src.read_u8().await?)),
        (2, _) => ColumnData::I16(Some(src.read_i16_le().await?)),
        (4, _) => ColumnData::I32(Some(src.read_i32_le().await?)),
        (8, _) => ColumnData::I64(Some(src.read_i64_le().await?)),
        _ => {
            return Err(Error::Protocol(
                format!("invalid integer length: {}", recv_len).into(),
            ))
        }
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    #[tokio::test]
    async fn invalid_intn_length_is_protocol_error() {
        // First byte is the received length prefix; 3 is not a valid Intn
        // length (only 0, 1, 2, 4, 8 are accepted).
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[3u8, 0, 0, 0]);

        let reader = &mut buf.into_sql_read_bytes();
        let err = decode(reader, 4).await.unwrap_err();

        match err {
            Error::Protocol(msg) => {
                assert!(msg.to_string().contains("invalid integer length"));
            }
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }
}
