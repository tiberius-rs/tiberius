use crate::{sql_read_bytes::SqlReadBytes, time::DateTime2, ColumnData};

pub(crate) async fn decode<R>(src: &mut R, len: usize) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let rlen = src.read_u8().await?;

    let date = match rlen {
        0 => ColumnData::DateTime2(None),
        rlen => {
            // A datetime2 value is a `time` portion (rlen - 3 bytes) followed by
            // a 3-byte `date`. A server-supplied rlen < 3 would underflow.
            let time_len = (rlen as usize).checked_sub(3).ok_or_else(|| {
                crate::Error::Protocol(format!("datetime2: invalid value length {rlen}").into())
            })?;
            let dt = DateTime2::decode(src, len, time_len).await?;
            ColumnData::DateTime2(Some(dt))
        }
    };

    Ok(date)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    #[tokio::test]
    async fn rejects_underlength_value_instead_of_panicking() {
        // rlen is 1 (non-NULL but < 3): must be a protocol error, not a panic.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[1u8]);
        let err = decode(&mut buf.into_sql_read_bytes(), 8)
            .await
            .expect_err("rlen < 3 must be rejected");
        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    #[tokio::test]
    async fn zero_length_is_null() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0u8]);
        let v = decode(&mut buf.into_sql_read_bytes(), 8).await.unwrap();
        assert!(matches!(v, ColumnData::DateTime2(None)));
    }
}
