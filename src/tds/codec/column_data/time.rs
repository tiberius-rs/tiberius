use crate::{sql_read_bytes::SqlReadBytes, time::Time, ColumnData};

pub(crate) async fn decode<R>(src: &mut R, len: usize) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let rlen = src.read_u8().await?;

    let time = match rlen {
        0 => ColumnData::Time(None),
        // A `time` value is 3..=5 bytes on the wire (MS-TDS §2.2.5.5.1.2); the
        // exact width depends on the scale. Bound the server-supplied `rlen` to
        // that range here, mirroring the sibling temporal decoders, instead of
        // deferring the check to `Time::decode`.
        3..=5 => {
            let time = Time::decode(src, len, rlen as usize).await?;
            ColumnData::Time(Some(time))
        }
        _ => {
            return Err(crate::Error::Protocol(
                format!("timen: invalid value length {rlen}").into(),
            ))
        }
    };

    Ok(time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn zero_length_is_null() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        let v = decode(&mut buf.into_sql_read_bytes(), 2).await.unwrap();
        assert!(matches!(v, ColumnData::Time(None)));
    }

    #[tokio::test]
    async fn rejects_out_of_range_rlen() {
        // rlen of 7 is outside the legal 3..=5 range for a `time` value and must
        // be a protocol error, not read as an oversized value.
        let mut buf = BytesMut::new();
        buf.put_u8(7);
        let err = decode(&mut buf.into_sql_read_bytes(), 2)
            .await
            .expect_err("rlen out of range must be rejected");
        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    #[tokio::test]
    async fn decodes_normal_value() {
        // scale (len) = 2 => 3-byte value: u16 low + u8 high.
        let mut buf = BytesMut::new();
        buf.put_u8(3); // rlen
        buf.put_u16_le(0x0102);
        buf.put_u8(0x03);

        let v = decode(&mut buf.into_sql_read_bytes(), 2).await.unwrap();
        match v {
            ColumnData::Time(Some(t)) => {
                assert_eq!(t.increments(), 0x0102 | (0x03u64 << 16));
                assert_eq!(t.scale(), 2);
            }
            other => panic!("expected Time(Some(..)), got {other:?}"),
        }
    }
}
