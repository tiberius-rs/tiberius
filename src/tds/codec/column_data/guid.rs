use uuid::Uuid;

use crate::{error::Error, sql_read_bytes::SqlReadBytes, tds::codec::guid, ColumnData};

pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let len = src.read_u8().await? as usize;

    let res = match len {
        0 => ColumnData::Guid(None),
        16 => {
            // Bulk-read the 16 GUID bytes in one packet-aware pass instead of
            // 16 separate `read_u8().await` calls (one per byte, per row).
            let mut buf = Vec::new();
            crate::sql_read_bytes::read_bytes_into(src, &mut buf, 16, 16).await?;

            let mut data = [0u8; 16];
            data.copy_from_slice(&buf);

            guid::reorder_bytes(&mut data);
            ColumnData::Guid(Some(Uuid::from_bytes(data)))
        }
        _ => {
            return Err(Error::Protocol(
                format!("guid: length of {} is invalid", len).into(),
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
    async fn decode_null_when_length_zero() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        assert_eq!(
            decode(&mut buf.into_sql_read_bytes()).await.unwrap(),
            ColumnData::Guid(None)
        );
    }

    #[tokio::test]
    async fn invalid_guid_length_is_protocol_error() {
        // Only 0 and 16 are valid GUID lengths.
        let mut buf = BytesMut::new();
        buf.put_u8(4);
        buf.put_slice(&[0, 0, 0, 0]);

        let err = decode(&mut buf.into_sql_read_bytes()).await.unwrap_err();
        match err {
            Error::Protocol(msg) => assert!(msg.to_string().contains("guid")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decode_reorders_guid_byte_groups() {
        // The wire bytes are reordered (first three groups swapped from GUID
        // native order to UUID network order) on decode.
        let wire: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let mut buf = BytesMut::new();
        buf.put_u8(16);
        buf.put_slice(&wire);

        let mut expected = wire;
        guid::reorder_bytes(&mut expected);

        assert_eq!(
            decode(&mut buf.into_sql_read_bytes()).await.unwrap(),
            ColumnData::Guid(Some(Uuid::from_bytes(expected)))
        );
    }
}
