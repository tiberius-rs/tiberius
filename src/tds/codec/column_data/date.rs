use crate::Error;

use crate::{sql_read_bytes::SqlReadBytes, time::Date, ColumnData};

pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let len = src.read_u8().await?;

    let res = match len {
        0 => ColumnData::Date(None),
        3 => ColumnData::Date(Some(Date::decode(src).await?)),
        _ => {
            return Err(Error::Protocol(
                format!("daten: length of {} is invalid", len).into(),
            ))
        }
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use crate::tds::codec::Encode;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn invalid_daten_length_is_protocol_error() {
        // Only 0 and 3 are valid `date` lengths.
        let mut buf = BytesMut::new();
        buf.put_u8(2);
        buf.put_slice(&[0, 0]);

        let err = decode(&mut buf.into_sql_read_bytes()).await.unwrap_err();
        match err {
            Error::Protocol(msg) => assert!(msg.to_string().contains("daten")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decode_null_when_length_zero() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        assert_eq!(
            decode(&mut buf.into_sql_read_bytes()).await.unwrap(),
            ColumnData::Date(None)
        );
    }

    #[tokio::test]
    async fn decode_date_round_trip() {
        let date = Date::new(737_425);
        let mut body = BytesMut::new();
        date.encode(&mut body).unwrap();
        assert_eq!(body.len(), 3);

        let mut buf = BytesMut::new();
        buf.put_u8(3);
        buf.extend_from_slice(&body);

        assert_eq!(
            decode(&mut buf.into_sql_read_bytes()).await.unwrap(),
            ColumnData::Date(Some(date))
        );
    }
}
