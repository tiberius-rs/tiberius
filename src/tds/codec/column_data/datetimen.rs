use crate::{
    error::Error,
    sql_read_bytes::SqlReadBytes,
    time::{DateTime, SmallDateTime},
    ColumnData,
};

pub(crate) async fn decode<R>(src: &mut R, rlen: u8, len: u8) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let datetime = match (rlen, len) {
        (0, 4) => ColumnData::SmallDateTime(None),
        (0, 8) => ColumnData::DateTime(None),
        (4, _) => ColumnData::SmallDateTime(Some(SmallDateTime::decode(src).await?)),
        (8, _) => ColumnData::DateTime(Some(DateTime::decode(src).await?)),
        _ => {
            return Err(Error::Protocol(
                format!("datetimen: length of {} is invalid", len).into(),
            ))
        }
    };

    Ok(datetime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use crate::tds::codec::Encode;
    use bytes::BytesMut;

    #[tokio::test]
    async fn decode_null_dispatches_on_len() {
        // rlen 0 selects NULL; `len` picks small vs. full datetime. No value
        // bytes are consumed on the NULL arms.
        let buf = BytesMut::new();
        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 0, 4).await.unwrap(),
            ColumnData::SmallDateTime(None)
        );

        let buf = BytesMut::new();
        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 0, 8).await.unwrap(),
            ColumnData::DateTime(None)
        );
    }

    #[tokio::test]
    async fn decode_smalldatetime_round_trip() {
        // rlen 4 -> the four value bytes are read directly (no length prefix).
        let value = SmallDateTime::new(1234, 567);
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 4, 4).await.unwrap(),
            ColumnData::SmallDateTime(Some(value))
        );
    }

    #[tokio::test]
    async fn decode_datetime_round_trip() {
        // rlen 8 -> the eight value bytes are read directly.
        let value = DateTime::new(-100, 90_000);
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(
            decode(&mut buf.into_sql_read_bytes(), 8, 8).await.unwrap(),
            ColumnData::DateTime(Some(value))
        );
    }

    #[tokio::test]
    async fn invalid_rlen_len_combo_is_protocol_error() {
        // rlen 5 is neither a NULL marker nor a valid value length.
        let buf = BytesMut::new();
        let err = decode(&mut buf.into_sql_read_bytes(), 5, 8)
            .await
            .unwrap_err();
        match err {
            Error::Protocol(msg) => assert!(msg.to_string().contains("datetimen")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }
}
