use crate::{sql_read_bytes::SqlReadBytes, time::DateTimeOffset, ColumnData};

pub(crate) async fn decode<R>(src: &mut R, len: usize) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let rlen = src.read_u8().await?;

    let dto = match rlen {
        0 => ColumnData::DateTimeOffset(None),
        _ => {
            // A datetimeoffset value is a `time` portion (rlen - 5 bytes) then a
            // 3-byte `date` and a 2-byte offset. A server rlen < 5 would underflow.
            let time_len = rlen.checked_sub(5).ok_or_else(|| {
                crate::Error::Protocol(
                    format!("datetimeoffset: invalid value length {rlen}").into(),
                )
            })?;
            let dto = DateTimeOffset::decode(src, len, time_len).await?;
            ColumnData::DateTimeOffset(Some(dto))
        }
    };

    Ok(dto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    #[tokio::test]
    async fn rejects_underlength_value_instead_of_panicking() {
        // rlen in 1..=4 (non-NULL but < 5): must be a protocol error, not a panic.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[4u8]);
        let err = decode(&mut buf.into_sql_read_bytes(), 8)
            .await
            .expect_err("rlen < 5 must be rejected");
        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    // Build the on-the-wire bytes for a non-NULL `datetimeoffsetn` value at
    // scale 7 (time = 5 bytes, date = 3 bytes, offset = 2 bytes) from the given
    // components, prefixed with the 1-byte value length.
    #[cfg(all(feature = "tds73", feature = "time"))]
    fn wire_bytes(dto: DateTimeOffset) -> BytesMut {
        use crate::tds::codec::Encode;

        let mut inner = BytesMut::new();
        dto.encode(&mut inner).unwrap();

        let mut buf = BytesMut::new();
        // rlen = time(5) + date(3) + offset(2) = 10.
        buf.extend_from_slice(&[inner.len() as u8]);
        buf.extend_from_slice(&inner);
        buf
    }

    // Regression: a malicious/compromised server can send a `datetimeoffset`
    // whose (clamped, near-`Date::MAX`) date plus a valid positive offset lands
    // outside the range `time` can represent. The `time`-feature conversion used
    // to call the panicking `OffsetDateTime::to_offset`; it must now return a
    // protocol error rather than panic on wire input.
    #[cfg(all(feature = "tds73", feature = "time"))]
    #[tokio::test]
    async fn rejects_unrepresentable_offset_conversion_instead_of_panicking() {
        use crate::tds::time::{Date, DateTime2, Time};
        use crate::FromSql;

        // 0x00ff_ffff days -> clamps to `Date::MAX` (9999-12-31); 23:00:00 at
        // scale 7; +14h offset. Shifting 9999-12-31 23:00 by +14h overflows.
        let dto = DateTimeOffset::new(
            DateTime2::new(Date::new(0x00ff_ffff), Time::new(828_000_000_000, 7)),
            840,
        );

        let buf = wire_bytes(dto);
        let column = decode(&mut buf.into_sql_read_bytes(), 7).await.unwrap();

        let res = <time::OffsetDateTime as FromSql>::from_sql(&column);
        assert!(
            matches!(res, Err(crate::Error::Protocol(_))),
            "expected a protocol error, got {res:?}"
        );
    }

    // A `datetimeoffset` whose offset (in minutes) is outside the range
    // `UtcOffset` can represent must be reported as an error, not silently
    // coerced to another zone.
    #[cfg(all(feature = "tds73", feature = "time"))]
    #[tokio::test]
    async fn rejects_out_of_range_offset_field() {
        use crate::tds::time::{Date, DateTime2, Time};
        use crate::FromSql;

        // Ordinary date/time, but an offset of 2000 minutes (~33h) is far
        // outside the ±~25h range `UtcOffset` supports.
        let dto = DateTimeOffset::new(DateTime2::new(Date::new(730_000), Time::new(0, 7)), 2000);

        let buf = wire_bytes(dto);
        let column = decode(&mut buf.into_sql_read_bytes(), 7).await.unwrap();

        let res = <time::OffsetDateTime as FromSql>::from_sql(&column);
        assert!(
            matches!(res, Err(crate::Error::Protocol(_))),
            "expected a protocol error, got {res:?}"
        );
    }
}
