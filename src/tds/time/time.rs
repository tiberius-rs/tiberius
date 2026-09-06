//! Mappings between TDS and and time crate types (with `time` feature flag
//! enabled).
//!
//! The time library offers better ergonomy and are highly recommended if
//! needing to modify and deal with date and time in SQL Server.

use std::time::Duration;
pub use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

use crate::tds::codec::ColumnData;

#[inline]
fn from_days(days: i64, start_year: i32) -> crate::Result<Date> {
    // Use the signed `time::Duration` so that negative day offsets (dates
    // before `start_year`, e.g. `datetime` values prior to 1900) do not
    // overflow. Casting a negative day count into an unsigned type and
    // multiplying it out panics with "multiply with overflow".
    //
    // `days` ultimately comes from untrusted server bytes, so a malformed value
    // can land outside the range `time::Date` can represent. Every valid SQL
    // date (SQL's 0001-01-01..=9999-12-31 all fit within `time::Date`) succeeds;
    // a genuinely out-of-range/malformed day offset is rejected as a protocol
    // error rather than silently clamped to MIN/MAX (which would yield a wrong
    // date).
    let base = Date::from_calendar_date(start_year, Month::January, 1).unwrap();
    base.checked_add(time::Duration::days(days)).ok_or_else(|| {
        crate::Error::Protocol(
            format!("date day offset {days} is out of the representable range").into(),
        )
    })
}

/// Validate and convert a server-supplied UTC offset (in whole minutes) into a
/// `UtcOffset`. SQL Server's `datetimeoffset` is only valid for the range
/// -14:00..=+14:00; a malformed offset outside that range is rejected as a
/// protocol error rather than silently falling back to UTC (which would shift
/// the represented instant).
#[inline]
#[cfg(feature = "tds73")]
fn offset_from_minutes(minutes: i16) -> crate::Result<UtcOffset> {
    if !(-840..=840).contains(&minutes) {
        return Err(crate::Error::Protocol(
            format!(
                "datetimeoffset offset {minutes} minutes is outside the valid -14:00..=+14:00 range"
            )
            .into(),
        ));
    }

    UtcOffset::from_whole_seconds(minutes as i32 * 60)
        .map_err(|_| crate::Error::Protocol("datetimeoffset offset is not representable".into()))
}

/// Convert a server-supplied fractional-seconds `increments` at the given
/// `scale` into nanoseconds without panicking. `scale` and `increments` are
/// untrusted; a `scale > 9` would otherwise underflow `9 - scale`, and a large
/// `increments` would overflow the multiply.
#[inline]
#[cfg(feature = "tds73")]
fn nanos_from_increments(increments: u64, scale: u8) -> u64 {
    let pow = 9u32.saturating_sub(scale as u32);
    increments.saturating_mul(10u64.saturating_pow(pow))
}

#[inline]
#[cfg(feature = "tds73")]
fn from_secs(secs: u64) -> Time {
    Time::from_hms(0, 0, 0).unwrap() + Duration::from_secs(secs)
}

#[inline]
fn from_sec_fragments(sec_fragments: u64) -> Time {
    Time::from_hms(0, 0, 0).unwrap() + Duration::from_nanos(sec_fragments * (1e9 as u64) / 300)
}

#[inline]
fn to_days(date: Date, start_year: i32) -> i64 {
    (date - Date::from_calendar_date(start_year, Month::January, 1).unwrap()).whole_days()
}

#[inline]
#[cfg(not(feature = "tds73"))]
fn to_sec_fragments(from: Time) -> i64 {
    let nanos: i64 = (from - Time::from_hms(0, 0, 0).unwrap())
        .whole_nanoseconds()
        .try_into()
        .unwrap();

    nanos * 300 / (1e9 as i64)
}

#[cfg(feature = "tds73")]
from_sql!(
    PrimitiveDateTime:
        ColumnData::SmallDateTime(ref dt) => match *dt {
            Some(dt) => Some(PrimitiveDateTime::new(
                from_days(dt.days as i64, 1900)?,
                from_secs(dt.seconds_fragments as u64 * 60),
            )),
            None => None,
        },
        ColumnData::DateTime2(ref dt) => match *dt {
            Some(dt) => Some(PrimitiveDateTime::new(
                from_days(dt.date.days() as i64, 1)?,
                Time::from_hms(0,0,0).unwrap() + Duration::from_nanos(nanos_from_increments(dt.time.increments, dt.time.scale))
            )),
            None => None,
        },
        ColumnData::DateTime(ref dt) => match *dt {
            Some(dt) => Some(PrimitiveDateTime::new(
                from_days(dt.days as i64, 1900)?,
                from_sec_fragments(dt.seconds_fragments as u64)
            )),
            None => None,
        };
    Time:
        ColumnData::Time(ref time) => match *time {
            Some(time) => {
                let ns = nanos_from_increments(time.increments, time.scale);
                Some(Time::from_hms(0,0,0).unwrap() + Duration::from_nanos(ns))
            }
            None => None,
        };
    Date:
        ColumnData::Date(ref date) => match *date {
            Some(date) => Some(from_days(date.days() as i64, 1)?),
            None => None,
        };
    OffsetDateTime:
        ColumnData::DateTimeOffset(ref dto) => match *dto {
            Some(dto) => {
                let date = from_days(dto.datetime2.date.days() as i64, 1)?;
                let dt = dto.datetime2;

                let time = Time::from_hms(0,0,0).unwrap()
                    + Duration::from_nanos(nanos_from_increments(dt.time.increments, dt.time.scale));

                // A malformed server offset outside ±14h is rejected as a
                // protocol error rather than silently shifting the instant to UTC.
                let offset = offset_from_minutes(dto.offset)?;

                Some(date.with_time(time).assume_utc().to_offset(offset))
            }
            None => None,
        }
);

#[cfg(feature = "tds73")]
to_sql!(self_,
        Date: (ColumnData::Date, super::Date::new(to_days(*self_, 1) as u32));
        Time: (ColumnData::Time, {
            let nanos: u64 = (*self_ - Time::from_hms(0, 0, 0).unwrap()).whole_nanoseconds().try_into().unwrap();
            let increments = nanos / 100;

            super::Time {increments, scale: 7}
        });
        PrimitiveDateTime: (ColumnData::DateTime2, {
            let time = self_.time();
            let nanos: u64 = (time - Time::from_hms(0, 0, 0).unwrap()).whole_nanoseconds().try_into().unwrap();
            let increments = nanos / 100;

            let date = super::Date::new(to_days(self_.date(), 1) as u32);
            let time = super::Time {increments, scale: 7};

            super::DateTime2::new(date, time)
        });
        OffsetDateTime: (ColumnData::DateTimeOffset, {
            let tz = self_.offset();
            let offset = (tz.whole_seconds() / 60) as i16;

            let utc_date = self_.to_offset(UtcOffset::UTC);

            let nanos: u64 = (utc_date.time() - Time::from_hms(0, 0, 0).unwrap()).whole_nanoseconds().try_into().unwrap();

            let date = super::Date::new(to_days(utc_date.date(), 1) as u32);
            let time = super::Time { increments: nanos / 100, scale: 7 };

            super::DateTimeOffset::new(super::DateTime2::new(date, time), offset)
        });
);

#[cfg(not(feature = "tds73"))]
to_sql!(self_,
        PrimitiveDateTime: (ColumnData::DateTime, {
            let date = self_.date();
            let time = self_.time();

            let days = to_days(date, 1900) as i32;
            let seconds_fragments = to_sec_fragments(time);

            super::DateTime::new(days, seconds_fragments as u32)
        });
);

#[cfg(not(feature = "tds73"))]
from_sql!(
    PrimitiveDateTime:
    ColumnData::DateTime(ref dt) => match *dt {
        Some(dt) => Some(
            from_days(dt.days as i64, 1900)?.with_time(from_sec_fragments(dt.seconds_fragments as u64))
        ),
        None => None,
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for #316: a `datetime` value with a date before 1900 has
    // a negative day offset from the 1900 base date. This must round-trip
    // without a "multiply with overflow" panic.
    #[test]
    fn from_days_handles_negative_offsets() {
        // 1899-12-31 is one day before the 1900 base date.
        assert_eq!(
            from_days(-1, 1900).unwrap(),
            Date::from_calendar_date(1899, Month::December, 31).unwrap()
        );

        // A date well before 1900, at the lower edge of the `datetime` range.
        let expected = Date::from_calendar_date(1850, Month::January, 1).unwrap();
        let days = to_days(expected, 1900);
        assert!(
            days < 0,
            "expected a negative day offset for pre-1900 dates"
        );

        // Rebuilding from the (negative) day offset must not overflow.
        assert_eq!(from_days(days, 1900).unwrap(), expected);
    }

    // Exercise the full decode path (`DateTime` -> `PrimitiveDateTime`) for a
    // pre-1900 value, matching what happens when reading a `datetime` column.
    #[test]
    fn datetime_before_1900_decodes() {
        let expected_date = Date::from_calendar_date(1850, Month::January, 1).unwrap();
        let days = to_days(expected_date, 1900) as i32;

        // Reconstruct the way the `from_sql!` mapping does for `ColumnData::DateTime`.
        let dt = crate::tds::time::DateTime::new(days, 0);
        let decoded = from_days(dt.days() as i64, 1900)
            .unwrap()
            .with_time(from_sec_fragments(dt.seconds_fragments() as u64));

        assert_eq!(decoded.date(), expected_date);
        assert_eq!(decoded.time(), Time::from_hms(0, 0, 0).unwrap());
    }

    #[test]
    fn from_days_out_of_range_errors() {
        // A day offset far outside the representable `time::Date` range must
        // return a protocol error (rather than silently clamping to MIN/MAX,
        // which would decode a malformed value to a plausible-but-wrong date).
        for days in [10_000_000_i64, -10_000_000_i64] {
            let err = from_days(days, 1).expect_err("out-of-range day offset must error");
            assert!(
                matches!(err, crate::Error::Protocol(_)),
                "expected a protocol error, got {err:?}"
            );
        }

        // A valid in-range date still decodes correctly (happy path unchanged).
        assert_eq!(
            from_days(0, 1).unwrap(),
            Date::from_calendar_date(1, Month::January, 1).unwrap()
        );
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn offset_from_minutes_rejects_out_of_range() {
        // Valid SQL Server range -14:00..=+14:00 (±840 minutes) succeeds.
        assert_eq!(
            offset_from_minutes(60).unwrap(),
            UtcOffset::from_whole_seconds(3600).unwrap()
        );
        assert_eq!(
            offset_from_minutes(-840).unwrap(),
            UtcOffset::from_whole_seconds(-840 * 60).unwrap()
        );

        // A malformed offset beyond ±14h must error, not silently fall back to UTC.
        for minutes in [841_i16, -841, 5000, -5000] {
            let err = offset_from_minutes(minutes).expect_err("out-of-range offset must error");
            assert!(
                matches!(err, crate::Error::Protocol(_)),
                "expected a protocol error, got {err:?}"
            );
        }
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn nanos_from_increments_survives_large_scale() {
        // A server-controlled `scale > 9` must not panic on the `9 - scale`
        // underflow; the saturating arithmetic yields a bounded value.
        let _ = nanos_from_increments(1, 255);
        let _ = nanos_from_increments(u64::MAX, 0);
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn datetimeoffset_out_of_range_offset_errors() {
        use crate::FromSql;

        // Build a DateTimeOffset with an offset well outside ±14h.
        let dt2 =
            super::super::DateTime2::new(super::super::Date::new(0), super::super::Time::new(0, 7));
        let dto = super::super::DateTimeOffset::new(dt2, 5000);
        let data = ColumnData::DateTimeOffset(Some(dto));

        let err =
            OffsetDateTime::from_sql(&data).expect_err("out-of-range offset must error, not panic");
        assert!(
            matches!(err, crate::Error::Protocol(_)),
            "expected a protocol error, got {err:?}"
        );
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn from_secs_converts() {
        // 3600 s past midnight == 01:00:00 (pins the `+` in `from_secs`).
        assert_eq!(from_secs(3600), Time::from_hms(1, 0, 0).unwrap());
    }

    #[test]
    fn from_sec_fragments_converts() {
        // 300 sec-fragments (1/300 s units) == exactly one second.
        assert_eq!(from_sec_fragments(300), Time::from_hms(0, 0, 1).unwrap());
    }

    #[cfg(not(feature = "tds73"))]
    #[test]
    fn to_sec_fragments_converts() {
        // One second == 300 sec-fragments (1/300 s units).
        assert_eq!(to_sec_fragments(Time::from_hms(0, 0, 1).unwrap()), 300);
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn time_from_sql_and_back() {
        use crate::FromSql;

        // 12:34:56 as 100ns increments since midnight, scale 7.
        let expected = Time::from_hms(12, 34, 56).unwrap();
        let nanos: u64 = (expected - Time::from_hms(0, 0, 0).unwrap())
            .whole_nanoseconds()
            .try_into()
            .unwrap();
        let increments: u64 = nanos / 100;

        let tds_time = super::super::Time::new(increments, 7);
        let data = ColumnData::Time(Some(tds_time));

        let decoded = Time::from_sql(&data).unwrap().unwrap();
        assert_eq!(decoded, expected);

        // Round trip back through ToSql.
        use crate::ToSql;
        let round_tripped = decoded.to_sql();
        match round_tripped {
            ColumnData::Time(Some(t)) => assert_eq!(t.increments, increments),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn date_from_sql_and_back() {
        use crate::{FromSql, ToSql};

        let expected = Date::from_calendar_date(2020, Month::June, 15).unwrap();
        let days = to_days(expected, 1) as u32;

        let data = ColumnData::Date(Some(super::super::Date::new(days)));
        let decoded = Date::from_sql(&data).unwrap().unwrap();
        assert_eq!(decoded, expected);

        match decoded.to_sql() {
            ColumnData::Date(Some(d)) => assert_eq!(d.days(), days),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn primitive_datetime_from_datetime2_and_back() {
        use crate::{FromSql, ToSql};

        let date = Date::from_calendar_date(2020, Month::June, 15).unwrap();
        let time = Time::from_hms(1, 2, 3).unwrap();
        let expected = PrimitiveDateTime::new(date, time);

        let days = to_days(date, 1) as u32;
        let nanos: u64 = (time - Time::from_hms(0, 0, 0).unwrap())
            .whole_nanoseconds()
            .try_into()
            .unwrap();
        let increments = nanos / 100;

        let dt2 = super::super::DateTime2::new(
            super::super::Date::new(days),
            super::super::Time::new(increments, 7),
        );
        let data = ColumnData::DateTime2(Some(dt2));

        let decoded = PrimitiveDateTime::from_sql(&data).unwrap().unwrap();
        assert_eq!(decoded, expected);

        match decoded.to_sql() {
            ColumnData::DateTime2(Some(dt)) => {
                assert_eq!(dt.date.days(), days);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn primitive_datetime_from_smalldatetime_and_datetime() {
        use crate::FromSql;

        // SmallDateTime path.
        let sdt = crate::tds::time::SmallDateTime::new(1, 30); // 30 minutes past midnight on day 1 (1900-01-02)
        let data = ColumnData::SmallDateTime(Some(sdt));
        let decoded = PrimitiveDateTime::from_sql(&data).unwrap().unwrap();
        assert_eq!(decoded.date(), from_days(1, 1900).unwrap());

        // DateTime path.
        let dt = crate::tds::time::DateTime::new(1, 0);
        let data = ColumnData::DateTime(Some(dt));
        let decoded = PrimitiveDateTime::from_sql(&data).unwrap().unwrap();
        assert_eq!(decoded.date(), from_days(1, 1900).unwrap());
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn offset_date_time_from_sql_and_back() {
        use crate::{FromSql, ToSql};

        let date = Date::from_calendar_date(2020, Month::June, 15).unwrap();
        let time = Time::from_hms(1, 2, 3).unwrap();
        let days = to_days(date, 1) as u32;
        let nanos: u64 = (time - Time::from_hms(0, 0, 0).unwrap())
            .whole_nanoseconds()
            .try_into()
            .unwrap();
        let increments = nanos / 100;

        let dt2 = super::super::DateTime2::new(
            super::super::Date::new(days),
            super::super::Time::new(increments, 7),
        );
        let dto = super::super::DateTimeOffset::new(dt2, 60); // +1h offset

        let data = ColumnData::DateTimeOffset(Some(dto));
        let decoded = OffsetDateTime::from_sql(&data).unwrap().unwrap();

        assert_eq!(
            decoded.offset(),
            UtcOffset::from_whole_seconds(3600).unwrap()
        );

        match decoded.to_sql() {
            ColumnData::DateTimeOffset(Some(round_tripped)) => {
                assert_eq!(round_tripped.offset, 60);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    // `ColumnData::Time`/`Date`/`DateTimeOffset` and their `time`-crate
    // `FromSql` impls only exist with the `tds73` feature.
    #[cfg(feature = "tds73")]
    #[test]
    fn from_sql_null_variants_return_none_tds73() {
        use crate::FromSql;

        assert_eq!(Time::from_sql(&ColumnData::Time(None)).unwrap(), None);
        assert_eq!(Date::from_sql(&ColumnData::Date(None)).unwrap(), None);
        assert_eq!(
            OffsetDateTime::from_sql(&ColumnData::DateTimeOffset(None)).unwrap(),
            None
        );
    }

    #[test]
    fn primitive_datetime_from_sql_null_returns_none() {
        use crate::FromSql;

        assert_eq!(
            PrimitiveDateTime::from_sql(&ColumnData::DateTime(None)).unwrap(),
            None
        );
    }
}
