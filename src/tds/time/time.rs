//! Mappings between TDS and and time crate types (with `time` feature flag
//! enabled).
//!
//! The time library offers better ergonomy and are highly recommended if
//! needing to modify and deal with date and time in SQL Server.

use std::time::Duration;
pub use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

use crate::tds::codec::ColumnData;

#[inline]
fn from_days(days: i64, start_year: i32) -> Date {
    // Use the signed `time::Duration` so that negative day offsets (dates
    // before `start_year`, e.g. `datetime` values prior to 1900) do not
    // overflow. Casting a negative day count into an unsigned type and
    // multiplying it out panics with "multiply with overflow".
    Date::from_calendar_date(start_year, Month::January, 1).unwrap() + time::Duration::days(days)
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
        ColumnData::SmallDateTime(ref dt) => dt.map(|dt| PrimitiveDateTime::new(
            from_days(dt.days as i64, 1900),
            from_secs(dt.seconds_fragments as u64 * 60),
        )),
        ColumnData::DateTime2(ref dt) => dt.map(|dt| PrimitiveDateTime::new(
            from_days(dt.date.days() as i64, 1),
            Time::from_hms(0,0,0).unwrap() + Duration::from_nanos(dt.time.increments * 10u64.pow(9 - dt.time.scale as u32))
        )),
        ColumnData::DateTime(ref dt) => dt.map(|dt| PrimitiveDateTime::new(
            from_days(dt.days as i64, 1900),
            from_sec_fragments(dt.seconds_fragments as u64)
        ));
    Time:
        ColumnData::Time(ref time) => time.map(|time| {
            let ns = time.increments * 10u64.pow(9 - time.scale as u32);
            Time::from_hms(0,0,0).unwrap() + Duration::from_nanos(ns)
        });
    Date:
        ColumnData::Date(ref date) => date.map(|date| from_days(date.days() as i64, 1));
    OffsetDateTime:
        ColumnData::DateTimeOffset(ref dto) => dto.map(|dto| {
            let date = from_days(dto.datetime2.date.days() as i64, 1);
            let dt = dto.datetime2;

            let time = Time::from_hms(0,0,0).unwrap()
                + Duration::from_nanos(dt.time.increments * 10u64.pow(9 - dt.time.scale as u32));

            let offset = UtcOffset::from_whole_seconds(dto.offset as i32 * 60).unwrap();

            date.with_time(time).assume_utc().to_offset(offset)
        })
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
    ColumnData::DateTime(ref dt) => dt.map(|dt| {
        from_days(dt.days as i64, 1900).with_time(from_sec_fragments(dt.seconds_fragments as u64))
    })
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
            from_days(-1, 1900),
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
        assert_eq!(from_days(days, 1900), expected);
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
            .with_time(from_sec_fragments(dt.seconds_fragments() as u64));

        assert_eq!(decoded.date(), expected_date);
        assert_eq!(decoded.time(), Time::from_hms(0, 0, 0).unwrap());
    }
}
