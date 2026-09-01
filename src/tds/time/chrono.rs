//! Mappings between TDS and and Chrono types (with `chrono` feature flag
//! enabled).
//!
//! The chrono library offers better ergonomy, but is known to hold certain
//! security vulnerabilities. The code here is for legacy purposes, please use
//! `time` crate for greenfield projects.

#[cfg(not(feature = "tds73"))]
use super::DateTime as DateTime1;
#[cfg(feature = "tds73")]
use super::{Date, DateTime2, DateTimeOffset, Time};
use crate::tds::codec::ColumnData;
#[cfg(feature = "tds73")]
#[cfg_attr(docsrs, doc(cfg(feature = "tds73")))]
pub use chrono::offset::{FixedOffset, Utc};
pub use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime};

#[inline]
fn from_days(days: i64, start_year: i32) -> NaiveDate {
    // `days` derives from untrusted server bytes; clamp to the representable
    // range instead of panicking on overflow.
    let base = NaiveDate::from_ymd_opt(start_year, 1, 1).unwrap();
    base.checked_add_signed(chrono::Duration::days(days))
        .unwrap_or(if days < 0 {
            NaiveDate::MIN
        } else {
            NaiveDate::MAX
        })
}

/// Convert a server-supplied fractional-seconds `increments` at the given
/// `scale` into nanoseconds without panicking (`scale > 9` would underflow
/// `9 - scale`; a large `increments` would overflow the multiply).
#[inline]
#[cfg(feature = "tds73")]
fn nanos_from_increments(increments: u64, scale: u8) -> i64 {
    let pow = 9u32.saturating_sub(scale as u32);
    increments
        .saturating_mul(10u64.saturating_pow(pow))
        .min(i64::MAX as u64) as i64
}

#[inline]
fn from_sec_fragments(sec_fragments: i64) -> NaiveTime {
    NaiveTime::from_hms_opt(0, 0, 0).unwrap()
        + chrono::Duration::nanoseconds(sec_fragments * (1e9 as i64) / 300)
}

#[inline]
#[cfg(feature = "tds73")]
fn from_mins(mins: u32) -> NaiveTime {
    NaiveTime::from_num_seconds_from_midnight_opt(mins, 0).unwrap()
}

#[inline]
fn to_days(date: NaiveDate, start_year: i32) -> i64 {
    date.signed_duration_since(NaiveDate::from_ymd_opt(start_year, 1, 1).unwrap())
        .num_days()
}

#[inline]
#[cfg(not(feature = "tds73"))]
fn to_sec_fragments(time: NaiveTime) -> i64 {
    time.signed_duration_since(NaiveTime::from_hms_opt(0, 0, 0).unwrap())
        .num_nanoseconds()
        .unwrap()
        * 300
        / (1e9 as i64)
}

#[cfg(feature = "tds73")]
from_sql!(
    NaiveDateTime:
        ColumnData::SmallDateTime(ref dt) => dt.map(|dt| NaiveDateTime::new(
            from_days(dt.days as i64, 1900),
            from_mins(dt.seconds_fragments as u32 * 60),
        )),
        ColumnData::DateTime2(ref dt) => dt.map(|dt| NaiveDateTime::new(
            from_days(dt.date.days() as i64, 1),
            NaiveTime::from_hms_opt(0,0,0).unwrap() + chrono::Duration::nanoseconds(nanos_from_increments(dt.time.increments, dt.time.scale))
        )),
        ColumnData::DateTime(ref dt) => dt.map(|dt| NaiveDateTime::new(
            from_days(dt.days as i64, 1900),
            from_sec_fragments(dt.seconds_fragments as i64)
        ));
    NaiveTime:
        ColumnData::Time(ref time) => time.map(|time| {
            let ns = nanos_from_increments(time.increments, time.scale);
            NaiveTime::from_hms_opt(0,0,0).unwrap() + chrono::Duration::nanoseconds(ns)
        });
    NaiveDate:
        ColumnData::Date(ref date) => date.map(|date| from_days(date.days() as i64, 1));
    chrono::DateTime<Utc>:
        ColumnData::DateTimeOffset(ref dto) => dto.map(|dto| {
            let date = from_days(dto.datetime2.date.days() as i64, 1);
            let ns = nanos_from_increments(dto.datetime2.time.increments, dto.datetime2.time.scale);
            let time = NaiveTime::from_hms_opt(0,0,0).unwrap() + chrono::Duration::nanoseconds(ns);

            let offset = chrono::Duration::minutes(dto.offset as i64);
            let base = NaiveDateTime::new(date, time);
            let naive = base.checked_sub_signed(offset).unwrap_or(base);

            chrono::DateTime::from_naive_utc_and_offset(naive, Utc)
        }),
        ColumnData::DateTime2(ref dt2) => dt2.map(|dt2| {
            let date = from_days(dt2.date.days() as i64, 1);
            let ns = nanos_from_increments(dt2.time.increments, dt2.time.scale);
            let time = NaiveTime::from_hms_opt(0,0,0).unwrap() + chrono::Duration::nanoseconds(ns);
            let naive = NaiveDateTime::new(date, time);

            chrono::DateTime::from_naive_utc_and_offset(naive, Utc)
        });
    chrono::DateTime<FixedOffset>: ColumnData::DateTimeOffset(ref dto) => dto.map(|dto| {
        let date = from_days(dto.datetime2.date.days() as i64, 1);
        let ns = nanos_from_increments(dto.datetime2.time.increments, dto.datetime2.time.scale);
        let time = NaiveTime::from_hms_opt(0,0,0).unwrap() + chrono::Duration::nanoseconds(ns);

        let offset = FixedOffset::east_opt((dto.offset as i32) * 60).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
        let naive = NaiveDateTime::new(date, time);

        chrono::DateTime::from_naive_utc_and_offset(naive, offset)
    })
);

#[cfg(feature = "tds73")]
to_sql!(self_,
        NaiveDate: (ColumnData::Date, Date::new(to_days(*self_, 1) as u32));
        NaiveTime: (ColumnData::Time, {
            use chrono::Timelike;

            let nanos = self_.num_seconds_from_midnight() as u64 * 1e9 as u64 + self_.nanosecond() as u64;
            let increments = nanos / 100;

            Time {increments, scale: 7}
        });
        NaiveDateTime: (ColumnData::DateTime2, {
            use chrono::Timelike;

            let time = self_.time();
            let nanos = time.num_seconds_from_midnight() as u64 * 1e9 as u64 + time.nanosecond() as u64;
            let increments = nanos / 100;

            let date = Date::new(to_days(self_.date(), 1) as u32);
            let time = Time {increments, scale: 7};

            DateTime2::new(date, time)
        });
        chrono::DateTime<Utc>: (ColumnData::DateTime2, {
            use chrono::Timelike;

            let naive = self_.naive_utc();
            let time = naive.time();
            let nanos = time.num_seconds_from_midnight() as u64 * 1e9 as u64 + time.nanosecond() as u64;

            let date = Date::new(to_days(naive.date(), 1) as u32);
            let time = Time {increments: nanos / 100, scale: 7};

            DateTime2::new(date, time)
        });
        chrono::DateTime<FixedOffset>: (ColumnData::DateTimeOffset, {
            use chrono::Timelike;

            let naive = self_.naive_utc();
            let time = naive.time();
            let nanos = time.num_seconds_from_midnight() as u64 * 1e9 as u64 + time.nanosecond() as u64;

            let date = Date::new(to_days(naive.date(), 1) as u32);
            let time = Time { increments: nanos / 100, scale: 7 };

            let tz = self_.timezone();
            let offset = (tz.local_minus_utc() / 60) as i16;

            DateTimeOffset::new(DateTime2::new(date, time), offset)
        });
);

#[cfg(feature = "tds73")]
into_sql!(self_,
        NaiveDate: (ColumnData::Date, Date::new(to_days(self_, 1) as u32));
        NaiveTime: (ColumnData::Time, {
            use chrono::Timelike;

            let nanos = self_.num_seconds_from_midnight() as u64 * 1e9 as u64 + self_.nanosecond() as u64;
            let increments = nanos / 100;

            Time {increments, scale: 7}
        });
        NaiveDateTime: (ColumnData::DateTime2, {
            use chrono::Timelike;

            let time = self_.time();
            let nanos = time.num_seconds_from_midnight() as u64 * 1e9 as u64 + time.nanosecond() as u64;
            let increments = nanos / 100;

            let date = Date::new(to_days(self_.date(), 1) as u32);
            let time = Time {increments, scale: 7};

            DateTime2::new(date, time)
        });
        chrono::DateTime<Utc>: (ColumnData::DateTime2, {
            use chrono::Timelike;

            let naive = self_.naive_utc();
            let time = naive.time();
            let nanos = time.num_seconds_from_midnight() as u64 * 1e9 as u64 + time.nanosecond() as u64;

            let date = Date::new(to_days(naive.date(), 1) as u32);
            let time = Time {increments: nanos / 100, scale: 7};

            DateTime2::new(date, time)
        });
        chrono::DateTime<FixedOffset>: (ColumnData::DateTimeOffset, {
            use chrono::Timelike;

            let naive = self_.naive_utc();
            let time = naive.time();
            let nanos = time.num_seconds_from_midnight() as u64 * 1e9 as u64 + time.nanosecond() as u64;

            let date = Date::new(to_days(naive.date(), 1) as u32);
            let time = Time { increments: nanos / 100, scale: 7 };

            let tz = self_.timezone();
            let offset = (tz.local_minus_utc() / 60) as i16;

            DateTimeOffset::new(DateTime2::new(date, time), offset)
        });
);

#[cfg(not(feature = "tds73"))]
to_sql!(self_,
        NaiveDateTime: (ColumnData::DateTime, {
            let date = self_.date();
            let time = self_.time();

            let days = to_days(date, 1900) as i32;
            let seconds_fragments = to_sec_fragments(time);

            DateTime1::new(days, seconds_fragments as u32)
        });
);

#[cfg(not(feature = "tds73"))]
into_sql!(self_,
        NaiveDateTime: (ColumnData::DateTime, {
            let date = self_.date();
            let time = self_.time();

            let days = to_days(date, 1900) as i32;
            let seconds_fragments = to_sec_fragments(time);

            DateTime1::new(days, seconds_fragments as u32)
        });
);

#[cfg(not(feature = "tds73"))]
from_sql!(
    NaiveDateTime:
        ColumnData::DateTime(ref dt) => dt.map(|dt| NaiveDateTime::new(
            from_days(dt.days as i64, 1900),
            from_sec_fragments(dt.seconds_fragments as i64)
        ))
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FromSql, IntoSql};

    #[test]
    fn from_days_clamps_on_overflow() {
        // A day offset far outside the representable `NaiveDate` range forces
        // the `checked_add_signed` fallback. Positive overflow must clamp to
        // MAX, negative overflow to MIN. This pins the `days < 0` sign test
        // (distinguishing it from `==` and `>`).
        assert_eq!(from_days(200_000_000, 1), NaiveDate::MAX);
        assert_eq!(from_days(-200_000_000, 1), NaiveDate::MIN);
    }

    #[test]
    fn from_sec_fragments_converts() {
        // 300 sec-fragments (1/300 s units) == exactly one second.
        assert_eq!(
            from_sec_fragments(300),
            NaiveTime::from_hms_opt(0, 0, 1).unwrap()
        );
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn from_mins_converts() {
        // `from_mins` takes seconds-from-midnight; 3600 s == 01:00:00.
        assert_eq!(from_mins(3600), NaiveTime::from_hms_opt(1, 0, 0).unwrap());
    }

    #[cfg(not(feature = "tds73"))]
    #[test]
    fn to_sec_fragments_converts() {
        // One second == 300 sec-fragments (1/300 s units).
        assert_eq!(
            to_sec_fragments(NaiveTime::from_hms_opt(0, 0, 1).unwrap()),
            300
        );
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn naive_date_round_trip() {
        let date = NaiveDate::from_ymd_opt(2021, 6, 15).unwrap();
        let cd: ColumnData<'static> = date.into_sql();
        assert!(matches!(cd, ColumnData::Date(Some(_))));
        assert_eq!(NaiveDate::from_sql(&cd).unwrap(), Some(date));
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn naive_time_round_trip() {
        let time = NaiveTime::from_hms_opt(13, 37, 42).unwrap();
        let cd: ColumnData<'static> = time.into_sql();
        assert!(matches!(cd, ColumnData::Time(Some(_))));
        assert_eq!(NaiveTime::from_sql(&cd).unwrap(), Some(time));
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn naive_datetime_round_trip() {
        let dt = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(2000, 12, 31).unwrap(),
            NaiveTime::from_hms_opt(23, 59, 58).unwrap(),
        );
        let cd: ColumnData<'static> = dt.into_sql();
        assert!(matches!(cd, ColumnData::DateTime2(Some(_))));
        assert_eq!(NaiveDateTime::from_sql(&cd).unwrap(), Some(dt));
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn datetime_utc_round_trip() {
        let naive = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(2015, 3, 4).unwrap(),
            NaiveTime::from_hms_opt(1, 2, 3).unwrap(),
        );
        let dt = chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        let cd: ColumnData<'static> = dt.into_sql();
        assert!(matches!(cd, ColumnData::DateTime2(Some(_))));
        assert_eq!(chrono::DateTime::<Utc>::from_sql(&cd).unwrap(), Some(dt));
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn datetime_fixed_offset_round_trip() {
        let offset = FixedOffset::east_opt(2 * 3600).unwrap();
        let naive = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(2015, 3, 4).unwrap(),
            NaiveTime::from_hms_opt(1, 2, 3).unwrap(),
        );
        let dt = chrono::DateTime::from_naive_utc_and_offset(naive, offset);
        let cd: ColumnData<'static> = dt.into_sql();
        assert!(matches!(cd, ColumnData::DateTimeOffset(Some(_))));
        assert_eq!(
            chrono::DateTime::<FixedOffset>::from_sql(&cd).unwrap(),
            Some(dt)
        );
    }

    // The tds73 `from_sql` NaiveDateTime path has a dedicated arm for the legacy
    // `ColumnData::DateTime` wire type; exercise it directly (round-trips produce
    // `DateTime2`, never `DateTime`, so this arm is otherwise unreachable).
    #[cfg(feature = "tds73")]
    #[test]
    fn naive_datetime_from_legacy_datetime_column() {
        let cd = ColumnData::DateTime(Some(crate::tds::time::DateTime::new(0, 0)));
        let dt = NaiveDateTime::from_sql(&cd).unwrap().unwrap();
        assert_eq!(
            dt,
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(1900, 1, 1).unwrap(),
                NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            )
        );
    }

    // The `DateTimeOffset -> DateTime<Utc>` conversion arm (distinct from the
    // `DateTime<FixedOffset>` arm exercised by the round-trip test).
    #[cfg(feature = "tds73")]
    #[test]
    fn datetime_offset_reads_as_utc() {
        let offset = FixedOffset::east_opt(2 * 3600).unwrap();
        let naive = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(2015, 3, 4).unwrap(),
            NaiveTime::from_hms_opt(1, 2, 3).unwrap(),
        );
        let dt: chrono::DateTime<FixedOffset> =
            chrono::DateTime::from_naive_utc_and_offset(naive, offset);
        let cd: ColumnData<'static> = dt.into_sql();
        assert!(matches!(cd, ColumnData::DateTimeOffset(Some(_))));

        let utc = chrono::DateTime::<Utc>::from_sql(&cd).unwrap();
        assert!(utc.is_some());
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn null_maps_to_none() {
        assert_eq!(NaiveDate::from_sql(&ColumnData::Date(None)).unwrap(), None);
        assert_eq!(NaiveTime::from_sql(&ColumnData::Time(None)).unwrap(), None);
    }

    #[cfg(not(feature = "tds73"))]
    #[test]
    fn naive_datetime_round_trip_legacy() {
        let dt = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(1990, 1, 1).unwrap(),
            NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
        );
        let cd: ColumnData<'static> = dt.into_sql();
        assert!(matches!(cd, ColumnData::DateTime(Some(_))));
        assert_eq!(NaiveDateTime::from_sql(&cd).unwrap(), Some(dt));
    }
}
