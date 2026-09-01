use crate::{error::Error, sql_read_bytes::SqlReadBytes, ColumnData};
use bytes::BufMut;
use std::fmt::Display;

/// Money is a fixed-point decimal with this many fractional digits; it is stored
/// on the wire as the value multiplied by `10^MONEY_SCALE`.
const MONEY_SCALE: u32 = 4;

/// `10^MONEY_SCALE`, as an `f64`, used to scale an `f64` value into the on-wire
/// fixed-point integer domain.
const MONEY_SCALE_FACTOR: f64 = 1e4;

/// Range-check an already-scaled money value (`value * 10^MONEY_SCALE`, held in
/// an `i128` so no rounding or overflow can occur here) against the target
/// column's integer range and, if it fits, emit the on-wire bytes. `max_len` is
/// the column's declared length (8 for `money`, 4 for `smallmoney`). `value` is
/// only used to build a descriptive error message.
///
/// `length_prefixed` selects the wire framing. A nullable `MONEYN` column
/// (`TypeInfo::VarLenSized(Money)`) is a BYTELEN variable-length type whose row
/// value is preceded by a single length byte, so pass `true`. A NOT-NULL `MONEY`
/// / `SMALLMONEY` column arrives as `TypeInfo::FixedLen(Money/Money4)`, a
/// FIXEDLENTYPE whose row value is the raw fixed-width bytes with NO length
/// prefix (mirroring `fixed_len::decode`, which reads exactly `max_len` raw
/// bytes for money) — pass `false`.
fn put_scaled<B>(
    dst: &mut B,
    max_len: usize,
    scaled: i128,
    value: &dyn Display,
    length_prefixed: bool,
) -> crate::Result<()>
where
    B: BufMut,
{
    if max_len == 4 {
        // smallmoney: scaled value must fit in an i32.
        if scaled < i32::MIN as i128 || scaled > i32::MAX as i128 {
            return Err(Error::BulkInput(
                format!(
                    "money: value {value} is out of range for smallmoney \
                     (-214_748.3648 ..= 214_748.3647)"
                )
                .into(),
            ));
        }
        if length_prefixed {
            dst.put_u8(4);
        }
        dst.put_i32_le(scaled as i32);
    } else {
        // money: scaled value must fit in an i64.
        if scaled < i64::MIN as i128 || scaled > i64::MAX as i128 {
            return Err(Error::BulkInput(
                format!(
                    "money: value {value} is out of range for money \
                     (-922_337_203_685_477.5808 ..= 922_337_203_685_477.5807)"
                )
                .into(),
            ));
        }
        if length_prefixed {
            dst.put_u8(8);
        }
        let scaled = scaled as i64;
        // money is transmitted as two 32-bit words, high word first.
        dst.put_i32_le((scaled >> 32) as i32);
        dst.put_u32_le(scaled as u32);
    }

    Ok(())
}

/// Encode an `f64` as a length-prefixed money/smallmoney value into `dst` (the
/// framing a nullable `MONEYN`/`VarLenSized` column expects in a bulk-load row).
/// For a NOT-NULL `MONEY`/`SMALLMONEY` column, which arrives as
/// `TypeInfo::FixedLen` and takes the raw fixed-width bytes with no length
/// prefix, use [`encode_fixed`]. `max_len` is the column's declared length (8
/// for `money`, 4 for `smallmoney`). Money is stored on the wire as a scaled
/// integer (value * 10_000).
///
/// Returns an error (rather than silently corrupting the value) when `val` is
/// not finite (`NaN`/`±Inf`) or when the scaled value falls outside the range
/// representable by the target column. The range-check is performed in `i128`,
/// not `f64`: `i64::MAX` is not representable in `f64` (it rounds up to 2^63), so
/// comparing the scaled `f64` against `i64::MAX as f64` would let a value one
/// hundredth-of-a-cent past the maximum slip through and then saturate on the
/// `as i64` cast. Casting the rounded value to `i128` first is exact for every
/// in-range magnitude and rejects the 2^63 boundary correctly.
///
/// Note: money's exact extremes (`±922_337_203_685_477.5807/.5808`) are not
/// representable in `f64`, so values within ~0.05 of the maximum may round to
/// 2^63 and be rejected by this path. Callers needing exact extreme values
/// should use [`encode_numeric`], whose arithmetic is exact.
pub(crate) fn encode<B>(dst: &mut B, max_len: usize, val: f64) -> crate::Result<()>
where
    B: BufMut,
{
    encode_inner(dst, max_len, val, true)
}

/// Like [`encode`], but writes the raw fixed-width money bytes with NO length
/// prefix, as a NOT-NULL `MONEY`/`SMALLMONEY` column (`TypeInfo::FixedLen`)
/// expects in a bulk-load row (mirroring `fixed_len::decode`, which reads exactly
/// `max_len` raw bytes for money).
pub(crate) fn encode_fixed<B>(dst: &mut B, max_len: usize, val: f64) -> crate::Result<()>
where
    B: BufMut,
{
    encode_inner(dst, max_len, val, false)
}

fn encode_inner<B>(
    dst: &mut B,
    max_len: usize,
    val: f64,
    length_prefixed: bool,
) -> crate::Result<()>
where
    B: BufMut,
{
    if !val.is_finite() {
        return Err(Error::BulkInput(
            format!("money: value {val} is not finite (NaN/Inf cannot be encoded)").into(),
        ));
    }

    // Scale into money's fixed-point domain, rounding in f64 for parity with the
    // previous behaviour, then narrow to i128 (exact for every finite in-range
    // magnitude; a huge finite value saturates to i128::MIN/MAX and is rejected
    // by the range-check in `put_scaled`).
    let scaled = (val * MONEY_SCALE_FACTOR).round() as i128;

    put_scaled(dst, max_len, scaled, &val, length_prefixed)
}

/// Encode a [`Numeric`] into a length-prefixed money/smallmoney value into
/// `dst`, using exact integer arithmetic (the `MONEYN`/`VarLenSized` framing).
/// For a NOT-NULL `FixedLen` money column, use [`encode_numeric_fixed`].
///
/// Money is a fixed-point decimal with scale 4 stored as a scaled integer
/// (`value * 10_000`). Going via `f64` (as the plain `f64` path does) is lossy
/// for large magnitudes: money's scaled range reaches ~9.2e18, well beyond the
/// 2^53 exact-integer range of `f64`, so big values would be corrupted. This
/// path rescales the `Numeric`'s i128 mantissa to scale 4 entirely in i128, so
/// every in-range money value round-trips exactly.
///
/// Rounding, when the source scale is finer than 4, is round-half-away-from-zero
/// to match the `.round()` used by the `f64` [`encode`] path. Values that do not
/// fit the target column's integer range (`i64` for money, `i32` for
/// smallmoney) are rejected with [`Error::BulkInput`] rather than silently
/// wrapping or saturating.
pub(crate) fn encode_numeric<B>(
    dst: &mut B,
    max_len: usize,
    num: &crate::tds::Numeric,
) -> crate::Result<()>
where
    B: BufMut,
{
    encode_numeric_inner(dst, max_len, num, true)
}

/// Like [`encode_numeric`], but writes the raw fixed-width money bytes with NO
/// length prefix, for a NOT-NULL `FixedLen` money/smallmoney column.
pub(crate) fn encode_numeric_fixed<B>(
    dst: &mut B,
    max_len: usize,
    num: &crate::tds::Numeric,
) -> crate::Result<()>
where
    B: BufMut,
{
    encode_numeric_inner(dst, max_len, num, false)
}

fn encode_numeric_inner<B>(
    dst: &mut B,
    max_len: usize,
    num: &crate::tds::Numeric,
    length_prefixed: bool,
) -> crate::Result<()>
where
    B: BufMut,
{
    let scale = num.scale() as u32;
    let mantissa = num.value();

    // Rescale the mantissa to money's fixed scale, in i128.
    let scaled: i128 = match scale.cmp(&MONEY_SCALE) {
        std::cmp::Ordering::Equal => mantissa,
        std::cmp::Ordering::Less => {
            let factor = 10i128.pow(MONEY_SCALE - scale);
            mantissa.checked_mul(factor).ok_or_else(|| {
                Error::BulkInput(
                    format!("money: value {num} overflows while rescaling to money").into(),
                )
            })?
        }
        std::cmp::Ordering::Greater => {
            // finer than money's scale: divide, rounding half away from zero.
            let divisor = 10i128.pow(scale - MONEY_SCALE);
            let quotient = mantissa / divisor;
            let remainder = (mantissa % divisor).abs();
            if remainder * 2 >= divisor {
                quotient + mantissa.signum()
            } else {
                quotient
            }
        }
    };

    put_scaled(dst, max_len, scaled, &num, length_prefixed)
}

pub(crate) async fn decode<R>(src: &mut R, len: u8) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let res = match len {
        0 => ColumnData::F64(None),
        4 => ColumnData::F64(Some(src.read_i32_le().await? as f64 / 1e4)),
        8 => ColumnData::F64(Some({
            let high = src.read_i32_le().await? as i64;
            let low = src.read_u32_le().await? as f64;

            ((high << 32) as f64 + low) / 1e4
        })),
        _ => {
            return Err(Error::Protocol(
                format!("money: length of {} is invalid", len).into(),
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

    // `smallmoney` (len 4) is a single scaled `i32` divided by 1e4. Uses a value
    // that is not a boundary: kills "delete match arm 4" (would fall through to
    // the error arm) and "replace `/` with `%`/`*`" (12345/1e4 = 1.2345, whereas
    // 12345 % 1e4 = 2345.0 and 12345 * 1e4 = 1.2345e8).
    #[tokio::test]
    async fn decode_smallmoney_arm() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(12345);

        let data = decode(&mut buf.into_sql_read_bytes(), 4).await.unwrap();
        match data {
            ColumnData::F64(Some(v)) => assert!((v - 1.2345).abs() < 1e-9, "v={}", v),
            other => panic!("expected F64, got {:?}", other),
        }
    }

    // `money` (len 8) is two 32-bit words: `((high << 32) + low) / 1e4`.
    // high = 1, low = 30000 gives ((1 << 32) + 30000) / 1e4 = 429499.7296.
    // Kills: "delete match arm 8" (error fallthrough); "replace `<<` with `>>`"
    // (1 >> 32 = 0 => 3.0); "replace `+` with `-`/`*`" (subtraction/mult differ);
    // and "replace outer `/` with `%`/`*`" (4294997296 % 1e4 = 7296.0).
    #[tokio::test]
    async fn decode_money_arm() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(1); // high word
        buf.put_u32_le(30000); // low word

        let data = decode(&mut buf.into_sql_read_bytes(), 8).await.unwrap();
        match data {
            ColumnData::F64(Some(v)) => assert!((v - 429499.7296).abs() < 1e-6, "v={}", v),
            other => panic!("expected F64, got {:?}", other),
        }
    }

    // Reverses the on-wire money representation the same way `decode` does,
    // so we can assert `encode` is the exact inverse without a live server.
    fn decode_bytes(bytes: &[u8]) -> f64 {
        let len = bytes[0];
        match len {
            4 => i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as f64 / 1e4,
            8 => {
                let high = i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as i64;
                let low = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as f64;
                ((high << 32) as f64 + low) / 1e4
            }
            _ => panic!("invalid length"),
        }
    }

    #[test]
    fn encode_smallmoney_roundtrips() {
        let mut buf = Vec::new();
        encode(&mut buf, 4, 1234.5678).unwrap();
        assert_eq!(buf[0], 4);
        assert_eq!(buf.len(), 5);
        assert_eq!(decode_bytes(&buf), 1234.5678);
    }

    // A length other than 0/4/8 is an invalid money encoding. Covers 38-42.
    #[tokio::test]
    async fn decode_invalid_length_errors() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        let err = decode(&mut buf.into_sql_read_bytes(), 5).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // The `decode_bytes` test helper panics on an unexpected length prefix.
    // Covers line 99 (the helper's fallthrough arm).
    #[test]
    fn decode_bytes_invalid_length_panics() {
        let result = std::panic::catch_unwind(|| decode_bytes(&[2u8, 0, 0, 0, 0]));
        assert!(result.is_err());
    }

    #[test]
    fn encode_money_roundtrips() {
        for val in [0.0, 1.0, -1.0, 1234.5678, -9999.9999, 92233720368.5477] {
            let mut buf = Vec::new();
            encode(&mut buf, 8, val).unwrap();
            assert_eq!(buf[0], 8);
            assert_eq!(buf.len(), 9);
            assert!((decode_bytes(&buf) - val).abs() < 1e-3, "val={}", val);
        }
    }

    // `NaN` must be rejected: the old `as i32`/`as i64` cast turned it silently
    // into `0`, corrupting the row without any error.
    #[test]
    fn encode_nan_is_rejected() {
        for max_len in [4usize, 8usize] {
            let mut buf = Vec::new();
            let err = encode(&mut buf, max_len, f64::NAN).unwrap_err();
            assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
            assert!(buf.is_empty(), "nothing must be written on rejection");
        }
    }

    // `+Inf` must be rejected: the old cast saturated it to `i32::MAX`/`i64::MAX`.
    #[test]
    fn encode_positive_infinity_is_rejected() {
        for max_len in [4usize, 8usize] {
            let mut buf = Vec::new();
            let err = encode(&mut buf, max_len, f64::INFINITY).unwrap_err();
            assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
            assert!(buf.is_empty());
        }
    }

    // `-Inf` must be rejected: the old cast saturated it to `i32::MIN`/`i64::MIN`.
    #[test]
    fn encode_negative_infinity_is_rejected() {
        for max_len in [4usize, 8usize] {
            let mut buf = Vec::new();
            let err = encode(&mut buf, max_len, f64::NEG_INFINITY).unwrap_err();
            assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
            assert!(buf.is_empty());
        }
    }

    // Finite values beyond the column's range must be rejected rather than
    // saturating to the min/max on the wire.
    #[test]
    fn encode_over_max_is_rejected() {
        // Just past smallmoney's max (214_748.3647).
        let mut buf = Vec::new();
        let err = encode(&mut buf, 4, 214_749.0).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
        assert!(buf.is_empty());

        // Below smallmoney's min (-214_748.3648).
        let mut buf = Vec::new();
        let err = encode(&mut buf, 4, -214_749.0).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");

        // Well beyond money's max (~9.22e14).
        let mut buf = Vec::new();
        let err = encode(&mut buf, 8, 1e15).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
        assert!(buf.is_empty());

        // Well below money's min.
        let mut buf = Vec::new();
        let err = encode(&mut buf, 8, -1e15).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
    }

    // Boundary values at the edge of each column's range must still be accepted
    // and round-trip correctly.
    #[test]
    fn encode_boundaries_are_accepted() {
        // smallmoney min/max: both are exactly representable and must pass.
        for val in [214748.3647_f64, -214748.3648_f64] {
            let mut buf = Vec::new();
            encode(&mut buf, 4, val).unwrap();
            assert_eq!(buf[0], 4);
            assert!((decode_bytes(&buf) - val).abs() < 1e-3, "val={val}");
        }

        // money: `f64` cannot represent the exact money extremes, so use values
        // comfortably inside the range (still far beyond f64's 2^53 exact range).
        for val in [922337203685477.5_f64, -922337203685477.5_f64] {
            let mut buf = Vec::new();
            encode(&mut buf, 8, val).unwrap();
            assert_eq!(buf[0], 8);
            // f64 cannot represent the money extremes exactly; allow a tolerance
            // proportional to the magnitude (~0.1 currency units here).
            assert!((decode_bytes(&buf) - val).abs() < 1.0, "val={val}");
        }
    }

    // The scaled money max (i64::MAX = 9_223_372_036_854_775_807) is not
    // representable in f64. The earlier `scaled as f64 > i64::MAX as f64` check
    // let a value one hundredth-of-a-cent past the max through, then saturated
    // on the cast, silently writing i64::MAX. The i128 range-check must reject it.
    #[test]
    fn encode_rejects_float_boundary_just_past_max() {
        // smallmoney: 214748.3648 is exactly one ten-thousandth past i32::MAX.
        let mut buf = Vec::new();
        let err = encode(&mut buf, 4, 214748.3648).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
        assert!(buf.is_empty());

        // smallmoney accepts the exact max.
        let mut buf = Vec::new();
        encode(&mut buf, 4, 214748.3647).unwrap();
        assert_eq!(decode_bytes_scaled(&buf), i32::MAX as i64);

        // money: a value just past the max scales (in f64) to 2^63, one past
        // i64::MAX; it must be rejected, not saturated to i64::MAX.
        let mut buf = Vec::new();
        let err = encode(&mut buf, 8, 922337203685477.6).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
        assert!(buf.is_empty());
    }

    // Reconstruct the exact scaled integer from the on-wire bytes without going
    // through `f64`, so large-magnitude values can be asserted exactly.
    fn decode_bytes_scaled(bytes: &[u8]) -> i64 {
        match bytes[0] {
            4 => i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as i64,
            8 => {
                let high = i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as i64;
                let low = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as i64;
                (high << 32) | low
            }
            _ => panic!("invalid length"),
        }
    }

    // A large money value whose scaled form (value * 1e4) exceeds 2^53: the old
    // `f64::from(num)` path would corrupt it, but `encode_numeric` keeps it exact.
    #[test]
    fn encode_numeric_large_value_is_exact() {
        // 12_345_678_901_234.5678 in money units => scaled = 123456789012345678,
        // which is far larger than 2^53 (~9.007e15).
        let scaled: i128 = 123_456_789_012_345_678;
        let num = crate::tds::Numeric::new_with_scale(scaled, 4);

        let mut buf = Vec::new();
        encode_numeric(&mut buf, 8, &num).unwrap();
        assert_eq!(buf[0], 8);
        assert_eq!(decode_bytes_scaled(&buf) as i128, scaled);

        // Demonstrate the f64 path is lossy for the same value (guards the
        // motivation for this function): the round-tripped f64 scaled integer
        // differs from the exact one.
        let via_f64 = (f64::from(num) * 1e4).round() as i128;
        assert_ne!(via_f64, scaled, "f64 path unexpectedly stayed exact");
    }

    // scale < 4 is rescaled up by 10^(4-scale) with no loss.
    #[test]
    fn encode_numeric_scale_less_than_four() {
        // 12.34 stored as mantissa 1234 at scale 2.
        let num = crate::tds::Numeric::new_with_scale(1234, 2);
        let mut buf = Vec::new();
        encode_numeric(&mut buf, 8, &num).unwrap();
        // 12.34 * 1e4 = 123400.
        assert_eq!(decode_bytes_scaled(&buf), 123_400);
    }

    // scale > 4 divides by 10^(scale-4), rounding half away from zero.
    #[test]
    fn encode_numeric_scale_greater_than_four_rounds_half_away() {
        // 1.23455 at scale 5 -> scale 4 rounds to 1.2346 (half rounds away).
        let num = crate::tds::Numeric::new_with_scale(123_455, 5);
        let mut buf = Vec::new();
        encode_numeric(&mut buf, 8, &num).unwrap();
        assert_eq!(decode_bytes_scaled(&buf), 12_346);

        // Same magnitude negative: -1.23455 -> -1.2346.
        let num = crate::tds::Numeric::new_with_scale(-123_455, 5);
        let mut buf = Vec::new();
        encode_numeric(&mut buf, 8, &num).unwrap();
        assert_eq!(decode_bytes_scaled(&buf), -12_346);

        // Below the half point truncates toward zero: 1.23454 -> 1.2345.
        let num = crate::tds::Numeric::new_with_scale(123_454, 5);
        let mut buf = Vec::new();
        encode_numeric(&mut buf, 8, &num).unwrap();
        assert_eq!(decode_bytes_scaled(&buf), 12_345);
    }

    // Numeric values beyond the target column's range are rejected.
    #[test]
    fn encode_numeric_out_of_range_is_rejected() {
        // Past smallmoney's i32 scaled range.
        let num = crate::tds::Numeric::new_with_scale(3_000_000_000, 4);
        let mut buf = Vec::new();
        let err = encode_numeric(&mut buf, 4, &num).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
        assert!(buf.is_empty());

        // Past money's i64 scaled range.
        let num = crate::tds::Numeric::new_with_scale(10_000_000_000_000_000_000, 4);
        let mut buf = Vec::new();
        let err = encode_numeric(&mut buf, 8, &num).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
        assert!(buf.is_empty());

        // Overflow while rescaling a low-scale, huge mantissa up to scale 4.
        let num = crate::tds::Numeric::new_with_scale(i128::MAX, 0);
        let mut buf = Vec::new();
        let err = encode_numeric(&mut buf, 8, &num).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
    }

    // `encode_fixed` writes the raw fixed-width bytes with NO length prefix (the
    // `FixedLen`/NOT-NULL money framing), unlike `encode` which prefixes a length
    // byte. Assert the byte count and that the raw bytes decode to the value.
    #[test]
    fn encode_fixed_has_no_length_prefix() {
        // smallmoney: 4 raw bytes, scaled i32.
        let mut buf = Vec::new();
        encode_fixed(&mut buf, 4, 1234.5678).unwrap();
        assert_eq!(buf.len(), 4, "smallmoney fixed len must be exactly 4 bytes");
        let scaled = i32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(scaled, 12_345_678);

        // money: 8 raw bytes, two 32-bit words high-first.
        let mut buf = Vec::new();
        encode_fixed(&mut buf, 8, 1234.5678).unwrap();
        assert_eq!(buf.len(), 8, "money fixed len must be exactly 8 bytes");
        let high = i32::from_le_bytes(buf[0..4].try_into().unwrap()) as i64;
        let low = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as i64;
        assert_eq!((high << 32) | low, 12_345_678);
    }

    // `encode_numeric_fixed` mirrors `encode_fixed`: raw bytes, no length prefix.
    #[test]
    fn encode_numeric_fixed_has_no_length_prefix() {
        let num = crate::tds::Numeric::new_with_scale(12_345_678, 4); // 1234.5678

        let mut buf = Vec::new();
        encode_numeric_fixed(&mut buf, 4, &num).unwrap();
        assert_eq!(buf.len(), 4);
        assert_eq!(i32::from_le_bytes(buf[..4].try_into().unwrap()), 12_345_678);

        let mut buf = Vec::new();
        encode_numeric_fixed(&mut buf, 8, &num).unwrap();
        assert_eq!(buf.len(), 8);
        let high = i32::from_le_bytes(buf[0..4].try_into().unwrap()) as i64;
        let low = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as i64;
        assert_eq!((high << 32) | low, 12_345_678);
    }

    // The fixed path still range-checks: an out-of-range value is rejected and
    // nothing is written (no partial/desyncing bytes).
    #[test]
    fn encode_fixed_out_of_range_is_rejected() {
        let mut buf = Vec::new();
        let err = encode_fixed(&mut buf, 4, 214_749.0).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
        assert!(buf.is_empty());
    }

    // Boundary money/smallmoney values encode exactly through the integer path.
    #[test]
    fn encode_numeric_boundaries_are_exact() {
        // smallmoney max/min (scaled i32 bounds), as scale-4 Numerics.
        for scaled in [i32::MAX as i128, i32::MIN as i128] {
            let num = crate::tds::Numeric::new_with_scale(scaled, 4);
            let mut buf = Vec::new();
            encode_numeric(&mut buf, 4, &num).unwrap();
            assert_eq!(buf[0], 4);
            assert_eq!(decode_bytes_scaled(&buf) as i128, scaled);
        }

        // money max/min (scaled i64 bounds).
        for scaled in [i64::MAX as i128, i64::MIN as i128] {
            let num = crate::tds::Numeric::new_with_scale(scaled, 4);
            let mut buf = Vec::new();
            encode_numeric(&mut buf, 8, &num).unwrap();
            assert_eq!(buf[0], 8);
            assert_eq!(decode_bytes_scaled(&buf) as i128, scaled);
        }
    }
}
