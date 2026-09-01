//! Representations of numeric types.

use super::codec::Encode;
use crate::{sql_read_bytes::SqlReadBytes, Error};
#[cfg(feature = "bigdecimal")]
#[cfg_attr(docsrs, doc(cfg(feature = "bigdecimal")))]
pub use bigdecimal::{num_bigint::BigInt, BigDecimal};
use byteorder::{ByteOrder, LittleEndian};
use bytes::{BufMut, BytesMut};
#[cfg(feature = "rust_decimal")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust_decimal")))]
pub use rust_decimal::Decimal;
use std::cmp::{Ordering, PartialEq};
use std::fmt::{self, Debug, Display, Formatter};

/// Represent a sql Decimal / Numeric type. It is stored in a i128 and has a
/// maximum precision of 38 decimals.
///
/// A recommended way of dealing with numeric values is by enabling the
/// `rust_decimal` feature and using its `Decimal` type instead.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Numeric {
    value: i128,
    scale: u8,
}

impl Numeric {
    /// Creates a new Numeric value.
    ///
    /// # Panic
    /// It will panic if the scale exceeds 38.
    pub fn new_with_scale(value: i128, scale: u8) -> Self {
        // SQL Server allows a maximum precision of 38, and scale may equal
        // precision (e.g. `decimal(38, 38)`), so scale 38 is valid; 10^38 still
        // fits in i128.
        assert!(scale <= 38);

        Numeric { value, scale }
    }

    /// Extract the decimal part.
    pub fn dec_part(self) -> i128 {
        let scale = self.pow_scale();
        self.value - (self.value / scale) * scale
    }

    /// Extract the integer part.
    pub fn int_part(self) -> i128 {
        self.value / self.pow_scale()
    }

    #[inline]
    fn pow_scale(self) -> i128 {
        10i128.pow(self.scale as u32)
    }

    /// The scale (where is the decimal point) of the value.
    #[inline]
    pub fn scale(self) -> u8 {
        self.scale
    }

    /// The internal integer value
    #[inline]
    pub fn value(self) -> i128 {
        self.value
    }

    /// The precision of the `Number` as a number of digits.
    pub fn precision(self) -> u8 {
        let mut result = 0;
        let mut n = self.int_part();

        while n != 0 {
            n /= 10;
            result += 1;
        }

        if result == 0 {
            1 + self.scale()
        } else {
            result + self.scale()
        }
    }

    pub(crate) fn len(self) -> u8 {
        match self.precision() {
            1..=9 => 5,
            10..=19 => 9,
            20..=28 => 13,
            _ => 17,
        }
    }

    pub(crate) async fn decode<R>(src: &mut R, scale: u8) -> crate::Result<Option<Self>>
    where
        R: SqlReadBytes + Unpin,
    {
        fn decode_d128(buf: &[u8]) -> u128 {
            let low_part = LittleEndian::read_u64(&buf[0..]) as u128;

            if !buf[8..].iter().any(|x| *x != 0) {
                return low_part;
            }

            let high_part = match buf.len() {
                12 => LittleEndian::read_u32(&buf[8..]) as u128,
                16 => LittleEndian::read_u64(&buf[8..]) as u128,
                _ => unreachable!(),
            };

            // `byteorder::LittleEndian` already yields the correct host-native
            // integer regardless of target endianness, so `low_part`/`high_part`
            // need no further swapping (a previous `cfg(target_endian = "big")`
            // swap here corrupted large decimals on big-endian hosts).
            let high_part = high_part * (u64::MAX as u128 + 1);
            low_part + high_part
        }

        let len = src.read_u8().await?;

        if len == 0 {
            Ok(None)
        } else {
            let sign = match src.read_u8().await? {
                0 => -1i128,
                1 => 1i128,
                _ => return Err(Error::Protocol("decimal: invalid sign".into())),
            };

            let value = match len {
                5 => src.read_u32_le().await? as i128 * sign,
                9 => src.read_u64_le().await? as i128 * sign,
                13 => {
                    let mut bytes = [0u8; 12]; //u96
                    for item in &mut bytes {
                        *item = src.read_u8().await?;
                    }
                    decode_d128(&bytes) as i128 * sign
                }
                17 => {
                    let mut bytes = [0u8; 16];
                    for item in &mut bytes {
                        *item = src.read_u8().await?;
                    }
                    let magnitude = decode_d128(&bytes);
                    // A legal `decimal(38, s)` magnitude is < 10^38 < i128::MAX,
                    // so any 16-byte magnitude that does not fit in i128 is
                    // malformed. Reject it rather than letting `as i128` wrap to
                    // a negative value (and `i128::MIN * -1` overflow-panic).
                    if magnitude > i128::MAX as u128 {
                        return Err(Error::Protocol(
                            "decimal/numeric: magnitude exceeds the representable range".into(),
                        ));
                    }
                    magnitude as i128 * sign
                }
                x => {
                    return Err(Error::Protocol(
                        format!("decimal/numeric: invalid length of {} received", x).into(),
                    ))
                }
            };

            Ok(Some(Numeric::new_with_scale(value, scale)))
        }
    }
}

impl Encode<BytesMut> for Numeric {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        // `len()` recomputes `precision()` via a division loop; compute it once.
        let len = self.len();
        dst.put_u8(len);

        if self.value < 0 {
            dst.put_u8(0);
        } else {
            dst.put_u8(1);
        }

        let value = self.value().abs();

        match len {
            5 => dst.put_u32_le(value as u32),
            9 => dst.put_u64_le(value as u64),
            13 => {
                dst.put_u64_le(value as u64);
                dst.put_u32_le((value >> 64) as u32)
            }
            _ => dst.put_u128_le(value as u128),
        }

        Ok(())
    }
}

impl Debug for Numeric {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        // Use `unsigned_abs()` rather than `.abs()`: a server may send an
        // adversarial magnitude that decodes to `i128::MIN` (or any value whose
        // negation overflows), and `i128::abs()` panics ("attempt to negate with
        // overflow") for `i128::MIN`. `unsigned_abs()` returns a `u128` and never
        // overflows, so `Debug`-formatting is total for all i128 inputs while
        // preserving the output for every in-range value.
        write!(
            f,
            "{}{}.{:0pad$}",
            if self.value() < 0 { "-" } else { "" },
            self.int_part().unsigned_abs(),
            self.dec_part().unsigned_abs(),
            pad = self.scale as usize
        )
    }
}

impl Display for Numeric {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}

impl Eq for Numeric {}

impl From<Numeric> for f64 {
    fn from(n: Numeric) -> f64 {
        n.dec_part() as f64 / n.pow_scale() as f64 + n.int_part() as f64
    }
}

impl From<Numeric> for i128 {
    fn from(n: Numeric) -> i128 {
        n.int_part()
    }
}

impl From<Numeric> for u128 {
    fn from(n: Numeric) -> u128 {
        n.int_part() as u128
    }
}

impl PartialEq for Numeric {
    fn eq(&self, other: &Self) -> bool {
        match self.scale.cmp(&other.scale) {
            Ordering::Greater => {
                10i128.pow((self.scale - other.scale) as u32) * other.value == self.value
            }
            Ordering::Less => {
                10i128.pow((other.scale - self.scale) as u32) * self.value == other.value
            }
            Ordering::Equal => self.value == other.value,
        }
    }
}

#[cfg(feature = "rust_decimal")]
mod decimal {
    use super::{Decimal, Numeric};
    use crate::ColumnData;

    #[cfg(feature = "tds73")]
    from_sql!(Decimal: ColumnData::Numeric(ref num) => num.map(|num| {
        Decimal::from_i128_with_scale(
            num.value(),
            num.scale() as u32,
        )})
    );

    #[cfg(feature = "tds73")]
    to_sql!(self_,
            Decimal: (ColumnData::Numeric, {
                let unpacked = self_.unpack();

                let mut value = (((unpacked.hi as u128) << 64)
                                 + ((unpacked.mid as u128) << 32)
                                 + unpacked.lo as u128) as i128;

                if self_.is_sign_negative() {
                    value = -value;
                }

                Numeric::new_with_scale(value, self_.scale() as u8)
            });
    );

    #[cfg(feature = "tds73")]
    into_sql!(self_,
            Decimal: (ColumnData::Numeric, {
                let unpacked = self_.unpack();

                let mut value = (((unpacked.hi as u128) << 64)
                                 + ((unpacked.mid as u128) << 32)
                                 + unpacked.lo as u128) as i128;

                if self_.is_sign_negative() {
                    value = -value;
                }

                Numeric::new_with_scale(value, self_.scale() as u8)
            });
    );
}

#[cfg(feature = "bigdecimal")]
mod bigdecimal_ {
    use super::{BigDecimal, BigInt, Numeric};
    use crate::ColumnData;
    use num_traits::ToPrimitive;
    use std::convert::TryFrom;

    #[cfg(feature = "tds73")]
    from_sql!(BigDecimal: ColumnData::Numeric(ref num) => num.map(|num| {
        let int = BigInt::from(num.value());

        BigDecimal::new(int, num.scale() as i64)
    }));

    #[cfg(feature = "tds73")]
    to_sql!(self_,
            BigDecimal: (ColumnData::Numeric, {
                let (int, exp) = self_.as_bigint_and_exponent();
                // SQL Server cannot store negative scales, so we have
                // to convert the number to the correct exponent
                // before storing.
                //
                // E.g. `Decimal(9, -3)` would be stored as
                // `Decimal(9000, 0)`.
                let (int, exp) = if exp < 0 {
                    self_.with_scale(0).into_bigint_and_exponent()
                } else {
                    (int, exp)
                };

                let value = int.to_i128().expect("Given BigDecimal overflowing the maximum accepted value.");

                let scale = u8::try_from(std::cmp::max(exp, 0))
                    .expect("Given BigDecimal exponent overflowing the maximum accepted scale (255).");

                Numeric::new_with_scale(value, scale)
            });
    );

    #[cfg(feature = "tds73")]
    into_sql!(self_,
            BigDecimal: (ColumnData::Numeric, {
                let (int, exp) = self_.as_bigint_and_exponent();
                // SQL Server cannot store negative scales, so we have
                // to convert the number to the correct exponent
                // before storing.
                //
                // E.g. `Decimal(9, -3)` would be stored as
                // `Decimal(9000, 0)`.
                let (int, exp) = if exp < 0 {
                    self_.with_scale(0).into_bigint_and_exponent()
                } else {
                    (int, exp)
                };
                let value = int.to_i128().expect("Given BigDecimal overflowing the maximum accepted value.");

                let scale = u8::try_from(std::cmp::max(exp, 0))
                    .expect("Given BigDecimal exponent overflowing the maximum accepted scale (255).");

                Numeric::new_with_scale(value, scale)
            });
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_eq() {
        assert_eq!(
            Numeric {
                value: 100501,
                scale: 2
            },
            Numeric {
                value: 1005010,
                scale: 3
            }
        );
        assert!(
            Numeric {
                value: 100501,
                scale: 2
            } != Numeric {
                value: 10050,
                scale: 1
            }
        );
    }

    #[test]
    fn numeric_eq_normalizes_across_a_scale_gap() {
        // 1.23 at scale 5 (123000) equals 1.23 at scale 2 (123). A scale gap of
        // 3 is chosen so the `self.scale - other.scale` exponent (3) differs from
        // both `+` (7) and `/` (1) — pinning the subtraction — and the
        // `10^gap * v` multiply differs from `+`/`/`. Both comparison directions
        // exercise the Greater and Less arms.
        let wide = Numeric {
            value: 123_000,
            scale: 5,
        };
        let narrow = Numeric {
            value: 123,
            scale: 2,
        };
        assert_eq!(wide, narrow); // Greater arm (self.scale > other.scale)
        assert_eq!(narrow, wide); // Less arm
        assert!(
            narrow
                != Numeric {
                    value: 124,
                    scale: 2
                }
        );
    }

    #[test]
    fn encode_byte_layout_matches_length_bucket() {
        // The encoder writes 1 length byte + 1 sign byte + (len-1) magnitude
        // bytes. This pins the per-length arms (deleting the 9- or 13-byte arm
        // would change the byte count) and the sign byte for zero.
        for value in [1i128, 10i128.pow(12), 10i128.pow(20), 10i128.pow(30)] {
            let n = Numeric::new_with_scale(value, 0);
            let expected = n.len() as usize + 1;
            let mut buf = BytesMut::new();
            n.encode(&mut buf).unwrap();
            assert_eq!(buf.len(), expected, "byte count for {value}");
        }

        // Zero is encoded as positive (sign byte 1), not negative.
        let mut zero = BytesMut::new();
        Numeric::new_with_scale(0, 0).encode(&mut zero).unwrap();
        assert_eq!(zero[1], 1, "zero must carry the positive sign byte");
    }

    #[tokio::test]
    async fn decode_d128_keeps_high_and_low_words() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

        // A magnitude whose high bytes are all non-zero: if decode_d128 wrongly
        // short-circuited on "all high bytes non-zero" it would drop the high
        // word and mis-decode. Positive (high byte 0x01 < i128::MAX high bit).
        let value = 0x0101_0101_0101_0101_0101_0101_0101_0101i128;
        let n = Numeric::new_with_scale(value, 0);
        let mut buf = BytesMut::new();
        n.encode(&mut buf).unwrap();
        let decoded = Numeric::decode(&mut buf.into_sql_read_bytes(), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded.value(), value);
    }

    #[tokio::test]
    async fn decode_accepts_magnitude_at_i128_max_but_rejects_beyond() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

        // 17-byte form: len, sign(1 = positive), then 16 magnitude bytes.
        let mut at_max = BytesMut::new();
        at_max.put_u8(17);
        at_max.put_u8(1);
        at_max.put_i128_le(i128::MAX); // magnitude exactly i128::MAX
        let decoded = Numeric::decode(&mut at_max.into_sql_read_bytes(), 0)
            .await
            .expect("i128::MAX magnitude is representable")
            .unwrap();
        assert_eq!(decoded.value(), i128::MAX);

        // One past i128::MAX (high bit set) must be rejected, not wrapped.
        let mut beyond = BytesMut::new();
        beyond.put_u8(17);
        beyond.put_u8(1);
        beyond.put_u128_le((i128::MAX as u128) + 1);
        assert!(Numeric::decode(&mut beyond.into_sql_read_bytes(), 0)
            .await
            .is_err());
    }

    #[test]
    fn numeric_to_f64() {
        assert_eq!(f64::from(Numeric::new_with_scale(57705, 2)), 577.05);
    }

    #[test]
    fn numeric_to_int_dec_part() {
        let n = Numeric::new_with_scale(57705, 2);
        assert_eq!(n.int_part(), 577);
        assert_eq!(n.dec_part(), 5);
    }

    #[test]
    fn numeric_to_string() {
        assert_eq!(Numeric::new_with_scale(123, 0).to_string(), "123.0");
        assert_eq!(Numeric::new_with_scale(123, 1).to_string(), "12.3");
        assert_eq!(Numeric::new_with_scale(123, 2).to_string(), "1.23");
        assert_eq!(Numeric::new_with_scale(123, 3).to_string(), "0.123");
        assert_eq!(Numeric::new_with_scale(123, 4).to_string(), "0.0123");
        assert_eq!(
            Numeric::new_with_scale(123, 36).to_string(),
            "0.000000000000000000000000000000000123"
        );
        assert_eq!(
            Numeric::new_with_scale(123, 37).to_string(),
            "0.0000000000000000000000000000000000123"
        );
        assert_eq!(Numeric::new_with_scale(-123, 0).to_string(), "-123.0");
        assert_eq!(Numeric::new_with_scale(-123, 1).to_string(), "-12.3");
        assert_eq!(Numeric::new_with_scale(-123, 2).to_string(), "-1.23");
        assert_eq!(Numeric::new_with_scale(-123, 3).to_string(), "-0.123");
        assert_eq!(Numeric::new_with_scale(-123, 4).to_string(), "-0.0123");
        assert_eq!(
            Numeric::new_with_scale(-123, 36).to_string(),
            "-0.000000000000000000000000000000000123"
        );
        assert_eq!(
            Numeric::new_with_scale(-123, 37).to_string(),
            "-0.0000000000000000000000000000000000123"
        );
    }

    // An adversarial server can send a 17-byte NUMERIC magnitude that
    // `Numeric::decode` casts `as i128` into `i128::MIN` (whose two's-complement
    // negation overflows). `Debug`/`Display` must not panic on such a value.
    #[test]
    fn debug_does_not_panic_on_i128_min() {
        for scale in [0u8, 2, 37] {
            let n = Numeric {
                value: i128::MIN,
                scale,
            };
            // Both must produce *some* string without panicking on `.abs()`.
            let _ = format!("{:?}", n);
            let _ = format!("{}", n);
        }
    }

    // A value just below 2^127 also wraps negative when cast `as i128`; formatting
    // it must likewise be total.
    #[test]
    fn debug_does_not_panic_near_2_pow_127() {
        // (2^127 - 1) reinterpreted as i128 is i128::MAX; (2^127) wraps to i128::MIN.
        // Exercise a spread of large-magnitude values around the boundary.
        for value in [i128::MAX, i128::MIN, i128::MIN + 1, i128::MAX - 1] {
            for scale in [0u8, 5, 37] {
                let n = Numeric { value, scale };
                let _ = format!("{:?}", n);
            }
        }
    }

    #[test]
    fn calculates_precision_correctly() {
        let n = Numeric::new_with_scale(57705, 2);
        assert_eq!(5, n.precision());
    }

    #[test]
    fn new_with_scale_accessors() {
        let n = Numeric::new_with_scale(12345, 3);
        assert_eq!(n.value(), 12345);
        assert_eq!(n.scale(), 3);
        assert_eq!(n.int_part(), 12);
        assert_eq!(n.dec_part(), 345);
    }

    #[test]
    fn new_with_scale_allows_max_scale() {
        // decimal(38, 38) is valid in SQL Server, so scale 38 must be accepted.
        assert_eq!(Numeric::new_with_scale(1, 38).scale(), 38);
    }

    #[test]
    #[should_panic]
    fn new_with_scale_panics_on_too_large_scale() {
        Numeric::new_with_scale(1, 39);
    }

    #[test]
    fn precision_with_zero_int_part() {
        // int_part == 0 -> precision is 1 + scale.
        let n = Numeric::new_with_scale(5, 2);
        assert_eq!(n.int_part(), 0);
        assert_eq!(n.precision(), 3);
    }

    #[test]
    fn precision_scaling_by_length_buckets() {
        assert_eq!(Numeric::new_with_scale(1, 0).len(), 5);
        assert_eq!(Numeric::new_with_scale(1_000_000_000, 0).len(), 9);
        assert_eq!(Numeric::new_with_scale(10i128.pow(19), 0).len(), 13);
        assert_eq!(Numeric::new_with_scale(10i128.pow(28), 0).len(), 17);
    }

    #[test]
    fn display_and_debug() {
        let n = Numeric::new_with_scale(57705, 2);
        assert_eq!(format!("{:?}", n), "577.05");
        assert_eq!(format!("{}", n), "577.05");

        // Negative values format with a single leading sign and an unsigned
        // fractional part (see #390).
        let n = Numeric::new_with_scale(-57705, 3);
        assert_eq!(format!("{}", n), "-57.705");

        // Zero-padded fractional part for small decimals.
        let n = Numeric::new_with_scale(102, 4);
        assert_eq!(format!("{}", n), "0.0102");
    }

    #[test]
    fn from_numeric_conversions() {
        let n = Numeric::new_with_scale(57705, 2);
        assert_eq!(i128::from(n), 577);
        assert_eq!(u128::from(n), 577);
        assert!((f64::from(n) - 577.05).abs() < f64::EPSILON);
    }

    #[test]
    fn eq_across_scales_negative() {
        assert_eq!(
            Numeric::new_with_scale(-100501, 2),
            Numeric::new_with_scale(-1005010, 3),
        );
    }

    async fn round_trip(value: i128, scale: u8) {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

        let n = Numeric::new_with_scale(value, scale);
        let mut buf = BytesMut::new();
        n.encode(&mut buf).expect("encode must succeed");

        let decoded = Numeric::decode(&mut buf.into_sql_read_bytes(), scale)
            .await
            .expect("decode must succeed")
            .expect("value must be present");

        assert_eq!(decoded, n);
        assert_eq!(decoded.value(), value);
    }

    #[tokio::test]
    async fn encode_decode_round_trip() {
        round_trip(0, 0).await; // len 5
        round_trip(42, 0).await; // len 5
        round_trip(-42, 2).await; // negative, len 5
        round_trip(10i128.pow(12), 0).await; // len 9
        round_trip(10i128.pow(20), 0).await; // len 13
        round_trip(-(10i128.pow(20)), 3).await; // negative, len 13
        round_trip(10i128.pow(30), 0).await; // len 17
    }

    #[tokio::test]
    async fn decode_zero_length_is_none() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

        let mut buf = BytesMut::new();
        buf.put_u8(0);

        let decoded = Numeric::decode(&mut buf.into_sql_read_bytes(), 0)
            .await
            .expect("decode must succeed");

        assert!(decoded.is_none());
    }

    #[tokio::test]
    async fn decode_rejects_len17_magnitude_over_i128_max() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

        // len = 17, sign = 1 (positive), magnitude = 2^127 (byte[15] = 0x80),
        // which exceeds i128::MAX. Must return a protocol error rather than
        // wrapping to a negative value (or panicking on i128::MIN * -1).
        let mut buf = BytesMut::new();
        buf.put_u8(17);
        buf.put_u8(1);
        let mut mag = [0u8; 16];
        mag[15] = 0x80;
        buf.extend_from_slice(&mag);

        let err = Numeric::decode(&mut buf.into_sql_read_bytes(), 0)
            .await
            .expect_err("out-of-range magnitude must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn decode_rejects_invalid_sign_and_length() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

        // Invalid sign byte (2 is neither 0 nor 1).
        let mut buf = BytesMut::new();
        buf.put_u8(5);
        buf.put_u8(2);
        buf.put_u32_le(1);
        let err = Numeric::decode(&mut buf.into_sql_read_bytes(), 0)
            .await
            .expect_err("invalid sign must error");
        assert!(matches!(err, Error::Protocol(_)));

        // Invalid length byte (6 is not one of 0/5/9/13/17).
        let mut buf = BytesMut::new();
        buf.put_u8(6);
        buf.put_u8(1);
        buf.extend_from_slice(&[0u8; 4]);
        let err = Numeric::decode(&mut buf.into_sql_read_bytes(), 0)
            .await
            .expect_err("invalid length must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    #[cfg(feature = "bigdecimal")]
    fn no_overflowing_pow() {
        use crate::{ColumnData, ToSql};
        use bigdecimal::FromPrimitive;

        let dec = BigDecimal::new(BigInt::from_i8(1).unwrap(), -20);
        let res = dec.to_sql();

        assert_eq!(
            ColumnData::Numeric(Some(Numeric::new_with_scale(100000000000000000000i128, 0))),
            res
        );
    }
}
