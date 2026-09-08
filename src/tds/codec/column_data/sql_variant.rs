//! Decoding of the `SQL_VARIANT` (`0x62`) column value.
//!
//! A `sql_variant` stores an intrinsic value together with the metadata needed
//! to interpret it. On the wire the value is laid out as described in
//! [MS-TDS] §2.2.5.5.3:
//!
//! ```text
//! totalLen  (ULONG, 4 bytes)   -- length of everything that follows; 0 = NULL
//! baseType  (BYTE)             -- the TYPE token of the stored value
//! propBytes (BYTE)             -- number of type-specific metadata bytes
//! propData  (propBytes bytes)  -- e.g. collation, precision/scale, scale, ...
//! value     (totalLen - 2 - propBytes bytes)
//! ```
//!
//! Because tiberius exposes intrinsic values directly, the decoded value is
//! mapped onto the matching [`ColumnData`] variant of the base type (e.g. an
//! `int` sql_variant becomes [`ColumnData::I32`]). A `NULL` sql_variant, which
//! carries no base type, is surfaced as [`ColumnData::String`]`(None)`.
//!
//! [MS-TDS]: https://learn.microsoft.com/openspecs/windows_protocols/ms-tds/

use std::convert::TryFrom;

use byteorder::{ByteOrder, LittleEndian};
use bytes::{BufMut, BytesMut};

use crate::{
    error::Error,
    sql_read_bytes::SqlReadBytes,
    tds::{codec::guid, codec::Encode, Collation, Numeric},
    ColumnData, FixedLenType, VarLenType,
};

/// Reads exactly `len` raw bytes from the stream.
///
/// Uses the packet-aware `read_u8` (a `sql_variant` value can span TDS packet
/// boundaries; `AsyncReadExt::read_exact` would treat a boundary as EOF). `len`
/// is bounded by the caller to `MAX_VARIANT_PAYLOAD`.
async fn read_bytes<R>(src: &mut R, len: usize) -> crate::Result<Vec<u8>>
where
    R: SqlReadBytes + Unpin,
{
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(src.read_u8().await?);
    }
    Ok(buf)
}

/// Cross-checks the server-declared `propBytes` count against the number of
/// property bytes the decode arm for a given base type actually consumes. A
/// peer declaring the wrong count would otherwise leave `data_len` (derived as
/// `total_len - 2 - prop_bytes`) wrong and silently desync every subsequent
/// column.
fn check_prop_bytes(got: usize, want: usize) -> crate::Result<()> {
    if got != want {
        return Err(Error::Protocol(
            format!("sql_variant: expected {want} property byte(s), got {got}").into(),
        ));
    }
    Ok(())
}

/// Cross-checks the server-declared value length (`data_len`) against the fixed
/// number of value bytes a base type must carry (e.g. a `guid` is always 16
/// bytes). Prevents a wrong/inflated declared length from desyncing the stream.
fn check_data_len(got: usize, want: usize) -> crate::Result<()> {
    if got != want {
        return Err(Error::Protocol(
            format!("sql_variant: expected value length {want}, got {got}").into(),
        ));
    }
    Ok(())
}

pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let total_len = src.read_u32_le().await? as usize;

    // A zero total length is the NULL representation of a sql_variant. There is
    // no base type available, so surface a generic null value.
    if total_len == 0 {
        return Ok(ColumnData::String(None));
    }

    if total_len < 2 {
        return Err(Error::Protocol(
            format!("sql_variant: invalid total length {}", total_len).into(),
        ));
    }

    let base_type = src.read_u8().await?;
    let prop_bytes = src.read_u8().await? as usize;

    if total_len < 2 + prop_bytes {
        return Err(Error::Protocol(
            format!(
                "sql_variant: total length {} too small for {} property bytes",
                total_len, prop_bytes
            )
            .into(),
        ));
    }

    // Number of bytes of the actual value that follow the property metadata.
    let data_len = total_len - 2 - prop_bytes;

    // `sql_variant` cannot carry a LOB/(max) value, so `data_len` is bounded by
    // MAX_VARIANT_PAYLOAD. Reject an over-large server-supplied length before it
    // is used to size any allocation (read_bytes).
    if data_len > MAX_VARIANT_PAYLOAD {
        return Err(Error::Protocol(
            format!("sql_variant: value length {data_len} exceeds the maximum").into(),
        ));
    }

    // Fixed-length base types (bit, tinyint, smallint, int, bigint, real,
    // float, money, smallmoney, datetime, smalldatetime) carry no property
    // bytes and are decoded exactly like a fixed-length column value.
    if let Ok(fixed) = FixedLenType::try_from(base_type) {
        if prop_bytes != 0 {
            return Err(Error::Protocol(
                format!(
                    "sql_variant: fixed base type {:?} must not carry property bytes",
                    fixed
                )
                .into(),
            ));
        }

        return super::fixed_len::decode(src, &fixed).await;
    }

    let var = VarLenType::try_from(base_type).map_err(|_| {
        Error::Protocol(format!("sql_variant: unknown base type 0x{:02x}", base_type).into())
    })?;

    let res = match var {
        VarLenType::Guid => {
            check_prop_bytes(prop_bytes, 0)?;
            check_data_len(data_len, 16)?;
            let bytes = read_bytes(src, 16).await?;
            let mut data: [u8; 16] = bytes
                .try_into()
                .map_err(|_| Error::Protocol("sql_variant: short guid".into()))?;
            guid::reorder_bytes(&mut data);
            ColumnData::Guid(Some(uuid::Uuid::from_bytes(data)))
        }
        VarLenType::Decimaln | VarLenType::Numericn => {
            // propData = precision (1 byte) + scale (1 byte)
            check_prop_bytes(prop_bytes, 2)?;
            let _precision = src.read_u8().await?;
            let scale = src.read_u8().await?;

            decode_numeric(src, data_len, scale).await?
        }
        VarLenType::BigChar | VarLenType::BigVarChar => {
            // propData = collation (5 bytes) + max length (2 bytes)
            check_prop_bytes(prop_bytes, 7)?;
            let collation = read_collation(src).await?;
            let _max_len = src.read_u16_le().await?;

            let buf = read_bytes(src, data_len).await?;
            let encoder = collation.encoding()?;
            let s = encoder
                .decode_without_bom_handling_and_without_replacement(buf.as_ref())
                .ok_or_else(|| Error::Encoding("sql_variant: invalid sequence".into()))?
                .to_string();

            ColumnData::String(Some(s.into()))
        }
        VarLenType::NChar | VarLenType::NVarchar => {
            // propData = collation (5 bytes) + max length (2 bytes)
            check_prop_bytes(prop_bytes, 7)?;
            let _collation = read_collation(src).await?;
            let _max_len = src.read_u16_le().await?;

            let buf = read_bytes(src, data_len).await?;

            if buf.len() % 2 != 0 {
                return Err(Error::Protocol("sql_variant: invalid nchar length".into()));
            }

            let buf: Vec<u16> = buf.chunks(2).map(LittleEndian::read_u16).collect();
            ColumnData::String(Some(String::from_utf16(&buf)?.into()))
        }
        VarLenType::BigBinary | VarLenType::BigVarBin => {
            // propData = max length (2 bytes)
            check_prop_bytes(prop_bytes, 2)?;
            let _max_len = src.read_u16_le().await?;
            let buf = read_bytes(src, data_len).await?;

            ColumnData::Binary(Some(buf.into()))
        }
        #[cfg(feature = "tds73")]
        VarLenType::Daten => {
            // propData is empty; value is a 3 byte date.
            check_prop_bytes(prop_bytes, 0)?;
            check_data_len(data_len, 3)?;
            ColumnData::Date(Some(crate::tds::time::Date::decode(src).await?))
        }
        #[cfg(feature = "tds73")]
        VarLenType::Timen => {
            // propData = scale (1 byte)
            check_prop_bytes(prop_bytes, 1)?;
            let scale = src.read_u8().await? as usize;
            let time = crate::tds::time::Time::decode(src, scale, data_len).await?;

            ColumnData::Time(Some(time))
        }
        #[cfg(feature = "tds73")]
        VarLenType::Datetime2 => {
            // propData = scale (1 byte); value = time bytes + 3 date bytes.
            check_prop_bytes(prop_bytes, 1)?;
            let scale = src.read_u8().await? as usize;
            let time_len = data_len
                .checked_sub(3)
                .ok_or_else(|| Error::Protocol("sql_variant: datetime2 value too short".into()))?;
            let dt = crate::tds::time::DateTime2::decode(src, scale, time_len).await?;

            ColumnData::DateTime2(Some(dt))
        }
        #[cfg(feature = "tds73")]
        VarLenType::DatetimeOffsetn => {
            // propData = scale (1 byte); value = datetime2 bytes + 2 offset bytes.
            check_prop_bytes(prop_bytes, 1)?;
            let scale = src.read_u8().await? as usize;
            let time_len = data_len.checked_sub(5).ok_or_else(|| {
                Error::Protocol("sql_variant: datetimeoffset value too short".into())
            })?;
            let time_len = u8::try_from(time_len).map_err(|_| {
                Error::Protocol("sql_variant: datetimeoffset time length too large".into())
            })?;
            let dto = crate::tds::time::DateTimeOffset::decode(src, scale, time_len).await?;

            ColumnData::DateTimeOffset(Some(dto))
        }
        other => {
            return Err(Error::Protocol(
                format!("sql_variant: unsupported base type {:?}", other).into(),
            ))
        }
    };

    Ok(res)
}

/// Reads a 5 byte collation (`info` `u32` + `sort_id` `u8`).
async fn read_collation<R>(src: &mut R) -> crate::Result<Collation>
where
    R: SqlReadBytes + Unpin,
{
    let info = src.read_u32_le().await?;
    let sort_id = src.read_u8().await?;

    Ok(Collation::new(info, sort_id))
}

/// Decodes the value part of a `numeric`/`decimal` sql_variant. Unlike a
/// regular column, the value has no leading length byte; it is a single sign
/// byte followed by the little-endian magnitude, filling `data_len` bytes.
async fn decode_numeric<R>(
    src: &mut R,
    data_len: usize,
    scale: u8,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    if data_len == 0 {
        return Err(Error::Protocol("sql_variant: empty numeric value".into()));
    }

    // The scale byte is server-controlled; Numeric::new_with_scale requires
    // scale <= 38 (and would otherwise panic).
    if scale > 38 {
        return Err(Error::Protocol(
            format!("sql_variant: invalid numeric scale {scale}").into(),
        ));
    }

    let sign = match src.read_u8().await? {
        0 => -1i128,
        1 => 1i128,
        _ => return Err(Error::Protocol("sql_variant: invalid numeric sign".into())),
    };

    let magnitude = read_bytes(src, data_len - 1).await?;

    let value = match magnitude.len() {
        4 => LittleEndian::read_u32(&magnitude) as i128,
        8 => LittleEndian::read_u64(&magnitude) as i128,
        12 => {
            let low = LittleEndian::read_u64(&magnitude[0..8]) as i128;
            let high = LittleEndian::read_u32(&magnitude[8..12]) as i128;
            low + high * (1i128 << 64)
        }
        16 => {
            let low = LittleEndian::read_u64(&magnitude[0..8]) as i128;
            let high = LittleEndian::read_u64(&magnitude[8..16]) as i128;
            low + high * (1i128 << 64)
        }
        n => {
            return Err(Error::Protocol(
                format!("sql_variant: invalid numeric magnitude length {}", n).into(),
            ))
        }
    };

    Ok(ColumnData::Numeric(Some(Numeric::new_with_scale(
        value * sign,
        scale,
    ))))
}

/// The maximum length in bytes of the character/binary payload a `sql_variant`
/// can carry. `sql_variant` cannot hold the `(max)`/LOB variants, so anything
/// larger cannot be represented.
const MAX_VARIANT_PAYLOAD: usize = 8000;

/// Encodes a [`ColumnData`] value as a `SQL_VARIANT` (`0x62`) value into `dst`.
///
/// The wire layout mirrors [`decode`] (MS-TDS §2.2.5.5.3): a 4 byte total
/// length followed by the base-type byte, a property-bytes count, the
/// type-specific property metadata and the raw value. A `NULL` value of any
/// variant is written as a zero total length.
///
/// The base type written for a given [`ColumnData`] variant is the same one the
/// decoder maps back onto that variant, so the two are symmetric. [`ColumnData::Xml`]
/// has no `sql_variant` base type and returns a [`crate::Error::Conversion`].
pub(crate) fn encode(dst: &mut BytesMut, data: ColumnData<'_>) -> crate::Result<()> {
    // The value part is built up first so its total length can be prefixed.
    let mut body = BytesMut::new();

    let has_value = match data {
        ColumnData::Bit(Some(val)) => {
            body.put_u8(FixedLenType::Bit as u8);
            body.put_u8(0);
            body.put_u8(val as u8);
            true
        }
        ColumnData::U8(Some(val)) => {
            body.put_u8(FixedLenType::Int1 as u8);
            body.put_u8(0);
            body.put_u8(val);
            true
        }
        ColumnData::I16(Some(val)) => {
            body.put_u8(FixedLenType::Int2 as u8);
            body.put_u8(0);
            body.put_i16_le(val);
            true
        }
        ColumnData::I32(Some(val)) => {
            body.put_u8(FixedLenType::Int4 as u8);
            body.put_u8(0);
            body.put_i32_le(val);
            true
        }
        ColumnData::I64(Some(val)) => {
            body.put_u8(FixedLenType::Int8 as u8);
            body.put_u8(0);
            body.put_i64_le(val);
            true
        }
        ColumnData::F32(Some(val)) => {
            body.put_u8(FixedLenType::Float4 as u8);
            body.put_u8(0);
            body.put_f32_le(val);
            true
        }
        ColumnData::F64(Some(val)) => {
            body.put_u8(FixedLenType::Float8 as u8);
            body.put_u8(0);
            body.put_f64_le(val);
            true
        }
        ColumnData::DateTime(Some(dt)) => {
            body.put_u8(FixedLenType::Datetime as u8);
            body.put_u8(0);
            dt.encode(&mut body)?;
            true
        }
        ColumnData::SmallDateTime(Some(dt)) => {
            body.put_u8(FixedLenType::Datetime4 as u8);
            body.put_u8(0);
            dt.encode(&mut body)?;
            true
        }
        ColumnData::Guid(Some(uuid)) => {
            body.put_u8(VarLenType::Guid as u8);
            body.put_u8(0);
            let mut bytes = *uuid.as_bytes();
            guid::reorder_bytes(&mut bytes);
            body.extend_from_slice(&bytes);
            true
        }
        ColumnData::Numeric(Some(num)) => {
            body.put_u8(VarLenType::Numericn as u8);
            // propData = precision (1 byte) + scale (1 byte)
            body.put_u8(2);
            body.put_u8(num.precision());
            body.put_u8(num.scale());

            // `Numeric::encode` emits a leading length byte followed by the
            // sign byte and the little-endian magnitude. A sql_variant value
            // carries no length byte, so drop it and keep sign + magnitude.
            let mut tmp = BytesMut::new();
            num.encode(&mut tmp)?;
            body.extend_from_slice(&tmp[1..]);
            true
        }
        ColumnData::String(Some(ref s)) => {
            let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

            if utf16.len() > MAX_VARIANT_PAYLOAD {
                return Err(Error::Conversion(
                    format!(
                        "sql_variant: string of {} bytes exceeds the {} byte limit",
                        utf16.len(),
                        MAX_VARIANT_PAYLOAD
                    )
                    .into(),
                ));
            }

            body.put_u8(VarLenType::NVarchar as u8);
            // propData = collation (5 bytes) + max length (2 bytes)
            body.put_u8(7);
            // A zero collation lets the server apply the database default, as
            // done elsewhere when encoding strings without a known collation.
            body.extend_from_slice(&[0u8; 5]);
            body.put_u16_le(MAX_VARIANT_PAYLOAD as u16);
            body.extend_from_slice(&utf16);
            true
        }
        ColumnData::Binary(Some(ref bytes)) => {
            if bytes.len() > MAX_VARIANT_PAYLOAD {
                return Err(Error::Conversion(
                    format!(
                        "sql_variant: binary of {} bytes exceeds the {} byte limit",
                        bytes.len(),
                        MAX_VARIANT_PAYLOAD
                    )
                    .into(),
                ));
            }

            body.put_u8(VarLenType::BigVarBin as u8);
            // propData = max length (2 bytes)
            body.put_u8(2);
            body.put_u16_le(MAX_VARIANT_PAYLOAD as u16);
            body.extend_from_slice(bytes);
            true
        }
        #[cfg(feature = "tds73")]
        ColumnData::Date(Some(date)) => {
            body.put_u8(VarLenType::Daten as u8);
            body.put_u8(0);
            date.encode(&mut body)?;
            true
        }
        #[cfg(feature = "tds73")]
        ColumnData::Time(Some(time)) => {
            body.put_u8(VarLenType::Timen as u8);
            // propData = scale (1 byte)
            body.put_u8(1);
            body.put_u8(time.scale());
            time.encode(&mut body)?;
            true
        }
        #[cfg(feature = "tds73")]
        ColumnData::DateTime2(Some(dt)) => {
            body.put_u8(VarLenType::Datetime2 as u8);
            // propData = scale (1 byte)
            body.put_u8(1);
            body.put_u8(dt.time().scale());
            dt.encode(&mut body)?;
            true
        }
        #[cfg(feature = "tds73")]
        ColumnData::DateTimeOffset(Some(dto)) => {
            body.put_u8(VarLenType::DatetimeOffsetn as u8);
            // propData = scale (1 byte)
            body.put_u8(1);
            body.put_u8(dto.datetime2().time().scale());
            dto.encode(&mut body)?;
            true
        }
        ColumnData::Xml(Some(_)) => {
            return Err(Error::Conversion(
                "sql_variant: xml is not a valid sql_variant base type".into(),
            ));
        }
        // Every `None` value (and a null XML) is a NULL sql_variant.
        _ => false,
    };

    if has_value {
        dst.put_u32_le(body.len() as u32);
        dst.extend_from_slice(&body);
    } else {
        // A zero total length is the NULL sql_variant representation.
        dst.put_u32_le(0);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    fn variant_reader(payload: &[u8]) -> impl SqlReadBytes {
        let mut buf = BytesMut::new();
        buf.put_u32_le(payload.len() as u32);
        buf.extend_from_slice(payload);
        buf.into_sql_read_bytes()
    }

    #[tokio::test]
    async fn decode_null() {
        let mut buf = BytesMut::new();
        buf.put_u32_le(0);
        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::String(None));
    }

    #[tokio::test]
    async fn decode_int() {
        // baseType = INT4 (0x38), propBytes = 0, value = 42 (i32 LE)
        let mut payload = vec![FixedLenType::Int4 as u8, 0];
        payload.extend_from_slice(&42i32.to_le_bytes());

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::I32(Some(42)));
    }

    #[tokio::test]
    async fn decode_bigint() {
        let mut payload = vec![FixedLenType::Int8 as u8, 0];
        payload.extend_from_slice(&(-7i64).to_le_bytes());

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::I64(Some(-7)));
    }

    #[tokio::test]
    async fn decode_bit() {
        let payload = vec![FixedLenType::Bit as u8, 0, 1];
        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::Bit(Some(true)));
    }

    #[tokio::test]
    async fn decode_nvarchar() {
        // baseType = NVARCHAR (0xE7), propBytes = 7 (5 collation + 2 max len)
        let text = "hi€";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let mut payload = vec![VarLenType::NVarchar as u8, 7];
        payload.extend_from_slice(&0u32.to_le_bytes()); // collation info
        payload.push(0); // sort id
        payload.extend_from_slice(&40u16.to_le_bytes()); // max length
        payload.extend_from_slice(&utf16);

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::String(Some(text.into())));
    }

    #[tokio::test]
    async fn decode_varchar() {
        // baseType = BIGVARCHAR (0xA7), latin1 collation.
        let mut payload = vec![VarLenType::BigVarChar as u8, 7];
        // Collation 13632521 / sort id 52 resolves to a windows-1252 codepage.
        payload.extend_from_slice(&13632521u32.to_le_bytes());
        payload.push(52);
        payload.extend_from_slice(&40u16.to_le_bytes());
        payload.extend_from_slice(b"abc");

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::String(Some("abc".into())));
    }

    #[tokio::test]
    async fn decode_binary() {
        let mut payload = vec![VarLenType::BigVarBin as u8, 2];
        payload.extend_from_slice(&40u16.to_le_bytes());
        payload.extend_from_slice(&[1u8, 2, 3, 4]);

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::Binary(Some(vec![1, 2, 3, 4].into())));
    }

    #[tokio::test]
    async fn decode_guid() {
        let uuid = uuid::Uuid::from_u128(0x0102030405060708090a0b0c0d0e0f10);
        let mut wire = *uuid.as_bytes();
        guid::reorder_bytes(&mut wire);

        let mut payload = vec![VarLenType::Guid as u8, 0];
        payload.extend_from_slice(&wire);

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::Guid(Some(uuid)));
    }

    #[tokio::test]
    async fn decode_numeric_value() {
        // numeric(18, 2) value of 123 (=> 1.23), stored as sign + 4 byte magnitude.
        let mut payload = vec![VarLenType::Numericn as u8, 2, 18, 2];
        payload.push(1); // positive sign
        payload.extend_from_slice(&123u32.to_le_bytes());

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(
            data,
            ColumnData::Numeric(Some(Numeric::new_with_scale(123, 2)))
        );
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn decode_date_value() {
        use crate::tds::time::Date;

        let mut payload = vec![VarLenType::Daten as u8, 0];
        payload.extend_from_slice(&730119u32.to_le_bytes()[..3]);

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::Date(Some(Date::new(730119))));
    }

    /// Encodes `value` as a sql_variant then decodes it back, asserting the
    /// round-trip is lossless and that the whole buffer is consumed.
    async fn round_trip(value: ColumnData<'static>) {
        let mut buf = BytesMut::new();
        encode(&mut buf, value.clone()).expect("encode must succeed");

        let reader = &mut buf.into_sql_read_bytes();
        let decoded = decode(reader).await.expect("decode must succeed");

        assert_eq!(decoded, value);

        reader
            .read_u8()
            .await
            .expect_err("decode must consume the entire buffer");
    }

    #[tokio::test]
    async fn round_trip_bit() {
        round_trip(ColumnData::Bit(Some(true))).await;
        round_trip(ColumnData::Bit(Some(false))).await;
    }

    #[tokio::test]
    async fn round_trip_integers() {
        round_trip(ColumnData::U8(Some(200))).await;
        round_trip(ColumnData::I16(Some(-1234))).await;
        round_trip(ColumnData::I32(Some(42))).await;
        round_trip(ColumnData::I64(Some(-9_000_000_000))).await;
    }

    #[tokio::test]
    async fn round_trip_floats() {
        round_trip(ColumnData::F32(Some(1.5))).await;
        round_trip(ColumnData::F64(Some(-2.5))).await;
    }

    #[tokio::test]
    async fn round_trip_guid() {
        let uuid = uuid::Uuid::from_u128(0x0102030405060708090a0b0c0d0e0f10);
        round_trip(ColumnData::Guid(Some(uuid))).await;
    }

    #[tokio::test]
    async fn round_trip_numeric() {
        round_trip(ColumnData::Numeric(Some(Numeric::new_with_scale(123, 2)))).await;
        round_trip(ColumnData::Numeric(Some(Numeric::new_with_scale(-4567, 4)))).await;
        round_trip(ColumnData::Numeric(Some(Numeric::new_with_scale(
            10i128.pow(30),
            0,
        ))))
        .await;
    }

    #[tokio::test]
    async fn round_trip_string() {
        round_trip(ColumnData::String(Some("hello€".into()))).await;
        round_trip(ColumnData::String(Some("".into()))).await;
    }

    #[tokio::test]
    async fn round_trip_binary() {
        round_trip(ColumnData::Binary(Some(vec![1u8, 2, 3, 4, 5].into()))).await;
        round_trip(ColumnData::Binary(Some(vec![].into()))).await;
    }

    #[tokio::test]
    async fn round_trip_datetime() {
        use crate::tds::time::{DateTime, SmallDateTime};

        round_trip(ColumnData::DateTime(Some(DateTime::new(200, 3000)))).await;
        round_trip(ColumnData::SmallDateTime(Some(SmallDateTime::new(
            200, 3000,
        ))))
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn round_trip_temporal_tds73() {
        use crate::tds::time::{Date, DateTime2, DateTimeOffset, Time};

        round_trip(ColumnData::Date(Some(Date::new(730119)))).await;
        round_trip(ColumnData::Time(Some(Time::new(222, 7)))).await;
        round_trip(ColumnData::DateTime2(Some(DateTime2::new(
            Date::new(55),
            Time::new(222, 7),
        ))))
        .await;
        round_trip(ColumnData::DateTimeOffset(Some(DateTimeOffset::new(
            DateTime2::new(Date::new(55), Time::new(222, 7)),
            -8,
        ))))
        .await;
    }

    #[tokio::test]
    async fn round_trip_null() {
        // A NULL of any variant decodes to the generic null representation.
        let mut buf = BytesMut::new();
        encode(&mut buf, ColumnData::I32(None)).expect("encode must succeed");
        let decoded = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(decoded, ColumnData::String(None));
    }

    #[tokio::test]
    async fn xml_is_rejected() {
        use crate::xml::XmlData;
        use std::borrow::Cow;

        let mut buf = BytesMut::new();
        let err = encode(
            &mut buf,
            ColumnData::Xml(Some(Cow::Owned(XmlData::new("<a/>")))),
        )
        .expect_err("xml must not encode as a sql_variant");

        assert!(matches!(err, Error::Conversion(_)));
    }

    // A `total_len` of exactly 2 is the smallest valid sql_variant (base type +
    // prop-bytes count, zero property bytes, empty value). The guard is
    // `total_len < 2`; mutating `<` to `<=`/`==` would reject this valid value.
    #[tokio::test]
    async fn decode_total_len_exactly_two() {
        let mut buf = BytesMut::new();
        buf.put_u32_le(2); // total length
        buf.put_u8(FixedLenType::Bit as u8); // base type
        buf.put_u8(0); // prop bytes
        buf.put_u8(1); // the Bit value (read by fixed_len::decode)

        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::Bit(Some(true)));
    }

    // `data_len` of exactly MAX_VARIANT_PAYLOAD (8000) is allowed; the guard is
    // `data_len > MAX_VARIANT_PAYLOAD`. Mutating `>` to `>=`/`==` would reject a
    // value that is exactly at the limit.
    #[tokio::test]
    async fn decode_data_len_at_max_payload() {
        let payload_bytes = vec![0x5Au8; MAX_VARIANT_PAYLOAD];

        let mut payload = vec![VarLenType::BigVarBin as u8, 2];
        payload.extend_from_slice(&40u16.to_le_bytes()); // max length prop
        payload.extend_from_slice(&payload_bytes);

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(data, ColumnData::Binary(Some(payload_bytes.into())));
    }

    // The numeric-scale guard is `scale > 38`; a scale of exactly 38 is valid.
    // Mutating `>` to `>=`/`==` would reject scale 38.
    #[tokio::test]
    async fn decode_numeric_scale_at_limit() {
        let mut payload = vec![VarLenType::Numericn as u8, 2, 38, 38];
        payload.push(1); // positive sign
        payload.extend_from_slice(&123u32.to_le_bytes());

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(
            data,
            ColumnData::Numeric(Some(Numeric::new_with_scale(123, 38)))
        );
    }

    // A 12-byte magnitude is reconstructed as `low + high * (1 << 64)`.
    // low = 5, high = 3 => 5 + 3 * 2^64. This kills the mutations of the three
    // operators on that line: `+`->`-`/`*`, `*`->`+`/`/`, and `<<`->`>>`
    // (which would give 5, 5*3*2^64, 5+(3+2^64), 5+3/2^64=5, and 5+3*1=8
    // respectively - all different from the true value).
    #[tokio::test]
    async fn decode_numeric_twelve_byte_magnitude() {
        let mut payload = vec![VarLenType::Numericn as u8, 2, 38, 0];
        payload.push(1); // positive sign
        payload.extend_from_slice(&5u64.to_le_bytes()); // low 8 bytes
        payload.extend_from_slice(&3u32.to_le_bytes()); // high 4 bytes

        let expected = 5i128 + 3i128 * (1i128 << 64);
        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(
            data,
            ColumnData::Numeric(Some(Numeric::new_with_scale(expected, 0)))
        );
    }

    // A string whose UTF-16 encoding is exactly MAX_VARIANT_PAYLOAD (8000)
    // bytes = 4000 BMP chars is allowed; the guard is `utf16.len() > MAX`.
    // Mutating `>` to `>=`/`==` would reject a value exactly at the limit.
    #[tokio::test]
    async fn encode_string_at_max_payload() {
        let s: String = "a".repeat(MAX_VARIANT_PAYLOAD / 2);
        let mut buf = BytesMut::new();
        encode(&mut buf, ColumnData::String(Some(s.into())))
            .expect("a string exactly at the limit must encode");
    }

    // Binary of exactly MAX_VARIANT_PAYLOAD (8000) bytes is allowed; the guard
    // is `bytes.len() > MAX`. Mutating `>` to `>=`/`==` would reject it.
    #[tokio::test]
    async fn encode_binary_at_max_payload() {
        let bytes = vec![0u8; MAX_VARIANT_PAYLOAD];
        let mut buf = BytesMut::new();
        encode(&mut buf, ColumnData::Binary(Some(bytes.into())))
            .expect("binary exactly at the limit must encode");
    }

    /// Builds a reader from a raw buffer where `total_len` is set explicitly
    /// (rather than derived from the payload), so the length-guard error arms
    /// can be exercised. Covers lines 63-65, 72-78, 88-90, 98-104.
    fn raw_reader(total_len: u32, rest: &[u8]) -> impl SqlReadBytes {
        let mut buf = BytesMut::new();
        buf.put_u32_le(total_len);
        buf.extend_from_slice(rest);
        buf.into_sql_read_bytes()
    }

    // total_len of 1 is non-zero but below the 2 byte minimum (base type +
    // prop-bytes count). Covers 62-66.
    #[tokio::test]
    async fn decode_total_len_below_two_errors() {
        let err = decode(&mut raw_reader(1, &[])).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // total_len smaller than 2 + prop_bytes is rejected. Covers 71-79.
    #[tokio::test]
    async fn decode_total_len_too_small_for_props_errors() {
        // base type + prop count = 5, but total_len is only 2.
        let err = decode(&mut raw_reader(2, &[FixedLenType::Int4 as u8, 5]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // data_len exceeding MAX_VARIANT_PAYLOAD is rejected before any allocation.
    // Covers 87-91.
    #[tokio::test]
    async fn decode_data_len_over_max_payload_errors() {
        // total_len 8005, prop_bytes 2 => data_len 8001 (> 8000).
        let err = decode(&mut raw_reader(8005, &[VarLenType::BigVarBin as u8, 2]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A fixed-length base type must not carry property bytes. Covers 97-105.
    #[tokio::test]
    async fn decode_fixed_type_with_props_errors() {
        // base = Int4 (fixed), prop_bytes = 1, total_len 3 => data_len 0.
        let err = decode(&mut raw_reader(3, &[FixedLenType::Int4 as u8, 1]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A base type that is neither a known fixed nor var-len type is rejected.
    // Covers 110-112.
    #[tokio::test]
    async fn decode_unknown_base_type_errors() {
        // 0x00 is not a FixedLenType nor a VarLenType.
        let err = decode(&mut variant_reader(&[0x00, 0])).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // An nchar/nvarchar value with an odd byte count cannot be a UTF-16 string.
    // Covers 151-153.
    #[tokio::test]
    async fn decode_nchar_odd_length_errors() {
        let mut payload = vec![VarLenType::NChar as u8, 7];
        payload.extend_from_slice(&0u32.to_le_bytes()); // collation info
        payload.push(0); // sort id
        payload.extend_from_slice(&40u16.to_le_bytes()); // max length
        payload.extend_from_slice(&[1u8, 2, 3]); // 3 = odd value bytes

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A var-len base type with no sql_variant decode arm (here: Xml) is
    // rejected via the `other` arm. Covers 203-207.
    #[tokio::test]
    async fn decode_unsupported_var_type_errors() {
        let err = decode(&mut variant_reader(&[VarLenType::Xml as u8, 0]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // decode_numeric rejects a zero-length value. Covers 235-237.
    #[tokio::test]
    async fn decode_numeric_empty_value_errors() {
        // prop_bytes 2 (precision + scale), no value bytes => data_len 0.
        let payload = vec![VarLenType::Numericn as u8, 2, 18, 2];
        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // decode_numeric rejects a scale greater than 38. Covers 241-245.
    #[tokio::test]
    async fn decode_numeric_scale_too_large_errors() {
        let mut payload = vec![VarLenType::Numericn as u8, 2, 18, 39]; // scale 39
        payload.push(1); // sign
        payload.extend_from_slice(&123u32.to_le_bytes());

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // decode_numeric rejects a sign byte that is neither 0 nor 1. Covers 250.
    #[tokio::test]
    async fn decode_numeric_invalid_sign_errors() {
        let mut payload = vec![VarLenType::Numericn as u8, 2, 18, 2];
        payload.push(5); // invalid sign
        payload.extend_from_slice(&123u32.to_le_bytes());

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // An 8-byte magnitude is read as a little-endian u64. Covers 257.
    #[tokio::test]
    async fn decode_numeric_eight_byte_magnitude() {
        let mut payload = vec![VarLenType::Numericn as u8, 2, 18, 0];
        payload.push(1); // positive sign
        payload.extend_from_slice(&123_456_789_012u64.to_le_bytes());

        let data = decode(&mut variant_reader(&payload)).await.unwrap();
        assert_eq!(
            data,
            ColumnData::Numeric(Some(Numeric::new_with_scale(123_456_789_012, 0)))
        );
    }

    // A magnitude whose length is not 4/8/12/16 is rejected. Covers 268-272.
    #[tokio::test]
    async fn decode_numeric_bad_magnitude_length_errors() {
        let mut payload = vec![VarLenType::Numericn as u8, 2, 18, 0];
        payload.push(1); // positive sign
        payload.extend_from_slice(&[1u8, 2, 3, 4, 5]); // 5-byte magnitude

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A string whose UTF-16 encoding exceeds MAX_VARIANT_PAYLOAD is rejected.
    // Covers 381-390.
    #[tokio::test]
    async fn encode_string_over_max_payload_errors() {
        // 4001 BMP chars => 8002 UTF-16 bytes (> 8000).
        let s: String = "a".repeat(MAX_VARIANT_PAYLOAD / 2 + 1);
        let mut buf = BytesMut::new();
        let err = encode(&mut buf, ColumnData::String(Some(s.into()))).unwrap_err();
        assert!(matches!(err, Error::Conversion(_)), "got {err:?}");
    }

    // Binary larger than MAX_VARIANT_PAYLOAD is rejected. Covers 403-412.
    #[tokio::test]
    async fn encode_binary_over_max_payload_errors() {
        let bytes = vec![0u8; MAX_VARIANT_PAYLOAD + 1];
        let mut buf = BytesMut::new();
        let err = encode(&mut buf, ColumnData::Binary(Some(bytes.into()))).unwrap_err();
        assert!(matches!(err, Error::Conversion(_)), "got {err:?}");
    }

    // datetimeoffset value shorter than the mandatory 5 trailing bytes
    // (datetime2 + 2 offset bytes) is rejected. Covers 192-195.
    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn decode_datetimeoffset_too_short_errors() {
        // prop_bytes 1 (scale), value = 4 bytes (< 5).
        let mut payload = vec![VarLenType::DatetimeOffsetn as u8, 1, 0 /* scale */];
        payload.extend_from_slice(&[0u8; 4]);

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // datetimeoffset whose computed time length overflows a u8 is rejected.
    // Covers 196-198.
    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn decode_datetimeoffset_time_len_too_large_errors() {
        // prop_bytes 1 (scale), value = 261 bytes => time_len 256 (> u8::MAX).
        let mut payload = vec![VarLenType::DatetimeOffsetn as u8, 1, 0 /* scale */];
        payload.extend_from_slice(&[0u8; 261]);

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A guid arm consumes exactly 16 value bytes; a peer declaring a different
    // (here inflated) data_len must error rather than read 16 and desync the
    // rest of the row.
    #[tokio::test]
    async fn decode_guid_wrong_data_len_errors() {
        let uuid = uuid::Uuid::from_u128(0x0102030405060708090a0b0c0d0e0f10);
        let mut wire = *uuid.as_bytes();
        guid::reorder_bytes(&mut wire);

        // total_len 22, base + prop count = 2, prop_bytes 0 => data_len 20 (!= 16).
        let mut rest = vec![VarLenType::Guid as u8, 0];
        rest.extend_from_slice(&wire);
        rest.extend_from_slice(&[0u8; 4]); // 4 extra bytes to match total_len 22

        let err = decode(&mut raw_reader(22, &rest)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A guid must not declare any property bytes.
    #[tokio::test]
    async fn decode_guid_with_prop_bytes_errors() {
        // total_len 19, prop_bytes 1 => data_len 16, but prop_bytes must be 0.
        let mut rest = vec![VarLenType::Guid as u8, 1, 0xff /* stray prop */];
        rest.extend_from_slice(&[0u8; 16]);

        let err = decode(&mut raw_reader(19, &rest)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A char/varchar arm consumes exactly 7 property bytes (5 collation + 2 max
    // length). A peer declaring a different propBytes count must error rather
    // than read 7 and desync (data_len is derived from prop_bytes).
    #[tokio::test]
    async fn decode_bigvarchar_wrong_prop_bytes_errors() {
        // prop_bytes declared as 5 (should be 7).
        let mut payload = vec![VarLenType::BigVarChar as u8, 5];
        payload.extend_from_slice(&13632521u32.to_le_bytes());
        payload.push(52);
        payload.extend_from_slice(b"abc");

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // A binary arm consumes exactly 2 property bytes (max length). A wrong
    // propBytes count must error.
    #[tokio::test]
    async fn decode_binary_wrong_prop_bytes_errors() {
        // prop_bytes declared as 7 (should be 2).
        let mut payload = vec![VarLenType::BigVarBin as u8, 7];
        payload.extend_from_slice(&[0u8; 7]);
        payload.extend_from_slice(&[1u8, 2, 3, 4]);

        let err = decode(&mut variant_reader(&payload)).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }
}
