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
use futures_util::io::AsyncReadExt;

use crate::{
    error::Error,
    sql_read_bytes::SqlReadBytes,
    tds::{codec::guid, Collation, Numeric},
    ColumnData, FixedLenType, VarLenType,
};

/// Reads exactly `len` raw bytes from the stream.
async fn read_bytes<R>(src: &mut R, len: usize) -> crate::Result<Vec<u8>>
where
    R: SqlReadBytes + Unpin,
{
    let mut buf = vec![0u8; len];
    src.read_exact(&mut buf).await?;
    Ok(buf)
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
            let mut data = [0u8; 16];
            src.read_exact(&mut data).await?;
            guid::reorder_bytes(&mut data);
            ColumnData::Guid(Some(uuid::Uuid::from_bytes(data)))
        }
        VarLenType::Decimaln | VarLenType::Numericn => {
            // propData = precision (1 byte) + scale (1 byte)
            let _precision = src.read_u8().await?;
            let scale = src.read_u8().await?;

            decode_numeric(src, data_len, scale).await?
        }
        VarLenType::BigChar | VarLenType::BigVarChar => {
            // propData = collation (5 bytes) + max length (2 bytes)
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
            let _max_len = src.read_u16_le().await?;
            let buf = read_bytes(src, data_len).await?;

            ColumnData::Binary(Some(buf.into()))
        }
        #[cfg(feature = "tds73")]
        VarLenType::Daten => {
            // propData is empty; value is a 3 byte date.
            ColumnData::Date(Some(crate::tds::time::Date::decode(src).await?))
        }
        #[cfg(feature = "tds73")]
        VarLenType::Timen => {
            // propData = scale (1 byte)
            let scale = src.read_u8().await? as usize;
            let time = crate::tds::time::Time::decode(src, scale, data_len).await?;

            ColumnData::Time(Some(time))
        }
        #[cfg(feature = "tds73")]
        VarLenType::Datetime2 => {
            // propData = scale (1 byte); value = time bytes + 3 date bytes.
            let scale = src.read_u8().await? as usize;
            let dt = crate::tds::time::DateTime2::decode(src, scale, data_len - 3).await?;

            ColumnData::DateTime2(Some(dt))
        }
        #[cfg(feature = "tds73")]
        VarLenType::DatetimeOffsetn => {
            // propData = scale (1 byte); value = datetime2 bytes + 2 offset bytes.
            let scale = src.read_u8().await? as usize;
            let dto =
                crate::tds::time::DateTimeOffset::decode(src, scale, (data_len - 5) as u8).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    fn variant_reader(payload: &[u8]) -> impl SqlReadBytes + Unpin {
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
}
