mod binary;
mod bit;
mod bytes_mut_with_type_info;
#[cfg(feature = "tds73")]
mod date;
#[cfg(feature = "tds73")]
mod datetime2;
mod datetimen;
#[cfg(feature = "tds73")]
mod datetimeoffsetn;
mod fixed_len;
mod float;
mod guid;
mod image;
mod int;
mod money;
mod plp;
mod sql_variant;
mod string;
mod text;
#[cfg(feature = "tds73")]
mod time;
mod udt;
mod var_len;
mod xml;

/// Upper bound on how many bytes a value decoder will *pre-allocate* from a
/// server-supplied length field before it has read the corresponding data.
///
/// The wire length is untrusted: a malformed or hostile server can claim a
/// value is up to `u32::MAX`/`u64::MAX` bytes long. Reserving that up front is a
/// memory-exhaustion vector (and, for `u64` lengths, can even exceed `Vec`'s
/// `isize::MAX` capacity limit and panic). Decoders therefore cap the initial
/// reservation to this value and let the buffer grow as bytes actually arrive;
/// a short/lying length still fails cleanly when the read runs out of input.
pub(crate) const MAX_PREALLOC: usize = 8192; // 8 KiB

/// Absolute ceiling on the *total* size of a single PLP (partially
/// length-prefixed) value — `varchar(max)`, `nvarchar(max)`, `varbinary(max)`,
/// `xml`, and CLR UDTs. SQL Server's own MAX types top out at `2^31 - 1` bytes,
/// so any value that would grow past this is malformed. Without this bound the
/// "unknown length" PLP form (which streams an arbitrary number of chunks until
/// a zero-length terminator) lets a hostile server grow the accumulation buffer
/// without limit and OOM the client on a single column value.
pub(crate) const MAX_PLP_SIZE: usize = i32::MAX as usize;

use super::{Encode, FixedLenType, TypeInfo, VarLenType};
#[cfg(feature = "tds73")]
use crate::tds::time::{Date, DateTime2, DateTimeOffset, Time};
use crate::{
    tds::{time::DateTime, time::SmallDateTime, xml::XmlData, Numeric},
    FromSql, FromSqlOwned, IntoSql, SqlReadBytes, ToSql,
};
use bytes::BufMut;
pub(crate) use bytes_mut_with_type_info::BytesMutWithTypeInfo;
use std::borrow::{BorrowMut, Cow};
use uuid::Uuid;

const MAX_NVARCHAR_SIZE: usize = 1 << 30;

/// Number of days between `0001-01-01` (the `DateTime2`/`Date` epoch) and
/// `1900-01-01` (the `datetime`/`Datetimen` epoch).
#[cfg(feature = "tds73")]
const DAYS_YEAR_1_TO_1900: u32 = 693_595;

/// Converts a [`DateTime2`] value into the legacy `datetime` ([`DateTime`])
/// wire representation.
///
/// This is used when bulk-inserting a `DateTime2`/`Date` value into a column
/// whose server-side type is `datetime` (`Datetimen`). The `datetime` type
/// counts days from `1900-01-01` and stores the time of day as 1/300-second
/// fragments, so the sub-second precision of the source value is degraded to
/// match. Returns a [`Conversion`] error if the date is earlier than
/// `1900-01-01`, which `datetime` cannot represent.
///
/// [`Conversion`]: crate::Error::Conversion
#[cfg(feature = "tds73")]
fn datetime2_to_datetime(dt2: &DateTime2) -> crate::Result<DateTime> {
    let dt2_days = dt2.date().days();

    let days = dt2_days.checked_sub(DAYS_YEAR_1_TO_1900).ok_or_else(|| {
        crate::Error::Conversion(
            format!(
                "invalid datetime, expecting a date not earlier than 1900-01-01 but got {} days after year 1",
                dt2_days
            )
            .into(),
        )
    })? as i32;

    // `increments` are counted in 10^-scale seconds; convert to nanoseconds and
    // then to the 1/300-second fragments used by `datetime`, degrading the
    // sub-second precision in the process.
    let time = dt2.time();
    let nanos = time.increments() as u128 * 10u128.pow(9 - time.scale() as u32);
    let seconds_fragments = (nanos * 300 / 1_000_000_000) as u32;

    Ok(DateTime::new(days, seconds_fragments))
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A container of a value that can be represented as a TDS value.
pub enum ColumnData<'a> {
    /// 8-bit integer, unsigned.
    U8(Option<u8>),
    /// 16-bit integer, signed.
    I16(Option<i16>),
    /// 32-bit integer, signed.
    I32(Option<i32>),
    /// 64-bit integer, signed.
    I64(Option<i64>),
    /// 32-bit floating point number.
    F32(Option<f32>),
    /// 64-bit floating point number.
    F64(Option<f64>),
    /// Boolean.
    Bit(Option<bool>),
    /// A string value.
    String(Option<Cow<'a, str>>),
    /// A Guid (UUID) value.
    Guid(Option<Uuid>),
    /// Binary data.
    Binary(Option<Cow<'a, [u8]>>),
    /// Numeric value (a decimal).
    Numeric(Option<Numeric>),
    /// XML data.
    Xml(Option<Cow<'a, XmlData>>),
    /// DateTime value.
    DateTime(Option<DateTime>),
    /// A small DateTime value.
    SmallDateTime(Option<SmallDateTime>),
    #[cfg(feature = "tds73")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tds73")))]
    /// Time value.
    Time(Option<Time>),
    #[cfg(feature = "tds73")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tds73")))]
    /// Date value.
    Date(Option<Date>),
    #[cfg(feature = "tds73")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tds73")))]
    /// DateTime2 value.
    DateTime2(Option<DateTime2>),
    #[cfg(feature = "tds73")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tds73")))]
    /// DateTime2 value with an offset.
    DateTimeOffset(Option<DateTimeOffset>),
}

impl<'a> ColumnData<'a> {
    pub(crate) fn type_name(&self) -> Cow<'static, str> {
        match self {
            ColumnData::U8(_) => "tinyint".into(),
            ColumnData::I16(_) => "smallint".into(),
            ColumnData::I32(_) => "int".into(),
            ColumnData::I64(_) => "bigint".into(),
            ColumnData::F32(_) => "float(24)".into(),
            ColumnData::F64(_) => "float(53)".into(),
            ColumnData::Bit(_) => "bit".into(),
            ColumnData::String(None) => "nvarchar(4000)".into(),
            ColumnData::String(Some(ref s)) if s.len() <= 4000 => "nvarchar(4000)".into(),
            ColumnData::String(Some(ref s)) if s.len() <= MAX_NVARCHAR_SIZE => {
                "nvarchar(max)".into()
            }
            ColumnData::String(_) => "ntext(max)".into(),
            ColumnData::Guid(_) => "uniqueidentifier".into(),
            ColumnData::Binary(Some(ref b)) if b.len() <= 8000 => "varbinary(8000)".into(),
            ColumnData::Binary(_) => "varbinary(max)".into(),
            ColumnData::Numeric(Some(ref n)) => {
                format!("numeric({},{})", n.precision(), n.scale()).into()
            }
            ColumnData::Numeric(None) => "numeric".into(),
            ColumnData::Xml(_) => "xml".into(),
            ColumnData::DateTime(_) => "datetime".into(),
            ColumnData::SmallDateTime(_) => "smalldatetime".into(),
            #[cfg(feature = "tds73")]
            ColumnData::Time(_) => "time".into(),
            #[cfg(feature = "tds73")]
            ColumnData::Date(_) => "date".into(),
            #[cfg(feature = "tds73")]
            ColumnData::DateTime2(_) => "datetime2".into(),
            #[cfg(feature = "tds73")]
            ColumnData::DateTimeOffset(_) => "datetimeoffset".into(),
        }
    }

    pub(crate) async fn decode<R>(src: &mut R, ctx: &TypeInfo) -> crate::Result<ColumnData<'a>>
    where
        R: SqlReadBytes + Unpin,
    {
        let res = match ctx {
            TypeInfo::FixedLen(fixed_ty) => fixed_len::decode(src, fixed_ty).await?,
            TypeInfo::VarLenSized(cx) => var_len::decode(src, cx).await?,
            TypeInfo::VarLenSizedPrecision { ty, scale, .. } => match ty {
                VarLenType::Decimaln | VarLenType::Numericn => {
                    ColumnData::Numeric(Numeric::decode(src, *scale).await?)
                }
                _ => todo!(),
            },
            TypeInfo::Xml { schema, size } => xml::decode(src, *size, schema.clone()).await?,
            TypeInfo::Udt(_) => udt::decode(src).await?,
        };

        Ok(res)
    }
}

impl<'a> Encode<BytesMutWithTypeInfo<'a>> for ColumnData<'a> {
    fn encode(self, dst: &mut BytesMutWithTypeInfo<'a>) -> crate::Result<()> {
        match (self, dst.type_info()) {
            (ColumnData::Bit(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Bitn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(1);
                    dst.put_u8(val as u8);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Bit(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Bit))) => {
                dst.put_u8(val as u8);
            }
            (ColumnData::Bit(opt), None) => {
                // if TypeInfo was not given, encode a TypeInfo
                // the first 1 is part of TYPE_INFO
                let header = [VarLenType::Bitn as u8, 1];
                dst.extend_from_slice(&header);
                if let Some(val) = opt {
                    // the second 1 is part of TYPE_VARBYTE
                    dst.put_u8(1);
                    dst.put_u8(val as u8);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::U8(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(1);
                    dst.put_u8(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::U8(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int1))) => {
                dst.put_u8(val);
            }
            (ColumnData::U8(opt), None) => {
                let header = [VarLenType::Intn as u8, 1];
                dst.extend_from_slice(&header);
                if let Some(val) = opt {
                    dst.put_u8(1);
                    dst.put_u8(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I16(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int2))) => {
                dst.put_i16_le(val);
            }
            (ColumnData::I16(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(2);
                    dst.put_i16_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I16(opt), None) => {
                let header = [VarLenType::Intn as u8, 2];
                dst.extend_from_slice(&header);
                if let Some(val) = opt {
                    dst.put_u8(2);
                    dst.put_i16_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I32(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int4))) => {
                dst.put_i32_le(val);
            }
            (ColumnData::I32(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(4);
                    dst.put_i32_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I32(opt), None) => {
                let header = [VarLenType::Intn as u8, 4];
                dst.extend_from_slice(&header);
                if let Some(val) = opt {
                    dst.put_u8(4);
                    dst.put_i32_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Int8))) => {
                dst.put_i64_le(val);
            }
            (ColumnData::I64(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Intn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(8);
                    dst.put_i64_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::I64(opt), None) => {
                let header = [VarLenType::Intn as u8, 8];
                dst.extend_from_slice(&header);
                if let Some(val) = opt {
                    dst.put_u8(8);
                    dst.put_i64_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F32(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Float4))) => {
                dst.put_f32_le(val);
            }
            (ColumnData::F32(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Floatn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(4);
                    dst.put_f32_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F32(opt), None) => {
                let header = [VarLenType::Floatn as u8, 4];
                dst.extend_from_slice(&header);
                if let Some(val) = opt {
                    dst.put_u8(4);
                    dst.put_f32_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Float8))) => {
                dst.put_f64_le(val);
            }
            (ColumnData::F64(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Floatn =>
            {
                if let Some(val) = opt {
                    dst.put_u8(8);
                    dst.put_f64_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F64(opt), None) => {
                let header = [VarLenType::Floatn as u8, 8];
                dst.extend_from_slice(&header);
                if let Some(val) = opt {
                    dst.put_u8(8);
                    dst.put_f64_le(val);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::F64(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Money =>
            {
                if let Some(val) = opt {
                    money::encode(dst, vlc.len(), val)?;
                } else {
                    dst.put_u8(0);
                }
            }
            // A NOT-NULL `money` column arrives as `FixedLen(Money)` (8-byte) and
            // a NOT-NULL `smallmoney` as `FixedLen(Money4)` (4-byte). These are
            // FIXEDLENTYPEs: the row value is the raw fixed-width scaled bytes
            // with NO length prefix (unlike the `MONEYN`/`VarLenSized` path
            // above), matching `fixed_len::decode` and the sibling `FixedLen`
            // arms (e.g. `Float8`, `Datetime`). A `None` here would mean a null
            // into a NOT-NULL column, so — like the other `FixedLen` arms — only
            // `Some` matches and a null falls through to the `BulkInput` error.
            (ColumnData::F64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Money))) => {
                money::encode_fixed(dst, 8, val)?;
            }
            (ColumnData::F64(Some(val)), Some(TypeInfo::FixedLen(FixedLenType::Money4))) => {
                money::encode_fixed(dst, 4, val)?;
            }
            (ColumnData::Guid(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Guid =>
            {
                if let Some(uuid) = opt {
                    dst.put_u8(16);

                    let mut data = *uuid.as_bytes();
                    super::guid::reorder_bytes(&mut data);
                    dst.extend_from_slice(&data);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Guid(opt), None) => {
                let header = [VarLenType::Guid as u8, 16];
                dst.extend_from_slice(&header);
                if let Some(uuid) = opt {
                    dst.put_u8(16);
                    let mut data = *uuid.as_bytes();
                    super::guid::reorder_bytes(&mut data);
                    dst.extend_from_slice(&data);
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::String(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::BigChar
                    || vlc.r#type() == VarLenType::BigVarChar =>
            {
                if let Some(str) = opt {
                    let mut encoder = vlc.collation().as_ref().unwrap().encoding()?.new_encoder();
                    let len = encoder
                        .max_buffer_length_from_utf8_without_replacement(str.len())
                        .unwrap();
                    let mut bytes = Vec::with_capacity(len);
                    let (res, _) = encoder.encode_from_utf8_to_vec_without_replacement(
                        str.as_ref(),
                        &mut bytes,
                        true,
                    );
                    if let encoding_rs::EncoderResult::Unmappable(_) = res {
                        return Err(crate::Error::Encoding("unrepresentable character".into()));
                    }

                    if bytes.len() > vlc.len() {
                        return Err(crate::Error::BulkInput(
                            format!(
                                "Encoded string length {} exceed column limit {}",
                                bytes.len(),
                                vlc.len()
                            )
                            .into(),
                        ));
                    }

                    if vlc.len() < 0xffff {
                        dst.put_u16_le(bytes.len() as u16);
                        dst.extend_from_slice(bytes.as_slice());
                    } else {
                        // unknown size
                        dst.put_u64_le(0xfffffffffffffffe);

                        assert!(
                            str.len() < 0xffffffff,
                            "if str longer than this, need to implement multiple blobs"
                        );

                        dst.put_u32_le(bytes.len() as u32);
                        dst.extend_from_slice(bytes.as_slice());

                        if !bytes.is_empty() {
                            // no next blob
                            dst.put_u32_le(0u32);
                        }
                    }
                } else if vlc.len() < 0xffff {
                    dst.put_u16_le(0xffff);
                } else {
                    dst.put_u64_le(0xffffffffffffffff)
                }
            }
            (ColumnData::String(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::NVarchar || vlc.r#type() == VarLenType::NChar =>
            {
                if let Some(str) = opt {
                    if vlc.len() < 0xffff {
                        let len_pos = dst.len();
                        dst.put_u16_le(0u16);

                        for chr in str.encode_utf16() {
                            dst.put_u16_le(chr);
                        }

                        let length = dst.len() - len_pos - 2;

                        if length > vlc.len() {
                            return Err(crate::Error::BulkInput(
                                format!(
                                    "Encoded string length {} exceed column limit {}",
                                    length,
                                    vlc.len()
                                )
                                .into(),
                            ));
                        }

                        let dst: &mut [u8] = dst.borrow_mut();
                        let mut dst = &mut dst[len_pos..];
                        dst.put_u16_le(length as u16);
                    } else {
                        // unknown size
                        dst.put_u64_le(0xfffffffffffffffe);

                        assert!(
                            str.len() < 0xffffffff,
                            "if str longer than this, need to implement multiple blobs"
                        );

                        let len_pos = dst.len();
                        dst.put_u32_le(0u32);

                        for chr in str.encode_utf16() {
                            dst.put_u16_le(chr);
                        }

                        let length = dst.len() - len_pos - 4;

                        if length > vlc.len() {
                            return Err(crate::Error::BulkInput(
                                format!(
                                    "Encoded string length {} exceed column limit {}",
                                    length,
                                    vlc.len()
                                )
                                .into(),
                            ));
                        }

                        if length > 0 {
                            // no next blob
                            dst.put_u32_le(0u32);
                        }

                        let dst: &mut [u8] = dst.borrow_mut();
                        let mut dst = &mut dst[len_pos..];
                        dst.put_u32_le(length as u32);
                    }
                } else if vlc.len() < 0xffff {
                    dst.put_u16_le(0xffff);
                } else {
                    dst.put_u64_le(0xffffffffffffffff)
                }
            }
            (ColumnData::String(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Text || vlc.r#type() == VarLenType::NText =>
            {
                if let Some(str) = opt {
                    // TEXT/NTEXT row values carry a text pointer and a timestamp
                    // ahead of the payload. The server ignores the values we
                    // supply on bulk-load, so send a fixed-size dummy pointer
                    // and timestamp.
                    dst.put_u8(16); // text pointer length
                    dst.extend_from_slice(&[0u8; 16]); // text pointer
                    dst.extend_from_slice(&[0u8; 8]); // timestamp

                    if vlc.r#type() == VarLenType::Text {
                        // single-byte character data, encoded with the column collation
                        let mut encoder =
                            vlc.collation().as_ref().unwrap().encoding()?.new_encoder();
                        let len = encoder
                            .max_buffer_length_from_utf8_without_replacement(str.len())
                            .unwrap();
                        let mut bytes = Vec::with_capacity(len);
                        let (res, _) = encoder.encode_from_utf8_to_vec_without_replacement(
                            str.as_ref(),
                            &mut bytes,
                            true,
                        );
                        if let encoding_rs::EncoderResult::Unmappable(_) = res {
                            return Err(crate::Error::Encoding("unrepresentable character".into()));
                        }

                        dst.put_u32_le(bytes.len() as u32);
                        dst.extend_from_slice(bytes.as_slice());
                    } else {
                        // NTEXT: UCS-2/UTF-16LE data
                        let len_pos = dst.len();
                        dst.put_u32_le(0u32);

                        let mut length = 0u32;
                        for chr in str.encode_utf16() {
                            length += 2;
                            dst.put_u16_le(chr);
                        }

                        let dst: &mut [u8] = dst.borrow_mut();
                        let bytes = length.to_le_bytes();
                        dst[len_pos..len_pos + 4].copy_from_slice(&bytes);
                    }
                } else {
                    // NULL: zero-length text pointer
                    dst.put_u8(0);
                }
            }
            (ColumnData::String(Some(ref s)), None) if s.len() <= 4000 => {
                dst.put_u8(VarLenType::NVarchar as u8);
                dst.put_u16_le(8000);
                dst.extend_from_slice(&[0u8; 5][..]);

                let mut length = 0u16;
                let len_pos = dst.len();

                dst.put_u16_le(length);

                for chr in s.encode_utf16() {
                    length += 1;
                    dst.put_u16_le(chr);
                }

                let dst: &mut [u8] = dst.borrow_mut();
                let bytes = (length * 2).to_le_bytes(); // u16, two bytes

                for (i, byte) in bytes.iter().enumerate() {
                    dst[len_pos + i] = *byte;
                }
            }
            (ColumnData::String(Some(ref s)), None) => {
                // length: 0xffff and raw collation
                dst.put_u8(VarLenType::NVarchar as u8);
                dst.extend_from_slice(&[0xff_u8; 2]);
                dst.extend_from_slice(&[0u8; 5]);

                // we cannot cheaply predetermine the length of the UCS2 string beforehand
                // (2 * bytes(UTF8) is not always right) - so just let the SQL server handle it
                dst.put_u64_le(0xfffffffffffffffe_u64);

                // Write the varchar length
                let mut length = 0u32;
                let len_pos = dst.len();

                dst.put_u32_le(length);

                for chr in s.encode_utf16() {
                    length += 1;
                    dst.put_u16_le(chr);
                }

                if length > 0 {
                    // PLP_TERMINATOR
                    dst.put_u32_le(0);
                }

                let dst: &mut [u8] = dst.borrow_mut();
                let bytes = (length * 2).to_le_bytes(); // u32, four bytes

                for (i, byte) in bytes.iter().enumerate() {
                    dst[len_pos + i] = *byte;
                }
            }
            (ColumnData::Binary(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::BigBinary
                    || vlc.r#type() == VarLenType::BigVarBin =>
            {
                if let Some(bytes) = opt {
                    if bytes.len() > vlc.len() {
                        return Err(crate::Error::BulkInput(
                            format!(
                                "Binary length {} exceed column limit {}",
                                bytes.len(),
                                vlc.len()
                            )
                            .into(),
                        ));
                    }

                    if vlc.len() < 0xffff {
                        dst.put_u16_le(bytes.len() as u16);
                        dst.extend(bytes.into_owned());
                    } else {
                        // unknown size
                        dst.put_u64_le(0xfffffffffffffffe);
                        dst.put_u32_le(bytes.len() as u32);

                        if !bytes.is_empty() {
                            dst.extend(bytes.into_owned());
                            dst.put_u32_le(0);
                        }
                    }
                } else if vlc.len() < 0xffff {
                    dst.put_u16_le(0xffff);
                } else {
                    dst.put_u64_le(0xffffffffffffffff);
                }
            }
            (ColumnData::Binary(Some(bytes)), None) if bytes.len() <= 8000 => {
                dst.put_u8(VarLenType::BigVarBin as u8);
                dst.put_u16_le(8000);
                dst.put_u16_le(bytes.len() as u16);
                dst.extend(bytes.into_owned());
            }
            (ColumnData::Binary(Some(bytes)), None) => {
                dst.put_u8(VarLenType::BigVarBin as u8);
                // Max length
                dst.put_u16_le(0xffff_u16);
                // Also the length is unknown
                dst.put_u64_le(0xfffffffffffffffe_u64);
                // We'll write in one chunk, length is the whole bytes length
                dst.put_u32_le(bytes.len() as u32);

                if !bytes.is_empty() {
                    // Payload
                    dst.extend(bytes.into_owned());
                    // PLP_TERMINATOR
                    dst.put_u32_le(0);
                }
            }
            (ColumnData::DateTime(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Datetimen =>
            {
                if let Some(dt) = opt {
                    dst.put_u8(8);
                    dt.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::DateTime(Some(dt)), Some(TypeInfo::FixedLen(FixedLenType::Datetime))) => {
                dt.encode(dst)?;
            }
            (ColumnData::DateTime(Some(dt)), None) => {
                dst.extend_from_slice(&[VarLenType::Datetimen as u8, 8, 8]);
                dt.encode(&mut *dst)?;
            }
            (ColumnData::SmallDateTime(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Datetimen =>
            {
                if let Some(dt) = opt {
                    dst.put_u8(4);
                    dt.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (
                ColumnData::SmallDateTime(Some(dt)),
                Some(TypeInfo::FixedLen(FixedLenType::Datetime4)),
            ) => {
                dt.encode(dst)?;
            }
            (ColumnData::SmallDateTime(Some(dt)), None) => {
                dst.extend_from_slice(&[VarLenType::Datetimen as u8, 4, 4]);
                dt.encode(&mut *dst)?;
            }
            #[cfg(feature = "tds73")]
            (ColumnData::Date(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Daten =>
            {
                if let Some(dt) = opt {
                    dst.put_u8(3);
                    dt.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            #[cfg(feature = "tds73")]
            (ColumnData::Date(Some(date)), None) => {
                dst.extend_from_slice(&[VarLenType::Daten as u8, 3]);
                date.encode(&mut *dst)?;
            }
            #[cfg(feature = "tds73")]
            (ColumnData::Time(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Timen =>
            {
                if let Some(time) = opt {
                    dst.put_u8(time.len()?);
                    time.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            #[cfg(feature = "tds73")]
            (ColumnData::Time(Some(time)), None) => {
                dst.extend_from_slice(&[VarLenType::Timen as u8, time.scale(), time.len()?]);
                time.encode(&mut *dst)?;
            }
            #[cfg(feature = "tds73")]
            (ColumnData::DateTime2(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Datetimen =>
            {
                if let Some(dt2) = opt {
                    let dt = datetime2_to_datetime(&dt2)?;
                    dst.put_u8(8);
                    dt.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            #[cfg(feature = "tds73")]
            (ColumnData::DateTime2(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Datetime2 =>
            {
                if let Some(mut dt2) = opt {
                    if dt2.time().scale() != vlc.len() as u8 {
                        let time = dt2.time();
                        let increments = (time.increments() as f64
                            * 10_f64.powi(vlc.len() as i32 - time.scale() as i32))
                            as u64;
                        dt2 = DateTime2::new(dt2.date(), Time::new(increments, vlc.len() as u8));
                    }
                    dst.put_u8(dt2.time().len()? + 3);
                    dt2.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            #[cfg(feature = "tds73")]
            (ColumnData::DateTime2(Some(dt)), None) => {
                let len = dt.time().len()? + 3;
                dst.extend_from_slice(&[VarLenType::Datetime2 as u8, dt.time().scale(), len]);
                dt.encode(&mut *dst)?;
            }
            #[cfg(feature = "tds73")]
            (ColumnData::DateTimeOffset(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::DatetimeOffsetn =>
            {
                if let Some(dto) = opt {
                    dst.put_u8(dto.datetime2().time().len()? + 5);
                    dto.encode(dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            #[cfg(feature = "tds73")]
            (ColumnData::DateTimeOffset(Some(dto)), None) => {
                let headers = [
                    VarLenType::DatetimeOffsetn as u8,
                    dto.datetime2().time().scale(),
                    dto.datetime2().time().len()? + 5,
                ];

                dst.extend_from_slice(&headers);
                dto.encode(&mut *dst)?;
            }
            (ColumnData::Xml(opt), Some(TypeInfo::Xml { .. })) => {
                if let Some(xml) = opt {
                    xml.into_owned().encode(dst)?;
                } else {
                    dst.put_u64_le(0xffffffffffffffff_u64);
                }
            }
            (ColumnData::Xml(Some(xml)), None) => {
                dst.put_u8(VarLenType::Xml as u8);
                dst.put_u8(0);
                xml.into_owned().encode(&mut *dst)?;
            }
            (ColumnData::Numeric(opt), Some(TypeInfo::VarLenSized(vlc)))
                if vlc.r#type() == VarLenType::Money =>
            {
                if let Some(num) = opt {
                    money::encode_numeric(dst, vlc.len(), &num)?;
                } else {
                    dst.put_u8(0);
                }
            }
            // NOT-NULL `money`/`smallmoney` supplied as a `Numeric`: encoded as
            // the raw fixed-width bytes (no length prefix), same framing rationale
            // as the `F64` `FixedLen` money arms above.
            (ColumnData::Numeric(Some(num)), Some(TypeInfo::FixedLen(FixedLenType::Money))) => {
                money::encode_numeric_fixed(dst, 8, &num)?;
            }
            (ColumnData::Numeric(Some(num)), Some(TypeInfo::FixedLen(FixedLenType::Money4))) => {
                money::encode_numeric_fixed(dst, 4, &num)?;
            }
            (ColumnData::Numeric(opt), Some(TypeInfo::VarLenSizedPrecision { ty, scale, .. }))
                if ty == &VarLenType::Numericn || ty == &VarLenType::Decimaln =>
            {
                if let Some(num) = opt {
                    // The value is sent at the column's scale (the scale lives in
                    // the TYPE_INFO, not the value), so rescale when the client
                    // value's scale differs from the target column's scale.
                    let target_scale = *scale;
                    let num = if target_scale == num.scale() {
                        num
                    } else if target_scale > num.scale() {
                        // Scale up: multiply, checking for i128 overflow.
                        let factor = 10i128.pow((target_scale - num.scale()) as u32);
                        let value = num.value().checked_mul(factor).ok_or_else(|| {
                            crate::Error::Conversion(
                                "numeric value overflows when scaling to the column's scale".into(),
                            )
                        })?;
                        Numeric::new_with_scale(value, target_scale)
                    } else {
                        // Scale down: divide, rounding half away from zero
                        // (this loses precision beyond the column's scale).
                        let factor = 10i128.pow((num.scale() - target_scale) as u32);
                        let half = factor / 2;
                        let v = num.value();
                        let value = if v >= 0 {
                            (v + half) / factor
                        } else {
                            (v - half) / factor
                        };
                        Numeric::new_with_scale(value, target_scale)
                    };
                    num.encode(&mut *dst)?;
                } else {
                    dst.put_u8(0);
                }
            }
            (ColumnData::Numeric(Some(num)), None) => {
                let headers = &[
                    VarLenType::Numericn as u8,
                    num.len(),
                    num.precision(),
                    num.scale(),
                ];

                dst.extend_from_slice(headers);
                num.encode(&mut *dst)?;
            }
            (data, Some(TypeInfo::VarLenSized(vlc))) if vlc.r#type() == VarLenType::SSVariant => {
                sql_variant::encode(&mut *dst, data)?;
            }
            (_, None) => {
                // None/null
                dst.put_u8(FixedLenType::Null as u8);
            }
            (v, ref ti) => {
                return Err(crate::Error::BulkInput(
                    format!("invalid data type, expecting {:?} but found {:?}", ti, v).into(),
                ));
            }
        }

        Ok(())
    }
}

/// Reads a [`ColumnData`] straight out of a row without any conversion,
/// borrowing from the row's owned data.
impl<'a> FromSql<'a> for ColumnData<'a> {
    fn from_sql(value: &'a ColumnData<'static>) -> crate::Result<Option<Self>> {
        Ok(Some(value.clone()))
    }
}

/// Reads a [`ColumnData`] straight out of a row without any conversion, taking
/// ownership of the value.
impl<'a> FromSqlOwned for ColumnData<'a> {
    fn from_sql_owned(value: ColumnData<'static>) -> crate::Result<Option<Self>> {
        Ok(Some(value))
    }
}

/// Binds a [`ColumnData`] directly as a query parameter, by reference.
impl<'a> ToSql for ColumnData<'a> {
    fn to_sql(&self) -> ColumnData<'_> {
        self.clone()
    }
}

/// Binds a [`ColumnData`] directly as a query parameter, by value.
impl<'a> IntoSql<'a> for ColumnData<'a> {
    fn into_sql(self) -> ColumnData<'a> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use crate::tds::Collation;
    use crate::{Error, VarLenContext};
    use bytes::BytesMut;

    async fn test_round_trip(ti: TypeInfo, d: ColumnData<'_>) {
        let mut buf = BytesMut::new();
        let mut buf_with_ti = BytesMutWithTypeInfo::new(&mut buf).with_type_info(&ti);

        d.clone()
            .encode(&mut buf_with_ti)
            .expect("encode must succeed");

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti)
            .await
            .expect("decode must succeed");

        assert_eq!(nd, d);

        reader
            .read_u8()
            .await
            .expect_err("decode must consume entire buffer");
    }

    #[test]
    fn type_name_maps_each_variant() {
        assert_eq!(ColumnData::U8(Some(1)).type_name(), "tinyint");
        assert_eq!(ColumnData::I16(Some(1)).type_name(), "smallint");
        assert_eq!(ColumnData::I32(Some(1)).type_name(), "int");
        assert_eq!(ColumnData::I64(Some(1)).type_name(), "bigint");
        assert_eq!(ColumnData::F32(Some(1.0)).type_name(), "float(24)");
        assert_eq!(ColumnData::F64(Some(1.0)).type_name(), "float(53)");
        assert_eq!(ColumnData::Bit(Some(true)).type_name(), "bit");
        assert_eq!(ColumnData::Guid(None).type_name(), "uniqueidentifier");
        assert_eq!(ColumnData::Numeric(None).type_name(), "numeric");
        assert_eq!(ColumnData::DateTime(None).type_name(), "datetime");
        assert_eq!(ColumnData::SmallDateTime(None).type_name(), "smalldatetime");
    }

    #[test]
    fn type_name_string_length_thresholds() {
        // None and anything up to 4000 chars is a sized nvarchar; just past it
        // becomes nvarchar(max). The `<= 4000` and `<= MAX_NVARCHAR_SIZE` guards
        // each flip the answer at their boundary.
        assert_eq!(ColumnData::String(None).type_name(), "nvarchar(4000)");
        assert_eq!(
            ColumnData::String(Some("a".repeat(100).into())).type_name(),
            "nvarchar(4000)"
        );
        assert_eq!(
            ColumnData::String(Some("a".repeat(4000).into())).type_name(),
            "nvarchar(4000)"
        );
        assert_eq!(
            ColumnData::String(Some("a".repeat(4001).into())).type_name(),
            "nvarchar(max)"
        );
    }

    #[test]
    fn type_name_binary_length_threshold() {
        assert_eq!(
            ColumnData::Binary(Some(vec![0u8; 8000].into())).type_name(),
            "varbinary(8000)"
        );
        assert_eq!(
            ColumnData::Binary(Some(vec![0u8; 8001].into())).type_name(),
            "varbinary(max)"
        );
        assert_eq!(ColumnData::Binary(None).type_name(), "varbinary(max)");
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_json_round_trip() {
        let value = ColumnData::I32(Some(1234));
        let json = serde_json::to_string(&value).expect("serialize");
        let back: ColumnData<'static> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, back);
    }

    #[tokio::test]
    async fn i32_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            ColumnData::I32(Some(42)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            ColumnData::I32(None),
        )
        .await;
    }

    #[tokio::test]
    async fn i32_with_fixedlen_int() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int4),
            ColumnData::I32(Some(42)),
        )
        .await;
    }

    #[tokio::test]
    async fn bit_with_varlen_bit() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, 1, None)),
            ColumnData::Bit(Some(true)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_with_varlen_bit() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, 1, None)),
            ColumnData::Bit(None),
        )
        .await;
    }

    #[tokio::test]
    async fn bit_with_fixedlen_bit() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Bit),
            ColumnData::Bit(Some(true)),
        )
        .await;
    }

    #[tokio::test]
    async fn u8_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None)),
            ColumnData::U8(Some(8u8)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_u8_with_varlen_int() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None)),
            ColumnData::U8(None),
        )
        .await;
    }

    #[tokio::test]
    async fn u8_with_fixedlen_int() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int1),
            ColumnData::U8(Some(8u8)),
        )
        .await;
    }

    #[tokio::test]
    async fn i16_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None)),
            ColumnData::I16(Some(8i16)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_i16_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None)),
            ColumnData::I16(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_with_varlen_intn() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int2),
            ColumnData::I16(Some(8i16)),
        )
        .await;
    }

    #[tokio::test]
    async fn i64_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None)),
            ColumnData::I64(Some(8i64)),
        )
        .await;
    }

    #[tokio::test]
    async fn i64_none_with_varlen_intn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None)),
            ColumnData::I64(None),
        )
        .await;
    }

    #[tokio::test]
    async fn i64_with_fixedlen_int8() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Int8),
            ColumnData::I64(Some(8i64)),
        )
        .await;
    }

    #[tokio::test]
    async fn f32_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
            ColumnData::F32(Some(8f32)),
        )
        .await;
    }

    #[tokio::test]
    async fn null_f32_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
            ColumnData::F32(None),
        )
        .await;
    }

    #[tokio::test]
    async fn f32_with_fixedlen_float4() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Float4),
            ColumnData::F32(Some(8f32)),
        )
        .await;
    }

    #[tokio::test]
    async fn f64_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None)),
            ColumnData::F64(Some(8f64)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_f64_with_varlen_floatn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None)),
            ColumnData::F64(None),
        )
        .await;
    }

    #[tokio::test]
    async fn f64_with_fixedlen_float8() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Float8),
            ColumnData::F64(Some(8f64)),
        )
        .await;
    }

    #[tokio::test]
    async fn guid_with_varlen_guid() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None)),
            ColumnData::Guid(Some(Uuid::new_v4())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_guid_with_varlen_guid() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None)),
            ColumnData::Guid(None),
        )
        .await;
    }

    #[tokio::test]
    async fn numeric_with_varlen_sized_precision() {
        test_round_trip(
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: 17,
                precision: 18,
                scale: 0,
            },
            ColumnData::Numeric(Some(Numeric::new_with_scale(23, 0))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_numeric_with_varlen_sized_precision() {
        test_round_trip(
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: 17,
                precision: 18,
                scale: 0,
            },
            ColumnData::Numeric(None),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn long_string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_long_string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_bigchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_bigvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_bigvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn empty_string_with_varlen_bigvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_nvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hhh".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_nvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn empty_string_with_varlen_nvarchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hhh".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn long_string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hhh".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_long_string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_nchar() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 40, None)),
            ColumnData::Binary(Some(b"aaa".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn long_binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 0x8ffff, None)),
            ColumnData::Binary(Some(b"aaa".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 40, None)),
            ColumnData::Binary(None),
        )
        .await;
    }

    #[tokio::test]
    async fn none_long_binary_with_varlen_bigbinary() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 0x8ffff, None)),
            ColumnData::Binary(None),
        )
        .await;
    }

    #[tokio::test]
    async fn binary_with_varlen_bigvarbin() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 40, None)),
            ColumnData::Binary(Some(b"aaa".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_binary_with_varlen_bigvarbin() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 40, None)),
            ColumnData::Binary(None),
        )
        .await;
    }

    #[tokio::test]
    async fn empty_binary_with_varlen_bigvarbin() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigVarBin,
                0x8ffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::Binary(Some(b"".as_slice().into())),
        )
        .await;
    }

    #[tokio::test]
    async fn datetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None)),
            ColumnData::DateTime(Some(DateTime::new(200, 3000))),
        )
        .await;
    }

    // this is inconsistent: decode will decode any None datetime to smalldatetime, ignoring size
    // but it's non-critical, so let it be here
    #[tokio::test]
    async fn none_datetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None)),
            ColumnData::DateTime(None),
        )
        .await;
    }

    #[tokio::test]
    async fn datetime_with_fixedlen_datetime() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Datetime),
            ColumnData::DateTime(Some(DateTime::new(200, 3000))),
        )
        .await;
    }

    #[tokio::test]
    async fn smalldatetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 4, None)),
            ColumnData::SmallDateTime(Some(SmallDateTime::new(200, 3000))),
        )
        .await;
    }

    #[tokio::test]
    async fn none_smalldatetime_with_varlen_datetimen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 4, None)),
            ColumnData::SmallDateTime(None),
        )
        .await;
    }

    #[tokio::test]
    async fn smalldatetime_with_fixedlen_datetime4() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Datetime4),
            ColumnData::SmallDateTime(Some(SmallDateTime::new(200, 3000))),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn date_with_varlen_daten() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None)),
            ColumnData::Date(Some(Date::new(200))),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn none_date_with_varlen_daten() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None)),
            ColumnData::Date(None),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn time_with_varlen_timen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Timen, 7, None)),
            ColumnData::Time(Some(Time::new(55, 7))),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn none_time_with_varlen_timen() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Timen, 7, None)),
            ColumnData::Time(None),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn datetime2_with_varlen_datetime2() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetime2, 7, None)),
            ColumnData::DateTime2(Some(DateTime2::new(Date::new(55), Time::new(222, 7)))),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn none_datetime2_with_varlen_datetime2() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetime2, 7, None)),
            ColumnData::DateTime2(None),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn datetimeoffset_with_varlen_datetimeoffsetn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::DatetimeOffsetn, 7, None)),
            ColumnData::DateTimeOffset(Some(DateTimeOffset::new(
                DateTime2::new(Date::new(55), Time::new(222, 7)),
                -8,
            ))),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn none_datetimeoffset_with_varlen_datetimeoffsetn() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::DatetimeOffsetn, 7, None)),
            ColumnData::DateTimeOffset(None),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn xml_with_xml() {
        test_round_trip(
            TypeInfo::Xml {
                schema: None,
                size: 0xfffffffffffffffe_usize,
            },
            ColumnData::Xml(Some(Cow::Owned(XmlData::new("<a>ddd</a>")))),
        )
        .await;
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn none_xml_with_xml() {
        test_round_trip(
            TypeInfo::Xml {
                schema: None,
                size: 0xfffffffffffffffe_usize,
            },
            ColumnData::Xml(None),
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_type_fails() {
        let data = vec![
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
                ColumnData::I32(Some(42)),
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
                ColumnData::I32(None),
            ),
            (
                TypeInfo::FixedLen(FixedLenType::Int4),
                ColumnData::I32(None),
            ),
        ];

        for (ti, d) in data {
            let mut buf = BytesMut::new();
            let mut buf_ti = BytesMutWithTypeInfo::new(&mut buf).with_type_info(&ti);

            let err = d.encode(&mut buf_ti).expect_err("encode should fail");

            if let Error::BulkInput(_) = err {
            } else {
                panic!("Expected: Error::BulkInput, got: {:?}", err);
            }
        }
    }

    #[tokio::test]
    async fn f64_with_fixedlen_money() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Money),
            ColumnData::F64(Some(3.5)),
        )
        .await;
    }

    #[tokio::test]
    async fn f64_with_fixedlen_smallmoney() {
        test_round_trip(
            TypeInfo::FixedLen(FixedLenType::Money4),
            ColumnData::F64(Some(3.5)),
        )
        .await;
    }

    #[test]
    fn column_data_from_sql_clones_by_reference() {
        let value: ColumnData<'static> = ColumnData::I32(Some(42));
        let out = ColumnData::from_sql(&value).unwrap();
        assert_eq!(out, Some(ColumnData::I32(Some(42))));
    }

    #[test]
    fn column_data_from_sql_owned_passes_through() {
        let value: ColumnData<'static> = ColumnData::String(Some(Cow::Borrowed("hello")));
        let out = ColumnData::from_sql_owned(value).unwrap();
        assert_eq!(out, Some(ColumnData::String(Some(Cow::Borrowed("hello")))));
    }

    #[test]
    fn column_data_to_sql_clones_by_reference() {
        let value = ColumnData::Bit(Some(true));
        assert_eq!(value.to_sql(), ColumnData::Bit(Some(true)));
        // Original is untouched.
        assert_eq!(value, ColumnData::Bit(Some(true)));
    }

    #[test]
    fn column_data_into_sql_passes_through() {
        let value = ColumnData::F64(Some(1.5));
        assert_eq!(value.into_sql(), ColumnData::F64(Some(1.5)));
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn datetime2_to_datetime_conversion() {
        use crate::tds::time::{Date, DateTime2, Time};

        // 2020-01-01 00:00:00 with scale 7 (100ns increments).
        // Days from year 1 to 2020-01-01 is 737_425.
        let dt2 = DateTime2::new(Date::new(737_425), Time::new(0, 7));
        let dt = datetime2_to_datetime(&dt2).expect("conversion must succeed");

        assert_eq!(dt.days(), (737_425 - DAYS_YEAR_1_TO_1900) as i32);
        assert_eq!(dt.seconds_fragments(), 0);

        // 12:00:00 exactly => half a day of 1/300s fragments.
        let noon_increments = 12u64 * 3600 * 10u64.pow(7);
        let dt2 = DateTime2::new(Date::new(737_425), Time::new(noon_increments, 7));
        let dt = datetime2_to_datetime(&dt2).expect("conversion must succeed");

        assert_eq!(dt.seconds_fragments(), 12 * 3600 * 300);

        // Dates earlier than 1900-01-01 cannot be represented by `datetime`.
        let dt2 = DateTime2::new(Date::new(0), Time::new(0, 7));
        assert!(datetime2_to_datetime(&dt2).is_err());
    }

    // ----- helpers for the coverage tests below -----

    fn encode_with_ti(ti: &TypeInfo, d: ColumnData<'_>) -> crate::Result<BytesMut> {
        let mut buf = BytesMut::new();
        {
            let mut b = BytesMutWithTypeInfo::new(&mut buf).with_type_info(ti);
            d.encode(&mut b)?;
        }
        Ok(buf)
    }

    fn encode_without_ti(d: ColumnData<'_>) -> crate::Result<BytesMut> {
        let mut buf = BytesMut::new();
        {
            let mut b = BytesMutWithTypeInfo::new(&mut buf);
            d.encode(&mut b)?;
        }
        Ok(buf)
    }

    fn expect_bulk_input(ti: TypeInfo, d: ColumnData<'_>) {
        let mut buf = BytesMut::new();
        let mut b = BytesMutWithTypeInfo::new(&mut buf).with_type_info(&ti);
        let err = d.encode(&mut b).expect_err("encode should fail");
        assert!(matches!(err, Error::BulkInput(_)), "got {:?}", err);
    }

    // ----- decode: line 199 (VarLenSizedPrecision non-numeric -> todo!()) -----

    #[tokio::test]
    #[should_panic]
    async fn decode_varlen_sized_precision_unsupported_panics() {
        let ti = TypeInfo::VarLenSizedPrecision {
            ty: VarLenType::Money,
            size: 8,
            precision: 0,
            scale: 0,
        };
        let buf = BytesMut::new();
        let reader = &mut buf.into_sql_read_bytes();
        let _ = ColumnData::decode(reader, &ti).await;
    }

    // ----- decode: line 202 (Udt) -----

    #[tokio::test]
    async fn decode_udt_type_info() {
        use bytes::BufMut;

        let ti = TypeInfo::Udt(crate::tds::codec::type_info::UdtInfo {
            max_byte_size: 0xffff,
            db_name: "db".into(),
            schema_name: "dbo".into(),
            type_name: "geometry".into(),
            assembly_qualified_name: String::new(),
        });

        let mut buf = BytesMut::new();
        // PLP unknown-length sentinel + one chunk + terminator.
        buf.put_u64_le(0xfffffffffffffffe);
        buf.put_u32_le(4);
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.put_u32_le(0);

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti).await.unwrap();
        assert_eq!(nd, ColumnData::Binary(Some(vec![1, 2, 3, 4].into())));
    }

    // ----- F64 with Money (lines 376-383) -----

    #[tokio::test]
    async fn f64_with_varlen_money() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None)),
            ColumnData::F64(Some(3.5)),
        )
        .await;
    }

    #[tokio::test]
    async fn none_f64_with_varlen_money() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None)),
            ColumnData::F64(None),
        )
        .await;
    }

    // ----- BigChar error paths (lines 426, 430-437) -----

    #[tokio::test]
    async fn bigchar_unrepresentable_character_errors() {
        let ti = TypeInfo::VarLenSized(VarLenContext::new(
            VarLenType::BigChar,
            40,
            Some(Collation::new(13632521, 52)),
        ));
        let mut buf = BytesMut::new();
        let mut b = BytesMutWithTypeInfo::new(&mut buf).with_type_info(&ti);
        // An emoji has no representation in the (single-byte) column collation.
        let err = ColumnData::String(Some("\u{1F600}".into()))
            .encode(&mut b)
            .expect_err("encode should fail");
        assert!(matches!(err, Error::Encoding(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn bigchar_too_long_errors() {
        expect_bulk_input(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::BigChar,
                2,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        );
    }

    // ----- NVarchar error paths (lines 481-488 small, 513-520 unknown-size) -----

    #[tokio::test]
    async fn nvarchar_too_long_small_errors() {
        expect_bulk_input(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                2,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("aaa".into())),
        );
    }

    #[tokio::test]
    async fn nvarchar_too_long_unknown_size_errors() {
        // vlc.len() == 0xffff drives the unknown-size path; a string whose UTF-16
        // byte length exceeds the column limit trips the check at 513-520.
        expect_bulk_input(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NVarchar,
                0xffff,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("a".repeat(40_000).into())),
        );
    }

    // ----- Text / NText encode arms (lines 538-587) -----

    #[tokio::test]
    async fn string_with_varlen_text() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Text,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(Some("hello".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_text() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Text,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            ColumnData::String(None),
        )
        .await;
    }

    #[tokio::test]
    async fn string_with_varlen_ntext() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NText, 40, None)),
            ColumnData::String(Some("hi".into())),
        )
        .await;
    }

    #[tokio::test]
    async fn none_string_with_varlen_ntext() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NText, 40, None)),
            ColumnData::String(None),
        )
        .await;
    }

    // ----- Binary too long (lines 650-657) -----

    #[tokio::test]
    async fn binary_too_long_errors() {
        expect_bulk_input(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 2, None)),
            ColumnData::Binary(Some(b"aaa".as_slice().into())),
        );
    }

    // ----- DateTime / SmallDateTime encode without TypeInfo (714-716, 734-736) -----

    #[tokio::test]
    async fn datetime_encode_without_type_info() {
        let buf = encode_without_ti(ColumnData::DateTime(Some(DateTime::new(200, 3000)))).unwrap();
        assert_eq!(buf[0], VarLenType::Datetimen as u8);
        assert_eq!(buf[1], 8);
        assert_eq!(buf[2], 8);
    }

    #[tokio::test]
    async fn smalldatetime_encode_without_type_info() {
        let buf = encode_without_ti(ColumnData::SmallDateTime(Some(SmallDateTime::new(
            200, 3000,
        ))))
        .unwrap();
        assert_eq!(buf[0], VarLenType::Datetimen as u8);
        assert_eq!(buf[1], 4);
        assert_eq!(buf[2], 4);
    }

    // ----- DateTime2 into a `datetime` (Datetimen) column (lines 774-780) -----

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn datetime2_with_varlen_datetimen() {
        let ti = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None));
        // 2020-01-01 is representable by `datetime` (>= 1900-01-01).
        let dt2 = DateTime2::new(Date::new(737_425), Time::new(0, 7));
        let buf = encode_with_ti(&ti, ColumnData::DateTime2(Some(dt2))).unwrap();

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti).await.unwrap();
        assert!(matches!(nd, ColumnData::DateTime(Some(_))), "got {:?}", nd);
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn none_datetime2_with_varlen_datetimen() {
        let ti = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None));
        let buf = encode_with_ti(&ti, ColumnData::DateTime2(None)).unwrap();

        let reader = &mut buf.into_sql_read_bytes();
        // Just needs to decode a null cleanly.
        ColumnData::decode(reader, &ti).await.unwrap();
    }

    // ----- Numeric into a Money column (lines 840-847) -----

    #[tokio::test]
    async fn numeric_with_varlen_money() {
        let ti = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None));
        // Numeric 3.5 (value 35000, scale 4) -> money.
        let buf = encode_with_ti(
            &ti,
            ColumnData::Numeric(Some(Numeric::new_with_scale(35000, 4))),
        )
        .unwrap();

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti).await.unwrap();
        assert_eq!(nd, ColumnData::F64(Some(3.5)));
    }

    #[tokio::test]
    async fn none_numeric_with_varlen_money() {
        let ti = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None));
        let buf = encode_with_ti(&ti, ColumnData::Numeric(None)).unwrap();

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti).await.unwrap();
        assert_eq!(nd, ColumnData::F64(None));
    }

    // ----- Numeric rescale on encode (lines 859-879) -----

    #[tokio::test]
    async fn numeric_scaled_up_to_column_scale() {
        // Column scale 2 > value scale 0: value 23 -> 2300 at scale 2.
        let ti = TypeInfo::VarLenSizedPrecision {
            ty: VarLenType::Numericn,
            size: 17,
            precision: 18,
            scale: 2,
        };
        let buf = encode_with_ti(
            &ti,
            ColumnData::Numeric(Some(Numeric::new_with_scale(23, 0))),
        )
        .unwrap();

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti).await.unwrap();
        assert_eq!(
            nd,
            ColumnData::Numeric(Some(Numeric::new_with_scale(2300, 2)))
        );
    }

    #[tokio::test]
    async fn numeric_scaled_down_to_column_scale() {
        // Column scale 2 < value scale 4: 1.2345 -> 1.23 (rounded half away).
        let ti = TypeInfo::VarLenSizedPrecision {
            ty: VarLenType::Numericn,
            size: 17,
            precision: 18,
            scale: 2,
        };
        let buf = encode_with_ti(
            &ti,
            ColumnData::Numeric(Some(Numeric::new_with_scale(12345, 4))),
        )
        .unwrap();

        let reader = &mut buf.into_sql_read_bytes();
        let nd = ColumnData::decode(reader, &ti).await.unwrap();
        assert_eq!(
            nd,
            ColumnData::Numeric(Some(Numeric::new_with_scale(123, 2)))
        );
    }

    // ----- SQL_VARIANT encode (lines 897-898) -----

    #[tokio::test]
    async fn ssvariant_round_trip_i32() {
        test_round_trip(
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::SSVariant, 0, None)),
            ColumnData::I32(Some(42)),
        )
        .await;
    }
}
