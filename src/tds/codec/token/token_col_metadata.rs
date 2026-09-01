use std::{
    borrow::{BorrowMut, Cow},
    fmt::Display,
};

use crate::{
    tds::codec::{Encode, FixedLenType, TokenType, TypeInfo, VarLenType},
    Column, ColumnData, ColumnType, SqlReadBytes,
};
use asynchronous_codec::BytesMut;
use bytes::BufMut;
use enumflags2::{bitflags, BitFlags};

#[derive(Debug, Clone)]
pub struct TokenColMetaData<'a> {
    pub columns: Vec<MetaDataColumn<'a>>,
}

/// Metadata for a single result/table column: its name plus the
/// [`BaseMetaDataColumn`] describing its type, size and flags.
#[derive(Debug, Clone)]
pub struct MetaDataColumn<'a> {
    /// The type and flag metadata for the column.
    pub base: BaseMetaDataColumn,
    /// The name of the column.
    pub col_name: Cow<'a, str>,
}

impl<'a> MetaDataColumn<'a> {
    /// The name of the column.
    pub fn col_name(&self) -> &str {
        self.col_name.as_ref()
    }

    /// The [`BaseMetaDataColumn`] describing the column's type and flags
    /// (nullability, identity, etc.).
    pub fn base(&self) -> &BaseMetaDataColumn {
        &self.base
    }
}

impl<'a> Display for MetaDataColumn<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] ", self.col_name)?;

        match &self.base.ty {
            TypeInfo::FixedLen(fixed) => match fixed {
                FixedLenType::Int1 => write!(f, "tinyint")?,
                FixedLenType::Bit => write!(f, "bit")?,
                FixedLenType::Int2 => write!(f, "smallint")?,
                FixedLenType::Int4 => write!(f, "int")?,
                FixedLenType::Datetime4 => write!(f, "smalldatetime")?,
                FixedLenType::Float4 => write!(f, "real")?,
                FixedLenType::Money => write!(f, "money")?,
                FixedLenType::Datetime => write!(f, "datetime")?,
                FixedLenType::Float8 => write!(f, "float")?,
                FixedLenType::Money4 => write!(f, "smallmoney")?,
                FixedLenType::Int8 => write!(f, "bigint")?,
                // The TDS "null" fixed type carries no value; surface it as the
                // int it decodes to rather than panicking (a bare `SELECT NULL`
                // produces such a column).
                FixedLenType::Null => write!(f, "int")?,
            },
            TypeInfo::VarLenSized(ctx) => match ctx.r#type() {
                VarLenType::Bitn => write!(f, "bit")?,
                VarLenType::Guid => write!(f, "uniqueidentifier")?,
                #[cfg(feature = "tds73")]
                VarLenType::Daten => write!(f, "date")?,
                #[cfg(feature = "tds73")]
                VarLenType::Timen => write!(f, "time")?,
                #[cfg(feature = "tds73")]
                VarLenType::Datetime2 => write!(f, "datetime2({})", ctx.len())?,
                VarLenType::Datetimen => write!(f, "datetime")?,
                VarLenType::Money => match ctx.len() {
                    4 => write!(f, "smallmoney")?,
                    _ => write!(f, "money")?,
                },
                #[cfg(feature = "tds73")]
                VarLenType::DatetimeOffsetn => write!(f, "datetimeoffset")?,
                VarLenType::BigVarBin => {
                    if ctx.len() <= 8000 {
                        write!(f, "varbinary({})", ctx.len())?
                    } else {
                        write!(f, "varbinary(max)")?
                    }
                }
                VarLenType::BigVarChar => {
                    if ctx.len() <= 8000 {
                        write!(f, "varchar({})", ctx.len())?
                    } else {
                        write!(f, "varchar(max)")?
                    }
                }
                VarLenType::BigBinary => write!(f, "binary({})", ctx.len())?,
                VarLenType::BigChar => write!(f, "char({})", ctx.len())?,
                VarLenType::NVarchar => {
                    if ctx.len() <= 4000 {
                        write!(f, "nvarchar({})", ctx.len())?
                    } else {
                        write!(f, "nvarchar(max)")?
                    }
                }
                VarLenType::NChar => write!(f, "nchar({})", ctx.len())?,
                VarLenType::Text => write!(f, "text")?,
                VarLenType::Image => write!(f, "image")?,
                VarLenType::NText => write!(f, "ntext")?,
                VarLenType::Intn => match ctx.len() {
                    1 => write!(f, "tinyint")?,
                    2 => write!(f, "smallint")?,
                    4 => write!(f, "int")?,
                    _ => write!(f, "bigint")?,
                },
                VarLenType::Floatn => match ctx.len() {
                    4 => write!(f, "real")?,
                    _ => write!(f, "float")?,
                },
                VarLenType::SSVariant => write!(f, "sql_variant")?,
                // Any other var-len type: emit its debug name rather than
                // panicking, so formatting metadata never crashes.
                other => write!(f, "{other:?}")?,
            },
            TypeInfo::VarLenSizedPrecision {
                ty,
                size: _,
                precision,
                scale,
            } => match ty {
                VarLenType::Numericn => write!(f, "numeric({},{})", precision, scale)?,
                // Decimaln, and any other precision-carrying type.
                _ => write!(f, "decimal({},{})", precision, scale)?,
            },
            TypeInfo::Xml { .. } => write!(f, "xml")?,
            TypeInfo::Udt(info) => write!(f, "{}.{}", info.schema_name, info.type_name)?,
        }

        Ok(())
    }
}

/// Describes the type and flags of a column, exposing metadata such as the
/// column type (including size, precision and scale), whether the column is
/// nullable and whether it is an identity column.
#[derive(Debug, Clone)]
pub struct BaseMetaDataColumn {
    /// The set of [`ColumnFlag`]s describing the column (nullability, identity,
    /// updateability, and so on).
    pub flags: BitFlags<ColumnFlag>,
    /// The type of the column, including its size, precision and scale where
    /// applicable.
    pub ty: TypeInfo,
}

impl BaseMetaDataColumn {
    /// The type of the column, including its size, precision and scale where
    /// applicable.
    pub fn ty(&self) -> &TypeInfo {
        &self.ty
    }

    /// The set of flags describing the column.
    pub fn flags(&self) -> BitFlags<ColumnFlag> {
        self.flags
    }

    /// `true` if the column accepts `NULL` values.
    pub fn is_nullable(&self) -> bool {
        self.flags.contains(ColumnFlag::Nullable)
    }

    /// `true` if the column is an identity column.
    pub fn is_identity(&self) -> bool {
        self.flags.contains(ColumnFlag::Identity)
    }

    /// `true` if the column is writeable (e.g. usable as a bulk-insert target).
    pub fn is_updateable(&self) -> bool {
        self.flags.contains(ColumnFlag::Updateable)
    }

    pub(crate) fn null_value(&self) -> ColumnData<'static> {
        match &self.ty {
            TypeInfo::FixedLen(ty) => match ty {
                FixedLenType::Null => ColumnData::I32(None),
                FixedLenType::Int1 => ColumnData::U8(None),
                FixedLenType::Bit => ColumnData::Bit(None),
                FixedLenType::Int2 => ColumnData::I16(None),
                FixedLenType::Int4 => ColumnData::I32(None),
                FixedLenType::Datetime4 => ColumnData::SmallDateTime(None),
                FixedLenType::Float4 => ColumnData::F32(None),
                FixedLenType::Money => ColumnData::F64(None),
                FixedLenType::Datetime => ColumnData::DateTime(None),
                FixedLenType::Float8 => ColumnData::F64(None),
                FixedLenType::Money4 => ColumnData::F32(None),
                FixedLenType::Int8 => ColumnData::I64(None),
            },
            TypeInfo::VarLenSized(cx) => match cx.r#type() {
                VarLenType::Guid => ColumnData::Guid(None),
                VarLenType::Intn => match cx.len() {
                    1 => ColumnData::U8(None),
                    2 => ColumnData::I16(None),
                    4 => ColumnData::I32(None),
                    _ => ColumnData::I64(None),
                },
                VarLenType::Bitn => ColumnData::Bit(None),
                VarLenType::Decimaln => ColumnData::Numeric(None),
                VarLenType::Numericn => ColumnData::Numeric(None),
                VarLenType::Floatn => match cx.len() {
                    4 => ColumnData::F32(None),
                    _ => ColumnData::F64(None),
                },
                VarLenType::Money => ColumnData::F64(None),
                VarLenType::Datetimen => ColumnData::DateTime(None),
                #[cfg(feature = "tds73")]
                VarLenType::Daten => ColumnData::Date(None),
                #[cfg(feature = "tds73")]
                VarLenType::Timen => ColumnData::Time(None),
                #[cfg(feature = "tds73")]
                VarLenType::Datetime2 => ColumnData::DateTime2(None),
                #[cfg(feature = "tds73")]
                VarLenType::DatetimeOffsetn => ColumnData::DateTimeOffset(None),
                VarLenType::BigVarBin => ColumnData::Binary(None),
                VarLenType::BigVarChar => ColumnData::String(None),
                VarLenType::BigBinary => ColumnData::Binary(None),
                VarLenType::BigChar => ColumnData::String(None),
                VarLenType::NVarchar => ColumnData::String(None),
                VarLenType::NChar => ColumnData::String(None),
                VarLenType::Xml => ColumnData::Xml(None),
                // A null CLR UDT carries no payload; surface it as a null
                // binary, matching `udt::decode` (which yields
                // `ColumnData::Binary`). Previously this panicked via `todo!()`,
                // which a bulk insert of a NULL UDT column could reach.
                VarLenType::Udt => ColumnData::Binary(None),
                VarLenType::Text => ColumnData::String(None),
                VarLenType::Image => ColumnData::Binary(None),
                VarLenType::NText => ColumnData::String(None),
                // A null `sql_variant` carries no base type, so surface a
                // generic null value.
                VarLenType::SSVariant => ColumnData::String(None),
            },
            TypeInfo::VarLenSizedPrecision { ty, .. } => match ty {
                VarLenType::Guid => ColumnData::Guid(None),
                VarLenType::Intn => ColumnData::I32(None),
                VarLenType::Bitn => ColumnData::Bit(None),
                VarLenType::Decimaln => ColumnData::Numeric(None),
                VarLenType::Numericn => ColumnData::Numeric(None),
                VarLenType::Floatn => ColumnData::F32(None),
                VarLenType::Money => ColumnData::F64(None),
                VarLenType::Datetimen => ColumnData::DateTime(None),
                #[cfg(feature = "tds73")]
                VarLenType::Daten => ColumnData::Date(None),
                #[cfg(feature = "tds73")]
                VarLenType::Timen => ColumnData::Time(None),
                #[cfg(feature = "tds73")]
                VarLenType::Datetime2 => ColumnData::DateTime2(None),
                #[cfg(feature = "tds73")]
                VarLenType::DatetimeOffsetn => ColumnData::DateTimeOffset(None),
                VarLenType::BigVarBin => ColumnData::Binary(None),
                VarLenType::BigVarChar => ColumnData::String(None),
                VarLenType::BigBinary => ColumnData::Binary(None),
                VarLenType::BigChar => ColumnData::String(None),
                VarLenType::NVarchar => ColumnData::String(None),
                VarLenType::NChar => ColumnData::String(None),
                VarLenType::Xml => ColumnData::Xml(None),
                // A null CLR UDT carries no payload; surface it as a null
                // binary, matching `udt::decode` (which yields
                // `ColumnData::Binary`). Previously this panicked via `todo!()`,
                // which a bulk insert of a NULL UDT column could reach.
                VarLenType::Udt => ColumnData::Binary(None),
                VarLenType::Text => ColumnData::String(None),
                VarLenType::Image => ColumnData::Binary(None),
                VarLenType::NText => ColumnData::String(None),
                // A null `sql_variant` carries no base type, so surface a
                // generic null value.
                VarLenType::SSVariant => ColumnData::String(None),
            },
            TypeInfo::Xml { .. } => ColumnData::Xml(None),
            TypeInfo::Udt(_) => ColumnData::Binary(None),
        }
    }
}

impl<'a> Encode<BytesMut> for TokenColMetaData<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u8(TokenType::ColMetaData as u8);
        dst.put_u16_le(self.columns.len() as u16);

        for col in self.columns.into_iter() {
            col.encode(dst)?;
        }

        Ok(())
    }
}

impl<'a> Encode<BytesMut> for MetaDataColumn<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u32_le(0);
        self.base.encode(dst)?;

        let len_pos = dst.len();
        let mut length = 0u8;

        dst.put_u8(length);

        for chr in self.col_name.encode_utf16() {
            length += 1;
            dst.put_u16_le(chr);
        }

        let dst: &mut [u8] = dst.borrow_mut();
        dst[len_pos] = length;

        Ok(())
    }
}

impl Encode<BytesMut> for BaseMetaDataColumn {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u16_le(BitFlags::bits(self.flags));
        self.ty.encode(dst)?;

        Ok(())
    }
}

/// A setting a column can hold.
#[bitflags]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnFlag {
    /// The column can be null.
    Nullable = 1,
    /// Set for string columns with binary collation and always for the XML data
    /// type.
    CaseSensitive = 1 << 1,
    /// If column is writeable.
    Updateable = 1 << 3,
    /// Column modification status unknown.
    UpdateableUnknown = 1 << 2,
    /// Column is an identity.
    Identity = 1 << 4,
    /// Coulumn is computed.
    Computed = 1 << 7,
    /// Column is a fixed-length common language runtime user-defined type (CLR
    /// UDT).
    FixedLenClrType = 1 << 10,
    /// Column is the special XML column for the sparse column set.
    SparseColumnSet = 1 << 11,
    /// Column is encrypted transparently and has to be decrypted to view the
    /// plaintext value. This flag is valid when the column encryption feature
    /// is negotiated between client and server and is turned on.
    Encrypted = 1 << 12,
    /// Column is part of a hidden primary key created to support a T-SQL SELECT
    /// statement containing FOR BROWSE.
    Hidden = 1 << 13,
    /// Column is part of a primary key for the row and the T-SQL SELECT
    /// statement contains FOR BROWSE.
    Key = 1 << 14,
    /// It is unknown whether the column might be nullable.
    NullableUnknown = 1 << 15,
}

impl TokenColMetaData<'static> {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let column_count = src.read_u16_le().await?;
        // `column_count` is an untrusted u16 (up to 65535); cap the up-front
        // reservation so a hostile COLMETADATA token can't force a large
        // transient allocation before the column bodies arrive. The Vec still
        // grows as real columns are decoded.
        let mut columns = Vec::with_capacity(
            (column_count as usize).min(crate::tds::codec::column_data::MAX_PREALLOC),
        );

        // `0xffff` is the "no metadata" sentinel; any other count drives the
        // loop directly (a count of 0 simply iterates zero times).
        if column_count < 0xffff {
            for _ in 0..column_count {
                let base = BaseMetaDataColumn::decode(src).await?;
                let col_name = Cow::from(src.read_b_varchar().await?);

                columns.push(MetaDataColumn { base, col_name });
            }
        }

        Ok(TokenColMetaData { columns })
    }
}

impl<'a> TokenColMetaData<'a> {
    pub(crate) fn columns(&self) -> impl Iterator<Item = Column> + '_ {
        self.columns.iter().map(|x| Column {
            name: x.col_name.to_string(),
            column_type: ColumnType::from(&x.base.ty),
        })
    }
}

impl BaseMetaDataColumn {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        use VarLenType::*;

        let _user_ty = src.read_u32_le().await?;

        // The COLMETADATA `Flags` field (MS-TDS §2.2.7.4) is a 16-bit field that
        // includes reserved / ODBC bits the server may set and which future
        // protocol revisions may extend. Truncate to the flags we model rather
        // than rejecting the whole token on an unrecognized bit.
        let flags = BitFlags::from_bits_truncate(src.read_u16_le().await?);

        let ty = TypeInfo::decode(src).await?;

        if let TypeInfo::VarLenSized(cx) = ty {
            if let Text | NText | Image = cx.r#type() {
                let num_of_parts = src.read_u8().await?;

                // table name
                for _ in 0..num_of_parts {
                    src.read_us_varchar().await?;
                }
            };
        };

        Ok(BaseMetaDataColumn { flags, ty })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use crate::tds::Collation;
    use crate::VarLenContext;

    fn meta(ty: TypeInfo, name: &'static str) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty,
            },
            col_name: Cow::Borrowed(name),
        }
    }

    #[tokio::test]
    async fn round_trip_via_encode_decode() {
        let cmd = TokenColMetaData {
            columns: vec![
                meta(TypeInfo::FixedLen(FixedLenType::Int4), "id"),
                meta(
                    TypeInfo::VarLenSized(VarLenContext::new(
                        VarLenType::NVarchar,
                        4000,
                        Some(Collation::new(13632521, 52)),
                    )),
                    "name",
                ),
            ],
        };

        // Build a decodable buffer: column count followed by each column. The
        // MetaDataColumn encoder writes the leading user-type u32 that the
        // decoder expects.
        let mut buf = BytesMut::new();
        buf.put_u16_le(cmd.columns.len() as u16);
        for col in cmd.columns.iter().cloned() {
            col.encode(&mut buf).unwrap();
        }

        let decoded = TokenColMetaData::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(decoded.columns.len(), 2);
        assert_eq!(decoded.columns[0].col_name, "id");
        assert_eq!(decoded.columns[1].col_name, "name");

        let columns: Vec<_> = decoded.columns().collect();
        assert_eq!(columns.len(), 2);
        assert_eq!(columns[0].name(), "id");
    }

    #[test]
    fn encode_writes_token_header_and_column_count() {
        let cmd = TokenColMetaData {
            columns: vec![
                meta(TypeInfo::FixedLen(FixedLenType::Int4), "id"),
                meta(TypeInfo::FixedLen(FixedLenType::Bit), "flag"),
            ],
        };

        let mut buf = BytesMut::new();
        cmd.encode(&mut buf).unwrap();

        // First the ColMetaData token byte, then the little-endian column count.
        assert_eq!(buf[0], TokenType::ColMetaData as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 2);
        // The two column bodies follow the 3-byte header.
        assert!(buf.len() > 3);
    }

    #[tokio::test]
    async fn zero_columns_yields_empty() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0);

        let decoded = TokenColMetaData::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();
        assert!(decoded.columns.is_empty());
    }

    #[tokio::test]
    async fn text_column_reads_table_name_parts() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(1); // one column

        // user_ty + flags
        buf.put_u32_le(0);
        buf.put_u16_le(BitFlags::bits(BitFlags::from(ColumnFlag::Nullable)));

        // type info for a text column with collation
        let ti = TypeInfo::VarLenSized(VarLenContext::new(
            VarLenType::Text,
            2147483647,
            Some(Collation::new(13632521, 52)),
        ));
        ti.encode(&mut buf).unwrap();

        // table name: one part, us_varchar "dbo"
        buf.put_u8(1);
        let part: Vec<u16> = "dbo".encode_utf16().collect();
        buf.put_u16_le(part.len() as u16);
        for c in part {
            buf.put_u16_le(c);
        }

        // column name (b_varchar)
        let name: Vec<u16> = "body".encode_utf16().collect();
        buf.put_u8(name.len() as u8);
        for c in name {
            buf.put_u16_le(c);
        }

        let decoded = TokenColMetaData::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(decoded.columns.len(), 1);
        assert_eq!(decoded.columns[0].col_name, "body");
    }

    #[test]
    fn display_formats_various_types() {
        let cases = vec![
            (TypeInfo::FixedLen(FixedLenType::Int4), "c int"),
            (TypeInfo::FixedLen(FixedLenType::Bit), "c bit"),
            (TypeInfo::FixedLen(FixedLenType::Float8), "c float"),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None)),
                "c tinyint",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
                "c int",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
                "c real",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None)),
                "c uniqueidentifier",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 100, None)),
                "c varbinary(100)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 100000, None)),
                "c varbinary(max)",
            ),
            (
                TypeInfo::VarLenSizedPrecision {
                    ty: VarLenType::Decimaln,
                    size: 17,
                    precision: 18,
                    scale: 2,
                },
                "c decimal(18,2)",
            ),
            // Numericn must render as `numeric(...)`, distinct from the
            // `decimal(...)` fallback that every other precision type uses.
            (
                TypeInfo::VarLenSizedPrecision {
                    ty: VarLenType::Numericn,
                    size: 9,
                    precision: 10,
                    scale: 4,
                },
                "c numeric(10,4)",
            ),
            (
                TypeInfo::Xml {
                    schema: None,
                    size: 0,
                },
                "c xml",
            ),
        ];

        for (ty, expected) in cases {
            // Display brackets the column name for use in bulk `INSERT` statements.
            let expected = expected.replacen("c ", "[c] ", 1);
            assert_eq!(format!("{}", meta(ty, "c")), expected);
        }
    }

    #[test]
    fn null_value_maps_types() {
        let fixed = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
        };
        assert_eq!(fixed.null_value(), ColumnData::I32(None));

        let varlen = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None)),
        };
        assert_eq!(varlen.null_value(), ColumnData::I16(None));

        // Each Intn width maps to a distinct integer column; 1 and 4 sit either
        // side of the `_ => I64` fallback and pin their own arms.
        let tinyint = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 1, None)),
        };
        assert_eq!(tinyint.null_value(), ColumnData::U8(None));

        let int4 = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
        };
        assert_eq!(int4.null_value(), ColumnData::I32(None));

        let int8 = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None)),
        };
        assert_eq!(int8.null_value(), ColumnData::I64(None));

        // Floatn splits on width too: 4 bytes is F32, anything else F64.
        let real = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 4, None)),
        };
        assert_eq!(real.null_value(), ColumnData::F32(None));

        let double = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None)),
        };
        assert_eq!(double.null_value(), ColumnData::F64(None));

        let guid = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Guid, 16, None)),
        };
        assert_eq!(guid.null_value(), ColumnData::Guid(None));
    }

    #[test]
    fn null_value_maps_precision_and_xml_and_udt() {
        let precision = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: 17,
                precision: 18,
                scale: 2,
            },
        };
        assert_eq!(precision.null_value(), ColumnData::Numeric(None));

        let xml = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::Xml {
                schema: None,
                size: 0,
            },
        };
        assert_eq!(xml.null_value(), ColumnData::Xml(None));

        let udt = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::Udt(crate::tds::codec::type_info::UdtInfo {
                max_byte_size: 0,
                db_name: "db".into(),
                schema_name: "dbo".into(),
                type_name: "T".into(),
                assembly_qualified_name: "A".into(),
            }),
        };
        assert_eq!(udt.null_value(), ColumnData::Binary(None));
    }

    #[test]
    fn base_meta_data_column_flag_accessors() {
        let base = BaseMetaDataColumn {
            flags: ColumnFlag::Nullable | ColumnFlag::Identity | ColumnFlag::Updateable,
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
        };

        assert!(base.is_nullable());
        assert!(base.is_identity());
        assert!(base.is_updateable());
        assert_eq!(base.ty(), &TypeInfo::FixedLen(FixedLenType::Int4));
        assert_eq!(base.flags(), base.flags);

        let base2 = BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
        };
        assert!(!base2.is_nullable());
        assert!(!base2.is_identity());
        assert!(!base2.is_updateable());
    }

    #[test]
    fn meta_data_column_accessors() {
        let m = meta(TypeInfo::FixedLen(FixedLenType::Int4), "id");
        assert_eq!(m.col_name(), "id");
        assert!(m.base().is_nullable());
    }

    #[test]
    fn display_formats_more_types() {
        let cases = vec![
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Bitn, 1, None)),
                "c bit",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetimen, 8, None)),
                "c datetime",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 4, None)),
                "c smallmoney",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None)),
                "c money",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarChar, 100, None)),
                "c varchar(100)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarChar, 100000, None)),
                "c varchar(max)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigBinary, 10, None)),
                "c binary(10)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigChar, 10, None)),
                "c char(10)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NVarchar, 100, None)),
                "c nvarchar(100)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NVarchar, 100000, None)),
                "c nvarchar(max)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NChar, 10, None)),
                "c nchar(10)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Text, 0, None)),
                "c text",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Image, 0, None)),
                "c image",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::NText, 0, None)),
                "c ntext",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 2, None)),
                "c smallint",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 8, None)),
                "c bigint",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Floatn, 8, None)),
                "c float",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::SSVariant, 0, None)),
                "c sql_variant",
            ),
        ];

        for (ty, expected) in cases {
            let expected = expected.replacen("c ", "[c] ", 1);
            assert_eq!(format!("{}", meta(ty, "c")), expected);
        }
    }

    #[test]
    fn display_formats_udt_and_decimaln() {
        let udt = TypeInfo::Udt(crate::tds::codec::type_info::UdtInfo {
            max_byte_size: 0,
            db_name: "db".into(),
            schema_name: "dbo".into(),
            type_name: "MyType".into(),
            assembly_qualified_name: "asm".into(),
        });
        assert_eq!(format!("{}", meta(udt, "c")), "[c] dbo.MyType");

        let decimaln = TypeInfo::VarLenSizedPrecision {
            ty: VarLenType::Decimaln,
            size: 17,
            precision: 10,
            scale: 4,
        };
        assert_eq!(format!("{}", meta(decimaln, "c")), "[c] decimal(10,4)");
    }

    #[tokio::test]
    async fn decode_all_ones_column_count_yields_empty() {
        // column_count == 0xffff is treated as "no columns" (guards against a
        // sentinel/placeholder value rather than a real column list).
        let mut buf = BytesMut::new();
        buf.put_u16_le(0xffff);

        let decoded = TokenColMetaData::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();
        assert!(decoded.columns.is_empty());
    }

    #[test]
    fn display_formats_fixed_len_money_and_datetime_types() {
        // Covers the FixedLenType Display arms not exercised elsewhere:
        // tinyint/smallint/smalldatetime/real/money/datetime/smallmoney/bigint
        // and the `Null` sentinel (which surfaces as `int`).
        let cases = vec![
            (TypeInfo::FixedLen(FixedLenType::Int1), "c tinyint"),
            (TypeInfo::FixedLen(FixedLenType::Int2), "c smallint"),
            (
                TypeInfo::FixedLen(FixedLenType::Datetime4),
                "c smalldatetime",
            ),
            (TypeInfo::FixedLen(FixedLenType::Float4), "c real"),
            (TypeInfo::FixedLen(FixedLenType::Money), "c money"),
            (TypeInfo::FixedLen(FixedLenType::Datetime), "c datetime"),
            (TypeInfo::FixedLen(FixedLenType::Money4), "c smallmoney"),
            (TypeInfo::FixedLen(FixedLenType::Int8), "c bigint"),
            (TypeInfo::FixedLen(FixedLenType::Null), "c int"),
        ];

        for (ty, expected) in cases {
            let expected = expected.replacen("c ", "[c] ", 1);
            assert_eq!(format!("{}", meta(ty, "c")), expected);
        }
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn display_formats_tds73_date_time_types() {
        // date/time/datetime2/datetimeoffset Display arms (tds73-only).
        let cases = vec![
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None)),
                "c date",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Timen, 7, None)),
                "c time",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Datetime2, 7, None)),
                "c datetime2(7)",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::DatetimeOffsetn, 7, None)),
                "c datetimeoffset",
            ),
        ];

        for (ty, expected) in cases {
            let expected = expected.replacen("c ", "[c] ", 1);
            assert_eq!(format!("{}", meta(ty, "c")), expected);
        }
    }

    #[test]
    fn display_var_len_other_fallback_uses_debug_name() {
        // A VarLenSized carrying a type not matched by any explicit Display arm
        // (e.g. Decimaln) hits the `other => {other:?}` fallback rather than
        // panicking.
        let ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Decimaln, 17, None));
        assert_eq!(format!("{}", meta(ty, "c")), "[c] Decimaln");
    }

    #[test]
    fn null_value_all_fixed_len() {
        use FixedLenType::*;
        let cases = [
            (Null, ColumnData::I32(None)),
            (Int1, ColumnData::U8(None)),
            (Bit, ColumnData::Bit(None)),
            (Int2, ColumnData::I16(None)),
            (Int4, ColumnData::I32(None)),
            (Datetime4, ColumnData::SmallDateTime(None)),
            (Float4, ColumnData::F32(None)),
            (Money, ColumnData::F64(None)),
            (Datetime, ColumnData::DateTime(None)),
            (Float8, ColumnData::F64(None)),
            (Money4, ColumnData::F32(None)),
            (Int8, ColumnData::I64(None)),
        ];

        for (ty, expected) in cases {
            let base = BaseMetaDataColumn {
                flags: BitFlags::empty(),
                ty: TypeInfo::FixedLen(ty),
            };
            assert_eq!(base.null_value(), expected);
        }
    }

    fn vsize_null(ty: VarLenType, len: usize) -> ColumnData<'static> {
        BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(ty, len, None)),
        }
        .null_value()
    }

    #[test]
    fn null_value_all_var_len_sized() {
        use VarLenType::*;
        assert_eq!(vsize_null(Guid, 16), ColumnData::Guid(None));
        assert_eq!(vsize_null(Bitn, 1), ColumnData::Bit(None));
        assert_eq!(vsize_null(Decimaln, 17), ColumnData::Numeric(None));
        assert_eq!(vsize_null(Numericn, 17), ColumnData::Numeric(None));
        assert_eq!(vsize_null(Money, 8), ColumnData::F64(None));
        assert_eq!(vsize_null(Datetimen, 8), ColumnData::DateTime(None));
        assert_eq!(vsize_null(BigVarBin, 100), ColumnData::Binary(None));
        assert_eq!(vsize_null(BigVarChar, 100), ColumnData::String(None));
        assert_eq!(vsize_null(BigBinary, 10), ColumnData::Binary(None));
        assert_eq!(vsize_null(BigChar, 10), ColumnData::String(None));
        assert_eq!(vsize_null(NVarchar, 100), ColumnData::String(None));
        assert_eq!(vsize_null(NChar, 10), ColumnData::String(None));
        assert_eq!(vsize_null(Xml, 0), ColumnData::Xml(None));
        assert_eq!(vsize_null(Udt, 0), ColumnData::Binary(None));
        assert_eq!(vsize_null(Text, 0), ColumnData::String(None));
        assert_eq!(vsize_null(Image, 0), ColumnData::Binary(None));
        assert_eq!(vsize_null(NText, 0), ColumnData::String(None));
        assert_eq!(vsize_null(SSVariant, 0), ColumnData::String(None));
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn null_value_var_len_sized_tds73() {
        use VarLenType::*;
        assert_eq!(vsize_null(Daten, 3), ColumnData::Date(None));
        assert_eq!(vsize_null(Timen, 7), ColumnData::Time(None));
        assert_eq!(vsize_null(Datetime2, 7), ColumnData::DateTime2(None));
        assert_eq!(
            vsize_null(DatetimeOffsetn, 7),
            ColumnData::DateTimeOffset(None)
        );
    }

    fn vprec_null(ty: VarLenType) -> ColumnData<'static> {
        BaseMetaDataColumn {
            flags: BitFlags::empty(),
            ty: TypeInfo::VarLenSizedPrecision {
                ty,
                size: 8,
                precision: 18,
                scale: 2,
            },
        }
        .null_value()
    }

    #[test]
    fn null_value_all_var_len_precision() {
        use VarLenType::*;
        assert_eq!(vprec_null(Guid), ColumnData::Guid(None));
        assert_eq!(vprec_null(Intn), ColumnData::I32(None));
        assert_eq!(vprec_null(Bitn), ColumnData::Bit(None));
        assert_eq!(vprec_null(Decimaln), ColumnData::Numeric(None));
        assert_eq!(vprec_null(Numericn), ColumnData::Numeric(None));
        assert_eq!(vprec_null(Floatn), ColumnData::F32(None));
        assert_eq!(vprec_null(Money), ColumnData::F64(None));
        assert_eq!(vprec_null(Datetimen), ColumnData::DateTime(None));
        assert_eq!(vprec_null(BigVarBin), ColumnData::Binary(None));
        assert_eq!(vprec_null(BigVarChar), ColumnData::String(None));
        assert_eq!(vprec_null(BigBinary), ColumnData::Binary(None));
        assert_eq!(vprec_null(BigChar), ColumnData::String(None));
        assert_eq!(vprec_null(NVarchar), ColumnData::String(None));
        assert_eq!(vprec_null(NChar), ColumnData::String(None));
        assert_eq!(vprec_null(Xml), ColumnData::Xml(None));
        assert_eq!(vprec_null(Udt), ColumnData::Binary(None));
        assert_eq!(vprec_null(Text), ColumnData::String(None));
        assert_eq!(vprec_null(Image), ColumnData::Binary(None));
        assert_eq!(vprec_null(NText), ColumnData::String(None));
        assert_eq!(vprec_null(SSVariant), ColumnData::String(None));
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn null_value_var_len_precision_tds73() {
        use VarLenType::*;
        assert_eq!(vprec_null(Daten), ColumnData::Date(None));
        assert_eq!(vprec_null(Timen), ColumnData::Time(None));
        assert_eq!(vprec_null(Datetime2), ColumnData::DateTime2(None));
        assert_eq!(
            vprec_null(DatetimeOffsetn),
            ColumnData::DateTimeOffset(None)
        );
    }

    #[test]
    fn column_flag_bits_are_distinct() {
        let all = ColumnFlag::Nullable
            | ColumnFlag::CaseSensitive
            | ColumnFlag::Updateable
            | ColumnFlag::UpdateableUnknown
            | ColumnFlag::Identity
            | ColumnFlag::Computed
            | ColumnFlag::FixedLenClrType
            | ColumnFlag::SparseColumnSet
            | ColumnFlag::Encrypted
            | ColumnFlag::Hidden
            | ColumnFlag::Key
            | ColumnFlag::NullableUnknown;

        assert!(all.contains(ColumnFlag::Nullable));
        assert!(all.contains(ColumnFlag::NullableUnknown));
        assert_eq!(BitFlags::bits(all).count_ones(), 12);
    }
}
