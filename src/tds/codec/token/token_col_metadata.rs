use std::{
    borrow::{BorrowMut, Cow},
    fmt::Display,
};

use crate::{
    error::Error,
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

#[derive(Debug, Clone)]
pub struct MetaDataColumn<'a> {
    pub base: BaseMetaDataColumn,
    pub col_name: Cow<'a, str>,
}

impl<'a> Display for MetaDataColumn<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bracket-quote the identifier, escaping any literal `]` by doubling it
        // (`]]`) per the T-SQL rule. Without this a column name containing `]`
        // (e.g. `my]col`) would emit a malformed identifier `[my]col]`, breaking
        // the `INSERT BULK (...)` column list this Display feeds into.
        write!(f, "[{}] ", self.col_name.replace(']', "]]"))?;

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
                FixedLenType::Null => unreachable!(),
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
                    8 => write!(f, "bigint")?,
                    _ => unreachable!(),
                },
                VarLenType::Floatn => match ctx.len() {
                    4 => write!(f, "real")?,
                    8 => write!(f, "float")?,
                    _ => unreachable!(),
                },
                VarLenType::Money => {
                    if ctx.len() == 4 {
                        write!(f, "smallmoney")?
                    } else {
                        write!(f, "money")?
                    }
                }
                VarLenType::SSVariant => write!(f, "sql_variant")?,
                // Any other var-len type (e.g. Decimaln/Numericn arriving
                // without the precision/scale they need, or Xml/Udt appearing
                // in a sized context) has no valid SQL type name we can emit
                // here. Emitting a bogus name (such as the Debug name) would
                // produce an invalid `INSERT BULK` statement, so return a
                // formatting error instead. This keeps the library from ever
                // panicking on server-supplied metadata while refusing to emit
                // invalid SQL.
                _ => return Err(std::fmt::Error),
            },
            TypeInfo::VarLenSizedPrecision {
                ty,
                size: _,
                precision,
                scale,
            } => match ty {
                VarLenType::Decimaln => write!(f, "decimal({},{})", precision, scale)?,
                VarLenType::Numericn => write!(f, "numeric({},{})", precision, scale)?,
                _ => unreachable!(),
            },
            TypeInfo::Xml { .. } => write!(f, "xml")?,
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BaseMetaDataColumn {
    pub flags: BitFlags<ColumnFlag>,
    pub ty: TypeInfo,
    /// Destination table name, used only on the *encode* (bulk-load) path. Per
    /// MS-TDS §2.2.7.4, `text`/`ntext`/`image` columns carry a `TableName`
    /// element in COLMETADATA; the bulk-insert code sets this to the target
    /// table so [`BaseMetaDataColumn::encode`] can emit it. It is always `None`
    /// on the decode (server→client) path, which never needs it.
    pub table_name: Option<String>,
}

impl BaseMetaDataColumn {
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
                VarLenType::Udt => todo!("User-defined types not supported"),
                VarLenType::Text => ColumnData::String(None),
                VarLenType::Image => ColumnData::Binary(None),
                VarLenType::NText => ColumnData::String(None),
                VarLenType::SSVariant => todo!(),
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
                VarLenType::Udt => todo!("User-defined types not supported"),
                VarLenType::Text => ColumnData::String(None),
                VarLenType::Image => ColumnData::Binary(None),
                VarLenType::NText => ColumnData::String(None),
                VarLenType::SSVariant => todo!(),
            },
            TypeInfo::Xml { .. } => ColumnData::Xml(None),
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

        // `text`/`ntext`/`image` columns carry a TableName element after the
        // TYPE_INFO. The client->server INSERT BULK COLMETADATA uses a DIFFERENT
        // TableName shape than the server->client result COLMETADATA the decode
        // side reads:
        //
        //   * READ  (server->client): NumParts BYTE, then NumParts US_VARCHARs
        //     (see `BaseMetaDataColumn::decode` below and MS-TDS §2.2.7.4).
        //   * WRITE (client->server bulk): a single bare US_VARCHAR carrying the
        //     whole destination table name, with NO NumParts byte and no
        //     splitting on `.`.
        //
        // This asymmetry matches Microsoft's own go-mssqldb bulk-copy path
        // (`createColMetadata` in bulkcopy.go), verified against real SQL Server:
        // a `uint16` code-unit count + UTF-16LE bytes, no NumParts. Emitting the
        // spec/result-style `NumParts` byte here inserts one extra leading 0x01
        // the server does not expect, mis-parsing the column and overrunning the
        // row stream (TDS error 4804). Only these three types carry a TableName,
        // so the desync hits text/ntext/image bulk exclusively.
        //
        // Capture whether this is such a column before `encode` consumes `self.ty`.
        let emits_table_name = matches!(
            &self.ty,
            TypeInfo::VarLenSized(cx)
                if matches!(cx.r#type(), VarLenType::Text | VarLenType::NText | VarLenType::Image)
        );

        self.ty.encode(dst)?;

        if emits_table_name {
            let table_name = self.table_name.as_deref().unwrap_or("");
            encode_us_varchar(dst, table_name)?;
        }

        Ok(())
    }
}

/// Encode a US_VARCHAR: a `u16` length in UTF-16 code units followed by the
/// UTF-16LE characters. The length field is a `u16`, so a part longer than
/// `u16::MAX` code units cannot be represented and is rejected.
fn encode_us_varchar(dst: &mut BytesMut, s: &str) -> crate::Result<()> {
    let units = s.encode_utf16().count();
    if units > u16::MAX as usize {
        return Err(Error::BulkInput(
            format!("table name is too long ({units} UTF-16 code units, max 65535)").into(),
        ));
    }

    dst.put_u16_le(units as u16);
    for chr in s.encode_utf16() {
        dst.put_u16_le(chr);
    }

    Ok(())
}

/// A setting a column can hold.
#[bitflags]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnFlag {
    /// The column can be null.
    Nullable = 1 << 0,
    /// Set for string columns with binary collation and always for the XML data
    /// type.
    CaseSensitive = 1 << 1,
    /// If column is writeable.
    Updateable = 1 << 3,
    /// Column modification status unknown.
    UpdateableUnknown = 1 << 4,
    /// Column is an identity.
    Identity = 1 << 5,
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
        let mut columns = Vec::with_capacity(column_count as usize);

        if column_count > 0 && column_count < 0xffff {
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

        let flags = BitFlags::from_bits(src.read_u16_le().await?)
            .map_err(|_| Error::Protocol("column metadata: invalid flags".into()))?;

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

        Ok(BaseMetaDataColumn {
            flags,
            ty,
            table_name: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::type_info::VarLenContext;
    use std::fmt::Write as _;

    // Build the on-wire bytes a US_VARCHAR should produce for `s`.
    fn us_varchar_bytes(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let units: Vec<u16> = s.encode_utf16().collect();
        out.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn text_column(table_name: Option<&str>) -> BaseMetaDataColumn {
        BaseMetaDataColumn {
            flags: ColumnFlag::Nullable.into(),
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Text, 2147483647, None)),
            table_name: table_name.map(str::to_string),
        }
    }

    // On the client->server INSERT BULK path a `text` column's metadata must end
    // with the TableName as a SINGLE bare US_VARCHAR carrying the whole name --
    // NO NumParts byte and no splitting on `.` -- matching go-mssqldb's verified
    // bulkcopy `createColMetadata`. A dotted name is sent verbatim as one part.
    #[test]
    fn text_column_emits_dotted_name_as_bare_us_varchar() {
        let mut buf = BytesMut::new();
        text_column(Some("dbo.MyTable")).encode(&mut buf).unwrap();

        // Whole name as one US_VARCHAR, with no leading NumParts byte.
        let expected_tail = us_varchar_bytes("dbo.MyTable");

        assert!(
            buf.ends_with(&expected_tail),
            "buffer {:02x?} did not end with bare US_VARCHAR TableName {:02x?}",
            &buf[..],
            expected_tail
        );
    }

    // A single, unqualified name is likewise a single bare US_VARCHAR (no
    // NumParts byte).
    #[test]
    fn text_column_single_name_is_bare_us_varchar() {
        let mut buf = BytesMut::new();
        text_column(Some("##bulk_test")).encode(&mut buf).unwrap();

        let expected_tail = us_varchar_bytes("##bulk_test");
        assert!(buf.ends_with(&expected_tail), "got {:02x?}", &buf[..]);
    }

    // Non-text columns must not emit any TableName, even if one is set: the bytes
    // must be identical with and without a table name.
    #[test]
    fn non_text_column_never_emits_table_name() {
        let with = {
            let mut buf = BytesMut::new();
            BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::FixedLen(FixedLenType::Int4),
                table_name: Some("dbo.MyTable".to_string()),
            }
            .encode(&mut buf)
            .unwrap();
            buf.to_vec()
        };
        let without = {
            let mut buf = BytesMut::new();
            BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::FixedLen(FixedLenType::Int4),
                table_name: None,
            }
            .encode(&mut buf)
            .unwrap();
            buf.to_vec()
        };
        assert_eq!(with, without);
    }

    // A US_VARCHAR length field is a u16; an over-long name must error rather
    // than wrap the length (which would desync the wire).
    #[test]
    fn text_column_rejects_over_long_table_name() {
        let long = "a".repeat(u16::MAX as usize + 1);
        let mut buf = BytesMut::new();
        let err = text_column(Some(&long)).encode(&mut buf).unwrap_err();
        assert!(matches!(err, Error::BulkInput(_)), "got {err:?}");
    }

    fn meta(ty: TypeInfo, name: &'static str) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty,
                table_name: None,
            },
            col_name: Cow::Borrowed(name),
        }
    }

    #[test]
    fn display_var_len_unknown_type_yields_err_not_panic() {
        // A VarLenSized carrying a type with no valid sized SQL representation
        // (e.g. Decimaln/Numericn without precision/scale) must NOT panic and
        // must NOT emit a bogus SQL type name. Formatting it returns a
        // `std::fmt::Error` so the caller gets an `Err`, never a panic and
        // never invalid SQL.
        for ty in [VarLenType::Decimaln, VarLenType::Numericn] {
            let col = meta(TypeInfo::VarLenSized(VarLenContext::new(ty, 17, None)), "c");
            let mut out = String::new();
            let result = write!(out, "{col}");
            assert!(
                result.is_err(),
                "expected Err for unhandled var-len type {ty:?}, got Ok({out:?})"
            );
        }
    }

    #[test]
    fn display_money_columns_never_panic_and_render_expected() {
        // MONEY/SMALLMONEY reach the Display impl both as FixedLen (Money /
        // Money4) and as VarLenSized (Money with len 8 / 4). A money column
        // must never fall through to a catch-all; each renders its exact SQL
        // type name for the bulk `INSERT` column list. Assert the rendered type
        // token (with a leading space so `money` can't match `smallmoney`) so
        // the test is agnostic to how the column-name prefix is quoted.
        let cases = vec![
            (TypeInfo::FixedLen(FixedLenType::Money), " money"),
            (TypeInfo::FixedLen(FixedLenType::Money4), " smallmoney"),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None)),
                " money",
            ),
            (
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 4, None)),
                " smallmoney",
            ),
        ];

        for (ty, expected_suffix) in cases {
            // Must not panic, and must end with the expected SQL type token.
            let rendered = format!("{}", meta(ty, "c"));
            assert!(
                rendered.ends_with(expected_suffix),
                "expected {rendered:?} to end with {expected_suffix:?}"
            );
        }
    }

    fn column(name: &'static str) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: BitFlags::empty(),
                ty: TypeInfo::FixedLen(FixedLenType::Int4),
                table_name: None,
            },
            col_name: Cow::Borrowed(name),
        }
    }

    #[test]
    fn display_escapes_closing_bracket_in_column_name() {
        // A `]` in the column name must be doubled so the bracket-quoted
        // identifier stays well-formed for the `INSERT BULK (...)` column list.
        assert_eq!(format!("{}", column("my]col")), "[my]]col] int");
    }

    #[test]
    fn display_leaves_plain_column_name_unchanged() {
        assert_eq!(format!("{}", column("foo")), "[foo] int");
    }
}
