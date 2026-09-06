use asynchronous_codec::BytesMut;
use bytes::BufMut;

use crate::{tds::Collation, xml::XmlSchema, Error, SqlReadBytes};
use std::{convert::TryFrom, sync::Arc};

use super::Encode;

/// A length of a column in bytes or characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeLength {
    /// The number of bytes (or characters) reserved in the column.
    Limited(u16),
    /// Unlimited, stored in the heap outside of the row.
    Max,
}

/// Describes a type of a column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeInfo {
    /// A fixed-length type, whose size is fully determined by the type itself.
    FixedLen(FixedLenType),
    /// A variable-length type with an explicit size (and optional collation).
    VarLenSized(VarLenContext),
    /// A variable-length type carrying a precision and scale, such as `decimal`
    /// and `numeric`.
    VarLenSizedPrecision {
        /// The underlying variable-length type.
        ty: VarLenType,
        /// The reserved size of the column in bytes.
        size: usize,
        /// The total number of digits.
        precision: u8,
        /// The number of digits to the right of the decimal point.
        scale: u8,
    },
    /// The `xml` type, with an optional associated schema.
    Xml {
        /// The XML schema associated with the column, if any.
        schema: Option<Arc<XmlSchema>>,
        /// The reserved size of the column in bytes.
        size: usize,
    },
    /// A CLR user-defined type (UDT), MS-TDS §2.2.5.5.4.
    Udt(UdtInfo),
}

/// Metadata describing a CLR user-defined type (UDT) column, as defined by the
/// `UDT_INFO` rule in MS-TDS §2.2.5.5.4.
///
/// This carries only the identifying metadata of the type. The value bytes are
/// surfaced verbatim (see [`ColumnData::Binary`]); tiberius does not attempt to
/// deserialize the CLR representation.
///
/// [`ColumnData::Binary`]: crate::ColumnData::Binary
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdtInfo {
    /// Maximum size of the UDT value in bytes. A value of `0xFFFF` indicates a
    /// large (`MAX`) UDT with no fixed upper bound.
    pub max_byte_size: u16,
    /// Name of the database in which the UDT is defined.
    pub db_name: String,
    /// Name of the schema that owns the UDT.
    pub schema_name: String,
    /// Name of the UDT.
    pub type_name: String,
    /// Assembly-qualified name of the CLR type that implements the UDT.
    pub assembly_qualified_name: String,
}

/// The context of a variable-length column: its underlying type, size and
/// optional collation.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct VarLenContext {
    r#type: VarLenType,
    len: usize,
    collation: Option<Collation>,
}

impl VarLenContext {
    /// Create a new variable-length context from a type, length and optional
    /// collation.
    pub fn new(r#type: VarLenType, len: usize, collation: Option<Collation>) -> Self {
        Self {
            r#type,
            len,
            collation,
        }
    }

    /// Get the var len context's r#type.
    pub fn r#type(&self) -> VarLenType {
        self.r#type
    }

    /// Get the var len context's len.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if the column reserves no length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the var len context's collation.
    pub fn collation(&self) -> Option<Collation> {
        self.collation
    }
}

impl Encode<BytesMut> for VarLenContext {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u8(self.r#type() as u8);

        // length
        match self.r#type {
            #[cfg(feature = "tds73")]
            VarLenType::Daten
            | VarLenType::Timen
            | VarLenType::DatetimeOffsetn
            | VarLenType::Datetime2 => {
                dst.put_u8(self.len() as u8);
            }
            VarLenType::Bitn
            | VarLenType::Intn
            | VarLenType::Floatn
            | VarLenType::Decimaln
            | VarLenType::Numericn
            | VarLenType::Guid
            | VarLenType::Money
            | VarLenType::Datetimen => {
                dst.put_u8(self.len() as u8);
            }
            VarLenType::NChar
            | VarLenType::BigChar
            | VarLenType::NVarchar
            | VarLenType::BigVarChar
            | VarLenType::BigBinary
            | VarLenType::BigVarBin => {
                dst.put_u16_le(self.len() as u16);
            }
            VarLenType::Image | VarLenType::Text | VarLenType::NText | VarLenType::SSVariant => {
                dst.put_u32_le(self.len() as u32);
            }
            VarLenType::Xml => (),
            typ => todo!("encoding {:?} is not supported yet", typ),
        }

        if let Some(collation) = self.collation() {
            dst.put_u32_le(collation.info());
            dst.put_u8(collation.sort_id());
        }

        Ok(())
    }
}

uint_enum! {
    #[repr(u8)]
    pub enum FixedLenType {
        Null = 0x1F,
        Int1 = 0x30,
        Bit = 0x32,
        Int2 = 0x34,
        Int4 = 0x38,
        Datetime4 = 0x3A,
        Float4 = 0x3B,
        Money = 0x3C,
        Datetime = 0x3D,
        Float8 = 0x3E,
        Money4 = 0x7A,
        Int8 = 0x7F,
    }
}

#[cfg(not(feature = "tds73"))]
uint_enum! {
    /// 2.2.5.4.2
    #[repr(u8)]
    pub enum VarLenType {
        Guid = 0x24,
        Intn = 0x26,
        Bitn = 0x68,
        Decimaln = 0x6A,
        Numericn = 0x6C,
        Floatn = 0x6D,
        Money = 0x6E,
        Datetimen = 0x6F,
        BigVarBin = 0xA5,
        BigVarChar = 0xA7,
        BigBinary = 0xAD,
        BigChar = 0xAF,
        NVarchar = 0xE7,
        NChar = 0xEF,
        Xml = 0xF1,
        // not supported yet
        Udt = 0xF0,
        Text = 0x23,
        Image = 0x22,
        NText = 0x63,
        // not supported yet
        SSVariant = 0x62, // legacy types (not supported since post-7.2):
                          // Char = 0x2F,
                          // Binary = 0x2D,
                          // VarBinary = 0x25,
                          // VarChar = 0x27,
                          // Numeric = 0x3F,
                          // Decimal = 0x37
    }
}

#[cfg(feature = "tds73")]
uint_enum! {
    /// 2.2.5.4.2
    #[repr(u8)]
    pub enum VarLenType {
        Guid = 0x24,
        Intn = 0x26,
        Bitn = 0x68,
        Decimaln = 0x6A,
        Numericn = 0x6C,
        Floatn = 0x6D,
        Money = 0x6E,
        Datetimen = 0x6F,
        Daten = 0x28,
        Timen = 0x29,
        Datetime2 = 0x2A,
        DatetimeOffsetn = 0x2B,
        BigVarBin = 0xA5,
        BigVarChar = 0xA7,
        BigBinary = 0xAD,
        BigChar = 0xAF,
        NVarchar = 0xE7,
        NChar = 0xEF,
        Xml = 0xF1,
        // not supported yet
        Udt = 0xF0,
        Text = 0x23,
        Image = 0x22,
        NText = 0x63,
        // not supported yet
        SSVariant = 0x62, // legacy types (not supported since post-7.2):
                          // Char = 0x2F,
                          // Binary = 0x2D,
                          // VarBinary = 0x25,
                          // VarChar = 0x27,
                          // Numeric = 0x3F,
                          // Decimal = 0x37
    }
}

impl Encode<BytesMut> for TypeInfo {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        match self {
            TypeInfo::FixedLen(ty) => {
                dst.put_u8(ty as u8);
            }
            TypeInfo::VarLenSized(ctx) => ctx.encode(dst)?,
            TypeInfo::VarLenSizedPrecision {
                ty,
                size,
                precision,
                scale,
            } => {
                dst.put_u8(ty as u8);
                dst.put_u8(size as u8);
                dst.put_u8(precision);
                dst.put_u8(scale);
            }
            TypeInfo::Xml { schema, .. } => {
                dst.put_u8(VarLenType::Xml as u8);

                if let Some(xs) = schema {
                    dst.put_u8(1);

                    let db_name_encoded: Vec<u16> = xs.db_name().encode_utf16().collect();
                    dst.put_u8(db_name_encoded.len() as u8);
                    for chr in db_name_encoded {
                        dst.put_u16_le(chr);
                    }

                    let owner_encoded: Vec<u16> = xs.owner().encode_utf16().collect();
                    dst.put_u8(owner_encoded.len() as u8);
                    for chr in owner_encoded {
                        dst.put_u16_le(chr);
                    }

                    let collection_encoded: Vec<u16> = xs.collection().encode_utf16().collect();
                    dst.put_u16_le(collection_encoded.len() as u16);
                    for chr in collection_encoded {
                        dst.put_u16_le(chr);
                    }
                } else {
                    dst.put_u8(0);
                }
            }
            TypeInfo::Udt(info) => {
                dst.put_u8(VarLenType::Udt as u8);
                dst.put_u16_le(info.max_byte_size);

                let db_name: Vec<u16> = info.db_name.encode_utf16().collect();
                dst.put_u8(db_name.len() as u8);
                for chr in db_name {
                    dst.put_u16_le(chr);
                }

                let schema_name: Vec<u16> = info.schema_name.encode_utf16().collect();
                dst.put_u8(schema_name.len() as u8);
                for chr in schema_name {
                    dst.put_u16_le(chr);
                }

                let type_name: Vec<u16> = info.type_name.encode_utf16().collect();
                dst.put_u8(type_name.len() as u8);
                for chr in type_name {
                    dst.put_u16_le(chr);
                }

                let aqn: Vec<u16> = info.assembly_qualified_name.encode_utf16().collect();
                dst.put_u16_le(aqn.len() as u16);
                for chr in aqn {
                    dst.put_u16_le(chr);
                }
            }
        }

        Ok(())
    }
}

impl TypeInfo {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let ty = src.read_u8().await?;

        if let Ok(ty) = FixedLenType::try_from(ty) {
            return Ok(TypeInfo::FixedLen(ty));
        }

        match VarLenType::try_from(ty) {
            Err(()) => Err(Error::Protocol(
                format!("invalid or unsupported column type: {:?}", ty).into(),
            )),
            Ok(VarLenType::Xml) => {
                let has_schema = src.read_u8().await?;

                let schema = if has_schema == 1 {
                    let db_name = src.read_b_varchar().await?;
                    let owner = src.read_b_varchar().await?;
                    let collection = src.read_us_varchar().await?;

                    Some(Arc::new(XmlSchema::new(db_name, owner, collection)))
                } else {
                    None
                };

                Ok(TypeInfo::Xml {
                    schema,
                    size: 0xfffffffffffffffe_usize,
                })
            }
            Ok(VarLenType::Udt) => {
                // UDT_INFO, MS-TDS §2.2.5.5.4
                let max_byte_size = src.read_u16_le().await?;
                let db_name = src.read_b_varchar().await?;
                let schema_name = src.read_b_varchar().await?;
                let type_name = src.read_b_varchar().await?;
                let assembly_qualified_name = src.read_us_varchar().await?;

                Ok(TypeInfo::Udt(UdtInfo {
                    max_byte_size,
                    db_name,
                    schema_name,
                    type_name,
                    assembly_qualified_name,
                }))
            }
            Ok(ty) => {
                let len = match ty {
                    #[cfg(feature = "tds73")]
                    VarLenType::Timen | VarLenType::DatetimeOffsetn | VarLenType::Datetime2 => {
                        src.read_u8().await? as usize
                    }
                    #[cfg(feature = "tds73")]
                    VarLenType::Daten => 3,
                    VarLenType::Bitn
                    | VarLenType::Intn
                    | VarLenType::Floatn
                    | VarLenType::Decimaln
                    | VarLenType::Numericn
                    | VarLenType::Guid
                    | VarLenType::Money
                    | VarLenType::Datetimen => src.read_u8().await? as usize,
                    VarLenType::NChar
                    | VarLenType::BigChar
                    | VarLenType::NVarchar
                    | VarLenType::BigVarChar
                    | VarLenType::BigBinary
                    | VarLenType::BigVarBin => src.read_u16_le().await? as usize,
                    VarLenType::Image
                    | VarLenType::Text
                    | VarLenType::NText
                    | VarLenType::SSVariant => src.read_u32_le().await? as usize,
                    _ => todo!("not yet implemented for {:?}", ty),
                };

                let collation = match ty {
                    VarLenType::NText
                    | VarLenType::Text
                    | VarLenType::BigChar
                    | VarLenType::NChar
                    | VarLenType::NVarchar
                    | VarLenType::BigVarChar => {
                        let info = src.read_u32_le().await?;
                        let sort_id = src.read_u8().await?;

                        Some(Collation::new(info, sort_id))
                    }
                    _ => None,
                };

                let vty = match ty {
                    VarLenType::Decimaln | VarLenType::Numericn => {
                        let precision = src.read_u8().await?;
                        let scale = src.read_u8().await?;

                        // Validate the server-supplied precision/scale before they
                        // reach the `assert!(scale <= 38)` guards in `column_data`
                        // and `numeric`. Per MS-TDS §2.2.5.5.1.1, precision is
                        // 1..=38 and scale is 0..=precision. A malicious or
                        // buggy peer sending e.g. scale=39..=255 would otherwise
                        // panic the connection task (remote DoS).
                        if !(1..=38).contains(&precision) {
                            return Err(Error::Protocol(
                                format!(
                                    "invalid decimal/numeric precision {precision}, must be 1..=38"
                                )
                                .into(),
                            ));
                        }

                        if scale > precision {
                            return Err(Error::Protocol(
                                format!(
                                    "invalid decimal/numeric scale {scale}, must be 0..={precision}"
                                )
                                .into(),
                            ));
                        }

                        TypeInfo::VarLenSizedPrecision {
                            size: len,
                            ty,
                            precision,
                            scale,
                        }
                    }
                    _ => {
                        let cx = VarLenContext::new(ty, len, collation);
                        TypeInfo::VarLenSized(cx)
                    }
                };

                Ok(vty)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;

    #[tokio::test]
    async fn round_trip() {
        let types = vec![
            TypeInfo::Xml {
                schema: Some(
                    XmlSchema::new("fake-db-name", "fake-owner", "fake-collection").into(),
                ),
                size: 0xfffffffffffffffe_usize,
            },
            TypeInfo::Xml {
                schema: None,
                size: 0xfffffffffffffffe_usize,
            },
            TypeInfo::FixedLen(FixedLenType::Int4),
            TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::NChar,
                40,
                Some(Collation::new(13632521, 52)),
            )),
            TypeInfo::Udt(UdtInfo {
                max_byte_size: 0xffff,
                db_name: "fake-db".to_string(),
                schema_name: "dbo".to_string(),
                type_name: "geometry".to_string(),
                assembly_qualified_name:
                    "Microsoft.SqlServer.Types.SqlGeometry, Microsoft.SqlServer.Types".to_string(),
            }),
        ];

        for ti in types {
            let mut buf = BytesMut::new();

            ti.clone()
                .encode(&mut buf)
                .expect("encode should be successful");

            let nti = TypeInfo::decode(&mut buf.into_sql_read_bytes())
                .await
                .expect("decode must succeed");

            assert_eq!(nti, ti)
        }
    }

    // Builds the on-wire bytes of a Numericn TYPE_INFO: type byte, length byte,
    // precision byte, scale byte.
    fn numericn_bytes(len: u8, precision: u8, scale: u8) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(VarLenType::Numericn as u8);
        buf.put_u8(len);
        buf.put_u8(precision);
        buf.put_u8(scale);
        buf
    }

    // A server-supplied scale > 38 must decode to an Err, not panic the
    // connection task via the downstream `assert!(scale <= 38)`.
    #[tokio::test]
    async fn decode_numeric_scale_over_max_errors() {
        for scale in [39u8, 255u8] {
            let buf = numericn_bytes(17, 38, scale);
            let err = TypeInfo::decode(&mut buf.into_sql_read_bytes())
                .await
                .expect_err("scale > 38 must be rejected");
            assert!(
                matches!(err, Error::Protocol(_)),
                "scale {scale}: got {err:?}"
            );
        }
    }

    // Precision outside 1..=38 must be rejected.
    #[tokio::test]
    async fn decode_numeric_bad_precision_errors() {
        for precision in [0u8, 39u8, 255u8] {
            let buf = numericn_bytes(17, precision, 0);
            let err = TypeInfo::decode(&mut buf.into_sql_read_bytes())
                .await
                .expect_err("precision outside 1..=38 must be rejected");
            assert!(
                matches!(err, Error::Protocol(_)),
                "precision {precision}: got {err:?}"
            );
        }
    }

    // The scale=38 (precision=38) boundary is still accepted.
    #[tokio::test]
    async fn decode_numeric_scale_at_max_ok() {
        let buf = numericn_bytes(17, 38, 38);
        let ti = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("scale 38 must be accepted");
        assert!(matches!(
            ti,
            TypeInfo::VarLenSizedPrecision {
                precision: 38,
                scale: 38,
                ..
            }
        ));
    }
}
