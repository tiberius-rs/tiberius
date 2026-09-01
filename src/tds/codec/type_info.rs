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
            // DATE (0x28) carries NO scale byte in TYPE_INFO (MS-TDS
            // §2.2.5.4.2 / §2.2.5.5.1.2), unlike TIME/DATETIME2/DATETIMEOFFSET
            // which each carry a SCALE byte. The decoder already special-cases
            // this (`Daten => 3`, reading no byte); emitting a byte here would
            // desync every field after a `date` column in a TYPE_INFO stream
            // (bulk-load column metadata / TVP).
            #[cfg(feature = "tds73")]
            VarLenType::Daten => {}
            #[cfg(feature = "tds73")]
            VarLenType::Timen | VarLenType::DatetimeOffsetn | VarLenType::Datetime2 => {
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
            typ => {
                return Err(Error::Protocol(
                    format!("encoding a {typ:?} var-len context is not supported").into(),
                ))
            }
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
        // CLR user-defined type; decoded as raw PLP bytes (see column_data/udt.rs).
        Udt = 0xF0,
        Text = 0x23,
        Image = 0x22,
        NText = 0x63,
        // sql_variant; fully decoded/encoded (see column_data/sql_variant.rs).
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
        // CLR user-defined type; decoded as raw PLP bytes (see column_data/udt.rs).
        Udt = 0xF0,
        Text = 0x23,
        Image = 0x22,
        NText = 0x63,
        // sql_variant; fully decoded/encoded (see column_data/sql_variant.rs).
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
                    _ => {
                        return Err(Error::Protocol(
                            format!("unsupported column type in COLMETADATA: {:?}", ty).into(),
                        ))
                    }
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

                        // MS-TDS: precision is 1..=38 and scale 0..=precision.
                        // Reject out-of-range server values here so downstream
                        // (Numeric decode/Display) never sees an impossible scale.
                        if precision > 38 || scale > precision {
                            return Err(Error::Protocol(
                                format!(
                                    "decimal/numeric: invalid precision {precision} / scale {scale}"
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

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn date_typeinfo_round_trips_without_scale_byte() {
        // DATE (0x28) has no scale byte in TYPE_INFO: encode must emit only the
        // type token, and it must round-trip through decode.
        let ti = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Daten, 3, None));
        let mut buf = BytesMut::new();
        ti.clone().encode(&mut buf).expect("encode must succeed");

        assert_eq!(buf.as_ref(), &[VarLenType::Daten as u8]);

        let nti = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("decode must succeed");
        assert_eq!(nti, ti);
    }

    #[tokio::test]
    async fn decode_rejects_out_of_range_precision_scale() {
        // Decimaln TYPE_INFO: [type][size][precision][scale]. A precision > 38
        // from an untrusted server must be rejected rather than flowing into
        // Numeric decoding (which would later panic on an impossible scale).
        let mut buf = BytesMut::new();
        buf.put_u8(VarLenType::Decimaln as u8);
        buf.put_u8(17); // size
        buf.put_u8(200); // precision (invalid, > 38)
        buf.put_u8(2); // scale

        let err = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("out-of-range precision must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn var_len_context_is_empty() {
        assert!(VarLenContext::new(VarLenType::Intn, 0, None).is_empty());
        assert!(!VarLenContext::new(VarLenType::Intn, 4, None).is_empty());
    }

    #[tokio::test]
    async fn decode_intn_reads_one_byte_length() {
        // Covers the Bitn|Intn|Floatn|... match arm: the length is a single u8.
        let mut buf = BytesMut::new();
        buf.put_u8(VarLenType::Intn as u8);
        buf.put_u8(4); // length in bytes

        let ti = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("decode must succeed");
        assert_eq!(
            ti,
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None))
        );
    }

    #[cfg(feature = "tds73")]
    #[tokio::test]
    async fn decode_timen_reads_one_byte_scale() {
        // Covers the Timen|DatetimeOffsetn|Datetime2 match arm: reads a u8 scale
        // as the length. Deleting the arm would make this an error.
        let mut buf = BytesMut::new();
        buf.put_u8(VarLenType::Timen as u8);
        buf.put_u8(7); // scale

        let ti = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("decode must succeed");
        assert_eq!(
            ti,
            TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Timen, 7, None))
        );
    }

    #[tokio::test]
    async fn decode_accepts_precision_38_and_scale_below_precision() {
        // Boundary: precision == 38 is the maximum valid precision and must be
        // accepted; scale (10) is below precision.
        let mut buf = BytesMut::new();
        buf.put_u8(VarLenType::Decimaln as u8);
        buf.put_u8(17); // size
        buf.put_u8(38); // precision (max valid)
        buf.put_u8(10); // scale

        let ti = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("precision 38 must be accepted");
        assert_eq!(
            ti,
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Decimaln,
                size: 17,
                precision: 38,
                scale: 10,
            }
        );
    }

    #[tokio::test]
    async fn decode_accepts_scale_equal_to_precision() {
        // Boundary: scale == precision is valid (scale may equal precision).
        let mut buf = BytesMut::new();
        buf.put_u8(VarLenType::Numericn as u8);
        buf.put_u8(17); // size
        buf.put_u8(20); // precision
        buf.put_u8(20); // scale == precision

        let ti = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("scale == precision must be accepted");
        assert_eq!(
            ti,
            TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: 17,
                precision: 20,
                scale: 20,
            }
        );
    }

    #[test]
    fn var_len_context_encode_xml_emits_only_type_byte() {
        // Xml in a VarLenContext carries no length bytes: encode must emit only
        // the type token (the `VarLenType::Xml => ()` arm).
        let mut buf = BytesMut::new();
        VarLenContext::new(VarLenType::Xml, 0, None)
            .encode(&mut buf)
            .expect("encode must succeed");
        assert_eq!(buf.as_ref(), &[VarLenType::Xml as u8]);
    }

    #[test]
    fn var_len_context_encode_unsupported_type_errors() {
        // Udt is not encodable through VarLenContext (it has its own TypeInfo
        // arm), so it hits the `typ => Err(..)` fallback.
        let mut buf = BytesMut::new();
        let err = VarLenContext::new(VarLenType::Udt, 0, None)
            .encode(&mut buf)
            .expect_err("encoding a Udt var-len context must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn decode_rejects_invalid_type_byte() {
        // A leading byte that is neither a FixedLenType nor a VarLenType must be
        // rejected (`Err(())` arm of the VarLenType match).
        let mut buf = BytesMut::new();
        buf.put_u8(0x00);

        let err = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("invalid type byte must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn decode_udt_info_round_trips() {
        // Exercises the UDT_INFO decode arm: max_byte_size + three b_varchars +
        // a us_varchar assembly-qualified name.
        let ti = TypeInfo::Udt(UdtInfo {
            max_byte_size: 0xffff,
            db_name: "db".to_string(),
            schema_name: "dbo".to_string(),
            type_name: "geometry".to_string(),
            assembly_qualified_name: "asm".to_string(),
        });

        let mut buf = BytesMut::new();
        ti.clone().encode(&mut buf).expect("encode must succeed");

        let decoded = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("decode must succeed");
        assert_eq!(decoded, ti);
    }

    #[tokio::test]
    async fn decode_rejects_scale_greater_than_precision() {
        // scale > precision must be rejected.
        let mut buf = BytesMut::new();
        buf.put_u8(VarLenType::Decimaln as u8);
        buf.put_u8(17); // size
        buf.put_u8(10); // precision
        buf.put_u8(20); // scale > precision

        let err = TypeInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("scale > precision must error");
        assert!(matches!(err, Error::Protocol(_)));
    }
}
