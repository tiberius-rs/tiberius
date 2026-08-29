use std::borrow::BorrowMut;

use asynchronous_codec::BytesMut;
use bytes::BufMut;

use crate::ColumnData;

use super::{BytesMutWithTypeInfo, Encode, FixedLenType, MetaDataColumn, TypeInfo, VarLenContext};

const TVPTYPE: u8 = 0xF3;

/// A table-valued parameter (TVP), as described by section 2.2.5.5.5 of MS-TDS.
///
/// A TVP is passed to a stored procedure as an `RpcParam` and carries both the
/// column metadata (optionally resolved from the server) and the data rows.
#[derive(Debug)]
pub struct TypeInfoTvp<'a> {
    schema_name: &'a str,
    db_type_name: &'a str,
    columns: Option<Vec<MetaDataColumn<'a>>>,
    data: Vec<Vec<ColumnData<'a>>>,
}

impl<'a> Encode<BytesMut> for TypeInfoTvp<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        // TVPTYPE        =   %xF3
        // TVP_TYPE_INFO  =   TVPTYPE
        //                    TVP_TYPENAME
        //                    TVP_COLMETADATA
        //                    [TVP_ORDER_UNIQUE]
        //                    [TVP_COLUMN_ORDERING]
        //                    TVP_END_TOKEN

        dst.put_u8(TVPTYPE);
        put_b_varchar("", dst); // DB name (unused)
        put_b_varchar(self.schema_name, dst);
        put_b_varchar(self.db_type_name, dst);

        if let Some(ref columns_metadata) = self.columns {
            dst.put_u16_le(columns_metadata.len() as u16);
            for col in columns_metadata {
                // TvpColumnMetaData = UserType
                //                     Flags
                //                     TYPE_INFO
                //                     ColName
                dst.put_u32_le(0_u32); // UserType
                col.base.clone().encode(dst)?; // Flags + TYPE_INFO
                                               // 2.2.5.5.5.1: ColName MUST be a zero-length string in the TVP.
                put_b_varchar("", dst);
            }
        } else {
            // TVP_NULL_TOKEN: the server is expected to know the type.
            dst.put_u16_le(0xFFFF_u16);
        }

        dst.put_u8(0_u8); // end of TVP_COLMETADATA / optional metadata

        // TVP_ROW_TOKEN = %x01 ; A row as defined by TVP_COLMETADATA follows
        // TvpColumnData = TYPE_VARBYTE ; Actual value must match column metadata
        // AllColumnData = *TvpColumnData
        // TVP_ROW       = TVP_ROW_TOKEN AllColumnData
        for row in self.data.into_iter() {
            dst.put_u8(0x01u8); // TVP_ROW_TOKEN
            for (i, col) in row.into_iter().enumerate() {
                let mut dst_ti = BytesMutWithTypeInfo::new(dst);
                if let Some(ref metadata) = self.columns {
                    dst_ti = dst_ti.with_type_info(&metadata[i].base.ty);
                }
                col.encode(&mut dst_ti)?;
            }
        }

        dst.put_u8(0_u8); // TVP_END_TOKEN

        Ok(())
    }
}

/// Writes a `B_VARCHAR`: a single-byte code-unit count followed by that many
/// UTF-16 code units.
fn put_b_varchar<T: AsRef<str>>(s: T, dst: &mut BytesMut) {
    let len_pos = dst.len();
    dst.put_u8(0u8);
    let mut length = 0_u8;

    for chr in s.as_ref().encode_utf16() {
        dst.put_u16_le(chr);
        length += 1;
    }
    let dst: &mut [u8] = dst.borrow_mut();
    dst[len_pos] = length;
}

impl<'a> TypeInfoTvp<'a> {
    /// Creates a new TVP for the given database type name and data rows. The
    /// type name may be qualified with a schema (e.g. `dbo.MyType`).
    pub fn new(type_name: &'a str, rows: Vec<Vec<ColumnData<'a>>>) -> TypeInfoTvp<'a> {
        let (schema_name, db_type_name) = if let Some((s, t)) = type_name.split_once('.') {
            (s, t)
        } else {
            ("", type_name)
        };
        TypeInfoTvp {
            schema_name,
            db_type_name,
            columns: None,
            data: rows,
        }
    }

    /// Attaches column metadata resolved from the server. Fixed-length column
    /// types are rewritten to their nullable variable-length equivalents, as
    /// required for TVP column metadata (2.2.5.5.5.3).
    pub fn with_metadata(self, metadata: Vec<MetaDataColumn<'a>>) -> TypeInfoTvp<'a> {
        let mut metadata = metadata;
        for mdc in metadata.iter_mut() {
            let ty_replace = match mdc.base.ty {
                TypeInfo::FixedLen(ref ty) => fixed_to_var_len(*ty),
                _ => None,
            };
            if let Some(ty) = ty_replace {
                mdc.base.ty = ty;
            }
        }
        TypeInfoTvp {
            columns: Some(metadata),
            ..self
        }
    }
}

/// Maps a fixed-length column type to the nullable variable-length equivalent
/// that must be used in TVP column metadata.
fn fixed_to_var_len(ty: FixedLenType) -> Option<TypeInfo> {
    use super::VarLenType;

    let ctx = match ty {
        FixedLenType::Int1 => VarLenContext::new(VarLenType::Intn, 1, None),
        FixedLenType::Bit => VarLenContext::new(VarLenType::Bitn, 1, None),
        FixedLenType::Int2 => VarLenContext::new(VarLenType::Intn, 2, None),
        FixedLenType::Int4 => VarLenContext::new(VarLenType::Intn, 4, None),
        FixedLenType::Datetime4 => VarLenContext::new(VarLenType::Datetimen, 4, None),
        FixedLenType::Float4 => VarLenContext::new(VarLenType::Floatn, 4, None),
        FixedLenType::Money => VarLenContext::new(VarLenType::Money, 8, None),
        FixedLenType::Datetime => VarLenContext::new(VarLenType::Datetimen, 8, None),
        FixedLenType::Float8 => VarLenContext::new(VarLenType::Floatn, 8, None),
        FixedLenType::Money4 => VarLenContext::new(VarLenType::Money, 4, None),
        FixedLenType::Int8 => VarLenContext::new(VarLenType::Intn, 8, None),
        _ => return None,
    };
    Some(TypeInfo::VarLenSized(ctx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_schema_qualified_type_name() {
        let tvp = TypeInfoTvp::new("dbo.MyType", Vec::new());
        assert_eq!(tvp.schema_name, "dbo");
        assert_eq!(tvp.db_type_name, "MyType");
    }

    #[test]
    fn unqualified_type_name_has_empty_schema() {
        let tvp = TypeInfoTvp::new("MyType", Vec::new());
        assert_eq!(tvp.schema_name, "");
        assert_eq!(tvp.db_type_name, "MyType");
    }

    #[test]
    fn encodes_tvp_header_and_null_metadata() {
        let tvp = TypeInfoTvp::new("dbo.MyType", Vec::new());
        let mut buf = BytesMut::new();
        tvp.encode(&mut buf).unwrap();

        // TVPTYPE marker.
        assert_eq!(buf[0], TVPTYPE);
        // DB name is a zero-length B_VARCHAR.
        assert_eq!(buf[1], 0);
        // Schema name "dbo": length 3 followed by 3 UTF-16 code units.
        assert_eq!(buf[2], 3);

        // With no metadata, the column count must be the TVP_NULL_TOKEN.
        // Layout: F3, 00 (db), 03 + 6 bytes (schema), 06 + 12 bytes (type),
        // then the u16 null token.
        let null_token_pos = 1 + 1 + (1 + 6) + (1 + 12);
        let token = u16::from_le_bytes([buf[null_token_pos], buf[null_token_pos + 1]]);
        assert_eq!(token, 0xFFFF);
    }

    #[test]
    fn rewrites_fixed_len_to_nullable_var_len() {
        use super::super::VarLenType;
        assert!(matches!(
            fixed_to_var_len(FixedLenType::Int4),
            Some(TypeInfo::VarLenSized(ctx)) if ctx.r#type() == VarLenType::Intn
        ));
        assert!(matches!(
            fixed_to_var_len(FixedLenType::Bit),
            Some(TypeInfo::VarLenSized(ctx)) if ctx.r#type() == VarLenType::Bitn
        ));
        assert!(fixed_to_var_len(FixedLenType::Null).is_none());
    }
}
