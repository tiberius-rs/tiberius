use super::BaseMetaDataColumn;
use crate::{tds::codec::ColumnData, Error, SqlReadBytes};

#[derive(Debug)]
#[allow(dead_code)]
pub struct TokenReturnValue {
    pub param_ordinal: u16,
    pub param_name: String,
    /// return value of user defined function
    pub udf: bool,
    pub meta: BaseMetaDataColumn,
    pub value: ColumnData<'static>,
}

impl TokenReturnValue {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let param_ordinal = src.read_u16_le().await?;
        let param_name = src.read_b_varchar().await?;

        let udf = match src.read_u8().await? {
            0x01 => false,
            0x02 => true,
            _ => return Err(Error::Protocol("ReturnValue: invalid status".into())),
        };

        let meta = BaseMetaDataColumn::decode(src).await?;
        let value = ColumnData::decode(src, &meta.ty).await?;

        let token = TokenReturnValue {
            param_ordinal,
            param_name,
            udf,
            meta,
            value,
        };

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use crate::tds::codec::{Encode, FixedLenType, TypeInfo};
    use bytes::{BufMut, BytesMut};

    fn put_b_varchar(buf: &mut BytesMut, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        buf.put_u8(utf16.len() as u8);
        for c in utf16 {
            buf.put_u16_le(c);
        }
    }

    fn build(status: u8) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u16_le(1); // param ordinal
        put_b_varchar(&mut buf, "@out");
        buf.put_u8(status);

        // BaseMetaDataColumn: user_ty, flags, type info
        buf.put_u32_le(0);
        buf.put_u16_le(0);
        TypeInfo::FixedLen(FixedLenType::Int4)
            .encode(&mut buf)
            .unwrap();

        // value payload (i32)
        buf.put_i32_le(42);
        buf
    }

    #[tokio::test]
    async fn decodes_non_udf_value() {
        let token = TokenReturnValue::decode(&mut build(0x01).into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(token.param_ordinal, 1);
        assert_eq!(token.param_name, "@out");
        assert!(!token.udf);
        assert_eq!(token.value, ColumnData::I32(Some(42)));
    }

    #[tokio::test]
    async fn decodes_udf_flag() {
        let token = TokenReturnValue::decode(&mut build(0x02).into_sql_read_bytes())
            .await
            .unwrap();
        assert!(token.udf);
    }

    #[tokio::test]
    async fn invalid_status_errors() {
        let err = TokenReturnValue::decode(&mut build(0x00).into_sql_read_bytes())
            .await
            .expect_err("invalid status must fail");
        assert!(matches!(err, Error::Protocol(_)));
    }
}
