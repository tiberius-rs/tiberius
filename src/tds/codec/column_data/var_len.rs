use crate::{
    sql_read_bytes::SqlReadBytes, tds::codec::VarLenContext, ColumnData, Error, VarLenType,
};

pub(crate) async fn decode<R>(
    src: &mut R,
    ctx: &VarLenContext,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    use VarLenType::*;

    let ty = ctx.r#type();
    let len = ctx.len();
    let collation = ctx.collation();

    let res = match ty {
        Bitn => super::bit::decode(src).await?,
        Intn => super::int::decode(src, len).await?,
        Floatn => super::float::decode(src, len).await?,
        Guid => super::guid::decode(src).await?,
        BigChar | BigVarChar | NChar | NVarchar => {
            ColumnData::String(super::string::decode(src, ty, len, collation).await?)
        }
        Money => {
            let len = src.read_u8().await?;
            super::money::decode(src, len).await?
        }
        Datetimen => {
            let rlen = src.read_u8().await?;
            super::datetimen::decode(src, rlen, len as u8).await?
        }
        #[cfg(feature = "tds73")]
        Daten => super::date::decode(src).await?,
        #[cfg(feature = "tds73")]
        Timen => super::time::decode(src, len).await?,
        #[cfg(feature = "tds73")]
        Datetime2 => super::datetime2::decode(src, len).await?,
        #[cfg(feature = "tds73")]
        DatetimeOffsetn => super::datetimeoffsetn::decode(src, len).await?,
        BigBinary | BigVarBin => super::binary::decode(src, len).await?,
        Text => super::text::decode(src, collation).await?,
        NText => super::text::decode(src, None).await?,
        Image => super::image::decode(src).await?,
        SSVariant => super::sql_variant::decode(src).await?,
        t => {
            return Err(Error::Protocol(
                format!("unsupported column type: {:?}", t).into(),
            ))
        }
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decode_bitn_true() {
        let mut buf = BytesMut::new();
        buf.put_u8(1); // recv_len
        buf.put_u8(1); // true

        let ctx = VarLenContext::new(VarLenType::Bitn, 1, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::Bit(Some(true)));
    }

    #[tokio::test]
    async fn decode_intn_null() {
        let mut buf = BytesMut::new();
        buf.put_u8(0); // recv_len 0 -> null

        let ctx = VarLenContext::new(VarLenType::Intn, 4, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::I32(None));
    }

    #[tokio::test]
    async fn decode_guid_null() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);

        let ctx = VarLenContext::new(VarLenType::Guid, 16, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::Guid(None));
    }

    #[tokio::test]
    async fn decode_nvarchar_value() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(4); // 4 bytes of UTF-16
        buf.put_u16_le('a' as u16);
        buf.put_u16_le('b' as u16);

        let ctx = VarLenContext::new(VarLenType::NVarchar, 100, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::String(Some("ab".into())));
    }

    #[tokio::test]
    async fn decode_money_null() {
        let mut buf = BytesMut::new();
        buf.put_u8(0); // len byte read inside decode()

        let ctx = VarLenContext::new(VarLenType::Money, 8, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::F64(None));
    }

    #[tokio::test]
    async fn decode_datetimen_null_smalldatetime() {
        let mut buf = BytesMut::new();
        buf.put_u8(0); // rlen == 0

        let ctx = VarLenContext::new(VarLenType::Datetimen, 4, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::SmallDateTime(None));
    }

    #[tokio::test]
    async fn decode_text_null() {
        let mut buf = BytesMut::new();
        buf.put_u8(0); // ptr_len 0 -> null

        let ctx = VarLenContext::new(VarLenType::Text, 0, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::String(None));
    }

    #[tokio::test]
    async fn decode_ntext_null() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);

        let ctx = VarLenContext::new(VarLenType::NText, 0, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::String(None));
    }

    #[tokio::test]
    async fn decode_image_null() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);

        let ctx = VarLenContext::new(VarLenType::Image, 0, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::Binary(None));
    }

    #[tokio::test]
    async fn decode_ssvariant_null() {
        let mut buf = BytesMut::new();
        buf.put_u32_le(0); // total_len 0 -> null

        let ctx = VarLenContext::new(VarLenType::SSVariant, 0, None);
        let data = decode(&mut buf.into_sql_read_bytes(), &ctx).await.unwrap();
        assert_eq!(data, ColumnData::String(None));
    }

    #[tokio::test]
    async fn decode_unsupported_type_errors() {
        let buf = BytesMut::new();

        let ctx = VarLenContext::new(VarLenType::Udt, 0, None);
        let err = decode(&mut buf.into_sql_read_bytes(), &ctx)
            .await
            .unwrap_err();
        assert!(format!("{}", err).contains("unsupported column type"));
    }
}
