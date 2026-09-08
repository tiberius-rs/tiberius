use crate::{sql_read_bytes::SqlReadBytes, tds::codec::VarLenContext, ColumnData, VarLenType};

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
        // A VarLenType with no decode arm here is either a type the server must
        // not send in a ROW (e.g. Xml/Udt are handled elsewhere) or one we do
        // not model. Return a protocol error rather than `unimplemented!()`,
        // which would panic the connection task on server-controlled input.
        t => {
            return Err(crate::Error::Protocol(
                format!(
                    "unsupported variable-length column type in row data: {:?}",
                    t
                )
                .into(),
            ))
        }
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    // A VarLenType with no decode arm (here Udt) must surface a protocol error
    // rather than panic via `unimplemented!()` on server-controlled input.
    #[tokio::test]
    async fn unsupported_var_len_type_errors_not_panics() {
        let ctx = VarLenContext::new(VarLenType::Udt, 0, None);
        let mut reader = BytesMut::new().into_sql_read_bytes();

        let err = decode(&mut reader, &ctx)
            .await
            .expect_err("an unsupported var-len type must error");
        assert!(matches!(err, crate::Error::Protocol(_)), "got {err:?}");
    }
}
