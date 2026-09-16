use std::{borrow::Cow, sync::Arc};

use crate::{
    sql_read_bytes::SqlReadBytes,
    xml::{XmlData, XmlSchema},
    ColumnData, VarLenType,
};

pub(crate) async fn decode<R>(
    src: &mut R,
    len: usize,
    schema: Option<Arc<XmlSchema>>,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let xml = super::string::decode(src, VarLenType::Xml, len, None)
        .await?
        .map(|data| {
            let mut data = XmlData::new(data);

            if let Some(schema) = schema {
                data.set_schema(schema);
            }

            Cow::Owned(data)
        });

    Ok(ColumnData::Xml(xml))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    // A fixed-size PLP length of 0xffff marks a NULL value.
    #[tokio::test]
    async fn decode_null_xml() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0xffff);

        let data = decode(&mut buf.into_sql_read_bytes(), 8, None)
            .await
            .unwrap();
        assert_eq!(data, ColumnData::Xml(None));
    }

    #[tokio::test]
    async fn decode_present_xml() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(4); // 2 UTF-16 code units => 4 bytes
        buf.put_u16_le('h' as u16);
        buf.put_u16_le('i' as u16);

        let data = decode(&mut buf.into_sql_read_bytes(), 8, None)
            .await
            .unwrap();

        match data {
            ColumnData::Xml(Some(xml)) => assert_eq!(xml.to_string(), "hi"),
            other => panic!("expected present XML, got {other:?}"),
        }
    }
}
