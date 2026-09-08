use crate::SqlReadBytes;

#[allow(dead_code)] // we might want to debug the values
#[derive(Debug)]
pub struct TokenOrder {
    pub(crate) column_indexes: Vec<u16>,
}

impl TokenOrder {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u16_le().await? / 2;

        // `len` is derived from an untrusted u16; cap the up-front reservation
        // (the Vec still grows as indexes are actually read).
        let mut column_indexes =
            Vec::with_capacity((len as usize).min(crate::tds::codec::column_data::MAX_PREALLOC));

        for _ in 0..len {
            column_indexes.push(src.read_u16_le().await?);
        }

        Ok(TokenOrder { column_indexes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decodes_column_indexes() {
        let mut buf = BytesMut::new();
        // length is in bytes; three u16 indexes => 6 bytes
        buf.put_u16_le(6);
        buf.put_u16_le(1);
        buf.put_u16_le(2);
        buf.put_u16_le(3);

        let order = TokenOrder::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(order.column_indexes, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn decodes_empty() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0);

        let order = TokenOrder::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert!(order.column_indexes.is_empty());
    }
}
