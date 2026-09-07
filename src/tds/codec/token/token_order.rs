use crate::SqlReadBytes;

// The ordered column indexes are decoded and traced at TRACE on receipt but are
// not otherwise consumed; retained for `Debug` diagnostics and future surfacing
// of result ordering to callers.
#[allow(dead_code)]
#[derive(Debug)]
pub struct TokenOrder {
    pub(crate) column_indexes: Vec<u16>,
}

impl TokenOrder {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // `Length` is the byte length of the column-index list; each index is a
        // 2-byte USHORT, so it must be even. An odd length would truncate on the
        // `/ 2` below and leave a stray byte unconsumed, desyncing the stream.
        let raw_len = src.read_u16_le().await?;
        if raw_len % 2 != 0 {
            return Err(crate::Error::Protocol(
                format!("ORDER token length {raw_len} is not a multiple of 2").into(),
            ));
        }
        let len = raw_len / 2;

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

    #[tokio::test]
    async fn rejects_odd_length() {
        // An odd byte length cannot hold a whole number of 2-byte indexes; it
        // must be a protocol error rather than silently truncating and leaving a
        // stray byte on the wire.
        let mut buf = BytesMut::new();
        buf.put_u16_le(3); // odd
        buf.put_u16_le(1);

        let err = TokenOrder::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("odd length must be rejected");

        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    #[tokio::test]
    async fn consumes_exactly_declared_length() {
        // The decoder must read exactly `Length` bytes of index data and stop,
        // leaving anything that follows untouched. A trailing sentinel that
        // reads back cleanly proves the token did not over- or under-consume
        // and so did not desync the stream for the next token.
        let mut buf = BytesMut::new();
        buf.put_u16_le(4); // two u16 indexes
        buf.put_u16_le(10);
        buf.put_u16_le(20);
        buf.put_u16_le(0xBEEF); // sentinel: belongs to the *next* token

        let mut reader = buf.into_sql_read_bytes();
        let order = TokenOrder::decode(&mut reader).await.unwrap();
        assert_eq!(order.column_indexes, vec![10, 20]);

        let sentinel = reader
            .read_u16_le()
            .await
            .expect("the sentinel following the ORDER token must still be readable");
        assert_eq!(
            sentinel, 0xBEEF,
            "decode consumed past its declared length and desynced the stream"
        );
    }

    #[tokio::test]
    async fn rejects_length_longer_than_content() {
        // `Length` claims three indexes (6 bytes) but only one is present. The
        // decoder must surface a clean error when the stream runs out rather
        // than panicking or looping.
        let mut buf = BytesMut::new();
        buf.put_u16_le(6); // three indexes declared
        buf.put_u16_le(1); // only one provided

        let err = TokenOrder::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("a length longer than the content must error");
        // An out-of-data read surfaces as an IO error through the reader.
        assert!(matches!(err, crate::Error::Io { .. }));
    }
}
