use crate::{sql_read_bytes::SqlReadBytes, tds::codec::Encode};
use bytes::BytesMut;
use futures_util::io::AsyncReadExt;

#[derive(Debug)]
pub struct TokenSspi(Vec<u8>);

impl AsRef<[u8]> for TokenSspi {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TokenSspi {
    #[cfg(any(
        windows,
        all(unix, any(feature = "integrated-auth-gssapi", feature = "sspi-rs"))
    ))]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) async fn decode_async<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // `len` is bounded by the u16 length field (<= 64 KiB), so no named
        // allocation cap is required here.
        let len = src.read_u16_le().await? as usize;
        let mut bytes = vec![0; len];
        src.read_exact(&mut bytes[0..len]).await?;

        Ok(Self(bytes))
    }
}

impl Encode<BytesMut> for TokenSspi {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.extend(self.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use crate::Error;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decode_reads_declared_bytes() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(4); // declared length
        buf.put_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let token = TokenSspi::decode_async(&mut buf.into_sql_read_bytes())
            .await
            .expect("must decode");

        assert_eq!(token.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[tokio::test]
    async fn decode_truncated_body_is_clean_error() {
        // Declared length is 8 but only 2 bytes follow: the `read_exact` must
        // surface a clean IO/EOF error rather than panic.
        let mut buf = BytesMut::new();
        buf.put_u16_le(8); // declared length
        buf.put_slice(&[0x01, 0x02]); // short body

        let err = TokenSspi::decode_async(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("truncated body must error");

        assert!(matches!(err, Error::Io { .. }));
    }
}
