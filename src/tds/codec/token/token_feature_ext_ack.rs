use crate::{Error, SqlReadBytes, FEA_EXT_FEDAUTH, FEA_EXT_TERMINATOR};
use futures_util::AsyncReadExt;

#[derive(Debug)]
pub struct TokenFeatureExtAck {
    pub features: Vec<FeatureAck>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum FedAuthAck {
    SecurityToken { nonce: Option<[u8; 32]> },
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum FeatureAck {
    FedAuth(FedAuthAck),
}

impl TokenFeatureExtAck {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let mut features = Vec::new();
        loop {
            let feature_id = src.read_u8().await?;

            if feature_id == FEA_EXT_TERMINATOR {
                break;
            } else if feature_id == FEA_EXT_FEDAUTH {
                let data_len = src.read_u32_le().await?;

                let nonce = if data_len == 32 {
                    let mut n = [0u8; 32];
                    src.read_exact(&mut n).await?;

                    Some(n)
                } else if data_len == 0 {
                    None
                } else {
                    return Err(Error::Protocol(
                        format!(
                            "invalid Feature_Ext_Ack token: invalid data length {}",
                            data_len
                        )
                        .into(),
                    ));
                };

                features.push(FeatureAck::FedAuth(FedAuthAck::SecurityToken { nonce }))
            } else {
                return Err(Error::Protocol(
                    format!("unsupported feature {}", feature_id).into(),
                ));
            }
        }

        Ok(TokenFeatureExtAck { features })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decodes_fedauth_with_nonce() {
        let mut buf = BytesMut::new();
        buf.put_u8(FEA_EXT_FEDAUTH);
        buf.put_u32_le(32);
        buf.extend_from_slice(&[7u8; 32]);
        buf.put_u8(FEA_EXT_TERMINATOR);

        let ack = TokenFeatureExtAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(ack.features.len(), 1);
        match &ack.features[0] {
            FeatureAck::FedAuth(FedAuthAck::SecurityToken { nonce }) => {
                assert_eq!(*nonce, Some([7u8; 32]));
            }
        }
    }

    #[tokio::test]
    async fn decodes_fedauth_without_nonce() {
        let mut buf = BytesMut::new();
        buf.put_u8(FEA_EXT_FEDAUTH);
        buf.put_u32_le(0);
        buf.put_u8(FEA_EXT_TERMINATOR);

        let ack = TokenFeatureExtAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match &ack.features[0] {
            FeatureAck::FedAuth(FedAuthAck::SecurityToken { nonce }) => {
                assert!(nonce.is_none());
            }
        }
    }

    #[tokio::test]
    async fn decode_rejects_invalid_data_length() {
        // A FEDAUTH ack with a data length that is neither 0 nor 32 is invalid.
        let mut buf = BytesMut::new();
        buf.put_u8(FEA_EXT_FEDAUTH);
        buf.put_u32_le(5);
        buf.extend_from_slice(&[0u8; 5]);

        let err = TokenFeatureExtAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("invalid data length must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn decode_rejects_unsupported_feature() {
        // A feature id that is neither the terminator nor FEDAUTH is unsupported.
        let mut buf = BytesMut::new();
        buf.put_u8(0x99);

        let err = TokenFeatureExtAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("unsupported feature must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn empty_feature_list() {
        let mut buf = BytesMut::new();
        buf.put_u8(FEA_EXT_TERMINATOR);

        let ack = TokenFeatureExtAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert!(ack.features.is_empty());
    }
}
