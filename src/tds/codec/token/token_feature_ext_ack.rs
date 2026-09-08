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
    use bytes::BytesMut;

    #[tokio::test]
    async fn invalid_fedauth_data_length_is_protocol_error() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[FEA_EXT_FEDAUTH]);
        // A data length that is neither 0 (no nonce) nor 32 (nonce) bytes.
        buf.extend_from_slice(&5u32.to_le_bytes());

        let reader = &mut buf.into_sql_read_bytes();
        let err = TokenFeatureExtAck::decode(reader).await.unwrap_err();

        match err {
            Error::Protocol(msg) => {
                assert!(msg.to_string().contains("invalid data length"));
            }
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unsupported_feature_id_is_protocol_error() {
        let mut buf = BytesMut::new();
        // Neither the terminator nor the fedauth feature id.
        buf.extend_from_slice(&[0x01u8]);

        let reader = &mut buf.into_sql_read_bytes();
        let err = TokenFeatureExtAck::decode(reader).await.unwrap_err();

        match err {
            Error::Protocol(msg) => {
                assert!(msg.to_string().contains("unsupported feature"));
            }
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }
}
