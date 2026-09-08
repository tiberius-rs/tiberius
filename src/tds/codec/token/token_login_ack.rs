use crate::{Error, FeatureLevel, SqlReadBytes};
use std::convert::TryFrom;

#[allow(dead_code)] // we might want to debug the values
#[derive(Debug)]
pub struct TokenLoginAck {
    /// The type of interface with which the server will accept client requests
    /// 0: SQL_DFLT (server confirms that whatever is sent by the client is acceptable. If the client
    ///    requested SQL_DFLT, SQL_TSQL will be used)
    /// 1: SQL_TSQL (TSQL is accepted)
    pub(crate) interface: u8,
    pub(crate) tds_version: FeatureLevel,
    pub(crate) prog_name: String,
    /// major.minor.buildhigh.buildlow
    pub(crate) version: u32,
}

impl TokenLoginAck {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let _length = src.read_u16_le().await?;

        let interface = src.read_u8().await?;

        let tds_version = FeatureLevel::try_from(src.read_u32().await?)
            .map_err(|_| Error::Protocol("Login ACK: Invalid TDS version".into()))?;

        let prog_name = src.read_b_varchar().await?;
        let version = src.read_u32_le().await?;

        Ok(TokenLoginAck {
            interface,
            tds_version,
            prog_name,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    fn put_b_varchar(buf: &mut BytesMut, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        buf.put_u8(utf16.len() as u8);
        for c in utf16 {
            buf.put_u16_le(c);
        }
    }

    #[tokio::test]
    async fn decodes_valid_ack() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0); // length, ignored
        buf.put_u8(1); // interface
        buf.put_u32(FeatureLevel::SqlServerN as u32); // big-endian tds version
        put_b_varchar(&mut buf, "Microsoft SQL Server");
        buf.put_u32_le(0x0F00_0FA0); // version

        let ack = TokenLoginAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(ack.interface, 1);
        assert_eq!(ack.tds_version, FeatureLevel::SqlServerN);
        assert_eq!(ack.prog_name, "Microsoft SQL Server");
        assert_eq!(ack.version, 0x0F00_0FA0);
    }

    #[tokio::test]
    async fn invalid_tds_version_errors() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0);
        buf.put_u8(1);
        buf.put_u32(0xDEAD_BEEF); // not a valid FeatureLevel

        let err = TokenLoginAck::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("must fail on invalid version");

        assert!(matches!(err, Error::Protocol(_)));
    }
}
