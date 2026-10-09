#![cfg(not(feature = "aws-lc"))]

use tiberius::{error::Error, Client, Config, EncryptionLevel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_util::compat::TokioAsyncReadCompatExt;

// Separate test binary: installing a provider in installed.rs cannot affect this.
#[tokio::test]
async fn missing_provider_is_a_tls_error_on_both_tds_paths() {
    assert!(CryptoProvider::get_default().is_none());
    for encryption in [
        EncryptionLevel::Strict,
        EncryptionLevel::Required,
        EncryptionLevel::Off,
    ] {
        let mut config = Config::new();
        config.encryption(encryption);
        let (client, mut server) = tokio::io::duplex(4096);
        let peer = async {
            if encryption != EncryptionLevel::Strict {
                let mut header = [0; 8];
                server.read_exact(&mut header).await.unwrap();
                let len = u16::from_be_bytes([header[2], header[3]]) as usize;
                server.read_exact(&mut vec![0; len - 8]).await.unwrap();
                // TDS response containing only ENCRYPTION (offset 6, length 1).
                // Off/Off still performs TLS for login; Required negotiates full TLS.
                let level = if encryption == EncryptionLevel::Off {
                    0
                } else {
                    1
                };
                server
                    .write_all(&[4, 1, 0, 15, 0, 0, 1, 0, 1, 0, 6, 0, 1, 0xff, level])
                    .await
                    .unwrap();
            }
        };
        let (result, ()) = tokio::join!(Client::connect(config, client.compat()), peer);
        assert!(
            matches!(result, Err(Error::Tls(ref message))
                if message.contains("no process-installed rustls CryptoProvider")
                    && message.contains("CryptoProvider::install_default()")),
            "expected missing-provider error for {encryption:?}, got: {result:?}"
        );
    }
    assert!(CryptoProvider::get_default().is_none());
}
