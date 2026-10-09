use std::sync::Arc;
use tiberius::{Client, Config, EncryptionLevel};
use tokio::io::AsyncReadExt;
use tokio_rustls::{
    rustls::{
        self,
        crypto::CryptoProvider,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig, SupportedProtocolVersion,
    },
    TlsAcceptor,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

pub fn rsa_provider(mut provider: CryptoProvider) -> CryptoProvider {
    // The repository's server certificate has an RSA key.
    provider.cipher_suites.retain(|suite| {
        suite.version() == &rustls::version::TLS13
            || matches!(
                suite.suite(),
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            )
    });
    provider
}

pub async fn handshake(
    provider: CryptoProvider,
    version: &'static SupportedProtocolVersion,
    expected_suite: rustls::CipherSuite,
) {
    let chain =
        CertificateDer::pem_slice_iter(include_bytes!("../../../../docker/certs/server-full.crt"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../../../docker/certs/server.key"))
        .unwrap();
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    server_config.ignore_client_order = true;
    server_config.alpn_protocols = vec![b"tds/8.0".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut config = Config::new();
    config.host("localhost");
    config.encryption(EncryptionLevel::Strict);
    config.trust_cert_ca_bundle(include_bytes!("../../../../docker/certs/customCA.crt"));
    let (client, server) = tokio::io::duplex(4096);
    let peer = async {
        let mut tls = acceptor.accept(server).await.unwrap();
        assert_eq!(
            tls.get_ref().1.negotiated_cipher_suite().unwrap().suite(),
            expected_suite
        );
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"tds/8.0".as_slice()));
        // Verified TLS completed; the client has moved on to TDS prelogin.
        let mut header = [0; 8];
        tls.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x12);
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(Client::connect(config, client.compat()), peer)
    })
    .await
    .expect("in-memory TLS handshake must finish");
    // The fixture intentionally stops after TLS, without emulating a database.
    assert!(result.is_err());
}
