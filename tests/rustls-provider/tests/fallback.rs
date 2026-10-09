#![cfg(feature = "aws-lc")]

mod support;

use tokio_rustls::rustls::{
    self,
    crypto::{aws_lc_rs, CryptoProvider},
};

#[tokio::test]
async fn legacy_rustls_works_without_installing_a_provider() {
    assert!(CryptoProvider::get_default().is_none());
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let provider = support::rsa_provider(aws_lc_rs::default_provider());
        let suite = provider
            .cipher_suites
            .iter()
            .find(|suite| suite.version() == version)
            .unwrap()
            .suite();
        support::handshake(provider, version, suite).await;
    }
    assert!(
        CryptoProvider::get_default().is_none(),
        "fallback must remain connection-local"
    );
}
