#![cfg(any(
    feature = "ring",
    feature = "aws-lc",
    feature = "openssl",
    feature = "symcrypt"
))]

mod support;

use tokio_rustls::rustls::{self, crypto::CryptoProvider};

// Run with one provider feature at a time.
fn provider() -> CryptoProvider {
    #[cfg(feature = "ring")]
    return rustls::crypto::ring::default_provider();
    #[cfg(feature = "aws-lc")]
    return rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "openssl")]
    return rustls_openssl::default_provider();
    #[cfg(feature = "symcrypt")]
    return rustls_symcrypt::default_symcrypt_provider();
}

#[tokio::test]
async fn installed_provider_controls_the_actual_tls_handshake() {
    assert!(CryptoProvider::get_default().is_none());
    let mut selected = support::rsa_provider(provider());
    let suites: Vec<_> = [&rustls::version::TLS12, &rustls::version::TLS13]
        .into_iter()
        .map(|version| {
            let available: Vec<_> = selected
                .cipher_suites
                .iter()
                .filter(|suite| suite.version() == version)
                .copied()
                .collect();
            assert!(
                available.len() > 1,
                "fixture needs a distinguishable provider policy"
            );
            *available.last().unwrap()
        })
        .collect();
    // Server prefers its first suite; only an honored client provider forces
    // negotiation of its last suite instead of the backend's defaults.
    selected.cipher_suites = suites.clone();
    selected.install_default().expect("fresh test process");
    for (version, suite) in [&rustls::version::TLS12, &rustls::version::TLS13]
        .into_iter()
        .zip(suites)
    {
        support::handshake(provider(), version, suite.suite()).await;
    }
}
