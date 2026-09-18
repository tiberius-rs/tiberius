use super::certs;
use crate::{
    client::{
        config::{ClientCertSource, ClientCertificate, Config, RootSource},
        TrustConfig,
    },
    error::IoErrorKind,
    Error,
};
use futures_util::io::{AsyncRead, AsyncWrite};
use std::{
    fs, io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio_rustls::{
    rustls::{
        client::{
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            WantsClientCert,
        },
        crypto::{aws_lc_rs, CryptoProvider},
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        ClientConfig, ConfigBuilder, DigitallySignedStruct, Error as RustlsError, RootCertStore,
        SignatureScheme,
    },
    TlsConnector,
};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{event, Level};

impl From<tokio_rustls::rustls::Error> for Error {
    fn from(e: tokio_rustls::rustls::Error) -> Self {
        crate::Error::Tls(e.to_string())
    }
}

pub(crate) struct TlsStream<S: AsyncRead + AsyncWrite + Unpin + Send>(
    Compat<tokio_rustls::client::TlsStream<Compat<S>>>,
);

#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Advertised only; the trust bypass stubs verification to always succeed.
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn get_server_name(config: &Config) -> crate::Result<ServerName<'static>> {
    match (
        ServerName::try_from(config.get_hostname_in_certificate()),
        config.trust.bypass,
    ) {
        (Ok(sn), _) => Ok(sn.to_owned()),
        // Under the trust bypass the certificate (and thus its name) is not
        // validated, so the SNI value is irrelevant; use a syntactically-valid
        // placeholder when the configured hostname can't be parsed as a
        // `ServerName`. The literal is a valid DNS name, so
        // `try_from(...).unwrap()` cannot panic.
        (Err(_), true) => Ok(ServerName::try_from("placeholder.domain.com").unwrap()),
        (Err(e), false) => Err(crate::Error::Tls(e.to_string())),
    }
}

/// Translate a TLS-handshake failure into an actionable [`crate::Error`].
///
/// `tokio-rustls` surfaces handshake failures as [`io::Error`]s that wrap the
/// underlying [`RustlsError`]. When that inner error is a *certificate
/// validation* failure (e.g. `UnsupportedCertVersion` from an older or
/// non-conformant SQL Server certificate), the raw
/// message ("invalid peer certificate ... UnsupportedCertVersion") is opaque
/// and never names the fix. This maps such failures to an [`Error::Tls`] that
/// spells out the remedies, while leaving every other I/O error untouched (it
/// still flows through `From<io::Error>` as an [`Error::Io`]).
///
/// The message is only added for genuine certificate-validation failures under
/// a *validating* trust config; the trust bypass (`trust_cert`) already
/// short-circuits certificate checks in [`NoCertVerifier`], so a cert error
/// cannot originate there.
fn map_handshake_error(err: io::Error, trust: &TrustConfig) -> crate::Error {
    // Only certificate-*validation* failures get the extra guidance. Under the
    // trust bypass the verifier never rejects a cert, so any error there is
    // genuinely transport-level and should pass through unchanged.
    if !trust.bypass {
        if let Some(RustlsError::InvalidCertificate(cert_err)) =
            err.get_ref().and_then(|e| e.downcast_ref::<RustlsError>())
        {
            // `UnsupportedCertVersion` is the specific symptom. In
            // this rustls version it arrives from webpki wrapped in
            // `CertificateError::Other(..)` rather than as a named variant, so
            // detect it from the rendered message. The same remedies apply to
            // any validation rejection of a legacy/self-signed server cert.
            let rendered = cert_err.to_string();
            let hint = if rendered.contains("UnsupportedCertVersion") {
                " The SQL Server presented a certificate rustls considers too \
                 old (an outdated X.509 version), which frequently happens with \
                 the self-signed certificate SQL Server auto-generates."
            } else {
                ""
            };

            return Error::Tls(format!(
                "the server's certificate was rejected during the TLS handshake: {cert_err}.{hint} \
                 To connect anyway you can: (1) trust a specific CA certificate with \
                 `Config::trust_cert_ca(path)`, or an in-memory CA bundle with \
                 `Config::trust_cert_ca_bundle(bytes)`; (2) if the OS trust store is unusable, \
                 base trust on the bundled Mozilla roots with `Config::trust_webpki_roots()` \
                 (requires the `rustls-webpki-roots` feature); (3) skip certificate validation \
                 entirely with `Config::trust_cert()` (accepts any certificate and also disables \
                 hostname verification — only safe on a trusted network); or (4) build tiberius \
                 with the `native-tls` backend, which is more lenient toward legacy certificates. \
                 Note: SQL Server always performs a TLS handshake during login even when \
                 `Encrypt=false`, so this can occur regardless of the encryption setting."
            ));
        }
    }

    Error::from(err)
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsStream<S> {
    pub(super) async fn new(config: &Config, stream: S) -> crate::Result<Self> {
        event!(Level::DEBUG, "Performing a TLS handshake");

        let provider = resolve_crypto_provider(CryptoProvider::get_default().cloned());

        // Negotiate the best available protocol version (TLS 1.2 or 1.3), the
        // same policy as upstream's previous `with_safe_defaults()`.
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| crate::Error::Tls(e.to_string()))?;

        // First select the server-certificate verification strategy, yielding a
        // builder that still awaits the client-authentication decision.
        let cc_builder: ConfigBuilder<ClientConfig, WantsClientCert> = if config.trust.bypass {
            event!(
                Level::WARN,
                "Trusting the server certificate without validation."
            );
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        } else {
            // Build the root store from the configured base source plus any
            // accumulated extra CAs, then validate against it.
            let store = build_trust_store(&config.trust)?;
            builder.with_root_certificates(store)
        };

        // Present a client certificate (mutual TLS / TDS 8.0
        // `ENCRYPT_CLIENT_CERT`) if one was configured, otherwise finalize
        // without client authentication.
        let mut client_config = match config.get_client_certificate() {
            Some(cert) => {
                event!(
                    Level::DEBUG,
                    "Presenting a client certificate for mutual TLS."
                );
                let (chain, key) = load_client_auth(cert)?;
                cc_builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| crate::Error::Tls(e.to_string()))?
            }
            None => cc_builder.with_no_client_auth(),
        };

        // TDS 8.0 "strict" mode advertises the `tds/8.0` ALPN protocol so the
        // server knows to speak TDS directly over the TLS stream.
        if matches!(config.encryption, crate::EncryptionLevel::Strict) {
            client_config
                .alpn_protocols
                .push(super::TDS_ALPN_PROTOCOL_NAME.as_bytes().to_vec());
        }

        let connector = TlsConnector::from(Arc::new(client_config));

        let tls_stream = connector
            .connect(get_server_name(config)?, stream.compat())
            .await
            .map_err(|e| map_handshake_error(e, &config.trust))?;

        Ok(TlsStream(tls_stream.compat()))
    }

    pub(crate) fn get_mut(&mut self) -> &mut S {
        self.0.get_mut().get_mut().0.get_mut()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let inner = Pin::get_mut(self);
        Pin::new(&mut inner.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = Pin::get_mut(self);
        Pin::new(&mut inner.0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = Pin::get_mut(self);
        Pin::new(&mut inner.0).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = Pin::get_mut(self);
        Pin::new(&mut inner.0).poll_close(cx)
    }
}

/// Resolve the rustls `CryptoProvider`: honour a process-installed default
/// (`CryptoProvider::install_default`) if present, otherwise fall back to
/// aws-lc-rs.
fn resolve_crypto_provider(installed: Option<Arc<CryptoProvider>>) -> Arc<CryptoProvider> {
    match installed {
        Some(provider) => {
            event!(
                Level::DEBUG,
                "Using process-installed rustls CryptoProvider"
            );
            provider
        }
        None => {
            event!(
                Level::DEBUG,
                "No process-installed CryptoProvider; using the aws-lc-rs default"
            );
            Arc::new(aws_lc_rs::default_provider())
        }
    }
}

/// Load the OS trust store's certificates into `roots`, returning
/// `(added, had_load_errors)`.
fn load_native_roots_into(roots: &mut RootCertStore) -> (usize, bool) {
    let native = rustls_native_certs::load_native_certs();
    let had_load_errors = !native.errors.is_empty();
    if had_load_errors {
        event!(
            Level::DEBUG,
            "loading platform certificates reported errors: {:?}",
            native.errors
        );
    }
    let mut added = 0;
    for cert in native.certs {
        match roots.add(cert) {
            Ok(_) => added += 1,
            Err(err) => {
                event!(
                    Level::DEBUG,
                    "skipping invalid platform certificate: {:?}",
                    err
                )
            }
        }
    }
    (added, had_load_errors)
}

/// Build the root-certificate store for a validating [`TrustConfig`]: the base
/// trust anchors (the OS store, or the bundled Mozilla roots) **plus** every
/// accumulated extra CA.
///
/// Fail-closed invariant: when there are no extra CAs, an empty base
/// store is fatal — `Native` with an unusable OS store fails to connect rather
/// than trusting nothing. When extra CAs *are* supplied they provide trust on
/// their own, so an empty/best-effort base is tolerated (matching the additive
/// `trust_cert_ca` contract). Every extra source must yield at least one usable
/// certificate (enforced in [`certs::trust_anchors`]).
fn build_trust_store(trust: &TrustConfig) -> crate::Result<RootCertStore> {
    let mut store = RootCertStore::empty();

    // Base trust anchors from the configured source.
    let (base_added, base_had_errors) = match &trust.source {
        RootSource::Native => {
            let (added, had_errors) = load_native_roots_into(&mut store);
            event!(Level::TRACE, "native trust store added {added} certs");
            (added, had_errors)
        }
        #[cfg(feature = "rustls-webpki-roots")]
        RootSource::WebpkiRoots => {
            let before = store.roots.len();
            store
                .roots
                .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let added = store.roots.len() - before;
            event!(Level::TRACE, "webpki-roots added {added} certs");
            (added, false)
        }
    };

    // Layer the accumulated extra CAs on top. A DER blob that parses as bytes
    // but is not a valid certificate is rejected by `store.add`; name the
    // offending source so the failure is as actionable as the read/parse/zero
    // errors from `certs::trust_anchors`.
    for extra in &trust.extra_cas {
        for cert in certs::trust_anchors(extra)? {
            store
                .add(cert)
                .map_err(|e| certs::invalid_cert_error(extra, e))?;
        }
    }

    // Fail closed only when nothing else provides trust.
    ensure_base_or_extra(base_added, base_had_errors, !trust.extra_cas.is_empty())?;

    Ok(store)
}

/// Fail-closed decision for a validating trust store: with no extra
/// CAs, an empty base store is fatal — `Native` with an unusable OS store must
/// fail to connect rather than silently trust nothing. When extra CAs *are*
/// present they provide trust on their own, so a best-effort/empty base is
/// tolerated. Factored out so the invariant is unit-testable without needing to
/// simulate an empty OS trust store.
fn ensure_base_or_extra(
    base_added: usize,
    base_had_errors: bool,
    has_extras: bool,
) -> crate::Result<()> {
    if base_added == 0 && !has_extras {
        return Err(crate::Error::Io {
            kind: IoErrorKind::NotFound,
            message: if base_had_errors {
                "could not load platform certificates".to_string()
            } else {
                "no usable CA certificates found in the platform trust store".to_string()
            },
        });
    }
    Ok(())
}

/// Read a private-key file, dispatching on the extension: `pem`/`key` parse as
/// PEM (PKCS#8, PKCS#1 or SEC1), `der` as DER (PKCS#8). Mirrors `certs::certs_from_file`
/// and preserves the underlying I/O error in the message.
fn read_private_key(path: &Path) -> crate::Result<PrivateKeyDer<'static>> {
    let buf = fs::read(path).map_err(|e| crate::Error::Io {
        kind: IoErrorKind::InvalidData,
        message: format!("Could not read private key {}: {e}", path.to_string_lossy()),
    })?;

    match path.extension() {
        Some(ext) if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("key") => {
            PrivateKeyDer::from_pem_slice(&buf).map_err(|e| crate::Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!("Failed to parse PEM private key {}: {e}", path.to_string_lossy()),
            })
        }
        Some(ext) if ext.eq_ignore_ascii_case("der") => {
            PrivateKeyDer::try_from(buf).map_err(|e| crate::Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!("Failed to parse DER private key {}: {e}", path.to_string_lossy()),
            })
        }
        Some(_) | None => Err(crate::Error::Io {
            kind: IoErrorKind::InvalidInput,
            message: format!(
                "Private key {} has an unsupported file-extension! Supported types are pem, key and der.",
                path.to_string_lossy()
            ),
        }),
    }
}

/// Loads a client certificate chain and private key from the configured source
/// for use with rustls' `with_client_auth_cert`.
fn load_client_auth(
    cert: &ClientCertificate,
) -> crate::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match &cert.source {
        ClientCertSource::CertAndKey { cert, key } => {
            // Certificate chain: PEM (possibly multiple) or a single DER cert.
            let chain = certs::certs_from_file(cert)?;

            if chain.is_empty() {
                return Err(crate::Error::Io {
                    kind: IoErrorKind::InvalidInput,
                    message: format!(
                        "Client certificate file {} contains no certificates",
                        cert.to_string_lossy()
                    ),
                });
            }

            let key = read_private_key(key)?;

            Ok((chain, key))
        }
        #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
        ClientCertSource::Pkcs12 { .. } => Err(crate::Error::Tls(
            "The rustls backend does not support PKCS#12 client certificates; \
             supply separate PEM/DER certificate and key files via \
             `Config::client_certificate` instead."
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::config::{ClientCertSource, ClientCertificate, Config};
    use std::path::PathBuf;
    use tokio_rustls::rustls::CertificateError;

    use crate::client::config::ExtraCa;
    #[cfg(feature = "rustls-webpki-roots")]
    use crate::client::config::RootSource;

    fn make_config(host: Option<&str>, cert_host: Option<&str>, trust: TrustConfig) -> Config {
        let mut c = Config::new();
        c.trust = trust;
        if let Some(h) = host {
            c.host = Some(h.to_string());
        }
        if let Some(hc) = cert_host {
            c.hostname_in_certificate = Some(hc.to_string());
        }
        c
    }

    /// The validating default trust config (OS store, no extras, no bypass).
    fn default_trust() -> TrustConfig {
        TrustConfig::default()
    }

    /// The trust-everything bypass (`trust_cert`).
    fn bypass_trust() -> TrustConfig {
        TrustConfig {
            bypass: true,
            ..TrustConfig::default()
        }
    }

    /// Native source plus a single extra CA file.
    fn ca_file_trust(path: &str) -> TrustConfig {
        TrustConfig {
            extra_cas: vec![ExtraCa::File(PathBuf::from(path))],
            ..TrustConfig::default()
        }
    }

    #[test]
    fn resolve_crypto_provider_honours_installed() {
        let installed = Arc::new(aws_lc_rs::default_provider());
        let got = resolve_crypto_provider(Some(installed.clone()));
        assert!(
            Arc::ptr_eq(&got, &installed),
            "an installed CryptoProvider must be used as-is"
        );
    }

    #[test]
    fn resolve_crypto_provider_falls_back_to_aws_lc_rs() {
        let got = resolve_crypto_provider(None);
        assert!(
            !got.cipher_suites.is_empty(),
            "the aws-lc-rs fallback must provide cipher suites"
        );
    }

    #[test]
    fn server_name_valid_host_is_ok() {
        let c = make_config(Some("localhost"), None, default_trust());
        assert!(get_server_name(&c).is_ok());
    }

    #[test]
    fn server_name_invalid_host_bypass_uses_placeholder() {
        let c = make_config(None, Some("inv al id"), bypass_trust());
        let got = get_server_name(&c).expect("the bypass must fall back to the placeholder SNI");
        assert!(format!("{got:?}").contains("placeholder.domain.com"));
    }

    #[test]
    fn server_name_invalid_host_validating_errors() {
        let c = make_config(None, Some("inv al id"), default_trust());
        assert!(get_server_name(&c).is_err());
    }

    #[test]
    fn build_trust_store_augments_system_roots_with_custom_ca() {
        // Independently measure this machine's native root count using the same
        // loader `build_trust_store` uses, so the comparison holds on any host.
        let mut native_only = RootCertStore::empty();
        let (native, _) = load_native_roots_into(&mut native_only);

        let store = build_trust_store(&ca_file_trust("docker/certs/customCA.crt")).unwrap();

        // Custom CA must augment, not replace, the system roots (native + 1).
        assert_eq!(
            store.len(),
            native + 1,
            "custom CA must augment the system trust store, not replace it"
        );
    }

    #[test]
    fn build_trust_store_accepts_multi_cert_ca_file() {
        // The pre-0.13 single-certificate restriction is relaxed: every cert in
        // a multi-cert CA file is trusted.
        let mut native_only = RootCertStore::empty();
        let (native, _) = load_native_roots_into(&mut native_only);

        let n_certs = certs::certs_from_file(Path::new("docker/certs/server-full.crt"))
            .unwrap()
            .len();
        assert!(n_certs >= 2);

        let store = build_trust_store(&ca_file_trust("docker/certs/server-full.crt")).unwrap();
        assert_eq!(
            store.len(),
            native + n_certs,
            "all certs in a multi-cert CA file must be added"
        );
    }

    #[test]
    fn build_trust_store_accumulates_multiple_extra_cas() {
        // Accumulate semantics at the store level: two extra CAs => both added.
        let mut native_only = RootCertStore::empty();
        let (native, _) = load_native_roots_into(&mut native_only);

        let trust = TrustConfig {
            extra_cas: vec![
                ExtraCa::File(PathBuf::from("docker/certs/customCA.crt")),
                ExtraCa::Bundle(std::fs::read("docker/certs/customCA.crt").unwrap()),
            ],
            ..TrustConfig::default()
        };
        let store = build_trust_store(&trust).unwrap();
        assert_eq!(
            store.len(),
            native + 2,
            "both accumulated extra CAs must be trusted"
        );
    }

    #[test]
    fn build_trust_store_propagates_zero_cert_extra_ca_error() {
        // An extra CA that yields zero usable certs is fatal, naming it.
        let mut path = std::env::temp_dir();
        path.push(format!("tiberius_bts_zero_{}.pem", std::process::id()));
        std::fs::write(&path, b"# no certificates here\n").unwrap();
        let trust = TrustConfig {
            extra_cas: vec![ExtraCa::File(path.clone())],
            ..TrustConfig::default()
        };
        let err = build_trust_store(&trust);
        std::fs::remove_file(&path).ok();
        let msg = format!("{:?}", err.unwrap_err());
        assert!(
            msg.contains("contained no usable certificates"),
            "error should name the empty source, got: {msg}"
        );
    }

    #[test]
    fn build_trust_store_names_source_on_invalid_der_cert() {
        // A DER extra-CA whose bytes are not a valid certificate must fail with a
        // message naming the offending source, not an anonymous backend error.
        let trust = TrustConfig {
            extra_cas: vec![ExtraCa::Bundle(vec![0x30, 0x03, 0x02, 0x01, 0x7f])],
            ..TrustConfig::default()
        };
        let msg = format!("{:?}", build_trust_store(&trust).unwrap_err());
        assert!(
            msg.contains("in-memory CA bundle") && msg.contains("invalid certificate"),
            "invalid DER must name the source, got: {msg}"
        );
    }

    #[test]
    fn ensure_base_or_extra_enforces_fail_closed_rule7() {
        // Fail-closed empty-base behaviour, tested directly (an empty OS store can't be simulated in-process):
        // no base + no extras => fail closed, with the message distinguishing a
        // load error from a genuinely empty store.
        let empty_store = ensure_base_or_extra(0, false, false).unwrap_err();
        assert!(
            format!("{empty_store:?}").contains("no usable CA certificates found"),
            "empty store must fail closed, got: {empty_store:?}"
        );
        let load_err = ensure_base_or_extra(0, true, false).unwrap_err();
        assert!(
            format!("{load_err:?}").contains("could not load platform certificates"),
            "load failure must be reported distinctly, got: {load_err:?}"
        );
        // Extras present => tolerate an empty/best-effort base (additive contract).
        assert!(ensure_base_or_extra(0, true, true).is_ok());
        assert!(ensure_base_or_extra(0, false, true).is_ok());
        // A non-empty base is always fine.
        assert!(ensure_base_or_extra(5, false, false).is_ok());
    }

    #[cfg(feature = "rustls-webpki-roots")]
    #[test]
    fn build_trust_store_uses_bundled_webpki_roots() {
        // The webpki source seeds a non-empty store from the compiled-in Mozilla
        // snapshot, independent of the OS trust store.
        let trust = TrustConfig {
            source: RootSource::WebpkiRoots,
            ..TrustConfig::default()
        };
        let store = build_trust_store(&trust).unwrap();
        assert_eq!(
            store.len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "the store must be seeded from the bundled Mozilla roots"
        );
        assert!(!store.is_empty());
    }

    #[cfg(feature = "rustls-webpki-roots")]
    #[test]
    fn build_trust_store_webpki_roots_plus_extra_ca() {
        // Extras still layer on top of the webpki source.
        let base = webpki_roots::TLS_SERVER_ROOTS.len();
        let trust = TrustConfig {
            source: RootSource::WebpkiRoots,
            extra_cas: vec![ExtraCa::File(PathBuf::from("docker/certs/customCA.crt"))],
            ..TrustConfig::default()
        };
        let store = build_trust_store(&trust).unwrap();
        assert_eq!(store.len(), base + 1);
    }

    #[test]
    fn load_client_auth_reads_pem_cert_and_key() {
        let cert = ClientCertificate {
            source: ClientCertSource::CertAndKey {
                cert: PathBuf::from("docker/certs/server.crt"),
                key: PathBuf::from("docker/certs/server.key"),
            },
        };
        let (chain, _key) = load_client_auth(&cert).expect("valid PEM cert + key");
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn load_client_auth_missing_cert_errors() {
        let cert = ClientCertificate {
            source: ClientCertSource::CertAndKey {
                cert: PathBuf::from("docker/certs/does-not-exist.crt"),
                key: PathBuf::from("docker/certs/server.key"),
            },
        };
        assert!(load_client_auth(&cert).is_err());
    }

    #[test]
    fn read_private_key_missing_file_preserves_io_error() {
        let err = read_private_key(Path::new("docker/certs/does-not-exist.key")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Could not read private key"),
            "error should name the read failure, got: {msg}"
        );
    }

    #[test]
    fn read_private_key_reads_pem() {
        let key = read_private_key(Path::new("docker/certs/server.key")).unwrap();
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn read_private_key_reads_der() {
        // No .der fixture is checked in, so derive one from the PEM key and write
        // it to a temp file to exercise the `der` branch.
        let der = read_private_key(Path::new("docker/certs/server.key"))
            .unwrap()
            .secret_der()
            .to_vec();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tiberius_read_private_key_{}.der",
            std::process::id()
        ));
        std::fs::write(&path, &der).unwrap();
        let key = read_private_key(&path);
        std::fs::remove_file(&path).ok();
        assert!(!key.unwrap().secret_der().is_empty());
    }

    #[test]
    fn read_private_key_unsupported_extension_errors() {
        // README.md exists under docker/certs but isn't a supported key type.
        let err = read_private_key(Path::new("docker/certs/README.md")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unsupported file-extension"),
            "error should name the unsupported extension, got: {msg}"
        );
    }

    #[test]
    fn read_private_key_malformed_pem_errors() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tiberius_read_private_key_malformed_{}.pem",
            std::process::id()
        ));
        std::fs::write(
            &path,
            b"-----BEGIN PRIVATE KEY-----\nnot valid base64!!!\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let err = read_private_key(&path);
        std::fs::remove_file(&path).ok();
        let msg = format!("{:?}", err.unwrap_err());
        assert!(
            msg.contains("Failed to parse PEM private key"),
            "error should name the parse failure, got: {msg}"
        );
    }

    fn cert_io_error(cert_err: CertificateError) -> io::Error {
        // Mirror how tokio-rustls wraps a rustls handshake failure: the
        // `RustlsError` is carried as the inner error of an `io::Error`.
        io::Error::new(
            io::ErrorKind::InvalidData,
            RustlsError::InvalidCertificate(cert_err),
        )
    }

    /// Reproduce the exact shape of the failure: webpki's `UnsupportedCertVersion`
    /// reaches rustls as `CertificateError::Other(..)` whose message contains the
    /// string "UnsupportedCertVersion".
    fn unsupported_cert_version_error() -> CertificateError {
        use tokio_rustls::rustls::OtherError;

        // `CertificateError`'s `Display` renders the `Other` variant via `{:?}`
        // (Debug), so — matching real webpki, whose `UnsupportedCertVersion`
        // Debugs to exactly that string — the fake must Debug to the same text.
        struct WebpkiLike;
        impl std::fmt::Debug for WebpkiLike {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("UnsupportedCertVersion")
            }
        }
        impl std::fmt::Display for WebpkiLike {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("UnsupportedCertVersion")
            }
        }
        impl std::error::Error for WebpkiLike {}

        CertificateError::Other(OtherError(Arc::new(WebpkiLike)))
    }

    #[test]
    fn map_handshake_error_annotates_unsupported_cert_version() {
        let err = map_handshake_error(
            cert_io_error(unsupported_cert_version_error()),
            &default_trust(),
        );
        let msg = format!("{err}");
        // Must be a TLS error (not the opaque Io variant) and name each remedy.
        assert!(
            matches!(err, Error::Tls(_)),
            "expected Error::Tls, got: {msg}"
        );
        assert!(
            msg.contains("trust_cert_ca"),
            "should mention trust_cert_ca: {msg}"
        );
        assert!(
            msg.contains("trust_cert()"),
            "should mention trust_cert: {msg}"
        );
        assert!(
            msg.contains("native-tls"),
            "should mention native-tls backend: {msg}"
        );
        assert!(
            msg.contains("Encrypt=false"),
            "should explain the handshake still happens: {msg}"
        );
        // Version-specific hint present for this variant.
        assert!(
            msg.contains("outdated X.509 version"),
            "should add version hint: {msg}"
        );
    }

    #[test]
    fn map_handshake_error_annotates_other_cert_errors_without_version_hint() {
        let err = map_handshake_error(
            cert_io_error(CertificateError::NotValidForName),
            &default_trust(),
        );
        let msg = format!("{err}");
        assert!(
            matches!(err, Error::Tls(_)),
            "expected Error::Tls, got: {msg}"
        );
        assert!(
            msg.contains("trust_cert_ca"),
            "should mention remedies: {msg}"
        );
        // The version-specific hint is only for UnsupportedCertVersion.
        assert!(
            !msg.contains("outdated X.509 version"),
            "no version hint here: {msg}"
        );
    }

    #[test]
    fn map_handshake_error_passes_through_non_cert_io_errors() {
        let err = map_handshake_error(
            io::Error::new(io::ErrorKind::UnexpectedEof, "connection reset"),
            &default_trust(),
        );
        // Non-certificate transport failures keep the generic Io mapping.
        match err {
            Error::Io { kind, message } => {
                assert_eq!(kind, io::ErrorKind::UnexpectedEof);
                assert!(message.contains("connection reset"), "got: {message}");
            }
            other => panic!("expected Error::Io, got: {other:?}"),
        }
    }

    #[test]
    fn map_handshake_error_passes_through_non_certificate_rustls_errors() {
        // A rustls error that is *not* a certificate-validation failure (e.g. a
        // transport/decrypt error) must keep the generic Io mapping — the cert
        // remedies would be misleading for it.
        let inner = RustlsError::General("handshake alert".to_string());
        let err = map_handshake_error(
            io::Error::new(io::ErrorKind::InvalidData, inner),
            &default_trust(),
        );
        assert!(
            matches!(err, Error::Io { .. }),
            "non-certificate rustls errors must pass through as Io, got: {err:?}"
        );
    }

    #[test]
    fn no_cert_verifier_accepts_any_certificate_when_opted_in() {
        // `trust_cert` (TrustAll) installs `NoCertVerifier`, which must accept a
        // well-formed certificate that does NOT chain to any trusted root — this
        // is the explicit opt-in bypass. This is the very same
        // certificate the default verifier rejects in
        // `default_verifier_rejects_untrusted_certificate` below, so the pair
        // proves the bypass is opt-in rather than the default.
        let leaf = certs::certs_from_file(Path::new("docker/certs/server.crt")).unwrap();
        let leaf = leaf.into_iter().next().unwrap();
        let verifier = NoCertVerifier;
        let name = ServerName::try_from("legacy.sql.example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
                .is_ok(),
            "TrustAll must accept an untrusted server certificate"
        );
    }

    #[test]
    fn default_verifier_rejects_untrusted_certificate() {
        // Security-preserving invariant: with no explicit opt-in, a *well-formed*
        // certificate that does not chain to a trusted root MUST be rejected with
        // a genuine trust-chain failure (`UnknownIssuer`) — not merely a DER-parse
        // error. `NoCertVerifier` accepts this exact certificate under `trust_cert`
        // (see `no_cert_verifier_accepts_any_certificate_when_opted_in`), so this
        // proves the bypass is opt-in, not the default.
        //
        // `server.crt` is a well-formed leaf issued by `customCA`. Build a trust
        // store that does NOT contain `customCA` (it trusts an unrelated anchor),
        // so the leaf's real issuer is untrusted and path building must fail — this
        // exercises chain-of-trust enforcement, which a malformed blob would never
        // reach (it would be rejected at DER parsing instead).
        let leaf = certs::certs_from_file(Path::new("docker/certs/server.crt")).unwrap();
        let leaf = leaf.into_iter().next().unwrap();

        let mut roots = RootCertStore::empty();
        // Trust an unrelated anchor; `customCA` (the actual issuer of `leaf`) is
        // deliberately absent, so `leaf` cannot chain to anything trusted.
        roots.add(leaf.clone()).unwrap();

        let provider = Arc::new(aws_lc_rs::default_provider());
        let verifier = tokio_rustls::rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            provider,
        )
        .build()
        .expect("verifier builds over a non-empty root store");

        let name = ServerName::try_from("localhost").unwrap();
        // Pin verification time inside `server.crt`'s validity window
        // (notBefore 2026-05-11, notAfter 2027-11-02). webpki checks certificate
        // validity *before* issuer matching, so using the wall clock would make
        // this assertion flip from `UnknownIssuer` to `Expired` once the fixture
        // expires — a spurious failure unrelated to any code change. 2027-01-15.
        let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000));
        let result = verifier.verify_server_cert(&leaf, &[], &name, &[], at);
        assert!(
            matches!(
                result,
                Err(RustlsError::InvalidCertificate(
                    CertificateError::UnknownIssuer
                ))
            ),
            "the default verifier MUST reject a cert that does not chain to a trusted \
             root with UnknownIssuer (a real trust failure, not a parse error), got: {result:?}"
        );
    }

    #[test]
    fn map_handshake_error_trustall_does_not_annotate() {
        // Under TrustAll the verifier never rejects a cert, so even a cert-shaped
        // error must pass through unchanged rather than gaining misleading advice.
        let err = map_handshake_error(
            cert_io_error(unsupported_cert_version_error()),
            &bypass_trust(),
        );
        assert!(
            matches!(err, Error::Io { .. }),
            "TrustAll must not rewrite the error into TLS guidance"
        );
    }

    #[test]
    fn map_handshake_error_trustall_passes_through_non_cert_io_errors() {
        // Under TrustAll a plain transport error must also pass through as Io,
        // preserving kind and message (the cert-detection block is skipped
        // wholesale, regardless of the error's shape).
        let err = map_handshake_error(
            io::Error::new(io::ErrorKind::ConnectionReset, "reset by peer"),
            &bypass_trust(),
        );
        match err {
            Error::Io { kind, message } => {
                assert_eq!(kind, io::ErrorKind::ConnectionReset);
                assert!(message.contains("reset by peer"), "got: {message}");
            }
            other => panic!("expected Error::Io, got: {other:?}"),
        }
    }

    #[test]
    fn supported_verify_schemes_are_stable() {
        let schemes = NoCertVerifier.supported_verify_schemes();
        assert_eq!(schemes.len(), 11);
        assert!(schemes.contains(&SignatureScheme::ED25519));
    }
}
