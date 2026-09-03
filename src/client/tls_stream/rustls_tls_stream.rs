use crate::{
    client::{
        config::{ClientCertSource, ClientCertificate, Config},
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
        SignatureScheme, WantsVerifier,
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
        // Advertised only; TrustAll stubs verification to always succeed.
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
        &config.trust,
    ) {
        (Ok(sn), _) => Ok(sn.to_owned()),
        // Under TrustAll the certificate (and thus its name) is not validated, so
        // the SNI value is irrelevant; use a syntactically-valid placeholder when
        // the configured hostname can't be parsed as a `ServerName`. The literal
        // is a valid DNS name, so `try_from(...).unwrap()` cannot panic.
        (Err(_), TrustConfig::TrustAll) => {
            Ok(ServerName::try_from("placeholder.domain.com").unwrap())
        }
        (Err(e), _) => Err(crate::Error::Tls(e.to_string())),
    }
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
        let cc_builder: ConfigBuilder<ClientConfig, WantsClientCert> = match &config.trust {
            TrustConfig::CaCertificateLocation(path) => {
                // Trust the supplied CA *in addition to* the system trust store
                // (see `build_ca_trust_store`), matching the documented
                // `trust_cert_ca` contract and the native-tls backend.
                let store = build_ca_trust_store(read_cert_chain(path)?, path)?;
                builder.with_root_certificates(store)
            }
            TrustConfig::TrustAll => {
                event!(
                    Level::WARN,
                    "Trusting the server certificate without validation."
                );
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            }
            TrustConfig::Default => {
                event!(Level::DEBUG, "Using default trust configuration.");
                builder.with_native_roots()?
            }
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
            .await?;

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

/// Read a certificate file into a chain of DER certificates, dispatching on the
/// file extension: `pem`/`crt` parse as (possibly multi-cert) PEM, `der` as a
/// single DER certificate. The underlying I/O error is preserved in the message
/// so callers can tell missing-file / permission / parse failures apart.
fn read_cert_chain(path: &Path) -> crate::Result<Vec<CertificateDer<'static>>> {
    let buf = fs::read(path).map_err(|e| crate::Error::Io {
        kind: IoErrorKind::InvalidData,
        message: format!("Could not read certificate {}: {e}", path.to_string_lossy()),
    })?;

    match path.extension() {
        Some(ext) if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("crt") => {
            CertificateDer::pem_slice_iter(&buf)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::Error::Io {
                    kind: IoErrorKind::InvalidData,
                    message: format!(
                        "Failed to parse PEM certificate {}: {e}",
                        path.to_string_lossy()
                    ),
                })
        }
        Some(ext) if ext.eq_ignore_ascii_case("der") => Ok(vec![CertificateDer::from(buf)]),
        Some(_) | None => Err(crate::Error::Io {
            kind: IoErrorKind::InvalidInput,
            message: format!(
                "Certificate {} has an unsupported file-extension! Supported types are pem, crt and der.",
                path.to_string_lossy()
            ),
        }),
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

/// Build the root-certificate store for `TrustConfig::CaCertificateLocation`:
/// the system trust store (best-effort) **plus** the user-supplied CA. Exactly
/// one certificate is expected in `certs`. Augmenting rather than replacing the
/// system roots is what makes `trust_cert_ca` additive, per its docs and the
/// native-tls backend.
fn build_ca_trust_store(
    certs: Vec<CertificateDer<'static>>,
    path: &Path,
) -> crate::Result<RootCertStore> {
    if certs.len() != 1 {
        return Err(crate::Error::Io {
            kind: IoErrorKind::InvalidInput,
            message: format!(
                "CA certificate file {} must contain exactly one certificate, found {}",
                path.to_string_lossy(),
                certs.len()
            ),
        });
    }
    let mut store = RootCertStore::empty();
    load_native_roots_into(&mut store);
    store.add(certs.into_iter().next().unwrap())?;
    Ok(store)
}

/// Read a private-key file, dispatching on the extension: `pem`/`key` parse as
/// PEM (PKCS#8, PKCS#1 or SEC1), `der` as DER (PKCS#8). Mirrors `read_cert_chain`
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
            let chain = read_cert_chain(cert)?;

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

trait ConfigBuilderExt {
    fn with_native_roots(self) -> crate::Result<ConfigBuilder<ClientConfig, WantsClientCert>>;
}

impl ConfigBuilderExt for ConfigBuilder<ClientConfig, WantsVerifier> {
    fn with_native_roots(self) -> crate::Result<ConfigBuilder<ClientConfig, WantsClientCert>> {
        // The default trust path relies solely on the OS store, so — unlike the
        // best-effort CA-augment path — an empty result is fatal (fail closed).
        let mut roots = RootCertStore::empty();
        let (added, had_load_errors) = load_native_roots_into(&mut roots);
        event!(Level::TRACE, "with_native_roots added {added} certs");

        if roots.is_empty() {
            return Err(crate::Error::Io {
                kind: IoErrorKind::NotFound,
                message: if had_load_errors {
                    "could not load platform certificates".to_string()
                } else {
                    "no usable CA certificates found in the platform trust store".to_string()
                },
            });
        }

        Ok(self.with_root_certificates(roots))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::config::{ClientCertSource, ClientCertificate, Config};
    use std::path::PathBuf;

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
        let c = make_config(Some("localhost"), None, TrustConfig::Default);
        assert!(get_server_name(&c).is_ok());
    }

    #[test]
    fn server_name_invalid_host_trust_all_uses_placeholder() {
        let c = make_config(None, Some("inv al id"), TrustConfig::TrustAll);
        let got = get_server_name(&c).expect("TrustAll must fall back to the placeholder SNI");
        assert!(format!("{got:?}").contains("placeholder.domain.com"));
    }

    #[test]
    fn server_name_invalid_host_non_trustall_errors() {
        let c = make_config(None, Some("inv al id"), TrustConfig::Default);
        assert!(get_server_name(&c).is_err());
    }

    #[test]
    fn read_cert_chain_reads_single_pem() {
        let chain = read_cert_chain(Path::new("docker/certs/server.crt")).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn read_cert_chain_reads_multi_pem_chain() {
        let chain = read_cert_chain(Path::new("docker/certs/server-full.crt")).unwrap();
        assert!(
            chain.len() >= 2,
            "server-full.crt is a multi-certificate chain"
        );
    }

    #[test]
    fn read_cert_chain_missing_file_preserves_io_error() {
        let err = read_cert_chain(Path::new("docker/certs/does-not-exist.crt")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Could not read certificate"),
            "error should name the read failure, got: {msg}"
        );
    }

    #[test]
    fn read_cert_chain_unsupported_extension_errors() {
        // README.md exists under docker/certs but isn't a supported cert type.
        assert!(read_cert_chain(Path::new("docker/certs/README.md")).is_err());
    }

    #[test]
    fn read_cert_chain_reads_der() {
        // No .der fixture is checked in, so derive one from the PEM CA and write
        // it to a temp file to exercise the `der` branch.
        let der = read_cert_chain(Path::new("docker/certs/customCA.crt"))
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .as_ref()
            .to_vec();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tiberius_read_cert_chain_{}.der",
            std::process::id()
        ));
        std::fs::write(&path, &der).unwrap();
        let chain = read_cert_chain(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(chain.unwrap().len(), 1);
    }

    #[test]
    fn ca_trust_store_augments_system_roots_with_custom_ca() {
        let certs = read_cert_chain(Path::new("docker/certs/customCA.crt")).unwrap();

        // Independently measure this machine's native root count using the same
        // loader `build_ca_trust_store` uses, so the comparison holds on any host.
        let mut native_only = RootCertStore::empty();
        let (native, _) = load_native_roots_into(&mut native_only);

        let store = build_ca_trust_store(certs, Path::new("docker/certs/customCA.crt")).unwrap();

        // Custom CA must augment, not replace, the system roots (native + 1).
        assert_eq!(
            store.len(),
            native + 1,
            "custom CA must augment the system trust store, not replace it"
        );
    }

    #[test]
    fn build_ca_trust_store_rejects_multi_cert_file() {
        let certs = read_cert_chain(Path::new("docker/certs/server-full.crt")).unwrap();
        assert!(build_ca_trust_store(certs, Path::new("docker/certs/server-full.crt")).is_err());
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
    fn supported_verify_schemes_are_stable() {
        let schemes = NoCertVerifier.supported_verify_schemes();
        assert_eq!(schemes.len(), 11);
        assert!(schemes.contains(&SignatureScheme::ED25519));
    }
}
