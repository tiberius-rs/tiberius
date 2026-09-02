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
        (Err(_), TrustConfig::TrustAll) => {
            Ok(ServerName::try_from("placeholder.domain.com").unwrap())
        }
        (Err(e), _) => Err(crate::Error::Tls(e.to_string())),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsStream<S> {
    pub(super) async fn new(config: &Config, stream: S) -> crate::Result<Self> {
        event!(Level::DEBUG, "Performing a TLS handshake");

        // Honor a process-wide CryptoProvider if the application installed one
        // (via `CryptoProvider::install_default`), otherwise fall back to
        // aws-lc-rs. This lets callers choose their own backend (e.g. ring or a
        // FIPS provider) instead of being forced onto aws-lc-rs.
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(aws_lc_rs::default_provider()));

        // Negotiate the best available protocol version (TLS 1.2 or 1.3), the
        // same policy as upstream's previous `with_safe_defaults()`.
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| crate::Error::Tls(e.to_string()))?;

        // First select the server-certificate verification strategy, yielding a
        // builder that still awaits the client-authentication decision.
        let cc_builder: ConfigBuilder<ClientConfig, WantsClientCert> = match &config.trust {
            TrustConfig::CaCertificateLocation(path) => {
                if let Ok(buf) = fs::read(path) {
                    let cert = match path.extension() {
                        Some(ext)
                            if ext.eq_ignore_ascii_case("pem")
                                || ext.eq_ignore_ascii_case("crt") =>
                        {
                            let pem_certs = CertificateDer::pem_slice_iter(&buf)
                                .collect::<Result<Vec<CertificateDer<'static>>, _>>()
                                .map_err(|e| crate::Error::Io {
                                    kind: IoErrorKind::InvalidData,
                                    message: format!(
                                        "Failed to parse PEM certificate: {e}"
                                    ),
                                })?;
                            if pem_certs.len() != 1 {
                                return Err(crate::Error::Io {
                                    kind: IoErrorKind::InvalidInput,
                                    message: format!(
                                        "Certificate file {} contain 0 or more than 1 certs",
                                        path.to_string_lossy()
                                    ),
                                });
                            }

                            pem_certs.into_iter().next().unwrap()
                        }
                        Some(ext)
                            if ext.eq_ignore_ascii_case("der") =>
                        {
                            CertificateDer::from(buf)
                        }
                        Some(_) | None => {
                            return Err(crate::Error::Io {
                                kind: IoErrorKind::InvalidInput,
                                message: "Provided CA certificate with unsupported file-extension! Supported types are pem, crt and der.".to_string(),
                            })
                        }
                    };
                    let mut cert_store = RootCertStore::empty();
                    cert_store.add(cert)?;
                    builder.with_root_certificates(cert_store)
                } else {
                    return Err(Error::Io {
                        kind: IoErrorKind::InvalidData,
                        message: "Could not read provided CA certificate!".to_string(),
                    });
                }
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

/// Loads a client certificate chain and private key from the configured source
/// for use with rustls' `with_client_auth_cert`.
fn load_client_auth(
    cert: &ClientCertificate,
) -> crate::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match &cert.source {
        ClientCertSource::CertAndKey { cert, key } => {
            let cert_buf = fs::read(cert).map_err(|e| crate::Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!(
                    "Could not read client certificate {}: {e}",
                    cert.to_string_lossy()
                ),
            })?;

            // Certificate: PEM (possibly a chain) or a single DER cert.
            let chain: Vec<CertificateDer<'static>> = match cert.extension() {
                Some(ext) if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("crt") => {
                    CertificateDer::pem_slice_iter(&cert_buf)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| crate::Error::Io {
                            kind: IoErrorKind::InvalidData,
                            message: format!("Failed to parse PEM client certificate: {e}"),
                        })?
                }
                Some(ext) if ext.eq_ignore_ascii_case("der") => {
                    vec![CertificateDer::from(cert_buf)]
                }
                Some(_) | None => {
                    return Err(crate::Error::Io {
                        kind: IoErrorKind::InvalidInput,
                        message: "Client certificate has an unsupported file-extension! Supported types are pem, crt and der.".to_string(),
                    })
                }
            };

            if chain.is_empty() {
                return Err(crate::Error::Io {
                    kind: IoErrorKind::InvalidInput,
                    message: format!(
                        "Client certificate file {} contains no certificates",
                        cert.to_string_lossy()
                    ),
                });
            }

            // Private key: PEM (any of PKCS#8, PKCS#1 or SEC1) or DER (PKCS#8).
            let key_buf = fs::read(key).map_err(|e| crate::Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!(
                    "Could not read client private key {}: {e}",
                    key.to_string_lossy()
                ),
            })?;

            let key: PrivateKeyDer<'static> = match key.extension() {
                Some(ext)
                    if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("key") =>
                {
                    PrivateKeyDer::from_pem_slice(&key_buf).map_err(|e| crate::Error::Io {
                        kind: IoErrorKind::InvalidData,
                        message: format!("Failed to parse PEM private key: {e}"),
                    })?
                }
                Some(ext) if ext.eq_ignore_ascii_case("der") => PrivateKeyDer::try_from(key_buf)
                    .map_err(|e| crate::Error::Io {
                        kind: IoErrorKind::InvalidData,
                        message: format!("Failed to parse DER private key: {e}"),
                    })?,
                Some(_) | None => {
                    return Err(crate::Error::Io {
                        kind: IoErrorKind::InvalidInput,
                        message: "Client private key has an unsupported file-extension! Supported types are pem, key and der.".to_string(),
                    })
                }
            };

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
        let mut roots = RootCertStore::empty();
        let mut valid_count = 0;
        let mut invalid_count = 0;

        let native_certs = rustls_native_certs::load_native_certs();
        for err in native_certs.errors {
            event!(
                Level::DEBUG,
                "failed to load a native root certificate: {err}"
            );
        }

        for cert in native_certs.certs {
            match roots.add(cert) {
                Ok(_) => valid_count += 1,
                Err(err) => {
                    event!(Level::DEBUG, "certificate parsing failed: {:?}", err);
                    invalid_count += 1
                }
            }
        }
        event!(
            Level::TRACE,
            "with_native_roots processed {} valid and {} invalid certs",
            valid_count,
            invalid_count
        );

        if roots.is_empty() {
            return Err(crate::Error::Io {
                kind: IoErrorKind::NotFound,
                message: "no usable CA certificates found in the platform trust store".to_string(),
            });
        }

        Ok(self.with_root_certificates(roots))
    }
}
