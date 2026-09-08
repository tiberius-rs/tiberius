use crate::{
    client::{
        config::{ClientCertSource, ClientCertificate, Config},
        TrustConfig,
    },
    error::{Error, IoErrorKind},
};
pub(crate) use async_native_tls::TlsStream;
use async_native_tls::{Certificate, Identity, TlsConnector};
use futures_util::io::{AsyncRead, AsyncWrite};
use std::fs;
use tracing::{event, Level};

/// Loads a client identity from the configured source for `native-tls`.
fn load_identity(cert: &ClientCertificate) -> crate::Result<Identity> {
    match &cert.source {
        ClientCertSource::CertAndKey { cert, key } => {
            let is_pem = |p: &std::path::Path| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some(ext) if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("crt") || ext.eq_ignore_ascii_case("key")
                )
            };

            if !is_pem(cert) || !is_pem(key) {
                return Err(Error::Tls(
                    "The native-tls backend requires PEM certificate and key files; \
                     for a DER-bundled identity use `Config::client_certificate_pkcs12`."
                        .to_string(),
                ));
            }

            let cert_buf = fs::read(cert).map_err(|e| Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!(
                    "Could not read client certificate {}: {e}",
                    cert.to_string_lossy()
                ),
            })?;
            let key_buf = fs::read(key).map_err(|e| Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!(
                    "Could not read client private key {}: {e}",
                    key.to_string_lossy()
                ),
            })?;

            Ok(Identity::from_pkcs8(&cert_buf, &key_buf)?)
        }
        ClientCertSource::Pkcs12 { path, password } => {
            let buf = fs::read(path).map_err(|e| Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!(
                    "Could not read PKCS#12 identity {}: {e}",
                    path.to_string_lossy()
                ),
            })?;
            Ok(Identity::from_pkcs12(&buf, password)?)
        }
    }
}

pub(crate) async fn create_tls_stream<S: AsyncRead + AsyncWrite + Unpin + Send>(
    config: &Config,
    stream: S,
) -> crate::Result<TlsStream<S>> {
    let mut builder = TlsConnector::new();

    if matches!(config.encryption, crate::EncryptionLevel::Strict) {
        builder = builder.request_alpns(&[super::TDS_ALPN_PROTOCOL_NAME]);
    }

    if let Some(cert) = config.get_client_certificate() {
        event!(
            Level::DEBUG,
            "Presenting a client certificate for mutual TLS."
        );
        builder = builder.identity(load_identity(cert)?);
    }

    match &config.trust {
        TrustConfig::CaCertificateLocation(path) => {
            if let Ok(buf) = fs::read(path) {
                let cert = match path.extension() {
                        Some(ext)
                        if ext.eq_ignore_ascii_case("pem")
                            || ext.eq_ignore_ascii_case("crt") =>
                            {
                                Some(Certificate::from_pem(&buf)?)
                            }
                        Some(ext) if ext.eq_ignore_ascii_case("der") => {
                            Some(Certificate::from_der(&buf)?)
                        }
                        Some(_) | None => return Err(Error::Io {
                            kind: IoErrorKind::InvalidInput,
                            message: "Provided CA certificate with unsupported file-extension! Supported types are pem, crt and der.".to_string()}),
                    };
                if let Some(c) = cert {
                    builder = builder.add_root_certificate(c);
                }
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

            builder = builder.danger_accept_invalid_certs(true);
            builder = builder.danger_accept_invalid_hostnames(true);
            builder = builder.use_sni(false);
        }
        TrustConfig::Default => {
            event!(Level::DEBUG, "Using default trust configuration.");
        }
    }

    Ok(builder
        .connect(config.get_hostname_in_certificate(), stream)
        .await?)
}
