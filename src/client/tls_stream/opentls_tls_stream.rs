use crate::{
    client::{
        config::{ClientCertSource, ClientCertificate, Config},
        TrustConfig,
    },
    error::{Error, IoErrorKind},
};
use futures_util::io::{AsyncRead, AsyncWrite};
pub(crate) use opentls::async_io::{TlsConnector, TlsStream};
use opentls::{Certificate, Identity};
use std::fs;
use tracing::{event, Level};

/// Loads a client identity from the configured source for the `opentls`
/// (vendored OpenSSL) backend.
///
/// `opentls` only exposes `Identity::from_pkcs12`, so only a PKCS#12 / PFX
/// bundle (supplied via [`Config::client_certificate_pkcs12`]) is supported;
/// separate PEM/DER certificate and key files cannot be loaded by this backend.
fn load_identity(cert: &ClientCertificate) -> crate::Result<Identity> {
    match &cert.source {
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
        ClientCertSource::CertAndKey { .. } => Err(Error::Tls(
            "The vendored-openssl (opentls) backend does not support separate \
             certificate/key files for client authentication; supply a PKCS#12 \
             bundle via `Config::client_certificate_pkcs12` instead."
                .to_string(),
        )),
    }
}

pub(crate) async fn create_tls_stream<S: AsyncRead + AsyncWrite + Unpin + Send>(
    config: &Config,
    stream: S,
) -> crate::Result<TlsStream<S>> {
    let mut builder = TlsConnector::new();

    if matches!(config.encryption, crate::EncryptionLevel::Strict) {
        event!(
            Level::WARN,
            "OpenTLS does not support ALPN, so the TDS 8.0 ALPN protocol will not be requested. SQL Server will assume TDS 8.0."
        );
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
                        if ext.to_ascii_lowercase() == "pem"
                            || ext.to_ascii_lowercase() == "crt" =>
                            {
                                Some(Certificate::from_pem(&buf)?)
                            }
                        Some(ext) if ext.to_ascii_lowercase() == "der" => {
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
