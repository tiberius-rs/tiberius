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
            // Accept only the extensions valid for each role: a certificate is
            // `.pem`/`.crt`, a private key is `.pem`/`.key`. Sharing a single
            // set previously let a `.key` file pass as the certificate (and a
            // `.crt` as the key).
            //
            // `.pem` is legitimately ambiguous — it is valid for BOTH the cert
            // and the key role — so it is accepted for either slot. A swapped
            // `.pem`/`.pem` pair therefore passes this extension check and is
            // only caught later by `Identity::from_pkcs8`, which fails to parse
            // mismatched content. Rejecting `.pem` for either role would break
            // valid usage, so it is intentionally left accepted for both.
            let has_ext = |p: &std::path::Path, exts: &[&str]| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some(ext) if exts.iter().any(|e| ext.eq_ignore_ascii_case(e))
                )
            };

            if !has_ext(cert, &["pem", "crt"]) || !has_ext(key, &["pem", "key"]) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::config::ClientCertSource;
    use std::path::PathBuf;

    fn identity(cert: &str, key: &str) -> crate::Result<Identity> {
        load_identity(&ClientCertificate {
            source: ClientCertSource::CertAndKey {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
            },
        })
    }

    // A `.key` file must not be accepted in the certificate role, nor a `.crt`
    // in the key role. The extension check runs before any file read, so these
    // paths need not exist.
    #[test]
    fn key_extension_rejected_as_certificate() {
        assert!(matches!(
            identity("client.key", "client.key"),
            Err(Error::Tls(_))
        ));
    }

    #[test]
    fn crt_extension_rejected_as_key() {
        assert!(matches!(
            identity("client.crt", "client.crt"),
            Err(Error::Tls(_))
        ));
    }

    // The valid role combinations pass the extension check and fail only later,
    // when the nonexistent files are read (an `Io` error, not a `Tls` one).
    #[test]
    fn valid_extensions_pass_extension_check() {
        for (cert, key) in [
            ("client.crt", "client.key"),
            ("client.pem", "client.pem"),
            ("client.crt", "client.pem"),
            ("client.pem", "client.key"),
        ] {
            match identity(cert, key) {
                Err(Error::Tls(_)) => {
                    panic!("valid extensions {cert}/{key} were wrongly rejected by the check")
                }
                Err(Error::Io { .. }) => {}
                Err(e) => panic!("expected an Io error from the missing file, got {e:?}"),
                Ok(_) => panic!("nonexistent files should not yield an identity"),
            }
        }
    }
}
