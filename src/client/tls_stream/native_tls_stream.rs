use super::certs;
use crate::{
    client::config::{ClientCertSource, ClientCertificate, Config, ExtraCa},
    error::{Error, IoErrorKind},
};
pub(crate) use async_native_tls::TlsStream;
use async_native_tls::{Certificate, Identity, TlsConnector};
use futures_util::io::{AsyncRead, AsyncWrite};
use secrecy::ExposeSecret;
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
            // Expose the PKCS#12 password only for the decryption call itself.
            Ok(Identity::from_pkcs12(&buf, password.expose_secret())?)
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

    if config.trust.bypass {
        event!(
            Level::WARN,
            "Trusting the server certificate without validation."
        );

        builder = builder.danger_accept_invalid_certs(true);
        builder = builder.danger_accept_invalid_hostnames(true);
        builder = builder.use_sni(false);
    } else {
        // The base trust anchors are the platform trust store, which native-tls
        // consults automatically (there is no `WebpkiRoots` source here — that
        // variant only exists with the rustls backend). Layer every accumulated
        // extra CA on top, loading ALL certificates from each multi-cert file or
        // bundle via the shared, backend-agnostic loader.
        for cert in load_extra_cas(&config.trust.extra_cas)? {
            builder = builder.add_root_certificate(cert);
        }
    }

    Ok(builder
        .connect(config.get_hostname_in_certificate(), stream)
        .await?)
}

/// Load every accumulated extra CA into native-tls `Certificate`s, loading ALL
/// certificates from each multi-cert file/bundle and naming the offending source
/// if any DER blob is not a valid certificate. Factored out of the async connect
/// path so the load-and-name behaviour is unit-testable without a live server.
fn load_extra_cas(extras: &[ExtraCa]) -> crate::Result<Vec<Certificate>> {
    let mut out = Vec::new();
    for extra in extras {
        for cert in certs::trust_anchors(extra)? {
            out.push(
                Certificate::from_der(cert.as_ref())
                    .map_err(|e| certs::invalid_cert_error(extra, e))?,
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::config::{ClientCertSource, ExtraCa};
    use std::path::PathBuf;

    // Cross-backend loading: a multi-cert CA file must yield every
    // certificate, and each must convert into a native-tls `Certificate`. This
    // exercises the same shared loader + per-cert `Certificate::from_der`
    // conversion the connect path uses, without needing a live server.
    #[test]
    fn multi_cert_ca_file_loads_all_certs() {
        let ders = certs::trust_anchors(&ExtraCa::File(PathBuf::from(
            "docker/certs/server-full.crt",
        )))
        .expect("multi-cert CA file loads");
        assert!(ders.len() >= 2, "must not truncate a multi-cert file");
        for der in &ders {
            Certificate::from_der(der.as_ref()).expect("each DER cert converts for native-tls");
        }
    }

    #[test]
    fn multi_cert_ca_bundle_loads_all_certs() {
        let bytes = std::fs::read("docker/certs/server-full.crt").unwrap();
        let ders = certs::trust_anchors(&ExtraCa::Bundle(bytes)).expect("multi-cert bundle loads");
        assert!(ders.len() >= 2, "must not truncate a multi-cert bundle");
        for der in &ders {
            Certificate::from_der(der.as_ref()).expect("each DER cert converts for native-tls");
        }
    }

    #[test]
    fn empty_ca_file_is_hard_error_naming_source() {
        // A zero-cert CA never silently degrades to platform-only trust.
        let mut path = std::env::temp_dir();
        path.push(format!("tiberius_nt_zero_{}.pem", std::process::id()));
        std::fs::write(&path, b"# no certs\n").unwrap();
        let err = certs::trust_anchors(&ExtraCa::File(path.clone()));
        std::fs::remove_file(&path).ok();
        assert!(format!("{:?}", err.unwrap_err()).contains("contained no usable certificates"));
    }

    #[test]
    fn invalid_der_extra_ca_names_source() {
        // A DER blob that is not a valid certificate must fail the extra-CA load
        // with a message naming the offending source (exercises the native-tls
        // `Certificate::from_der` + source-naming path, not just the loader).
        // `Certificate` isn't `Debug`, so match instead of `unwrap_err`.
        let err = match load_extra_cas(&[ExtraCa::Bundle(vec![0x30, 0x03, 0x02, 0x01, 0x7f])]) {
            Ok(_) => panic!("an invalid DER extra CA must be a hard error"),
            Err(e) => e,
        };
        let msg = format!("{err:?}");
        assert!(
            msg.contains("in-memory CA bundle") && msg.contains("contains an invalid certificate"),
            "invalid DER must name the source, got: {msg}"
        );
    }

    #[test]
    fn multi_cert_extra_cas_load_all_via_helper() {
        // The helper loads every cert from a multi-cert file through the
        // real connect-path code, converting each to a native-tls Certificate.
        let certs = load_extra_cas(&[ExtraCa::File(PathBuf::from("docker/certs/server-full.crt"))])
            .expect("multi-cert file loads");
        assert!(certs.len() >= 2, "must not truncate a multi-cert file");
    }

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
