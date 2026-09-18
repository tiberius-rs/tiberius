use super::certs;
use crate::{
    client::config::{ClientCertSource, ClientCertificate, Config, ExtraCa},
    error::{Error, IoErrorKind},
};
use futures_util::io::{AsyncRead, AsyncWrite};
pub(crate) use opentls::async_io::{TlsConnector, TlsStream};
use opentls::{Certificate, Identity};
use secrecy::ExposeSecret;
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
            // Expose the PKCS#12 password only for the decryption call itself.
            Ok(Identity::from_pkcs12(&buf, password.expose_secret())?)
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

    if config.trust.bypass {
        event!(
            Level::WARN,
            "Trusting the server certificate without validation."
        );

        builder = builder.danger_accept_invalid_certs(true);
        builder = builder.danger_accept_invalid_hostnames(true);
        builder = builder.use_sni(false);
    } else {
        // The base trust anchors are the platform trust store, which opentls
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

/// Load every accumulated extra CA into opentls `Certificate`s, loading ALL
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
    use std::path::PathBuf;

    // Cross-backend loading (rule 4): a multi-cert CA file/bundle must yield
    // every certificate, and each must convert into an opentls `Certificate`.
    #[test]
    fn multi_cert_ca_file_loads_all_certs() {
        let ders = certs::trust_anchors(&ExtraCa::File(PathBuf::from(
            "docker/certs/server-full.crt",
        )))
        .expect("multi-cert CA file loads");
        assert!(ders.len() >= 2, "must not truncate a multi-cert file");
        for der in &ders {
            Certificate::from_der(der.as_ref()).expect("each DER cert converts for opentls");
        }
    }

    #[test]
    fn multi_cert_ca_bundle_loads_all_certs() {
        let bytes = std::fs::read("docker/certs/server-full.crt").unwrap();
        let ders = certs::trust_anchors(&ExtraCa::Bundle(bytes)).expect("multi-cert bundle loads");
        assert!(ders.len() >= 2, "must not truncate a multi-cert bundle");
        for der in &ders {
            Certificate::from_der(der.as_ref()).expect("each DER cert converts for opentls");
        }
    }

    #[test]
    fn empty_ca_file_is_hard_error_naming_source() {
        // Rule 2: a zero-cert CA never silently degrades to platform-only trust.
        let mut path = std::env::temp_dir();
        path.push(format!("tiberius_ot_zero_{}.pem", std::process::id()));
        std::fs::write(&path, b"# no certs\n").unwrap();
        let err = certs::trust_anchors(&ExtraCa::File(path.clone()));
        std::fs::remove_file(&path).ok();
        assert!(format!("{:?}", err.unwrap_err()).contains("contained no usable certificates"));
    }

    #[test]
    fn invalid_der_extra_ca_names_source() {
        // A DER blob that is not a valid certificate must fail the extra-CA load
        // with a message naming the offending source (exercises the opentls
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
        // The helper loads every cert from a multi-cert file (rule 4) through the
        // real connect-path code, converting each to an opentls Certificate.
        let certs = load_extra_cas(&[ExtraCa::File(PathBuf::from("docker/certs/server-full.crt"))])
            .expect("multi-cert file loads");
        assert!(certs.len() >= 2, "must not truncate a multi-cert file");
    }
}
