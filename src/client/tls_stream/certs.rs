//! Backend-agnostic CA-certificate loading.
//!
//! All three TLS backends (`rustls`, `native-tls`, `vendored-openssl`) trust
//! extra CAs through this one module, so the PEM/DER parsing and validation
//! cannot drift between them. It produces `Vec<CertificateDer<'static>>`; each
//! backend then hands those DER bytes to its own certificate type.
//!
//! Two input shapes are supported, mirroring [`ExtraCa`]:
//!
//! - A **file** ([`ExtraCa::File`]): the format is chosen from the extension —
//!   `.pem`/`.crt` parse as (possibly multi-certificate) PEM, `.der` as a single
//!   DER certificate, anything else is rejected.
//! - An in-memory **bundle** ([`ExtraCa::Bundle`]): the format is sniffed from
//!   the bytes — a `-----BEGIN` marker at the start of a line means PEM (every
//!   block is parsed), otherwise the bytes are treated as a single DER
//!   certificate.
//!
//! A leading UTF-8 byte-order mark (as written by some Windows editors /
//! PowerShell) is stripped before parsing, so a BOM-prefixed PEM file is still
//! recognised rather than mis-sniffed or rejected.
//!
//! Either shape yielding **zero** usable certificates is a hard error naming the
//! source, so a mistyped path, an empty/zero-byte input, or a bundle with no
//! certificate blocks can never silently degrade trust to "base roots only".

use crate::client::config::ExtraCa;
use crate::error::IoErrorKind;
use rustls_pki_types::{pem::PemObject, CertificateDer};
use std::{fs, path::Path};

/// Load every certificate from an [`ExtraCa`], guaranteeing at least one.
///
/// The returned certificates are additive trust anchors to be layered on top of
/// the configured [`RootSource`](crate::client::config::RootSource).
pub(crate) fn trust_anchors(extra: &ExtraCa) -> crate::Result<Vec<CertificateDer<'static>>> {
    let certs = match extra {
        ExtraCa::File(path) => certs_from_file(path)?,
        ExtraCa::Bundle(bytes) => certs_from_bundle(bytes)?,
    };

    // Rule 2: zero usable certificates is fatal and names the source — never a
    // silent degrade to base-roots-only.
    if certs.is_empty() {
        return Err(crate::Error::Io {
            kind: IoErrorKind::InvalidData,
            message: format!(
                "the CA source `{}` contained no usable certificates",
                source_name(extra)
            ),
        });
    }

    Ok(certs)
}

/// A human-readable name for an [`ExtraCa`] source, used in error messages so
/// every failure (read, parse, zero-cert, and an invalid certificate rejected by
/// the backend) names which configured CA is at fault.
pub(crate) fn source_name(extra: &ExtraCa) -> String {
    match extra {
        ExtraCa::File(path) => path.to_string_lossy().into_owned(),
        ExtraCa::Bundle(bytes) => format!("in-memory CA bundle ({} bytes)", bytes.len()),
    }
}

/// The error for a loaded DER blob a backend rejects as an invalid certificate,
/// naming the offending source so it matches the read/parse/zero-cert errors.
/// Shared by all three backends (via their extra-CA loaders) so the "every
/// failure names which configured CA is at fault" invariant can't drift and is
/// testable in one place.
pub(crate) fn invalid_cert_error<E: std::fmt::Display>(extra: &ExtraCa, err: E) -> crate::Error {
    crate::Error::Io {
        kind: IoErrorKind::InvalidData,
        message: format!(
            "the CA source `{}` contains an invalid certificate: {err}",
            source_name(extra)
        ),
    }
}

/// Strip a leading UTF-8 byte-order mark, if present. PEM is ASCII text and the
/// tokenizer requires `-----BEGIN` at the start of a line, so a BOM glued to the
/// first marker (common from Windows editors / PowerShell `Out-File`) would
/// otherwise cause an otherwise-valid certificate to parse as zero blocks.
fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// Parse a certificate file into DER certificates, dispatching on the extension.
/// The underlying I/O error is preserved in the message so callers can tell
/// missing-file / permission / parse failures apart, and the path is always
/// named (error-message parity across backends).
pub(crate) fn certs_from_file(path: &Path) -> crate::Result<Vec<CertificateDer<'static>>> {
    let buf = fs::read(path).map_err(|e| crate::Error::Io {
        kind: IoErrorKind::InvalidData,
        message: format!("Could not read certificate {}: {e}", path.to_string_lossy()),
    })?;

    match path.extension() {
        Some(ext) if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("crt") => {
            CertificateDer::pem_slice_iter(strip_bom(&buf))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::Error::Io {
                    kind: IoErrorKind::InvalidData,
                    message: format!(
                        "Failed to parse PEM certificate {}: {e}",
                        path.to_string_lossy()
                    ),
                })
        }
        // An empty `.der` file yields zero certificates (caught by the
        // zero-usable-certs check in `trust_anchors`), rather than a bogus
        // zero-length "certificate" that only fails later at the backend.
        Some(ext) if ext.eq_ignore_ascii_case("der") && buf.is_empty() => Ok(vec![]),
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

/// Parse in-memory certificate bytes, sniffing the format: a `-----BEGIN`
/// marker at the start of a line means PEM (every certificate block is parsed),
/// otherwise the bytes are treated as a single DER certificate. A zero-byte
/// input yields zero certificates (a hard, source-naming error in
/// [`trust_anchors`]) rather than a bogus empty "certificate".
pub(crate) fn certs_from_bundle(bytes: &[u8]) -> crate::Result<Vec<CertificateDer<'static>>> {
    let bytes = strip_bom(bytes);
    if looks_like_pem(bytes) {
        CertificateDer::pem_slice_iter(bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| crate::Error::Io {
                kind: IoErrorKind::InvalidData,
                message: format!("Failed to parse PEM CA bundle: {e}"),
            })
    } else if bytes.is_empty() {
        Ok(vec![])
    } else {
        Ok(vec![CertificateDer::from(bytes.to_vec())])
    }
}

/// A bundle is PEM if it contains a `-----BEGIN` marker at the start of a line
/// (start of the buffer, or immediately after a `\n`/`\r`). This mirrors the PEM
/// tokenizer's own line-start requirement, so a raw DER certificate that merely
/// *contains* those bytes somewhere in its ASN.1 body is not misclassified as
/// PEM (which would reject a perfectly valid DER cert). Callers strip a leading
/// BOM before calling, so a BOM-prefixed first line still matches.
fn looks_like_pem(bytes: &[u8]) -> bool {
    const MARKER: &[u8] = b"-----BEGIN";
    if bytes.starts_with(MARKER) {
        return true;
    }
    bytes
        .windows(MARKER.len() + 1)
        .any(|w| matches!(w[0], b'\n' | b'\r') && &w[1..] == MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn certs_from_file_reads_single_pem() {
        let chain = certs_from_file(Path::new("docker/certs/server.crt")).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn certs_from_file_reads_multi_pem_chain() {
        // Rule 4: multi-cert files must load ALL certs, never truncate.
        let chain = certs_from_file(Path::new("docker/certs/server-full.crt")).unwrap();
        assert!(
            chain.len() >= 2,
            "server-full.crt is a multi-certificate chain"
        );
        // Guard against a bug that duplicates the first block N times while
        // still inflating the count: the blocks must be genuinely distinct.
        assert_ne!(
            chain[0].as_ref(),
            chain[1].as_ref(),
            "the two blocks must be distinct certificates, not a repeated first block"
        );
    }

    #[test]
    fn certs_from_file_missing_file_preserves_io_error() {
        let err = certs_from_file(Path::new("docker/certs/does-not-exist.crt")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Could not read certificate") && msg.contains("does-not-exist.crt"),
            "error should name the read failure and path, got: {msg}"
        );
    }

    #[test]
    fn certs_from_file_unsupported_extension_errors() {
        let err = certs_from_file(Path::new("docker/certs/README.md")).unwrap_err();
        assert!(format!("{err:?}").contains("unsupported file-extension"));
    }

    #[test]
    fn certs_from_file_reads_der() {
        // Derive a DER from the PEM CA and round-trip it through the der branch.
        let der = certs_from_file(Path::new("docker/certs/customCA.crt"))
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .as_ref()
            .to_vec();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tiberius_certs_from_file_{}.der",
            std::process::id()
        ));
        std::fs::write(&path, &der).unwrap();
        let chain = certs_from_file(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(chain.unwrap().len(), 1);
    }

    #[test]
    fn certs_from_file_zero_cert_pem_is_empty() {
        let mut path = std::env::temp_dir();
        path.push(format!("tiberius_certs_zero_{}.pem", std::process::id()));
        std::fs::write(&path, b"# no certificates here\n").unwrap();
        let chain = certs_from_file(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(chain.unwrap().len(), 0);
    }

    #[test]
    fn certs_from_bundle_sniffs_pem_and_reads_all() {
        // Rule 3 + 4: a PEM bundle sniffed by `-----BEGIN`, all blocks parsed.
        let bytes = std::fs::read("docker/certs/server-full.crt").unwrap();
        let certs = certs_from_bundle(&bytes).unwrap();
        assert!(certs.len() >= 2, "PEM bundle must yield every block");
        assert_ne!(
            certs[0].as_ref(),
            certs[1].as_ref(),
            "the blocks must be distinct certificates, not a repeated first block"
        );
    }

    #[test]
    fn certs_from_bundle_sniffs_der() {
        // Rule 3: no `-----BEGIN` marker => treated as a single DER certificate.
        let der = certs_from_file(Path::new("docker/certs/customCA.crt"))
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .as_ref()
            .to_vec();
        let certs = certs_from_bundle(&der).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn certs_from_bundle_garbage_pem_errors() {
        let bytes =
            b"-----BEGIN CERTIFICATE-----\nnot valid base64!!!\n-----END CERTIFICATE-----\n";
        let err = certs_from_bundle(bytes).unwrap_err();
        assert!(format!("{err:?}").contains("Failed to parse PEM CA bundle"));
    }

    #[test]
    fn trust_anchors_file_zero_certs_errors_naming_source() {
        // Rule 2: a zero-cert file is a hard error naming the source path.
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tiberius_trust_anchors_zero_{}.pem",
            std::process::id()
        ));
        std::fs::write(&path, b"# no certificates here\n").unwrap();
        let err = trust_anchors(&ExtraCa::File(path.clone()));
        std::fs::remove_file(&path).ok();
        let msg = format!("{:?}", err.unwrap_err());
        assert!(
            msg.contains("contained no usable certificates") && msg.contains(".pem"),
            "error should name the empty source, got: {msg}"
        );
    }

    #[test]
    fn trust_anchors_bundle_no_certificate_blocks_errors_naming_source() {
        // Rule 2: a PEM bundle that contains no CERTIFICATE blocks (here only a
        // PRIVATE KEY) yields zero certs and must be a hard error naming the
        // in-memory source, never a silent degrade to base-roots-only.
        let bundle = b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n".to_vec();
        let err = trust_anchors(&ExtraCa::Bundle(bundle)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("contained no usable certificates") && msg.contains("in-memory CA bundle"),
            "error should name the empty in-memory source, got: {msg}"
        );
    }

    #[test]
    fn trust_anchors_bundle_multi_pem() {
        let bytes = std::fs::read("docker/certs/server-full.crt").unwrap();
        let certs = trust_anchors(&ExtraCa::Bundle(bytes)).unwrap();
        assert!(certs.len() >= 2);
    }

    #[test]
    fn trust_anchors_file_loads_all() {
        let certs = trust_anchors(&ExtraCa::File(PathBuf::from(
            "docker/certs/server-full.crt",
        )))
        .unwrap();
        assert!(certs.len() >= 2);
    }

    #[test]
    fn empty_der_bundle_is_zero_certs_naming_source() {
        // Rule 2: a zero-byte DER-sniffed bundle must be a hard error naming the
        // source, not a bogus 1-element vec of an empty "certificate" that only
        // fails later at the backend with an anonymous error.
        assert_eq!(certs_from_bundle(&[]).unwrap().len(), 0);
        let err = trust_anchors(&ExtraCa::Bundle(Vec::new())).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("contained no usable certificates") && msg.contains("in-memory CA bundle"),
            "empty bundle must be a source-naming zero-cert error, got: {msg}"
        );
    }

    #[test]
    fn empty_der_file_is_zero_certs_naming_source() {
        // Rule 2: a zero-byte `.der` file, same as above but the file shape.
        let mut path = std::env::temp_dir();
        path.push(format!("tiberius_empty_{}.der", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        assert_eq!(certs_from_file(&path).unwrap().len(), 0);
        let err = trust_anchors(&ExtraCa::File(path.clone()));
        std::fs::remove_file(&path).ok();
        let msg = format!("{:?}", err.unwrap_err());
        assert!(
            msg.contains("contained no usable certificates") && msg.contains(".der"),
            "empty .der must be a source-naming zero-cert error, got: {msg}"
        );
    }

    #[test]
    fn bom_prefixed_pem_still_parses() {
        // A UTF-8 BOM glued to the first `-----BEGIN` marker must not defeat
        // parsing. Use a MULTI-cert fixture so both assertions are load-bearing:
        // if `strip_bom` were dropped, the bundle would sniff as a single DER
        // blob (len 1, or an error) and the file path would parse zero blocks —
        // either way `>= 2` fails.
        let pem = std::fs::read("docker/certs/server-full.crt").unwrap();
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(&pem);

        // Bundle path (content sniff).
        assert!(
            certs_from_bundle(&with_bom).unwrap().len() >= 2,
            "BOM-prefixed PEM bundle must parse every block"
        );

        // File path (extension dispatch).
        let mut path = std::env::temp_dir();
        path.push(format!("tiberius_bom_{}.pem", std::process::id()));
        std::fs::write(&path, &with_bom).unwrap();
        let res = certs_from_file(&path);
        std::fs::remove_file(&path).ok();
        assert!(
            res.unwrap().len() >= 2,
            "BOM-prefixed PEM file must parse every block"
        );
    }

    #[test]
    fn der_with_embedded_begin_marker_is_treated_as_der() {
        // A raw DER cert whose body merely *contains* the `-----BEGIN` byte
        // sequence (not at a line start) must be sniffed as DER, not PEM — so a
        // valid DER cert isn't misclassified and rejected.
        let der = certs_from_file(Path::new("docker/certs/customCA.crt"))
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .as_ref()
            .to_vec();
        let mut crafted = der.clone();
        // Splice the marker into the middle of the DER body (not line-start).
        let mid = crafted.len() / 2;
        crafted.splice(mid..mid, b"-----BEGIN CERTIFICATE-----".iter().copied());
        assert!(
            !looks_like_pem(&crafted),
            "mid-body marker must not sniff PEM"
        );
        // The genuine DER (no marker) round-trips as a single DER certificate.
        assert!(!looks_like_pem(&der));
        assert_eq!(certs_from_bundle(&der).unwrap().len(), 1);
    }

    #[test]
    fn invalid_cert_error_names_source_for_every_shape() {
        // The shared error used by all three backends when a DER blob is
        // rejected must name the source (path / in-memory bundle) and carry the
        // backend's underlying error text.
        let file = invalid_cert_error(&ExtraCa::File(PathBuf::from("/tmp/ca.der")), "bad tag");
        let m = format!("{file:?}");
        assert!(
            m.contains("/tmp/ca.der")
                && m.contains("contains an invalid certificate")
                && m.contains("bad tag"),
            "file source must be named with the underlying error, got: {m}"
        );
        let bundle = invalid_cert_error(&ExtraCa::Bundle(vec![0u8; 7]), "bad der");
        let m2 = format!("{bundle:?}");
        assert!(
            m2.contains("in-memory CA bundle (7 bytes)")
                && m2.contains("contains an invalid certificate"),
            "bundle source must be named, got: {m2}"
        );
    }

    #[test]
    fn looks_like_pem_requires_line_start_marker() {
        assert!(looks_like_pem(b"-----BEGIN CERTIFICATE-----\n"));
        assert!(looks_like_pem(
            b"# a comment\n-----BEGIN CERTIFICATE-----\n"
        ));
        assert!(looks_like_pem(b"lead\r-----BEGIN CERTIFICATE-----\r\n"));
        assert!(!looks_like_pem(b"prefix -----BEGIN CERTIFICATE-----"));
        assert!(!looks_like_pem(b""));
        assert!(!looks_like_pem(b"short"));
    }
}
