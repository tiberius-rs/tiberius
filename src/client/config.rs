mod ado_net;
mod ado_parser;
mod jdbc;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Default upper bound on how long the connection handshake (TDS prelogin, TLS
/// negotiation and login) may take before [`Connection::connect`] gives up with
/// a timeout error. Matches the 15-second `Connect Timeout` default used by
/// ADO.NET / the Microsoft SQL Server drivers.
///
/// [`Connection::connect`]: crate::Client::connect
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Default per-response deadline applied while reading command results (see
/// [`Config::command_timeout`]). Matches the 30-second `Command Timeout` /
/// `CommandTimeout` default used by ADO.NET / the Microsoft SQL Server drivers.
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

use super::AuthMethod;
use crate::EncryptionLevel;
use ado_net::*;
use jdbc::*;
#[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
use secrecy::SecretString;

#[derive(Clone, Debug)]
/// The `Config` struct contains all configuration information
/// required for connecting to the database with a [`Client`]. It also provides
/// the server address when connecting to a `TcpStream` via the
/// [`get_addr`] method.
///
/// When using an [ADO.NET connection string], it can be
/// constructed using the [`from_ado_string`] function.
///
/// Alternatively, a [`ConfigBuilder`] can be used for an ergonomic,
/// chainable construction. Create one via [`builder`], call its
/// setter methods and finalize it with [`build`].
///
/// [`Client`]: struct.Client.html
/// [ADO.NET connection string]: https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/connection-strings
/// [`from_ado_string`]: struct.Config.html#method.from_ado_string
/// [`get_addr`]: struct.Config.html#method.get_addr
/// [`ConfigBuilder`]: struct.ConfigBuilder.html
/// [`builder`]: struct.Config.html#method.builder
/// [`build`]: struct.ConfigBuilder.html#method.build
pub struct Config {
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) database: Option<String>,
    pub(crate) instance_name: Option<String>,
    pub(crate) application_name: Option<String>,
    pub(crate) encryption: EncryptionLevel,
    pub(crate) trust: TrustConfig,
    pub(crate) auth: AuthMethod,
    pub(crate) readonly: bool,
    pub(crate) packet_size: Option<u32>,
    pub(crate) hostname_in_certificate: Option<String>,
    pub(crate) client_name: Option<String>,
    pub(crate) multi_subnet_failover: bool,
    pub(crate) handshake_timeout: Option<Duration>,
    pub(crate) command_timeout: Option<Duration>,
    pub(crate) lossy_utf16_decoding: bool,
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    pub(crate) client_cert: Option<ClientCertificate>,
}

/// How the server certificate is trusted.
///
/// Two orthogonal axes plus a bypass:
///
/// - [`source`](TrustConfig::source): the base set of trust anchors (mutually
///   exclusive — the OS store or a bundled Mozilla snapshot).
/// - [`extra_cas`](TrustConfig::extra_cas): additional CA certificates layered
///   *on top of* the source. This **accumulates**: every `trust_cert_ca` /
///   `trust_cert_ca_bundle` call appends one entry (composable) rather than
///   replacing the previous one.
/// - [`bypass`](TrustConfig::bypass): skip certificate validation entirely
///   (`trust_cert`). Mutually exclusive with configuring a `source` or
///   `extra_cas` — mixing them panics (or, from a connection string, errors)
///   rather than letting the bypass silently win.
///
/// `bypass` is deliberately a distinct axis (not folded into `source`) so a
/// future, narrower "relax hostname verification only" mode can be
/// added later without a public-API rewrite.
#[derive(Clone)]
pub(crate) struct TrustConfig {
    /// Base trust anchors. Mutually exclusive; defaults to [`RootSource::Native`].
    pub(crate) source: RootSource,
    /// Extra CA certificates added on top of `source`. Accumulates in call order.
    pub(crate) extra_cas: Vec<ExtraCa>,
    /// If set, certificate validation (and hostname verification) is skipped
    /// entirely. See [`Config::trust_cert`].
    pub(crate) bypass: bool,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            source: RootSource::Native,
            extra_cas: Vec::new(),
            bypass: false,
        }
    }
}

impl TrustConfig {
    /// True when nothing has been customised: the OS trust store, no extra CAs,
    /// no bypass. Used by tests to assert the default trust posture.
    #[cfg(test)]
    pub(crate) fn is_default(&self) -> bool {
        matches!(self.source, RootSource::Native) && self.extra_cas.is_empty() && !self.bypass
    }
}

// Manual `Debug` following the crate's curated-Debug convention: never dump raw
// certificate bytes. `ExtraCa::Bundle` is summarised as `Bundle { len: N }`.
impl std::fmt::Debug for TrustConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustConfig")
            .field("source", &self.source)
            .field("extra_cas", &self.extra_cas)
            .field("bypass", &self.bypass)
            .finish()
    }
}

/// The base set of trust anchors used to validate the server certificate.
/// Mutually exclusive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum RootSource {
    /// The operating system's trust store (the default).
    #[default]
    Native,
    /// A compiled-in snapshot of Mozilla's root CA store (`webpki-roots`).
    ///
    /// rustls-only, and gated on the `rustls-webpki-roots` feature so the
    /// variant cannot exist without the crate that consumes it. Selected via
    /// [`Config::trust_webpki_roots`].
    #[cfg(feature = "rustls-webpki-roots")]
    WebpkiRoots,
}

/// An additional CA certificate source layered on top of [`RootSource`].
#[derive(Clone)]
#[cfg_attr(
    not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )),
    allow(dead_code)
)]
pub(crate) enum ExtraCa {
    /// A certificate file on disk (PEM `.pem`/`.crt`, or DER `.der`). May hold
    /// multiple certificates when PEM.
    File(PathBuf),
    /// In-memory certificate bytes. Multi-certificate: sniffed as PEM (all
    /// blocks parsed) when the bytes contain a `-----BEGIN` marker at the start
    /// of a line, otherwise treated as a single DER certificate.
    Bundle(Vec<u8>),
}

// Manual `Debug`: summarise `Bundle` as `Bundle { len: N }` so raw certificate
// bytes are never dumped.
impl std::fmt::Debug for ExtraCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtraCa::File(path) => f.debug_tuple("File").field(path).finish(),
            ExtraCa::Bundle(bytes) => f.debug_struct("Bundle").field("len", &bytes.len()).finish(),
        }
    }
}

/// A client certificate and its private key, presented to the server during the
/// TLS handshake to authenticate the *client* (mutual TLS / TDS 8.0
/// `ENCRYPT_CLIENT_CERT`).
///
/// Construct one indirectly via [`Config::client_certificate`] (PEM/DER
/// certificate + private-key files) or [`Config::client_certificate_pkcs12`]
/// (a PKCS#12 / PFX bundle, `native-tls` and `vendored-openssl` only).
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
#[derive(Clone, Debug)]
pub(crate) struct ClientCertificate {
    pub(crate) source: ClientCertSource,
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
// `SecretString` redacts the PKCS#12 password from `Debug` (and zeroizes it on
// drop), so this can derive `Debug` without leaking the password.
#[derive(Clone, Debug)]
pub(crate) enum ClientCertSource {
    /// A certificate file and a separate private-key file. Both may be PEM
    /// (`.pem`/`.crt` for the certificate, `.pem`/`.key` for the key) or DER
    /// (`.der`); the concrete format is detected from the file extension by the
    /// active TLS backend.
    ///
    /// The `cert`/`key` fields are read only by the `rustls` and `native-tls`
    /// backends; the `vendored-openssl` (opentls) backend rejects this variant
    /// (it supports PKCS#12 only). In a `vendored-openssl`-only build the fields
    /// are therefore never read, so silence dead-code exactly there rather than
    /// unconditionally — this keeps the derived `Debug` (which no longer counts
    /// as a read) while still compiling clean under `-Dwarnings`.
    #[cfg_attr(not(any(feature = "rustls", feature = "native-tls")), allow(dead_code))]
    CertAndKey { cert: PathBuf, key: PathBuf },
    /// A PKCS#12 / PFX bundle path together with its decryption password. Only
    /// supported by the `native-tls` and `vendored-openssl` backends.
    #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
    Pkcs12 {
        path: PathBuf,
        password: SecretString,
    },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: None,
            port: None,
            database: None,
            instance_name: None,
            application_name: None,
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            encryption: EncryptionLevel::Required,
            #[cfg(not(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            )))]
            encryption: EncryptionLevel::NotSupported,
            trust: TrustConfig::default(),
            auth: AuthMethod::None,
            readonly: false,
            packet_size: None,
            hostname_in_certificate: None,
            client_name: None,
            multi_subnet_failover: false,
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
            command_timeout: Some(DEFAULT_COMMAND_TIMEOUT),
            lossy_utf16_decoding: false,
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            client_cert: None,
        }
    }
}

impl Config {
    /// Create a new `Config` with the default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`ConfigBuilder`] initialized with the default settings.
    ///
    /// This provides an ergonomic, chainable alternative to constructing a
    /// [`Config`] via its individual setter methods.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::{Config, AuthMethod};
    /// let config = Config::builder()
    ///     .host("localhost")
    ///     .port(1433)
    ///     .database("master")
    ///     .authentication(AuthMethod::sql_server("SA", "<password>"))
    ///     .build();
    ///
    /// assert_eq!("localhost:1433", config.get_addr());
    /// ```
    ///
    /// [`ConfigBuilder`]: struct.ConfigBuilder.html
    /// [`Config`]: struct.Config.html
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder {
            inner: Self::default(),
        }
    }

    /// A host or ip address to connect to.
    ///
    /// - Defaults to `localhost`.
    pub fn host(&mut self, host: impl ToString) {
        self.host = Some(host.to_string());
    }

    /// The server port.
    ///
    /// - Defaults to `1433`.
    pub fn port(&mut self, port: u16) {
        self.port = Some(port);
    }

    /// The database to connect to.
    ///
    /// - Defaults to `master`.
    pub fn database(&mut self, database: impl ToString) {
        self.database = Some(database.to_string())
    }

    /// The instance name as defined in the SQL Browser. Only available on
    /// Windows platforms.
    ///
    /// If specified, the port is replaced with the value returned from the
    /// browser.
    ///
    /// - Defaults to no name specified.
    pub fn instance_name(&mut self, name: impl ToString) {
        self.instance_name = Some(name.to_string());
    }

    /// Sets the application name to the connection, queryable with the
    /// `APP_NAME()` command.
    ///
    /// - Defaults to no name specified.
    pub fn application_name(&mut self, name: impl ToString) {
        self.application_name = Some(name.to_string());
    }

    /// Sets the TDS packet size for the connection.
    ///
    /// Larger packet sizes can improve bulk insert performance by reducing
    /// the number of network round-trips. Valid values are 512 to 32767.
    /// The server may negotiate a different size.
    ///
    /// - Defaults to 4096 bytes.
    pub fn packet_size(&mut self, size: u32) {
        self.packet_size = Some(size);
    }

    /// Gets the configured packet size, if set.
    pub fn get_packet_size(&self) -> Option<u32> {
        self.packet_size
    }

    /// Set the preferred encryption level.
    ///
    /// - With a TLS backend enabled (any of the `rustls`, `native-tls`, or
    ///   `vendored-openssl` features), defaults to `Required`.
    /// - Without a TLS backend, defaults to `NotSupported`.
    pub fn encryption(&mut self, encryption: EncryptionLevel) {
        self.encryption = encryption;
    }

    /// If set, the server certificate will not be validated and it is accepted
    /// as-is.
    ///
    /// On production setting, the certificate should be added to the local key
    /// storage (or use `trust_cert_ca` instead), using this setting is potentially dangerous.
    ///
    /// This also bypasses the rustls backend's certificate *version* checks, so
    /// it is the escape hatch for the `invalid peer certificate:
    /// UnsupportedCertVersion` failure some older or self-signed SQL Server
    /// certificates trigger. Prefer [`trust_cert_ca`] when you
    /// can point at the server's CA; reach for `trust_cert` only when you cannot.
    /// Note that SQL Server performs a TLS handshake during login even when
    /// `Encrypt=false`, so certificate errors can surface regardless of the
    /// encryption level.
    ///
    /// # Security
    ///
    /// This accepts **any** certificate: it disables both certificate-chain
    /// validation *and* hostname verification, so it provides no protection
    /// against a man-in-the-middle. Only use it on a network you already trust.
    /// Prefer [`trust_cert_ca`] / [`trust_cert_ca_bundle`] to pin the server's
    /// CA instead.
    ///
    /// [`trust_cert_ca`]: Self::trust_cert_ca
    /// [`trust_cert_ca_bundle`]: Self::trust_cert_ca_bundle
    ///
    /// # Panics
    /// Will panic if any of [`trust_cert_ca`], [`trust_cert_ca_bundle`] or
    /// [`trust_webpki_roots`] was called before — the trust bypass is mutually
    /// exclusive with configuring trust anchors.
    ///
    /// [`trust_webpki_roots`]: Self::trust_webpki_roots
    ///
    /// - Defaults to `default`, meaning server certificate is validated against system-truststore.
    pub fn trust_cert(&mut self) {
        if !self.trust.extra_cas.is_empty() || !matches!(self.trust.source, RootSource::Native) {
            panic!(
                "'trust_cert' and 'trust_cert_ca'/'trust_cert_ca_bundle'/'trust_webpki_roots' \
                 are mutual exclusive! Only use one."
            )
        }
        self.trust.bypass = true;
    }

    /// Trust an additional CA certificate (from a file) *in addition to* the
    /// base trust anchors (the system trust store by default).
    /// Useful when using self-signed certificates on the server without having to disable the
    /// trust-chain.
    ///
    /// The file may be PEM (`.pem`/`.crt`) or DER (`.der`); a PEM file may
    /// contain **multiple** certificates and all of them are trusted.
    ///
    /// This **accumulates**: calling it more than once (or alongside
    /// [`trust_cert_ca_bundle`]) trusts every supplied CA — repeated calls are
    /// additive, not replace-last-wins.
    ///
    /// # Panics
    /// Will panic in case [`trust_cert`] was called before.
    ///
    /// [`trust_cert`]: Self::trust_cert
    /// [`trust_cert_ca_bundle`]: Self::trust_cert_ca_bundle
    ///
    /// - Defaults to validating the server certificate is validated against system's certificate storage.
    pub fn trust_cert_ca(&mut self, path: impl ToString) {
        if self.trust.bypass {
            panic!("'trust_cert' and 'trust_cert_ca' are mutual exclusive! Only use one.")
        }
        self.trust
            .extra_cas
            .push(ExtraCa::File(PathBuf::from(path.to_string())));
    }

    /// Trust additional CA certificates supplied as in-memory bytes, *in
    /// addition to* the base trust anchors. This avoids having to write an
    /// in-memory certificate out to a temporary file, and accepts a whole
    /// **bundle** of CA certificates (for example the AWS RDS root bundle).
    ///
    /// The byte format is auto-detected: if the bytes contain a `-----BEGIN`
    /// marker at the start of a line they are parsed as PEM (every certificate
    /// block is trusted), otherwise they are treated as a single DER
    /// certificate. A leading UTF-8 byte-order mark is tolerated.
    ///
    /// Like [`trust_cert_ca`], this **accumulates**: each call appends to the
    /// set of trusted CAs.
    ///
    /// # Panics
    /// Will panic in case [`trust_cert`] was called before.
    ///
    /// [`trust_cert`]: Self::trust_cert
    /// [`trust_cert_ca`]: Self::trust_cert_ca
    pub fn trust_cert_ca_bundle(&mut self, bundle: impl Into<Vec<u8>>) {
        if self.trust.bypass {
            panic!("'trust_cert' and 'trust_cert_ca_bundle' are mutual exclusive! Only use one.")
        }
        self.trust.extra_cas.push(ExtraCa::Bundle(bundle.into()));
    }

    /// Use a compiled-in snapshot of Mozilla's root CA store (via the
    /// `webpki-roots` crate) as the base trust anchors instead of the operating
    /// system's trust store. Any CAs added with [`trust_cert_ca`] /
    /// [`trust_cert_ca_bundle`] are still layered on top.
    ///
    /// This is useful on platforms with no usable OS trust store. It is only
    /// available with the `rustls` backend (via the `rustls-webpki-roots`
    /// feature); with any other backend the method does not exist, so misuse is
    /// a compile error.
    ///
    /// # Security
    ///
    /// The bundled roots are a **pinned snapshot** taken when this crate's
    /// `webpki-roots` dependency was last updated. Unlike the OS trust store
    /// they do not receive security updates on their own — they go stale (newly
    /// distrusted or newly added CAs are missed) unless the dependency is
    /// updated and the application rebuilt.
    ///
    /// # Panics
    /// Will panic in case [`trust_cert`] was called before.
    ///
    /// [`trust_cert`]: Self::trust_cert
    /// [`trust_cert_ca`]: Self::trust_cert_ca
    /// [`trust_cert_ca_bundle`]: Self::trust_cert_ca_bundle
    #[cfg(feature = "rustls-webpki-roots")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls-webpki-roots")))]
    pub fn trust_webpki_roots(&mut self) {
        if self.trust.bypass {
            panic!("'trust_cert' and 'trust_webpki_roots' are mutual exclusive! Only use one.")
        }
        self.trust.source = RootSource::WebpkiRoots;
    }

    /// Sets the hostname that the server certificate is validated against,
    /// instead of the value given to [`host`].
    ///
    /// This is useful when connecting through an IP address, a tunnel, or a
    /// load balancer whose certificate carries a different subject/SAN than the
    /// address used to reach it (see issue #340).
    ///
    /// - Defaults to the value of [`host`].
    ///
    /// [`host`]: Config::host
    pub fn hostname_in_certificate(&mut self, hostname: impl ToString) {
        self.hostname_in_certificate = Some(hostname.to_string());
    }

    /// Sets the client / workstation name reported to the server in the login
    /// record (queryable with `HOST_NAME()`).
    ///
    /// - Defaults to the local workstation id (the machine hostname).
    pub fn client_name(&mut self, name: impl ToString) {
        self.client_name = Some(name.to_string());
    }

    /// Sets the authentication method.
    ///
    /// - Defaults to `None`.
    pub fn authentication(&mut self, auth: AuthMethod) {
        self.auth = auth;
    }

    /// Sets ApplicationIntent readonly.
    ///
    /// - Defaults to `false`.
    pub fn readonly(&mut self, readonly: bool) {
        self.readonly = readonly;
    }

    /// Enable multi-subnet failover.
    ///
    /// When enabled and the server host name resolves to more than one IP
    /// address (for example, an Always On availability group listener spread
    /// across subnets), connections are attempted to all resolved addresses in
    /// parallel and the first one to succeed is used. This mirrors the ADO.NET
    /// `MultiSubnetFailover` connection-string keyword.
    ///
    /// - Defaults to `false`.
    pub fn multi_subnet_failover(&mut self, multi_subnet_failover: bool) {
        self.multi_subnet_failover = multi_subnet_failover;
    }

    /// Returns whether multi-subnet failover is enabled.
    pub fn get_multi_subnet_failover(&self) -> bool {
        self.multi_subnet_failover
    }

    /// Sets an upper bound on how long the connection handshake may take.
    ///
    /// The handshake covers everything [`Client::connect`] does after it is
    /// handed a connected TCP stream: the TDS prelogin exchange, the TLS
    /// negotiation and the login. If the server accepts the TCP connection but
    /// then stops responding mid-handshake (for example a TLS handshake that
    /// stalls indefinitely), the connect future would otherwise hang forever
    /// with no error. This bound makes such a stall surface as a
    /// [`Error::Io`] with [`std::io::ErrorKind::TimedOut`] instead.
    ///
    /// The timer is runtime-agnostic (it does not depend on tokio or smol), so
    /// it applies regardless of the async runtime driving the connection. Note
    /// that it does **not** cover establishing the TCP connection itself, which
    /// happens before the stream is passed to [`Client::connect`]; bound that
    /// with your runtime's own connect timeout (e.g. `tokio::time::timeout`).
    ///
    /// Enable `tracing` at the `DEBUG` level to see which handshake stage was
    /// reached, which pinpoints where a stall occurred.
    ///
    /// - Defaults to 15 seconds, matching ADO.NET's `Connect Timeout`. Pass
    ///   `None` to wait indefinitely. A zero duration is a degenerate bound
    ///   that fails as soon as the handshake would block.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// # use std::time::Duration;
    /// let mut config = Config::new();
    /// // Fail fast if the handshake stalls.
    /// config.handshake_timeout(Some(Duration::from_secs(5)));
    /// ```
    ///
    /// [`Client::connect`]: crate::Client::connect
    /// [`Error::Io`]: crate::error::Error::Io
    pub fn handshake_timeout(&mut self, timeout: Option<Duration>) {
        self.handshake_timeout = timeout;
    }

    /// Returns the configured connection-handshake timeout, if any.
    ///
    /// See [`handshake_timeout`](Config::handshake_timeout).
    pub fn get_handshake_timeout(&self) -> Option<Duration> {
        self.handshake_timeout
    }

    /// Sets a per-response deadline applied while reading command results
    /// (`query`, `execute`, `simple_query`, the `bulk_insert` server
    /// acknowledgement and `column_metadata`).
    ///
    /// # Semantics
    ///
    /// This bounds **each server round-trip**, not the total time to enumerate a
    /// result stream. Query results are lazy, caller-driven streams: the timer
    /// only runs while the client is actively waiting on the server for the next
    /// chunk of the response, and it is **reset every time a token is
    /// delivered**. A slow *consumer* (code that pauses between pulling rows)
    /// therefore never trips it — only a stalled *server* does. Concretely, if
    /// the gap between the client asking for more data and the server delivering
    /// the next token exceeds the deadline, the stream yields an [`Error::Io`]
    /// with [`std::io::ErrorKind::TimedOut`]. This covers both the
    /// time-to-first-response and any mid-stream stall.
    ///
    /// The timer is runtime-agnostic (it does not depend on tokio or smol).
    ///
    /// Note: once a command times out, its connection is left mid-response and
    /// out of sync with the server; drop the [`Client`] and open a new one (a
    /// pool should discard the connection) rather than reuse it.
    ///
    /// - Defaults to 30 seconds, matching ADO.NET's `Command Timeout`. Pass
    ///   `None` to wait indefinitely. A zero duration is a degenerate bound
    ///   that trips on the first server round-trip that is not answered
    ///   immediately.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// # use std::time::Duration;
    /// let mut config = Config::new();
    /// // Fail a query if the server stops responding for 10s mid-result.
    /// config.command_timeout(Some(Duration::from_secs(10)));
    /// // Or wait forever (e.g. for a deliberately long-running batch):
    /// config.command_timeout(None);
    /// ```
    ///
    /// [`Client`]: crate::Client
    /// [`Error::Io`]: crate::error::Error::Io
    pub fn command_timeout(&mut self, timeout: Option<Duration>) {
        self.command_timeout = timeout;
    }

    /// Returns the configured per-response command timeout, if any.
    ///
    /// See [`command_timeout`](Config::command_timeout).
    pub fn get_command_timeout(&self) -> Option<Duration> {
        self.command_timeout
    }

    /// Controls how malformed UTF-16 in NVARCHAR/NTEXT row values is handled.
    ///
    /// SQL Server stores `NVARCHAR`/`NCHAR`/`NTEXT` as unchecked UCS-2/UTF-16,
    /// so a column can legitimately hold lone (unpaired) surrogates or other
    /// sequences that are not valid Unicode. By default tiberius decodes these
    /// values *strictly*: a malformed sequence aborts the row stream with an
    /// error — [`Error::Protocol`] for NVARCHAR/NCHAR and [`Error::Utf16`] for
    /// NTEXT (an odd, desynced byte length is always [`Error::Protocol`], in
    /// both modes; see below). Strict decoding
    /// is the safer default because it also surfaces framing desyncs (a decode
    /// that silently "succeeds" on garbage can mask a misaligned read).
    ///
    /// Enabling this option makes decoding *lossy* for the NVARCHAR/NCHAR and
    /// NTEXT text arms only: each invalid UTF-16 sequence is replaced with the
    /// Unicode replacement character (`U+FFFD`, `�`) instead of erroring, so a
    /// row containing bad Unicode stays readable.
    ///
    /// Scope and guarantees:
    ///
    /// - Only NVARCHAR/NCHAR (`string`) and NTEXT (`text`) decoding is affected.
    ///   `XML` columns and code-page (`VARCHAR`/`CHAR`/`TEXT`) columns are
    ///   always decoded strictly, regardless of this setting.
    /// - Framing/length validation is always enforced: an odd byte length for a
    ///   UTF-16 value is still a protocol error in both modes, because it
    ///   indicates a desynced stream rather than merely bad Unicode.
    ///
    /// - Defaults to `false` (strict decoding).
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// let mut config = Config::new();
    /// // Tolerate legacy rows that hold unchecked UCS-2 with lone surrogates.
    /// config.lossy_utf16_decoding(true);
    /// ```
    ///
    /// [`Error::Protocol`]: crate::error::Error::Protocol
    /// [`Error::Utf16`]: crate::error::Error::Utf16
    pub fn lossy_utf16_decoding(&mut self, lossy: bool) {
        self.lossy_utf16_decoding = lossy;
    }

    /// Returns whether lossy UTF-16 decoding is enabled for NVARCHAR/NTEXT
    /// values.
    ///
    /// See [`lossy_utf16_decoding`](Config::lossy_utf16_decoding).
    pub fn get_lossy_utf16_decoding(&self) -> bool {
        self.lossy_utf16_decoding
    }

    /// Supplies a client certificate and private key used to authenticate the
    /// client to the server during the TLS handshake (mutual TLS). This is
    /// required for TDS 8.0 "strict" connections that use client-certificate
    /// authentication (`ENCRYPT_CLIENT_CERT`), and may also be used with the
    /// classic (pre-8.0) TLS handshake when the server requests a client
    /// certificate.
    ///
    /// Both arguments are paths to files:
    ///
    /// - `cert`: the client certificate, PEM (`.pem`/`.crt`) or DER (`.der`).
    /// - `key`: the matching private key, PEM (`.pem`/`.key`) or DER (`.der`,
    ///   PKCS#8).
    ///
    /// Backend support:
    ///
    /// - `rustls`: PEM and DER certificate/key files.
    /// - `native-tls`: PEM certificate + PEM PKCS#8 key only (DER files are
    ///   rejected at connect time; use [`client_certificate_pkcs12`] for a
    ///   bundled DER identity).
    /// - `vendored-openssl` (opentls): does not support separate certificate/key
    ///   files; use [`client_certificate_pkcs12`] instead.
    ///
    /// - Defaults to no client certificate.
    ///
    /// [`client_certificate_pkcs12`]: Config::client_certificate_pkcs12
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "rustls",
            feature = "native-tls",
            feature = "vendored-openssl"
        )))
    )]
    pub fn client_certificate(&mut self, cert: impl Into<PathBuf>, key: impl Into<PathBuf>) {
        self.client_cert = Some(ClientCertificate {
            source: ClientCertSource::CertAndKey {
                cert: cert.into(),
                key: key.into(),
            },
        });
    }

    /// Supplies a client identity from a PKCS#12 / PFX bundle (certificate,
    /// private key and any chain, encrypted with `password`) used to
    /// authenticate the client to the server during the TLS handshake (mutual
    /// TLS).
    ///
    /// Only supported by the `native-tls` and `vendored-openssl` backends; the
    /// `rustls` backend rejects PKCS#12 identities at connect time (supply
    /// separate PEM/DER files via [`client_certificate`] instead).
    ///
    /// - Defaults to no client certificate.
    ///
    /// [`client_certificate`]: Config::client_certificate
    #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "vendored-openssl")))
    )]
    pub fn client_certificate_pkcs12(
        &mut self,
        path: impl Into<PathBuf>,
        password: impl Into<String>,
    ) {
        self.client_cert = Some(ClientCertificate {
            source: ClientCertSource::Pkcs12 {
                path: path.into(),
                password: crate::client::auth::secret_from_string(password.into()),
            },
        });
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    pub(crate) fn get_client_certificate(&self) -> Option<&ClientCertificate> {
        self.client_cert.as_ref()
    }

    pub(crate) fn get_host(&self) -> &str {
        self.host
            .as_deref()
            .filter(|v| v != &".")
            .unwrap_or("localhost")
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    pub(crate) fn get_hostname_in_certificate(&self) -> &str {
        self.hostname_in_certificate
            .as_deref()
            .unwrap_or_else(|| self.get_host())
    }

    pub(crate) fn get_port(&self) -> u16 {
        match (self.port, self.instance_name.as_ref()) {
            // A user-defined port, we must use that.
            (Some(port), _) => port,
            // If using a named instance, we'll give the default port of SQL
            // Browser.
            (None, Some(_)) => 1434,
            // Otherwise the defaulting to the default SQL Server port.
            (None, None) => 1433,
        }
    }

    /// Get the host address including port
    pub fn get_addr(&self) -> String {
        format!("{}:{}", self.get_host(), self.get_port())
    }

    /// Creates a new `Config` from an [ADO.NET connection string].
    ///
    /// # Supported parameters
    ///
    /// All parameter keys are handled case-insensitive.
    ///
    /// |Parameter|Allowed values|Description|
    /// |--------|--------|--------|
    /// |`server`|`<string>`|The name or network address of the instance of SQL Server to which to connect. The port number can be specified after the server name. The correct form of this parameter is either `tcp:host,port` or `tcp:host\\instance`|
    /// |`IntegratedSecurity`|`true`,`false`,`yes`,`no`|Toggle between Windows/Kerberos authentication and SQL authentication.|
    /// |`uid`,`username`,`user`,`user id`|`<string>`|The SQL Server login account.|
    /// |`password`,`pwd`|`<string>`|The password for the SQL Server account logging on.|
    /// |`database`|`<string>`|The name of the database.|
    /// |`TrustServerCertificate`|`true`,`false`,`yes`,`no`|Specifies whether the driver trusts the server certificate when connecting using TLS. Cannot be used toghether with `TrustServerCertificateCA`|
    /// |`TrustServerCertificateCA`|`<path>`|Path to a `pem`, `crt` or `der` certificate file. Cannot be used together with `TrustServerCertificate`|
    /// |`encrypt`|`strict`,`true`,`false`,`yes`,`no`,`DANGER_PLAINTEXT`|Specifies whether the driver uses TLS to encrypt communication. `strict` (TDS 8.0) requires the `tds80` feature.|
    /// |`Application Name`, `ApplicationName`|`<string>`|Sets the application name for the connection.|
    /// |`HostNameInCertificate`, `HostName In Certificate`|`<string>`|The hostname the server certificate is validated against. Defaults to the value of the `Server` keyword (host).|
    /// |`WorkstationID`, `Workstation ID`|`<string>`|The client / workstation name reported to the server.|
    /// |`MultiSubnetFailover`|`true`,`false`,`yes`,`no`|When enabled, connections are attempted in parallel to all IP addresses the server resolves to, and the first to succeed is used.|
    ///
    /// # Parsing model and special characters
    ///
    /// Pairs are separated by `;`, and each pair is split on its **first** `=`,
    /// so a value may itself contain `=`: a base64 or otherwise generated
    /// password with `=` padding (for example `password=Zm9vYmFy==`) parses
    /// without any quoting.
    ///
    /// Characters that are still structural inside a *value* — `;`, a leading
    /// `'`, `"` or `{`, and any leading or trailing spaces you want to keep —
    /// must be quoted. Wrap the value in single quotes, double quotes, or braces
    /// (`{...}`), choosing a style the value does not itself contain, and embed
    /// the enclosing quote by doubling it (`"a""b"` → `a"b`):
    ///
    /// - `password='p@ss;word=42'`
    /// - `password="p@ss;word=42"`
    /// - `password={p@ss;word=42}`
    ///
    /// Do **not** URL-encode the value: `%24` is sent to the server literally,
    /// not decoded back to `$`, which is a common cause of login failures.
    /// A bare `}` needs no quoting, but brace quoting cannot hold a literal `}`
    /// (there is no `}}` doubling), so a value that must be quoted *and*
    /// contains a `}` has to use single or double quotes. Only ASCII values are
    /// accepted by the parser.
    ///
    /// tiberius parses a **superset** of ADO.NET's documented rules: the ADO.NET
    /// semantics above, plus `{...}` brace quoting as an extension (braces are
    /// not part of ADO.NET itself). One consequence of that extension: because a
    /// value that *begins* with `{` is read as brace-quoted, a value whose
    /// literal first character is `{` must instead be single- or double-quoted
    /// (e.g. `password='{literal-braces}'`).
    ///
    /// For non-ASCII passwords, or to avoid escaping entirely, build the
    /// [`Config`] programmatically — the values are passed verbatim:
    ///
    /// ```
    /// # use tiberius::{Config, AuthMethod};
    /// // Quoted in an ADO.NET string: the `;`, `=` and `{}` are preserved.
    /// let _config = Config::from_ado_string(
    ///     r#"server=tcp:localhost,1433;user=sa;password='p@ss;w{}rd=42'"#,
    /// )?;
    ///
    /// // The programmatic API needs no escaping and accepts any value.
    /// let mut config = Config::new();
    /// config.host("localhost");
    /// config.port(1433);
    /// config.authentication(AuthMethod::sql_server("sa", "p@ss;w{}rd=42"));
    /// # Ok::<(), tiberius::error::Error>(())
    /// ```
    ///
    /// [ADO.NET connection string]: https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/connection-strings
    pub fn from_ado_string(s: &str) -> crate::Result<Self> {
        let ado: AdoNetConfig = s.parse()?;
        Self::from_config_string(ado)
    }

    /// Creates a new `Config` from a [JDBC connection string].
    ///
    /// See [`from_ado_string`] method for supported parameters.
    ///
    /// # Special characters in values
    ///
    /// The JDBC parser understands only brace quoting: wrap a value that
    /// contains `;`, `=`, `:`, `{`, `\`, `/`, `[` or `]` in braces, e.g.
    /// `password={p@ss;word}`.
    /// Unlike ADO.NET, single and double quotes are **not** escape characters
    /// here — they are ordinary value characters, and spaces are kept verbatim
    /// without quoting (JDBC does not trim). Brace quoting cannot hold a literal
    /// `}` (there is no `}}` doubling), though a bare `}` needs no quoting. Do
    /// not URL-encode values, and note that only ASCII is accepted.
    /// For non-ASCII values, or to avoid escaping entirely, build the
    /// [`Config`] programmatically as shown in [`from_ado_string`]; the values
    /// are passed verbatim.
    ///
    /// [JDBC connection string]: https://docs.microsoft.com/en-us/sql/connect/jdbc/building-the-connection-url?view=sql-server-ver15
    /// [`from_ado_string`]: #method.from_ado_string
    pub fn from_jdbc_string(s: &str) -> crate::Result<Self> {
        let jdbc: JdbcConfig = s.parse()?;
        Self::from_config_string(jdbc)
    }

    fn from_config_string(s: impl ConfigString) -> crate::Result<Self> {
        let mut builder = Self::new();

        let server = s.server()?;

        if let Some(host) = server.host {
            builder.host(host);
        }

        if let Some(port) = server.port {
            builder.port(port);
        }

        if let Some(instance) = server.instance {
            builder.instance_name(instance);
        }

        builder.authentication(s.authentication()?);

        if let Some(database) = s.database() {
            builder.database(database);
        }

        if let Some(name) = s.application_name() {
            builder.application_name(name);
        }

        let trust_cert = s.trust_cert()?;
        let trust_cert_ca = s.trust_cert_ca();

        // `TrustServerCertificate` and `TrustServerCertificateCA` are mutually
        // exclusive. Detect the conflict here and return an error instead of
        // letting `trust_cert`/`trust_cert_ca` panic on external input.
        if trust_cert && trust_cert_ca.is_some() {
            return Err(crate::Error::Conversion(
                "'TrustServerCertificate' and 'TrustServerCertificateCA' are \
                 mutually exclusive; specify only one"
                    .into(),
            ));
        }

        if trust_cert {
            builder.trust_cert();
        }

        if let Some(ca) = trust_cert_ca {
            builder.trust_cert_ca(ca);
        }

        if let Some(hostname_in_cert) = s.hostname_in_certificate() {
            builder.hostname_in_certificate(hostname_in_cert);
        }

        builder.encryption(s.encrypt()?);

        builder.readonly(s.readonly());

        if let Some(client_name) = s.client_name() {
            builder.client_name(client_name);
        }
        builder.multi_subnet_failover(s.multi_subnet_failover()?);

        Ok(builder)
    }
}

/// A builder for [`Config`], providing an ergonomic, chainable way to
/// construct a connection configuration.
///
/// Create a builder with [`Config::builder`], set the desired options by
/// calling its methods (each returns the builder to allow chaining) and
/// finalize it with [`build`].
///
/// # Example
///
/// ```
/// # use tiberius::{Config, AuthMethod, EncryptionLevel};
/// let config = Config::builder()
///     .host("localhost")
///     .port(1433)
///     .database("master")
///     .encryption(EncryptionLevel::NotSupported)
///     .authentication(AuthMethod::sql_server("SA", "<password>"))
///     .build();
/// ```
///
/// [`Config`]: struct.Config.html
/// [`Config::builder`]: struct.Config.html#method.builder
/// [`build`]: struct.ConfigBuilder.html#method.build
#[derive(Clone, Debug)]
pub struct ConfigBuilder {
    inner: Config,
}

impl ConfigBuilder {
    /// A host or ip address to connect to.
    ///
    /// - Defaults to `localhost`.
    pub fn host(mut self, host: impl ToString) -> Self {
        self.inner.host = Some(host.to_string());
        self
    }

    /// The server port.
    ///
    /// - Defaults to `1433`.
    pub fn port(mut self, port: u16) -> Self {
        self.inner.port = Some(port);
        self
    }

    /// The database to connect to.
    ///
    /// - Defaults to `master`.
    pub fn database(mut self, database: impl ToString) -> Self {
        self.inner.database = Some(database.to_string());
        self
    }

    /// The instance name as defined in the SQL Browser. Only available on
    /// Windows platforms.
    ///
    /// If specified, the port is replaced with the value returned from the
    /// browser.
    ///
    /// - Defaults to no name specified.
    pub fn instance_name(mut self, name: impl ToString) -> Self {
        self.inner.instance_name = Some(name.to_string());
        self
    }

    /// Sets the application name to the connection, queryable with the
    /// `APP_NAME()` command.
    ///
    /// - Defaults to no name specified.
    pub fn application_name(mut self, name: impl ToString) -> Self {
        self.inner.application_name = Some(name.to_string());
        self
    }

    /// Set the preferred encryption level.
    ///
    /// - With a TLS backend enabled (any of the `rustls`, `native-tls`, or
    ///   `vendored-openssl` features), defaults to `Required`.
    /// - Without a TLS backend, defaults to `NotSupported`.
    pub fn encryption(mut self, encryption: EncryptionLevel) -> Self {
        self.inner.encryption = encryption;
        self
    }

    /// If set, the server certificate will not be validated and it is accepted
    /// as-is.
    ///
    /// On production setting, the certificate should be added to the local key
    /// storage (or use `trust_cert_ca` instead), using this setting is potentially dangerous.
    ///
    /// # Panics
    /// Will panic in case `trust_cert_ca` was called before.
    ///
    /// - Defaults to `default`, meaning server certificate is validated against system-truststore.
    pub fn trust_cert(mut self) -> Self {
        self.inner.trust_cert();
        self
    }

    /// Trust an additional CA certificate (from a file), in addition to the base
    /// trust anchors. Accumulates across calls.
    ///
    /// See [`Config::trust_cert_ca`] for details.
    ///
    /// # Panics
    /// Will panic in case `trust_cert` was called before.
    pub fn trust_cert_ca(mut self, path: impl ToString) -> Self {
        self.inner.trust_cert_ca(path);
        self
    }

    /// Trust additional CA certificates supplied as in-memory bytes (a
    /// PEM/DER bundle), in addition to the base trust anchors. Accumulates
    /// across calls.
    ///
    /// See [`Config::trust_cert_ca_bundle`] for details.
    ///
    /// # Panics
    /// Will panic in case `trust_cert` was called before.
    pub fn trust_cert_ca_bundle(mut self, bundle: impl Into<Vec<u8>>) -> Self {
        self.inner.trust_cert_ca_bundle(bundle);
        self
    }

    /// Use the compiled-in Mozilla root CA snapshot as the base trust anchors
    /// (rustls only).
    ///
    /// See [`Config::trust_webpki_roots`] for details and the staleness caveat.
    ///
    /// # Panics
    /// Will panic in case `trust_cert` was called before.
    #[cfg(feature = "rustls-webpki-roots")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls-webpki-roots")))]
    pub fn trust_webpki_roots(mut self) -> Self {
        self.inner.trust_webpki_roots();
        self
    }

    /// Sets the authentication method.
    ///
    /// - Defaults to `None`.
    pub fn authentication(mut self, auth: AuthMethod) -> Self {
        self.inner.auth = auth;
        self
    }

    /// Sets ApplicationIntent readonly.
    ///
    /// - Defaults to `false`.
    pub fn readonly(mut self, readonly: bool) -> Self {
        self.inner.readonly = readonly;
        self
    }

    /// Sets an upper bound on how long the connection handshake may take.
    ///
    /// See [`Config::handshake_timeout`] for details. Pass `None` to wait
    /// indefinitely.
    ///
    /// - Defaults to 15 seconds.
    pub fn handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inner.handshake_timeout = timeout;
        self
    }

    /// Sets a per-response deadline applied while reading command results.
    ///
    /// See [`Config::command_timeout`] for the exact (per-round-trip)
    /// semantics. Pass `None` to wait indefinitely.
    ///
    /// - Defaults to 30 seconds.
    pub fn command_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inner.command_timeout = timeout;
        self
    }

    /// Enables lossy UTF-16 decoding for NVARCHAR/NTEXT row values.
    ///
    /// See [`Config::lossy_utf16_decoding`] for the exact semantics (strict is
    /// the default; enabling replaces invalid UTF-16 with `U+FFFD` for the
    /// NVARCHAR/NCHAR and NTEXT arms only).
    ///
    /// - Defaults to `false`.
    pub fn lossy_utf16_decoding(mut self, lossy: bool) -> Self {
        self.inner.lossy_utf16_decoding = lossy;
        self
    }

    /// Supplies a client certificate and private key for mutual TLS.
    ///
    /// See [`Config::client_certificate`] for details and backend support.
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "rustls",
            feature = "native-tls",
            feature = "vendored-openssl"
        )))
    )]
    pub fn client_certificate(mut self, cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.inner.client_certificate(cert, key);
        self
    }

    /// Supplies a client identity from a PKCS#12 / PFX bundle for mutual TLS.
    ///
    /// See [`Config::client_certificate_pkcs12`] for details and backend
    /// support.
    #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "vendored-openssl")))
    )]
    pub fn client_certificate_pkcs12(
        mut self,
        path: impl Into<PathBuf>,
        password: impl Into<String>,
    ) -> Self {
        self.inner.client_certificate_pkcs12(path, password);
        self
    }

    /// Produces the finalized [`Config`] from this builder.
    ///
    /// [`Config`]: struct.Config.html
    pub fn build(self) -> Config {
        self.inner
    }
}

impl From<Config> for ConfigBuilder {
    fn from(config: Config) -> Self {
        ConfigBuilder { inner: config }
    }
}

impl From<ConfigBuilder> for Config {
    fn from(builder: ConfigBuilder) -> Self {
        builder.inner
    }
}

pub(crate) struct ServerDefinition {
    host: Option<String>,
    port: Option<u16>,
    instance: Option<String>,
}

/// Wrap a [`connection_string`] parse failure with actionable guidance.
///
/// The underlying ADO.NET / JDBC parser fails with a terse, low-level message
/// (for example "key-value pairs must be joined by a =") when a value contains
/// an unescaped special character such as `;`, `=` or `{` — a very common
/// cause of "cannot connect" reports for passwords with special characters.
/// Append a hint describing how to quote such values so the message is
/// self-explanatory. `quoting` spells out the escaping styles the specific
/// parser accepts (they differ between ADO.NET and JDBC) and `docs` names the
/// constructor whose rustdoc carries the full rules and the programmatic-build
/// workaround.
///
/// The hint is phrased conditionally because `connection_string::Error` is an
/// opaque string with no error kind, so this wrapper cannot tell a quoting
/// failure apart from an unrelated one (a bad port, a mistyped sub-protocol,
/// …); "if a value … contains a special character" keeps the guidance honest
/// for every failure while still solving the common quoting case.
fn connection_string_error(
    err: connection_string::Error,
    quoting: &str,
    docs: &str,
) -> crate::Error {
    // `connection_string::Error`'s `Display` already prefixes `Conversion
    // error: `; strip it so wrapping the text in `Error::Conversion` does not
    // duplicate the prefix.
    let err = err.to_string();
    let detail = err.strip_prefix("Conversion error: ").unwrap_or(&err);
    hinted_conversion_error(detail, quoting, docs)
}

/// Builds a `Conversion` error from a terse parser reason plus the shared
/// quoting hint, so every connection-string failure points the caller at the
/// escaping options and the programmatic `Config` API.
fn hinted_conversion_error(detail: &str, quoting: &str, docs: &str) -> crate::Error {
    crate::Error::Conversion(
        format!(
            "{detail}. hint: if a value such as a password contains a special \
             character (for example `;`, `=` or `{{`), it must be quoted — \
             {quoting}. Do not URL-encode the value (`%24` is sent literally, \
             not decoded to `$`). Non-ASCII values are not accepted by the \
             connection-string parser; build the `Config` programmatically \
             (see `{docs}`) to pass any value without escaping."
        )
        .into(),
    )
}

pub(crate) trait ConfigString {
    fn dict(&self) -> &HashMap<String, String>;

    fn server(&self) -> crate::Result<ServerDefinition>;

    fn authentication(&self) -> crate::Result<AuthMethod> {
        let user = self
            .dict()
            .get("uid")
            .or_else(|| self.dict().get("username"))
            .or_else(|| self.dict().get("user"))
            .or_else(|| self.dict().get("user id"))
            .map(|s| s.as_str());

        let pw = self
            .dict()
            .get("password")
            .or_else(|| self.dict().get("pwd"))
            .map(|s| s.as_str());

        match self
            .dict()
            .get("integratedsecurity")
            .or_else(|| self.dict().get("integrated security"))
        {
            #[cfg(all(windows, feature = "winauth"))]
            Some(val) if Self::is_sspi_or_truthy(val)? => match (user, pw) {
                (None, None) => Ok(AuthMethod::Integrated),
                _ => Ok(AuthMethod::windows(user.unwrap_or(""), pw.unwrap_or(""))),
            },
            // On Unix with `sspi-rs`, `IntegratedSecurity=SSPI` (or a truthy
            // value) uses NTLM when a username/password is supplied, and falls
            // back to Kerberos (`Integrated`) only if `integrated-auth-gssapi`
            // is also enabled and no credentials are given.
            #[cfg(all(unix, feature = "sspi-rs"))]
            Some(val) if Self::is_sspi_or_truthy(val)? => match (user, pw) {
                (Some(user), Some(pw)) => Ok(AuthMethod::windows(user, pw)),
                #[cfg(feature = "integrated-auth-gssapi")]
                (None, None) => Ok(AuthMethod::Integrated),
                _ => Ok(AuthMethod::windows(user.unwrap_or(""), pw.unwrap_or(""))),
            },
            #[cfg(all(
                feature = "integrated-auth-gssapi",
                not(all(unix, feature = "sspi-rs"))
            ))]
            Some(val) if Self::is_sspi_or_truthy(val)? => Ok(AuthMethod::Integrated),
            // Default (no integrated security): SQL Server authentication. A
            // missing user or password is intentionally passed through as an
            // empty string rather than rejected here — validation of the
            // credentials is deferred to the server LOGIN response, which
            // returns a precise authentication error. Failing early would also
            // break the (unusual but valid) case of an empty SQL login.
            _ => Ok(AuthMethod::sql_server(user.unwrap_or(""), pw.unwrap_or(""))),
        }
    }

    fn database(&self) -> Option<String> {
        self.dict()
            .get("database")
            .or_else(|| self.dict().get("initial catalog"))
            .or_else(|| self.dict().get("databasename"))
            .map(|db| db.to_string())
    }

    fn application_name(&self) -> Option<String> {
        self.dict()
            .get("application name")
            .or_else(|| self.dict().get("applicationname"))
            .map(|name| name.to_string())
    }

    fn trust_cert(&self) -> crate::Result<bool> {
        self.dict()
            .get("trustservercertificate")
            .map(Self::parse_bool)
            .unwrap_or(Ok(false))
    }

    fn trust_cert_ca(&self) -> Option<String> {
        self.dict()
            .get("trustservercertificateca")
            .map(|ca| ca.to_string())
    }

    fn hostname_in_certificate(&self) -> Option<String> {
        self.dict()
            .get("hostnameincertificate")
            .or_else(|| self.dict().get("hostname in certificate"))
            .map(|host| host.to_string())
    }

    fn client_name(&self) -> Option<String> {
        self.dict()
            .get("workstationid")
            .or_else(|| self.dict().get("workstation id"))
            .map(|name| name.to_string())
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn encrypt(&self) -> crate::Result<EncryptionLevel> {
        self.dict()
            .get("encrypt")
            .map(|val| match Self::parse_bool(val) {
                Ok(true) => Ok(EncryptionLevel::Required),
                Ok(false) => Ok(EncryptionLevel::Off),
                Err(_) if val == "DANGER_PLAINTEXT" => Ok(EncryptionLevel::NotSupported),
                Err(_) if val.eq_ignore_ascii_case("strict") && cfg!(feature = "tds80") => {
                    Ok(EncryptionLevel::Strict)
                }
                Err(_) if val.eq_ignore_ascii_case("strict") => Err(crate::Error::Conversion(
                    "encrypt=strict requires the crate's `tds80` feature to be enabled".into(),
                )),
                Err(e) => Err(e),
            })
            // When the `encrypt` keyword is omitted, default to requiring
            // encryption — matching `Config::default()` and modern ADO.NET
            // (`Encrypt=Mandatory`). Callers who want an unencrypted connection
            // must opt out explicitly with `encrypt=false` (or
            // `encrypt=DANGER_PLAINTEXT`).
            .unwrap_or(Ok(EncryptionLevel::Required))
    }

    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encrypt(&self) -> crate::Result<EncryptionLevel> {
        // Security (#305): a no-TLS build cannot encrypt, so an explicit request
        // to do so must fail loudly rather than silently downgrade to plaintext.
        // Token classification follows the with-TLS `encrypt()`: the values that
        // mean "encryption on" (`true`/`yes`/`strict`) become the TLS-missing
        // error, while opting out (`false`/`no`/`DANGER_PLAINTEXT`) and an
        // omitted keyword still resolve to `NotSupported`. (`strict` reports the
        // missing backend rather than the with-TLS `tds80`-required hint — a
        // TLS backend is the more fundamental thing it needs here.)
        let Some(val) = self.dict().get("encrypt") else {
            return Ok(EncryptionLevel::NotSupported);
        };

        match Self::parse_bool(val) {
            Ok(false) => Ok(EncryptionLevel::NotSupported),
            Err(_) if val == "DANGER_PLAINTEXT" => Ok(EncryptionLevel::NotSupported),
            Ok(true) => Err(Self::tls_backend_missing()),
            Err(_) if val.eq_ignore_ascii_case("strict") => Err(Self::tls_backend_missing()),
            Err(e) => Err(e),
        }
    }

    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn tls_backend_missing() -> crate::Error {
        crate::Error::Tls(
            "encryption was requested (`encrypt=...`) but the crate was compiled without a TLS \
             backend; enable one of the `native-tls`, `rustls` or `vendored-openssl` features."
                .to_string(),
        )
    }

    fn parse_bool<T: AsRef<str>>(v: T) -> crate::Result<bool> {
        match v.as_ref().trim().to_lowercase().as_str() {
            "true" | "yes" => Ok(true),
            "false" | "no" => Ok(false),
            _ => Err(crate::Error::Conversion(
                "Connection string: Not a valid boolean".into(),
            )),
        }
    }

    /// An `IntegratedSecurity` connection-string value selects Windows/SSPI auth
    /// when it is the literal `SSPI` (case-insensitive) or a truthy boolean.
    /// Uses `eq_ignore_ascii_case` so the `SSPI` comparison does not allocate.
    ///
    /// Only referenced by the integrated-auth match arms, which are themselves
    /// feature-gated; gate the helper identically so builds without any
    /// integrated-auth backend do not warn about it being unused.
    #[cfg(any(
        all(windows, feature = "winauth"),
        all(unix, feature = "sspi-rs"),
        feature = "integrated-auth-gssapi"
    ))]
    fn is_sspi_or_truthy<T: AsRef<str>>(v: T) -> crate::Result<bool> {
        let v = v.as_ref();
        Ok(v.eq_ignore_ascii_case("sspi") || Self::parse_bool(v)?)
    }

    fn readonly(&self) -> bool {
        self.dict()
            .get("applicationintent")
            .filter(|val| val.trim().eq_ignore_ascii_case("ReadOnly"))
            .is_some()
    }

    fn multi_subnet_failover(&self) -> crate::Result<bool> {
        self.dict()
            .get("multisubnetfailover")
            .map(Self::parse_bool)
            .unwrap_or(Ok(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
    use secrecy::ExposeSecret;

    #[test]
    fn config_debug_redacts_connection_password() {
        // The connection password lives inside `auth: AuthMethod`; the whole
        // `Config` Debug must never print it.
        let config = Config::builder()
            .authentication(AuthMethod::sql_server("SA", "conn-str-secret"))
            .build();

        let dbg = format!("{config:?}");
        assert!(
            !dbg.contains("conn-str-secret"),
            "connection password leaked in Config Debug: {dbg}"
        );
        assert!(dbg.contains("REDACTED"), "password not redacted: {dbg}");
    }

    #[test]
    fn config_builder_constructs_config() {
        let config = Config::builder()
            .host("db.example.com")
            .port(4433)
            .database("northwind")
            .application_name("my-app")
            .authentication(AuthMethod::sql_server("SA", "secret"))
            .readonly(true)
            .build();

        assert_eq!("db.example.com", config.get_host());
        assert_eq!(4433, config.get_port());
        assert_eq!("db.example.com:4433", config.get_addr());
        assert_eq!(Some("northwind"), config.database.as_deref());
        assert_eq!(Some("my-app"), config.application_name.as_deref());
        assert!(config.readonly);
        assert!(matches!(config.auth, AuthMethod::SqlServer(_)));
        assert!(config.trust.is_default());
    }

    #[test]
    fn config_builder_roundtrips_via_from() {
        let config = Config::builder().host("localhost").port(1433).build();
        let builder: ConfigBuilder = config.into();
        let config = builder.database("master").build();

        assert_eq!("localhost:1433", config.get_addr());
        assert_eq!(Some("master"), config.database.as_deref());
    }

    #[test]
    fn config_from_builder_carries_builder_settings() {
        // `From<ConfigBuilder>` must return the built inner config, not a default.
        let config: Config = Config::builder().host("db.internal").port(2020).into();
        assert_eq!("db.internal", config.get_host());
        assert_eq!(2020, config.get_port());
    }

    #[test]
    fn handshake_timeout_defaults_to_fifteen_seconds() {
        // A sensible, ADO.NET-matching default so a stalled handshake surfaces
        // an error instead of hanging forever.
        let config = Config::new();
        assert_eq!(
            config.get_handshake_timeout(),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn handshake_timeout_setter_roundtrips() {
        // Table-driven over the values a caller can set, including opting out.
        let cases = [
            Some(Duration::from_millis(1)),
            Some(Duration::from_secs(30)),
            None,
        ];
        for want in cases {
            let mut config = Config::new();
            config.handshake_timeout(want);
            assert_eq!(config.get_handshake_timeout(), want, "for {want:?}");
        }
    }

    #[test]
    fn config_builder_sets_handshake_timeout() {
        let config = Config::builder()
            .handshake_timeout(Some(Duration::from_secs(3)))
            .build();
        assert_eq!(config.get_handshake_timeout(), Some(Duration::from_secs(3)));

        // And can disable it.
        let config = Config::builder().handshake_timeout(None).build();
        assert_eq!(config.get_handshake_timeout(), None);
    }

    #[test]
    fn config_builder_defaults_handshake_timeout() {
        // The builder starts from `Config::default()`, so it inherits the bound.
        let config = Config::builder().build();
        assert_eq!(
            config.get_handshake_timeout(),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn command_timeout_defaults_to_thirty_seconds() {
        // ADO.NET-matching default so a mid-result server stall surfaces an
        // error instead of hanging forever.
        let config = Config::new();
        assert_eq!(config.get_command_timeout(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn command_timeout_setter_roundtrips() {
        let cases = [
            Some(Duration::from_millis(1)),
            Some(Duration::from_secs(60)),
            None,
        ];
        for want in cases {
            let mut config = Config::new();
            config.command_timeout(want);
            assert_eq!(config.get_command_timeout(), want, "for {want:?}");
        }
    }

    #[test]
    fn config_builder_sets_command_timeout() {
        let config = Config::builder()
            .command_timeout(Some(Duration::from_secs(7)))
            .build();
        assert_eq!(config.get_command_timeout(), Some(Duration::from_secs(7)));

        let config = Config::builder().command_timeout(None).build();
        assert_eq!(config.get_command_timeout(), None);
    }

    #[test]
    fn config_builder_defaults_command_timeout() {
        let config = Config::builder().build();
        assert_eq!(config.get_command_timeout(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn lossy_utf16_decoding_defaults_to_false() {
        let config = Config::new();
        assert!(!config.get_lossy_utf16_decoding());
    }

    #[test]
    fn lossy_utf16_decoding_setter_roundtrips() {
        let mut config = Config::new();
        config.lossy_utf16_decoding(true);
        assert!(config.get_lossy_utf16_decoding());
        config.lossy_utf16_decoding(false);
        assert!(!config.get_lossy_utf16_decoding());
    }

    #[test]
    fn config_builder_sets_lossy_utf16_decoding() {
        let config = Config::builder().lossy_utf16_decoding(true).build();
        assert!(config.get_lossy_utf16_decoding());
    }

    #[test]
    fn config_builder_defaults_lossy_utf16_decoding() {
        let config = Config::builder().build();
        assert!(!config.get_lossy_utf16_decoding());
    }

    #[test]
    fn timeouts_are_independent() {
        // The two knobs must not alias one another.
        let mut config = Config::new();
        config.handshake_timeout(Some(Duration::from_secs(1)));
        config.command_timeout(Some(Duration::from_secs(2)));
        assert_eq!(config.get_handshake_timeout(), Some(Duration::from_secs(1)));
        assert_eq!(config.get_command_timeout(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn get_packet_size_reflects_the_set_value() {
        let mut config = Config::new();
        assert_eq!(config.get_packet_size(), None);
        config.packet_size(8192);
        assert_eq!(config.get_packet_size(), Some(8192));
    }

    #[test]
    fn from_jdbc_string_parses_host_and_port() {
        let config =
            Config::from_jdbc_string("jdbc:sqlserver://db.example.com:2345").expect("valid jdbc");
        assert_eq!("db.example.com", config.get_host());
        assert_eq!(2345, config.get_port());
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[test]
    fn get_hostname_in_certificate_falls_back_to_host() {
        let mut config = Config::new();
        config.host("real.host");
        // Unset: falls back to the connection host.
        assert_eq!(config.get_hostname_in_certificate(), "real.host");
        // Set: returns the explicit certificate hostname.
        config.hostname_in_certificate("cert.host");
        assert_eq!(config.get_hostname_in_certificate(), "cert.host");
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[test]
    fn client_certificate_sets_cert_and_key_source() {
        let mut config = Config::new();
        assert!(config.get_client_certificate().is_none());

        config.client_certificate("/tmp/client.pem", "/tmp/client.key");

        let cert = config
            .get_client_certificate()
            .expect("client certificate should be set");
        match &cert.source {
            ClientCertSource::CertAndKey { cert, key } => {
                assert_eq!(cert, &PathBuf::from("/tmp/client.pem"));
                assert_eq!(key, &PathBuf::from("/tmp/client.key"));
            }
            #[allow(unreachable_patterns)]
            other => panic!("expected CertAndKey source, got {other:?}"),
        }
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[test]
    fn config_builder_sets_client_certificate() {
        let config = Config::builder()
            .host("localhost")
            .client_certificate("cert.der", "key.der")
            .build();

        match &config
            .get_client_certificate()
            .expect("client certificate should be set")
            .source
        {
            ClientCertSource::CertAndKey { cert, key } => {
                assert_eq!(cert, &PathBuf::from("cert.der"));
                assert_eq!(key, &PathBuf::from("key.der"));
            }
            #[allow(unreachable_patterns)]
            other => panic!("expected CertAndKey source, got {other:?}"),
        }
    }

    #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
    #[test]
    fn client_certificate_pkcs12_sets_bundle_source() {
        let mut config = Config::new();
        config.client_certificate_pkcs12("/tmp/identity.pfx", "s3cr3t");

        match &config
            .get_client_certificate()
            .expect("client certificate should be set")
            .source
        {
            ClientCertSource::Pkcs12 { path, password } => {
                assert_eq!(path, &PathBuf::from("/tmp/identity.pfx"));
                assert_eq!(password.expose_secret(), "s3cr3t");
            }
            other => panic!("expected Pkcs12 source, got {other:?}"),
        }
    }

    #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
    #[test]
    fn client_certificate_debug_redacts_pkcs12_password() {
        let mut config = Config::new();
        config.client_certificate_pkcs12("/tmp/identity.pfx", "topsecret");

        let dbg = format!("{:?}", config.get_client_certificate().unwrap());
        assert!(dbg.contains("REDACTED"), "password not redacted: {dbg}");
        assert!(!dbg.contains("topsecret"), "password leaked: {dbg}");
    }

    #[cfg(all(unix, feature = "sspi-rs"))]
    #[test]
    fn ado_integrated_security_sspi_with_credentials_uses_windows_ntlm() {
        let config = Config::from_ado_string(
            "server=tcp:localhost,1433;IntegratedSecurity=SSPI;uid=DOMAIN\\user;pwd=secret",
        )
        .unwrap();

        match config.auth {
            AuthMethod::Windows(auth) => {
                assert_eq!("user", auth.user);
                assert_eq!(Some("DOMAIN"), auth.domain.as_deref());
            }
            other => panic!("expected Windows NTLM auth, got {other:?}"),
        }
    }

    #[test]
    fn config_direct_setters_populate_fields() {
        let mut config = Config::new();
        config.database("northwind");
        config.instance_name("SQLEXPRESS");
        config.client_name("workstation-7");

        assert_eq!(Some("northwind"), config.database.as_deref());
        assert_eq!(Some("SQLEXPRESS"), config.instance_name.as_deref());
        assert_eq!(Some("workstation-7"), config.client_name.as_deref());
    }

    #[test]
    fn get_port_defaults_without_port_or_instance() {
        // No explicit port and no instance -> default SQL Server port.
        let config = Config::new();
        assert_eq!(1433, config.get_port());
    }

    #[test]
    fn get_port_uses_sql_browser_port_for_named_instance() {
        // A named instance without an explicit port -> SQL Browser port.
        let mut config = Config::new();
        config.instance_name("SQLEXPRESS");
        assert_eq!(1434, config.get_port());
    }

    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn trust_cert_after_trust_cert_ca_panics() {
        let mut config = Config::new();
        config.trust_cert_ca("/tmp/ca.crt");
        config.trust_cert();
    }

    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn trust_cert_ca_after_trust_cert_panics() {
        let mut config = Config::new();
        config.trust_cert();
        config.trust_cert_ca("/tmp/ca.crt");
    }

    #[test]
    fn trust_cert_ca_sets_ca_location() {
        let mut config = Config::new();
        config.trust_cert_ca("/tmp/ca.crt");
        assert!(matches!(
            config.trust.extra_cas.as_slice(),
            [ExtraCa::File(_)]
        ));
        assert!(!config.trust.bypass);
        assert!(matches!(config.trust.source, RootSource::Native));
    }

    #[test]
    fn trust_cert_ca_accumulates_across_calls() {
        // Repeated calls are additive (not replace-last-wins): both CAs must
        // be trusted, across file + bundle sources.
        let mut config = Config::new();
        config.trust_cert_ca("/tmp/a.crt");
        config.trust_cert_ca("/tmp/b.crt");
        config.trust_cert_ca_bundle(b"----- not really a cert -----".to_vec());

        assert_eq!(config.trust.extra_cas.len(), 3);
        match &config.trust.extra_cas[0] {
            ExtraCa::File(p) => assert_eq!(p, &PathBuf::from("/tmp/a.crt")),
            other => panic!("expected File, got {other:?}"),
        }
        match &config.trust.extra_cas[1] {
            ExtraCa::File(p) => assert_eq!(p, &PathBuf::from("/tmp/b.crt")),
            other => panic!("expected File, got {other:?}"),
        }
        assert!(matches!(config.trust.extra_cas[2], ExtraCa::Bundle(_)));
    }

    #[test]
    fn trust_cert_ca_bundle_pushes_bundle() {
        let mut config = Config::new();
        config.trust_cert_ca_bundle(vec![1u8, 2, 3]);
        match config.trust.extra_cas.as_slice() {
            [ExtraCa::Bundle(bytes)] => assert_eq!(bytes, &[1, 2, 3]),
            other => panic!("expected a single Bundle, got {other:?}"),
        }
    }

    #[test]
    fn trust_config_debug_redacts_bundle_bytes() {
        // The bundle's raw bytes must never appear in Debug; only a
        // length summary.
        let mut config = Config::new();
        config.trust_cert_ca_bundle(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let dbg = format!("{:?}", config.trust);
        assert!(dbg.contains("Bundle { len: 4 }"), "got: {dbg}");
        assert!(
            !dbg.contains("222") && !dbg.contains("0xde"),
            "bytes leaked: {dbg}"
        );
    }

    #[cfg(feature = "rustls-webpki-roots")]
    #[test]
    fn trust_webpki_roots_sets_source_and_is_mutually_exclusive_with_extras() {
        let mut config = Config::new();
        config.trust_webpki_roots();
        assert!(matches!(config.trust.source, RootSource::WebpkiRoots));
        // Extra CAs still layer on top of the webpki source.
        config.trust_cert_ca("/tmp/extra.crt");
        assert_eq!(config.trust.extra_cas.len(), 1);
    }

    #[cfg(feature = "rustls-webpki-roots")]
    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn trust_cert_after_trust_webpki_roots_panics() {
        let mut config = Config::new();
        config.trust_webpki_roots();
        config.trust_cert();
    }

    #[cfg(feature = "rustls-webpki-roots")]
    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn trust_webpki_roots_after_trust_cert_panics() {
        let mut config = Config::new();
        config.trust_cert();
        config.trust_webpki_roots();
    }

    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn trust_cert_after_trust_cert_ca_bundle_panics() {
        let mut config = Config::new();
        config.trust_cert_ca_bundle(vec![1, 2, 3]);
        config.trust_cert();
    }

    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn trust_cert_ca_bundle_after_trust_cert_panics() {
        let mut config = Config::new();
        config.trust_cert();
        config.trust_cert_ca_bundle(vec![1, 2, 3]);
    }

    #[test]
    fn trust_cert_sets_bypass() {
        // The default must be a validating config; `trust_cert()` is the explicit
        // opt-in that switches to bypass validation.
        let mut config = Config::new();
        assert!(config.trust.is_default());
        config.trust_cert();
        assert!(config.trust.bypass);
    }

    #[test]
    fn config_builder_covers_all_setters() {
        let config = Config::builder()
            .host("localhost")
            .instance_name("SQLEXPRESS")
            .encryption(EncryptionLevel::Off)
            .trust_cert_ca("/tmp/ca.crt")
            .build();

        assert_eq!(Some("SQLEXPRESS"), config.instance_name.as_deref());
        assert!(matches!(config.encryption, EncryptionLevel::Off));
        assert!(matches!(
            config.trust.extra_cas.as_slice(),
            [ExtraCa::File(_)]
        ));
    }

    #[test]
    fn config_builder_trust_cert_sets_bypass() {
        let config = Config::builder().trust_cert().build();
        assert!(config.trust.bypass);
    }

    #[test]
    fn config_builder_trust_cert_ca_bundle_accumulates() {
        let config = Config::builder()
            .trust_cert_ca("/tmp/a.crt")
            .trust_cert_ca_bundle(vec![1, 2, 3])
            .build();
        assert_eq!(config.trust.extra_cas.len(), 2);
    }

    #[cfg(feature = "rustls-webpki-roots")]
    #[test]
    fn config_builder_trust_webpki_roots_sets_source() {
        let config = Config::builder().trust_webpki_roots().build();
        assert!(matches!(config.trust.source, RootSource::WebpkiRoots));
    }

    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn config_builder_trust_cert_after_ca_panics() {
        Config::builder().trust_cert_ca("/tmp/ca.crt").trust_cert();
    }

    #[test]
    #[should_panic(expected = "mutual exclusive")]
    fn config_builder_trust_cert_ca_after_trust_cert_panics() {
        Config::builder().trust_cert().trust_cert_ca("/tmp/ca.crt");
    }

    #[test]
    fn from_ado_string_populates_optional_fields() {
        let config = Config::from_ado_string(
            "server=tcp:my-server.com\\SQLEXPRESS;database=northwind;\
             HostNameInCertificate=cert.host;WorkstationID=ws-1",
        )
        .expect("valid ado string");

        assert_eq!("my-server.com", config.get_host());
        assert_eq!(Some("SQLEXPRESS"), config.instance_name.as_deref());
        assert_eq!(Some("northwind"), config.database.as_deref());
        assert_eq!(Some("cert.host"), config.hostname_in_certificate.as_deref());
        assert_eq!(Some("ws-1"), config.client_name.as_deref());
    }

    #[test]
    fn from_ado_string_trust_cert_ca_populates_extra_cas() {
        let config = Config::from_ado_string(
            "server=tcp:localhost,1433;TrustServerCertificateCA=/tmp/ca.crt",
        )
        .expect("valid ado string");
        match config.trust.extra_cas.as_slice() {
            [ExtraCa::File(p)] => assert_eq!(p, &PathBuf::from("/tmp/ca.crt")),
            other => panic!("expected a single File CA, got {other:?}"),
        }
        assert!(!config.trust.bypass);
    }

    #[test]
    fn from_ado_string_trust_cert_populates_bypass() {
        let config =
            Config::from_ado_string("server=tcp:localhost,1433;TrustServerCertificate=true")
                .expect("valid ado string");
        assert!(config.trust.bypass);
    }

    #[test]
    fn from_ado_string_trust_cert_and_ca_conflict_errors() {
        // The conflict must surface as a hard error, never silently let
        // the bypass win. From a connection string it is an `Err`, not a panic.
        let err = Config::from_ado_string(
            "server=tcp:localhost,1433;TrustServerCertificate=true;\
             TrustServerCertificateCA=/tmp/ca.crt",
        )
        .expect_err("conflicting trust settings must error");
        match err {
            crate::Error::Conversion(msg) => {
                assert!(msg.contains("mutually exclusive"), "got: {msg}")
            }
            other => panic!("expected Conversion error, got {other:?}"),
        }
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[test]
    fn client_cert_source_debug_formats_cert_and_key() {
        let mut config = Config::new();
        config.client_certificate("/tmp/client.pem", "/tmp/client.key");

        let dbg = format!("{:?}", config.get_client_certificate().unwrap().source);
        assert!(dbg.contains("CertAndKey"));
        assert!(dbg.contains("client.pem"));
        assert!(dbg.contains("client.key"));
    }

    #[cfg(any(feature = "native-tls", feature = "vendored-openssl"))]
    #[test]
    fn config_builder_sets_pkcs12_client_certificate() {
        let config = Config::builder()
            .client_certificate_pkcs12("/tmp/identity.pfx", "s3cr3t")
            .build();

        match &config
            .get_client_certificate()
            .expect("client certificate should be set")
            .source
        {
            ClientCertSource::Pkcs12 { path, password } => {
                assert_eq!(path, &PathBuf::from("/tmp/identity.pfx"));
                assert_eq!(password.expose_secret(), "s3cr3t");
            }
            other => panic!("expected Pkcs12 source, got {other:?}"),
        }
    }

    #[cfg(all(unix, feature = "sspi-rs"))]
    #[test]
    fn ado_integrated_security_sspi_with_partial_credentials_uses_windows() {
        // Only a username (no password) -> falls into the catch-all NTLM arm.
        let config = Config::from_ado_string(
            "server=tcp:localhost,1433;IntegratedSecurity=SSPI;uid=onlyuser",
        )
        .unwrap();

        match config.auth {
            AuthMethod::Windows(auth) => {
                assert_eq!("onlyuser", auth.user);
            }
            other => panic!("expected Windows auth, got {other:?}"),
        }
    }
}
