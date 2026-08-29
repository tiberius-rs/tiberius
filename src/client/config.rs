mod ado_net;
mod jdbc;

use std::collections::HashMap;
use std::path::PathBuf;

use super::AuthMethod;
use crate::EncryptionLevel;
use ado_net::*;
use jdbc::*;

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
    pub(crate) multi_subnet_failover: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum TrustConfig {
    #[allow(dead_code)]
    CaCertificateLocation(PathBuf),
    TrustAll,
    Default,
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
            trust: TrustConfig::Default,
            auth: AuthMethod::None,
            readonly: false,
            multi_subnet_failover: false,
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
    /// - With `tls` feature, defaults to `Required`.
    /// - Without `tls` feature, defaults to `NotSupported`.
    pub fn encryption(&mut self, encryption: EncryptionLevel) {
        self.encryption = encryption;
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
    pub fn trust_cert(&mut self) {
        if let TrustConfig::CaCertificateLocation(_) = &self.trust {
            panic!("'trust_cert' and 'trust_cert_ca' are mutual exclusive! Only use one.")
        }
        self.trust = TrustConfig::TrustAll;
    }

    /// If set, the server certificate will be validated against the given CA certificate in
    /// in addition to the system-truststore.
    /// Useful when using self-signed certificates on the server without having to disable the
    /// trust-chain.
    ///
    /// # Panics
    /// Will panic in case `trust_cert` was called before.
    ///
    /// - Defaults to validating the server certificate is validated against system's certificate storage.
    pub fn trust_cert_ca(&mut self, path: impl ToString) {
        if let TrustConfig::TrustAll = &self.trust {
            panic!("'trust_cert' and 'trust_cert_ca' are mutual exclusive! Only use one.")
        } else {
            self.trust = TrustConfig::CaCertificateLocation(PathBuf::from(path.to_string()))
        }
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
    pub fn readonly(&mut self, readnoly: bool) {
        self.readonly = readnoly;
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
    /// |`MultiSubnetFailover`|`true`,`false`,`yes`,`no`|When enabled, connections are attempted in parallel to all IP addresses the server resolves to, and the first to succeed is used.|
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

        if s.trust_cert()? {
            builder.trust_cert();
        }

        if let Some(ca) = s.trust_cert_ca() {
            builder.trust_cert_ca(ca);
        }

        if let Some(hostname_in_cert) = s.hostname_in_certificate() {
            builder.hostname_in_certificate(hostname_in_cert);
        }

        builder.encryption(s.encrypt()?);

        builder.readonly(s.readonly());

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
    /// - With `tls` feature, defaults to `Required`.
    /// - Without `tls` feature, defaults to `NotSupported`.
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
        if let TrustConfig::CaCertificateLocation(_) = &self.inner.trust {
            panic!("'trust_cert' and 'trust_cert_ca' are mutual exclusive! Only use one.")
        }
        self.inner.trust = TrustConfig::TrustAll;
        self
    }

    /// If set, the server certificate will be validated against the given CA certificate in
    /// in addition to the system-truststore.
    /// Useful when using self-signed certificates on the server without having to disable the
    /// trust-chain.
    ///
    /// # Panics
    /// Will panic in case `trust_cert` was called before.
    ///
    /// - Defaults to validating the server certificate is validated against system's certificate storage.
    pub fn trust_cert_ca(mut self, path: impl ToString) -> Self {
        if let TrustConfig::TrustAll = &self.inner.trust {
            panic!("'trust_cert' and 'trust_cert_ca' are mutual exclusive! Only use one.")
        } else {
            self.inner.trust = TrustConfig::CaCertificateLocation(PathBuf::from(path.to_string()))
        }
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
            Some(val) if val.to_lowercase() == "sspi" || Self::parse_bool(val)? => match (user, pw)
            {
                (None, None) => Ok(AuthMethod::Integrated),
                _ => Ok(AuthMethod::windows(user.unwrap_or(""), pw.unwrap_or(""))),
            },
            // On Unix with `sspi-rs`, `IntegratedSecurity=SSPI` (or a truthy
            // value) uses NTLM when a username/password is supplied, and falls
            // back to Kerberos (`Integrated`) only if `integrated-auth-gssapi`
            // is also enabled and no credentials are given.
            #[cfg(all(unix, feature = "sspi-rs"))]
            Some(val) if val.to_lowercase() == "sspi" || Self::parse_bool(val)? => {
                match (user, pw) {
                    (Some(user), Some(pw)) => Ok(AuthMethod::windows(user, pw)),
                    #[cfg(feature = "integrated-auth-gssapi")]
                    (None, None) => Ok(AuthMethod::Integrated),
                    _ => Ok(AuthMethod::windows(user.unwrap_or(""), pw.unwrap_or(""))),
                }
            }
            #[cfg(all(
                feature = "integrated-auth-gssapi",
                not(all(unix, feature = "sspi-rs"))
            ))]
            Some(val) if val.to_lowercase() == "sspi" || Self::parse_bool(val)? => {
                Ok(AuthMethod::Integrated)
            }
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
                Err(e) => Err(e),
            })
            .unwrap_or(Ok(EncryptionLevel::Off))
    }

    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encrypt(&self) -> crate::Result<EncryptionLevel> {
        Ok(EncryptionLevel::NotSupported)
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
        assert!(matches!(config.trust, TrustConfig::Default));
    }

    #[test]
    fn config_builder_roundtrips_via_from() {
        let config = Config::builder().host("localhost").port(1433).build();
        let builder: ConfigBuilder = config.into();
        let config = builder.database("master").build();

        assert_eq!("localhost:1433", config.get_addr());
        assert_eq!(Some("master"), config.database.as_deref());
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
}
