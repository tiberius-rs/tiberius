use std::fmt::Debug;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub struct SqlServerAuth {
    user: String,
    password: Zeroizing<String>,
}

impl SqlServerAuth {
    pub(crate) fn into_credentials(self) -> (String, Zeroizing<String>) {
        (self.user, self.password)
    }
}

impl Debug for SqlServerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlServerAuth")
            .field("user", &self.user)
            .field("password", &"<HIDDEN>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"))))
)]
pub struct WindowsAuth {
    pub(crate) user: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: Option<String>,
}

#[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"))))
)]
impl Debug for WindowsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsAuth")
            .field("user", &self.user)
            .field("password", &"<HIDDEN>")
            .field("domain", &self.domain)
            .finish()
    }
}

/// Defines the method of authentication to the server.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// Authenticate directly with SQL Server.
    SqlServer(SqlServerAuth),
    /// Authenticate with Windows credentials. On Windows this uses SSPI via the
    /// `winauth` feature; on Unix it uses NTLM (no Kerberos) via the `sspi-rs`
    /// feature.
    #[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"))))
    )]
    Windows(WindowsAuth),
    /// Authenticate as the currently logged in user. On Windows uses SSPI and
    /// Kerberos on Unix platforms.
    #[cfg(any(
        all(windows, feature = "winauth"),
        all(unix, feature = "integrated-auth-gssapi"),
        doc
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(windows, all(unix, feature = "integrated-auth-gssapi"))))
    )]
    Integrated,
    /// Authenticate with an AAD token. The token should encode an AAD user/service principal
    /// which has access to SQL Server.
    AADToken(String),
    #[doc(hidden)]
    None,
}

// Manual Debug so the AAD bearer token is never printed. The credential-bearing
// SqlServer/Windows variants delegate to their inner types, which already redact.
impl Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqlServer(a) => f.debug_tuple("SqlServer").field(a).finish(),
            #[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
            Self::Windows(a) => f.debug_tuple("Windows").field(a).finish(),
            #[cfg(any(
                all(windows, feature = "winauth"),
                all(unix, feature = "integrated-auth-gssapi"),
                doc
            ))]
            Self::Integrated => f.write_str("Integrated"),
            Self::AADToken(_) => f.debug_tuple("AADToken").field(&"<HIDDEN>").finish(),
            Self::None => f.write_str("None"),
        }
    }
}

impl AuthMethod {
    /// Construct a new SQL Server authentication configuration.
    pub fn sql_server(user: impl ToString, password: impl ToString) -> Self {
        Self::SqlServer(SqlServerAuth {
            user: user.to_string(),
            password: Zeroizing::new(password.to_string()),
        })
    }

    /// Construct a new Windows authentication configuration.
    #[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"))))
    )]
    pub fn windows(user: impl AsRef<str>, password: impl ToString) -> Self {
        let (domain, user) = match user.as_ref().find('\\') {
            Some(idx) => (Some(&user.as_ref()[..idx]), &user.as_ref()[idx + 1..]),
            _ => (None, user.as_ref()),
        };

        Self::Windows(WindowsAuth {
            user: user.to_string(),
            password: Zeroizing::new(password.to_string()),
            domain: domain.map(|s| s.to_string()),
        })
    }

    /// Construct a new configuration with AAD auth token.
    pub fn aad_token(token: impl ToString) -> Self {
        Self::AADToken(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::AuthMethod;
    use zeroize::Zeroize;

    #[test]
    fn sql_server_password_can_be_consumed_and_zeroized() {
        let AuthMethod::SqlServer(auth) = AuthMethod::sql_server("sa", "secret") else {
            unreachable!();
        };

        let (user, mut password) = auth.into_credentials();

        assert_eq!("sa", user);
        assert_eq!("secret", password.as_str());

        password.zeroize();

        assert!(password.is_empty());
    }

    #[test]
    fn debug_redacts_credentials() {
        let sql = format!("{:?}", AuthMethod::sql_server("sa", "sql-secret"));
        assert!(!sql.contains("sql-secret"), "SQL password leaked: {sql}");

        let aad = format!("{:?}", AuthMethod::aad_token("aad-secret-token"));
        assert!(!aad.contains("aad-secret-token"), "AAD token leaked: {aad}");
        assert!(aad.contains("HIDDEN"));
    }

    #[test]
    fn debug_none_variant() {
        assert_eq!(format!("{:?}", AuthMethod::None), "None");
    }

    #[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs")))]
    #[test]
    fn windows_auth_parses_domain_and_debug_redacts() {
        // `DOMAIN\user` form exercises the domain-splitting branch of `windows()`.
        let auth = AuthMethod::windows("DOMAIN\\user", "win-secret");
        let dbg = format!("{:?}", auth);
        assert!(dbg.contains("Windows"), "variant name missing: {dbg}");
        assert!(dbg.contains("DOMAIN"), "domain not preserved: {dbg}");
        assert!(dbg.contains("user"), "user not preserved: {dbg}");
        assert!(!dbg.contains("win-secret"), "password leaked: {dbg}");

        // No backslash exercises the domain-less branch.
        let plain = AuthMethod::windows("plainuser", "pw");
        let dbg = format!("{:?}", plain);
        assert!(dbg.contains("plainuser"), "user not preserved: {dbg}");
        assert!(dbg.contains("None"), "domain should be None: {dbg}");
    }

    #[cfg(any(
        all(windows, feature = "winauth"),
        all(unix, feature = "integrated-auth-gssapi")
    ))]
    #[test]
    fn integrated_debug() {
        assert_eq!(format!("{:?}", AuthMethod::Integrated), "Integrated");
    }
}
