use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

/// Build a `SecretString` from owned bytes without leaving an un-zeroized copy
/// in freed heap. `SecretString::from(String)` routes through
/// `String::into_boxed_str()`, which reallocates and frees the source buffer
/// *without zeroizing* when the string has spare capacity. Copy the bytes into
/// an exact-sized `Box<str>` and wipe the original.
pub(crate) fn secret_from_string(mut s: String) -> SecretString {
    let boxed: Box<str> = s.as_str().into();
    s.zeroize();
    SecretString::new(boxed)
}

// Credentials are stored as `secrecy::SecretString`, which zeroizes the
// plaintext on drop and redacts it from `Debug`, so these types can derive
// `Debug` and still never print a secret. `SecretString` does not implement
// `PartialEq`/`Eq` (comparing secrets is deliberately opt-in), so the equality
// impls below are hand-written; they compare the exposed plaintext to preserve
// the previous derived behaviour (and the public `AuthMethod: Eq` bound).
#[derive(Clone, Debug)]
pub struct SqlServerAuth {
    user: String,
    password: SecretString,
}

impl SqlServerAuth {
    pub(crate) fn into_credentials(self) -> (String, SecretString) {
        (self.user, self.password)
    }
}

impl PartialEq for SqlServerAuth {
    fn eq(&self, other: &Self) -> bool {
        self.user == other.user && self.password.expose_secret() == other.password.expose_secret()
    }
}

impl Eq for SqlServerAuth {}

#[derive(Clone, Debug)]
#[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"))))
)]
pub struct WindowsAuth {
    pub(crate) user: String,
    pub(crate) password: SecretString,
    pub(crate) domain: Option<String>,
}

#[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
impl PartialEq for WindowsAuth {
    fn eq(&self, other: &Self) -> bool {
        self.user == other.user
            && self.domain == other.domain
            && self.password.expose_secret() == other.password.expose_secret()
    }
}

#[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
impl Eq for WindowsAuth {}

/// Defines the method of authentication to the server.
#[derive(Clone, Debug)]
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
    AADToken(SecretString),
    #[doc(hidden)]
    None,
}

// `SecretString` has no `PartialEq`, so `AuthMethod`'s public equality is
// hand-written. It mirrors the old derived behaviour: same variant + equal
// fields (secrets compared via their exposed plaintext).
impl PartialEq for AuthMethod {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SqlServer(a), Self::SqlServer(b)) => a == b,
            #[cfg(any(all(windows, feature = "winauth"), all(unix, feature = "sspi-rs"), doc))]
            (Self::Windows(a), Self::Windows(b)) => a == b,
            #[cfg(any(
                all(windows, feature = "winauth"),
                all(unix, feature = "integrated-auth-gssapi"),
                doc
            ))]
            (Self::Integrated, Self::Integrated) => true,
            (Self::AADToken(a), Self::AADToken(b)) => a.expose_secret() == b.expose_secret(),
            (Self::None, Self::None) => true,
            _ => false,
        }
    }
}

impl Eq for AuthMethod {}

impl AuthMethod {
    /// Construct a new SQL Server authentication configuration.
    pub fn sql_server(user: impl ToString, password: impl ToString) -> Self {
        Self::SqlServer(SqlServerAuth {
            user: user.to_string(),
            password: secret_from_string(password.to_string()),
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
            password: secret_from_string(password.to_string()),
            domain: domain.map(|s| s.to_string()),
        })
    }

    /// Construct a new configuration with AAD auth token.
    pub fn aad_token(token: impl ToString) -> Self {
        Self::AADToken(secret_from_string(token.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::AuthMethod;
    use secrecy::ExposeSecret;

    // Compile-time proof that the stored credential zeroizes its plaintext on
    // drop: `secrecy::SecretString` implements `ZeroizeOnDrop`.
    #[test]
    fn stored_credentials_are_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<secrecy::SecretString>();
    }

    #[test]
    fn sql_server_password_can_be_consumed_and_exposed() {
        let AuthMethod::SqlServer(auth) = AuthMethod::sql_server("sa", "secret") else {
            unreachable!();
        };

        let (user, password) = auth.into_credentials();

        assert_eq!("sa", user);
        // `expose_secret()` yields exactly the plaintext that was provided.
        assert_eq!("secret", password.expose_secret());
        // The credential is dropped (and zeroized) at the end of this scope.
    }

    #[test]
    fn aad_token_exposes_the_right_value() {
        let AuthMethod::AADToken(token) = AuthMethod::aad_token("aad-secret-token") else {
            unreachable!();
        };
        assert_eq!("aad-secret-token", token.expose_secret());
    }

    #[test]
    fn debug_redacts_credentials() {
        let sql = format!("{:?}", AuthMethod::sql_server("sa", "sql-secret"));
        assert!(!sql.contains("sql-secret"), "SQL password leaked: {sql}");
        // The non-secret user is still visible for diagnostics.
        assert!(sql.contains("sa"), "user should be shown: {sql}");
        assert!(sql.contains("REDACTED"), "password not redacted: {sql}");

        let aad = format!("{:?}", AuthMethod::aad_token("aad-secret-token"));
        assert!(!aad.contains("aad-secret-token"), "AAD token leaked: {aad}");
        assert!(aad.contains("REDACTED"), "AAD token not redacted: {aad}");
    }

    #[test]
    fn secret_from_string_preserves_value_with_spare_capacity() {
        // A `String` with spare capacity is exactly the input shape that would
        // trigger the leaky `SecretString::from(String)` reallocation path. This
        // test verifies the helper preserves the value for that shape. The
        // zeroization of the freed source is guaranteed by construction
        // (`s.zeroize()` before drop) and is not directly unit-observable in
        // safe Rust, so it is not asserted here.
        let mut s = String::with_capacity(64);
        s.push_str("pw");
        assert_eq!(super::secret_from_string(s).expose_secret(), "pw");
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
        assert!(dbg.contains("REDACTED"), "password not redacted: {dbg}");

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
