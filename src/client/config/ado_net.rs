use super::{ConfigString, ServerDefinition};
use std::str::FromStr;

pub(crate) struct AdoNetConfig {
    dict: connection_string::AdoNetString,
}

impl FromStr for AdoNetConfig {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        let dict = s.parse().map_err(|e| {
            super::connection_string_error(
                e,
                "wrap the value in single quotes (e.g. `password='p@ss;word'`), \
                 double quotes, or braces (e.g. `password={p@ss;word}`), and \
                 quote leading spaces too",
                "Config::from_ado_string",
            )
        })?;
        Ok(Self { dict })
    }
}

impl ConfigString for AdoNetConfig {
    fn dict(&self) -> &std::collections::HashMap<String, String> {
        &self.dict
    }

    fn server(&self) -> crate::Result<ServerDefinition> {
        fn parse_port(parts: &[&str]) -> crate::Result<Option<u16>> {
            Ok(match parts.first() {
                Some(s) => Some(s.parse()?),
                None => None,
            })
        }

        fn parse_server(parts: Vec<&str>) -> crate::Result<ServerDefinition> {
            if parts.is_empty() || parts.len() >= 3 {
                return Err(crate::Error::Conversion("Server value faulty.".into()));
            }

            let definition = if parts[0].contains('\\') {
                let port = parse_port(&parts[1..])?;
                let parts: Vec<&str> = parts[0].split('\\').collect();

                ServerDefinition {
                    host: Some(parts[0].replace("(local)", "localhost")),
                    port,
                    instance: Some(parts[1].into()),
                }
            } else {
                // Connect using a TCP target
                ServerDefinition {
                    host: Some(parts[0].replace("(local)", "localhost")),
                    port: parse_port(&parts[1..])?,
                    instance: None,
                }
            };

            Ok(definition)
        }

        match self
            .dict
            .get("server")
            .or_else(|| self.dict.get("data source"))
        {
            Some(value) if value.starts_with("tcp:") => {
                parse_server(value[4..].split(',').collect())
            }
            Some(value) => parse_server(value.split(',').collect()),
            None => Ok(ServerDefinition {
                host: None,
                port: None,
                instance: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::AuthMethod;

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    use crate::EncryptionLevel;

    #[test]
    fn server_parsing_no_browser() -> crate::Result<()> {
        let test_str = "server=tcp:my-server.com,4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        let test_str = "data source=tcp:my-server.com,4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        Ok(())
    }

    #[test]
    fn server_parsing_no_tcp() -> crate::Result<()> {
        let test_str = "server=my-server.com,4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        let test_str = "data source=my-server.com,4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        Ok(())
    }

    #[test]
    fn server_parsing_local() -> crate::Result<()> {
        let test_str = "server=tcp:(local),4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("localhost".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        let test_str = "data source=tcp:(local),4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("localhost".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        Ok(())
    }

    #[test]
    fn server_parsing_local_no_tcp() -> crate::Result<()> {
        let test_str = "server=(local),4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("localhost".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        let test_str = "data source=(local),4200";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("localhost".to_string()), server.host);
        assert_eq!(Some(4200), server.port);
        assert_eq!(None, server.instance);

        Ok(())
    }

    #[test]
    fn server_parsing_no_port() -> crate::Result<()> {
        let test_str = "server=tcp:my-server.com";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(None, server.port);
        assert_eq!(None, server.instance);

        let test_str = "server=my-server.com";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(None, server.port);
        assert_eq!(None, server.instance);

        Ok(())
    }

    #[test]
    fn server_parsing_with_browser() -> crate::Result<()> {
        let test_str = "server=tcp:my-server.com\\TIBERIUS";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(None, server.port);
        assert_eq!(Some("TIBERIUS".to_string()), server.instance);

        let test_str = "data source=tcp:my-server.com\\TIBERIUS";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(None, server.port);
        assert_eq!(Some("TIBERIUS".to_string()), server.instance);

        Ok(())
    }

    #[test]
    fn server_parsing_with_browser_and_port() -> crate::Result<()> {
        let test_str = "server=tcp:my-server.com\\TIBERIUS,666";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(Some(666), server.port);
        assert_eq!(Some("TIBERIUS".to_string()), server.instance);

        let test_str = "data source=tcp:my-server.com\\TIBERIUS,666";
        let ado: AdoNetConfig = test_str.parse()?;
        let server = ado.server()?;

        assert_eq!(Some("my-server.com".to_string()), server.host);
        assert_eq!(Some(666), server.port);
        assert_eq!(Some("TIBERIUS".to_string()), server.instance);

        Ok(())
    }

    #[test]
    fn server_parsing_too_many_parts_is_error() -> crate::Result<()> {
        // The Server value must have at most two comma-separated parts
        // (host[,port]). Three parts is invalid and must error. The guard is
        // `parts.is_empty() || parts.len() >= 3`; a `&&` mutation would never
        // trigger (a slice cannot be both empty and have >= 3 parts), so this
        // three-part value would be wrongly accepted.
        let ado: AdoNetConfig = "server=tcp:my-server.com,1433,extra".parse()?;
        assert!(ado.server().is_err());

        let ado: AdoNetConfig = "server=my-server.com,1433,extra".parse()?;
        assert!(ado.server().is_err());

        Ok(())
    }

    #[test]
    fn server_parsing_missing_key() -> crate::Result<()> {
        // No `server`/`data source` key at all -> an all-`None` definition.
        let ado: AdoNetConfig = "database=Foo".parse()?;
        let server = ado.server()?;

        assert_eq!(None, server.host);
        assert_eq!(None, server.port);
        assert_eq!(None, server.instance);

        // And the same path through the public constructor.
        let config = crate::Config::from_ado_string("database=Foo")?;
        assert_eq!("localhost", config.get_host());

        Ok(())
    }

    #[test]
    fn database_parsing() -> crate::Result<()> {
        let test_str = "database=Foo";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("Foo".to_string()), ado.database());

        let test_str = "databaseName=Foo";
        let jdbc: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("Foo".to_string()), jdbc.database());

        let test_str = "Initial Catalog=Foo";
        let jdbc: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("Foo".to_string()), jdbc.database());

        Ok(())
    }

    #[test]
    fn trust_cert_parsing_true() -> crate::Result<()> {
        let test_str = "TrustServerCertificate=true";
        let ado: AdoNetConfig = test_str.parse()?;

        assert!(ado.trust_cert()?);

        Ok(())
    }

    #[test]
    fn trust_cert_parsing_false() -> crate::Result<()> {
        let test_str = "TrustServerCertificate=false";
        let ado: AdoNetConfig = test_str.parse()?;

        assert!(!ado.trust_cert()?);

        Ok(())
    }

    #[test]
    fn trust_cert_parsing_yes() -> crate::Result<()> {
        let test_str = "TrustServerCertificate=yes";
        let ado: AdoNetConfig = test_str.parse()?;

        assert!(ado.trust_cert()?);

        Ok(())
    }

    #[test]
    fn trust_cert_parsing_no() -> crate::Result<()> {
        let test_str = "TrustServerCertificate=no";
        let ado: AdoNetConfig = test_str.parse()?;

        assert!(!ado.trust_cert()?);

        Ok(())
    }

    #[test]
    fn trust_cert_parsing_missing() -> crate::Result<()> {
        let test_str = "Something=foo;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert!(!ado.trust_cert()?);

        Ok(())
    }

    #[test]
    fn trust_cert_parsing_faulty() -> crate::Result<()> {
        let test_str = "TrustServerCertificate=musti;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert!(ado.trust_cert().is_err());

        Ok(())
    }

    #[test]
    fn trust_cert_ca_parsing_ok() -> crate::Result<()> {
        let test_str = "TrustServerCertificateCA=someca.crt;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("someca.crt".to_string()), ado.trust_cert_ca());

        Ok(())
    }

    #[test]
    fn parsing_sql_server_authentication() -> crate::Result<()> {
        let test_str = "uid=Musti; pwd=Naukio;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(
            AuthMethod::sql_server("Musti", "Naukio"),
            ado.authentication()?
        );

        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn parsing_sspi_authentication() -> crate::Result<()> {
        let test_str = "IntegratedSecurity=SSPI;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(AuthMethod::Integrated, ado.authentication()?);

        let test_str = "Integrated Security=SSPI;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(AuthMethod::Integrated, ado.authentication()?);

        Ok(())
    }

    #[test]
    #[cfg(all(feature = "integrated-auth-gssapi", unix))]
    fn parsing_sspi_authentication() -> crate::Result<()> {
        let test_str = "IntegratedSecurity=true;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(AuthMethod::Integrated, ado.authentication()?);

        let test_str = "Integrated Security=true;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(AuthMethod::Integrated, ado.authentication()?);

        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn parsing_windows_authentication() -> crate::Result<()> {
        let test_str = "uid=Musti;pwd=Naukio; IntegratedSecurity=SSPI;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(
            AuthMethod::windows("Musti", "Naukio"),
            ado.authentication()?
        );

        let test_str = "uid=Musti;pwd=Naukio; Integrated Security=SSPI;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(
            AuthMethod::windows("Musti", "Naukio"),
            ado.authentication()?
        );

        Ok(())
    }

    #[test]
    fn parsing_database() -> crate::Result<()> {
        let test_str = "database=Cats;";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("Cats".to_string()), ado.database());

        Ok(())
    }

    #[test]
    fn parsing_login_credentials_escaping() -> crate::Result<()> {
        let test_str = "User ID=musti; Password='abc;}45';";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(
            AuthMethod::sql_server("musti", "abc;}45"),
            ado.authentication()?
        );

        Ok(())
    }

    #[test]
    fn parsing_password_special_characters() -> crate::Result<()> {
        // (value as written in the connection string, exact parsed password).
        // The user and password must both round-trip exactly.
        let cases: &[(&str, &str)] = &[
            // Single quotes: the most general escape; any ASCII char except a
            // literal single quote can appear verbatim.
            ("'a;b'", "a;b"),
            ("'a=b'", "a=b"),
            ("'a{b'", "a{b"),
            ("'a}b'", "a}b"),
            ("'a b'", "a b"),
            ("'a$b'", "a$b"),
            ("'a@b'", "a@b"),
            ("'a!b'", "a!b"),
            ("'a#b'", "a#b"),
            ("'a%b'", "a%b"),
            ("'a&b'", "a&b"),
            ("'a,b'", "a,b"),
            ("'a\"b'", "a\"b"), // a double quote inside single quotes
            ("'p@ss;w{}rd=42'", "p@ss;w{}rd=42"),
            // Double quotes: same idea, and lets a single quote appear.
            ("\"a'b\"", "a'b"),
            ("\"a;b=c\"", "a;b=c"),
            // Braces (`{...}`): handy for `;` and `=`, but cannot hold a `}`.
            ("{a;b}", "a;b"),
            ("{a=b}", "a=b"),
            ("{a$b}", "a$b"),
            // Unquoted: non-structural characters pass through untouched.
            ("a$b", "a$b"),
            ("a@b", "a@b"),
            ("a!b", "a!b"),
            ("a#b", "a#b"),
            ("a%b", "a%b"),
            ("a&b", "a&b"),
            ("a,b", "a,b"),
            // A bare `}` is not structural: it passes through unquoted.
            ("a}b", "a}b"),
            // Percent-encoding is NOT decoded: `%24` stays literal, it does
            // not become `$`.
            ("a%24b", "a%24b"),
            // An empty password is accepted by the ADO parser.
            ("", ""),
        ];

        for (value, expected) in cases {
            let s = format!("User Id=sa;Password={value};");
            let ado: AdoNetConfig = s.parse()?;
            assert_eq!(
                AuthMethod::sql_server("sa", *expected),
                ado.authentication()?,
                "value `{value}` should parse to password `{expected}`"
            );
        }

        Ok(())
    }

    #[test]
    fn parsing_password_whitespace_quirks() -> crate::Result<()> {
        // Trailing whitespace is always trimmed, even inside quotes.
        let ado: AdoNetConfig = "User Id=sa;Password='a '".parse()?;
        assert_eq!(AuthMethod::sql_server("sa", "a"), ado.authentication()?);

        // Leading whitespace is preserved when the value is quoted.
        let ado: AdoNetConfig = "User Id=sa;Password=' a'".parse()?;
        assert_eq!(AuthMethod::sql_server("sa", " a"), ado.authentication()?);

        // Internal tabs survive.
        let ado: AdoNetConfig = "User Id=sa;Password='a\tb'".parse()?;
        assert_eq!(AuthMethod::sql_server("sa", "a\tb"), ado.authentication()?);

        Ok(())
    }

    #[test]
    fn parsing_password_brace_cannot_hold_close_brace() -> crate::Result<()> {
        // ADO.NET brace quoting has no `}}` doubling: the brace closes at the
        // first `}`, so the `}` between `a` and `b` is consumed as the
        // terminator and lost. This documents the limitation.
        let ado: AdoNetConfig = "User Id=sa;Password={a}b}".parse()?;
        assert_eq!(AuthMethod::sql_server("sa", "ab}"), ado.authentication()?);

        // Use single or double quotes for passwords that contain `}`.
        let ado: AdoNetConfig = "User Id=sa;Password='a}b}'".parse()?;
        assert_eq!(AuthMethod::sql_server("sa", "a}b}"), ado.authentication()?);

        Ok(())
    }

    #[test]
    fn parsing_password_non_ascii_is_rejected() {
        // The ADO parser only accepts ASCII; non-ASCII passwords must use the
        // programmatic `Config` API instead.
        assert!("User Id=sa;Password=café".parse::<AdoNetConfig>().is_err());
        assert!("User Id=sa;Password='café'"
            .parse::<AdoNetConfig>()
            .is_err());
    }

    #[test]
    fn unquoted_special_char_password_error_has_hint() {
        // An unquoted `;` in a password breaks parsing. The error must guide
        // the user toward quoting or the programmatic API while preserving the
        // underlying parser message.
        let err = "User Id=sa;Password=a;b"
            .parse::<AdoNetConfig>()
            .err()
            .unwrap();
        let msg = err.to_string();
        // Underlying terse parser message is preserved (not replaced).
        assert!(msg.contains("must be joined"), "message was: {msg}");
        // Hint mentions the ADO quoting styles and the programmatic API.
        assert!(msg.contains("single quotes"), "message was: {msg}");
        assert!(msg.contains("braces"), "message was: {msg}");
        assert!(
            msg.contains("Config::from_ado_string"),
            "message was: {msg}"
        );
        // The `Conversion error:` prefix must not be doubled.
        assert!(
            !msg.contains("Conversion error: Conversion error:"),
            "message was: {msg}"
        );
    }

    #[test]
    fn unclosed_quote_and_brace_errors_have_hint() {
        // Unclosed quote/brace are quoting mistakes; the hint should attach.
        for input in [
            "User Id=sa;Password='abc",  // unclosed single quote
            "User Id=sa;Password=\"abc", // unclosed double quote
            "User Id=sa;Password={abc",  // unclosed brace
        ] {
            let err = input.parse::<AdoNetConfig>().err().unwrap();
            let msg = err.to_string();
            assert!(msg.contains("must be quoted"), "message was: {msg}");
            assert!(
                !msg.contains("Conversion error: Conversion error:"),
                "message was: {msg}"
            );
        }
    }

    #[test]
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn encryption_parsing_on() -> crate::Result<()> {
        let test_str = "encrypt=true";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(EncryptionLevel::Required, ado.encrypt()?);

        Ok(())
    }

    #[test]
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn encryption_parsing_off() -> crate::Result<()> {
        let test_str = "encrypt=false";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(EncryptionLevel::Off, ado.encrypt()?);

        Ok(())
    }

    #[test]
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn encryption_parsing_plaintext() -> crate::Result<()> {
        let test_str = "encrypt=DANGER_PLAINTEXT";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(EncryptionLevel::NotSupported, ado.encrypt()?);

        Ok(())
    }

    #[test]
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn encryption_parsing_missing() -> crate::Result<()> {
        let test_str = "";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(EncryptionLevel::Required, ado.encrypt()?);

        Ok(())
    }

    #[test]
    #[cfg(feature = "tds80")]
    fn encryption_parsing_strict() -> crate::Result<()> {
        let test_str = "encrypt=strict";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(EncryptionLevel::Strict, ado.encrypt()?);

        Ok(())
    }

    // No-TLS build: an explicit encryption request must error (not silently
    // downgrade to plaintext, #305); opting out and an omitted keyword stay
    // `NotSupported`.

    #[test]
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encryption_parsing_on_errors_without_tls_backend() -> crate::Result<()> {
        for test_str in ["encrypt=true", "encrypt=yes"] {
            let ado: AdoNetConfig = test_str.parse()?;
            let err = ado.encrypt().unwrap_err();
            assert!(
                matches!(err, crate::Error::Tls(_)),
                "expected Error::Tls for {test_str}, got {err:?}"
            );
            let msg = err.to_string();
            assert!(msg.contains("without a TLS backend"), "message was: {msg}");
        }

        Ok(())
    }

    #[test]
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encryption_parsing_strict_errors_without_tls_backend() {
        let ado: AdoNetConfig = "encrypt=strict".parse().unwrap();
        let err = ado.encrypt().unwrap_err();
        assert!(
            matches!(err, crate::Error::Tls(_)),
            "expected Error::Tls, got {err:?}"
        );
    }

    #[test]
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encryption_parsing_mandatory_errors_without_tls_backend() {
        // `mandatory` is not an accepted token in either build; the with-TLS
        // parser rejects it as a bad boolean, so the no-TLS branch mirrors that
        // (still an error, just not the TLS-missing one).
        let ado: AdoNetConfig = "encrypt=mandatory".parse().unwrap();
        assert!(ado.encrypt().is_err());
    }

    #[test]
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encryption_parsing_off_ok_without_tls_backend() -> crate::Result<()> {
        for test_str in ["encrypt=false", "encrypt=no"] {
            let ado: AdoNetConfig = test_str.parse()?;
            assert_eq!(crate::EncryptionLevel::NotSupported, ado.encrypt()?);
        }

        Ok(())
    }

    #[test]
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encryption_parsing_plaintext_ok_without_tls_backend() -> crate::Result<()> {
        let ado: AdoNetConfig = "encrypt=DANGER_PLAINTEXT".parse()?;
        assert_eq!(crate::EncryptionLevel::NotSupported, ado.encrypt()?);

        Ok(())
    }

    #[test]
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn encryption_parsing_missing_ok_without_tls_backend() -> crate::Result<()> {
        let ado: AdoNetConfig = "".parse()?;
        assert_eq!(crate::EncryptionLevel::NotSupported, ado.encrypt()?);

        Ok(())
    }

    #[test]
    fn client_name_parsing() -> crate::Result<()> {
        let test_str = "workstationid=meow";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("meow".into()), ado.client_name());

        let test_str = "Workstation ID=meow";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("meow".into()), ado.client_name());

        Ok(())
    }

    #[test]
    fn hostname_in_certificate_parsing() -> crate::Result<()> {
        let test_str = "HostNameInCertificate=foo.example.com";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(
            Some("foo.example.com".into()),
            ado.hostname_in_certificate()
        );

        let test_str = "HostName In Certificate=foo.example.com";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(
            Some("foo.example.com".into()),
            ado.hostname_in_certificate()
        );

        Ok(())
    }

    #[test]
    fn application_name_parsing() -> crate::Result<()> {
        let test_str = "Application Name=meow";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("meow".into()), ado.application_name());

        let test_str = "ApplicationName=meow";
        let ado: AdoNetConfig = test_str.parse()?;

        assert_eq!(Some("meow".into()), ado.application_name());

        Ok(())
    }

    #[test]
    fn application_intent_readonly_parsing() -> crate::Result<()> {
        // Exact spelling from the ADO.NET connection string.
        let ado: AdoNetConfig = "ApplicationIntent=ReadOnly".parse()?;
        assert!(ado.readonly());

        // ADO.NET treats the value case-insensitively.
        let ado: AdoNetConfig = "applicationintent=readonly".parse()?;
        assert!(ado.readonly());

        // ReadWrite (the default) must not request read-only intent.
        let ado: AdoNetConfig = "ApplicationIntent=ReadWrite".parse()?;
        assert!(!ado.readonly());

        // Absent altogether.
        let ado: AdoNetConfig = "server=tcp:localhost,1433".parse()?;
        assert!(!ado.readonly());

        Ok(())
    }

    #[test]
    fn multi_subnet_failover_parsing() -> crate::Result<()> {
        let test_str = "MultiSubnetFailover=true";
        let ado: AdoNetConfig = test_str.parse()?;
        assert!(ado.multi_subnet_failover()?);

        let test_str = "MultiSubnetFailover=yes";
        let ado: AdoNetConfig = test_str.parse()?;
        assert!(ado.multi_subnet_failover()?);

        let test_str = "MultiSubnetFailover=false";
        let ado: AdoNetConfig = test_str.parse()?;
        assert!(!ado.multi_subnet_failover()?);

        Ok(())
    }

    #[test]
    fn multi_subnet_failover_parsing_missing() -> crate::Result<()> {
        let test_str = "";
        let ado: AdoNetConfig = test_str.parse()?;
        assert!(!ado.multi_subnet_failover()?);

        Ok(())
    }

    #[test]
    fn multi_subnet_failover_from_ado_string() -> crate::Result<()> {
        let config = crate::Config::from_ado_string(
            "server=tcp:my-server.com,1433;MultiSubnetFailover=true",
        )?;
        assert!(config.get_multi_subnet_failover());

        let config = crate::Config::from_ado_string("server=tcp:my-server.com,1433")?;
        assert!(!config.get_multi_subnet_failover());

        Ok(())
    }
}
