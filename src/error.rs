//! Error module
pub use crate::tds::codec::TokenError;
pub use std::io::ErrorKind as IoErrorKind;
use std::{borrow::Cow, convert::Infallible, io};
use thiserror::Error;

/// A unified error enum that contains several errors that might occurr during
/// the lifecycle of this driver
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Error {
    #[error("An error occurred during the attempt of performing I/O: {}", message)]
    /// An error occurred when performing I/O to the server.
    Io {
        /// A list specifying general categories of I/O error.
        kind: IoErrorKind,
        /// The error description.
        message: String,
    },
    #[error("Protocol error: {}", _0)]
    /// An error happened during the request or response parsing.
    Protocol(Cow<'static, str>),
    #[error("Encoding error: {}", _0)]
    /// Server responded with encoding not supported.
    Encoding(Cow<'static, str>),
    #[error("Conversion error: {}", _0)]
    /// Conversion failure from one type to another.
    Conversion(Cow<'static, str>),
    #[error("UTF-8 error")]
    /// Tried to convert data to UTF-8 that was not valid.
    Utf8,
    #[error("UTF-16 error")]
    /// Tried to convert data to UTF-16 that was not valid.
    Utf16,
    #[error("Error parsing an integer: {}", _0)]
    /// Tried to parse an integer that was not an integer.
    ParseInt(std::num::ParseIntError),
    #[error("Token error: {}", _0)]
    /// An error returned by the server.
    Server(TokenError),
    #[error("Error forming TLS connection: {}", _0)]
    /// An error in the TLS handshake.
    Tls(String),
    #[cfg(any(all(unix, feature = "integrated-auth-gssapi"), doc))]
    #[cfg_attr(docsrs, doc(cfg(all(unix, feature = "integrated-auth-gssapi"))))]
    /// An error from the GSSAPI library.
    #[error("GSSAPI Error: {}", _0)]
    Gssapi(String),
    #[cfg(any(all(unix, feature = "sspi-rs"), doc))]
    #[cfg_attr(docsrs, doc(cfg(all(unix, feature = "sspi-rs"))))]
    /// An error from the `sspi` (sspi-rs) library.
    #[error("sspi-rs Error: {}", _0)]
    SspiRs(String),
    #[error(
        "Server requested a connection to an alternative address: `{}:{}`",
        host,
        port
    )]
    /// Server requested a connection to an alternative address.
    Routing {
        /// The requested hostname
        host: String,
        /// The requested port.
        port: u16,
    },
    #[error("BULK UPLOAD input failure: {0}")]
    /// Invalid input in Bulk Upload
    BulkInput(Cow<'static, str>),
}

impl Error {
    /// True, if the error was caused by a deadlock.
    pub fn is_deadlock(&self) -> bool {
        self.code().map(|c| c == 1205).unwrap_or(false)
    }

    /// Returns the error code, if the error originates from the
    /// server.
    pub fn code(&self) -> Option<u32> {
        match self {
            Error::Server(e) => Some(e.code()),
            _ => None,
        }
    }
}

impl From<uuid::Error> for Error {
    fn from(e: uuid::Error) -> Self {
        Self::Conversion(format!("Error converting a Guid value {}", e).into())
    }
}

#[cfg(feature = "native-tls")]
impl From<async_native_tls::Error> for Error {
    fn from(v: async_native_tls::Error) -> Self {
        Error::Tls(format!("{}", v))
    }
}

#[cfg(feature = "vendored-openssl")]
impl From<opentls::Error> for Error {
    fn from(v: opentls::Error) -> Self {
        Error::Tls(format!("{}", v))
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Self::Io {
            kind: err.kind(),
            message: format!("{}", err),
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Error {
        Error::ParseInt(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_: std::str::Utf8Error) -> Error {
        Error::Utf8
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(_err: std::string::FromUtf8Error) -> Error {
        Error::Utf8
    }
}

impl From<std::string::FromUtf16Error> for Error {
    fn from(_err: std::string::FromUtf16Error) -> Error {
        Error::Utf16
    }
}

impl From<connection_string::Error> for Error {
    fn from(err: connection_string::Error) -> Error {
        let err = Cow::Owned(format!("{}", err));
        Error::Conversion(err)
    }
}

#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
#[cfg_attr(docsrs, doc(cfg(all(unix, feature = "integrated-auth-gssapi"))))]
impl From<libgssapi::error::Error> for Error {
    fn from(err: libgssapi::error::Error) -> Error {
        Error::Gssapi(format!("{}", err))
    }
}

#[cfg(all(unix, feature = "sspi-rs"))]
#[cfg_attr(docsrs, doc(cfg(all(unix, feature = "sspi-rs"))))]
impl From<sspi::Error> for Error {
    fn from(err: sspi::Error) -> Error {
        Error::SspiRs(format!("{}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_error(code: u32) -> TokenError {
        TokenError {
            code,
            state: 1,
            class: 16,
            message: "boom".to_string(),
            server: "srv".to_string(),
            procedure: "proc".to_string(),
            line: 3,
        }
    }

    #[test]
    fn code_and_is_deadlock() {
        let deadlock = Error::Server(token_error(1205));
        assert_eq!(deadlock.code(), Some(1205));
        assert!(deadlock.is_deadlock());

        let other = Error::Server(token_error(500));
        assert_eq!(other.code(), Some(500));
        assert!(!other.is_deadlock());

        let non_server = Error::Utf8;
        assert_eq!(non_server.code(), None);
        assert!(!non_server.is_deadlock());
    }

    #[test]
    fn display_variants() {
        assert_eq!(
            format!("{}", Error::Protocol("bad".into())),
            "Protocol error: bad"
        );
        assert_eq!(
            format!("{}", Error::Encoding("bad".into())),
            "Encoding error: bad"
        );
        assert_eq!(
            format!("{}", Error::Conversion("bad".into())),
            "Conversion error: bad"
        );
        assert_eq!(format!("{}", Error::Utf8), "UTF-8 error");
        assert_eq!(format!("{}", Error::Utf16), "UTF-16 error");
        assert_eq!(
            format!("{}", Error::BulkInput("bad".into())),
            "BULK UPLOAD input failure: bad"
        );

        let routing = Error::Routing {
            host: "host".to_string(),
            port: 1234,
        };
        assert!(format!("{}", routing).contains("host:1234"));
    }

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "eof");
        let err: Error = io_err.into();
        match err {
            Error::Io { kind, message } => {
                assert_eq!(kind, io::ErrorKind::UnexpectedEof);
                assert!(message.contains("eof"));
            }
            _ => panic!("expected Io"),
        }
    }

    #[test]
    fn from_parse_int_error() {
        let parse_err = "not-a-number".parse::<i32>().unwrap_err();
        let err: Error = parse_err.into();
        assert!(matches!(err, Error::ParseInt(_)));
    }

    #[test]
    fn from_utf8_and_utf16_errors() {
        let utf8_err = String::from_utf8(vec![0xff, 0xfe]).unwrap_err();
        assert!(matches!(Error::from(utf8_err), Error::Utf8));

        let str_utf8 = std::str::from_utf8(&[0xff, 0xfe]).unwrap_err();
        assert!(matches!(Error::from(str_utf8), Error::Utf8));

        let utf16_err = String::from_utf16(&[0xd800]).unwrap_err();
        assert!(matches!(Error::from(utf16_err), Error::Utf16));
    }

    #[test]
    fn from_uuid_error() {
        let uuid_err = uuid::Uuid::parse_str("not-a-uuid").unwrap_err();
        assert!(matches!(Error::from(uuid_err), Error::Conversion(_)));
    }

    #[test]
    fn equality_between_errors() {
        assert_eq!(Error::Utf8, Error::Utf8);
        assert_ne!(Error::Utf8, Error::Utf16);
    }
}
