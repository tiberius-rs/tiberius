pub mod codec;
pub(crate) mod collation;
mod context;
pub mod numeric;
pub mod stream;
pub mod time;
pub mod xml;

pub(crate) use collation::*;
pub(crate) use context::*;
pub(crate) use numeric::*;

/// The amount of bytes a packet header consists of
pub(crate) const HEADER_BYTES: usize = 8;

uint_enum! {
    /// The configured encryption level specifying if encryption is required
    #[repr(u8)]
    pub enum EncryptionLevel {
        /// Only use encryption for the login procedure
        Off = 0,
        /// Encrypt everything if possible
        On = 1,
        /// Do not encrypt anything
        NotSupported = 2,
        /// Encrypt everything and fail if not possible
        Required = 3,
        /// Start encryption before the TDS prelogin (TDS 8.0 "strict" mode) and
        /// encrypt everything, failing if not possible.
        Strict = 4,
    }

}

impl EncryptionLevel {
    /// The value sent on the wire in the prelogin `ENCRYPTION` option.
    ///
    /// `Strict` (TDS 8.0) is negotiated out-of-band via a TLS handshake before
    /// the prelogin, so when a prelogin is emitted at all it advertises the
    /// classic `Required` value.
    pub(crate) fn as_wire_value(&self) -> u8 {
        match self {
            EncryptionLevel::Strict => EncryptionLevel::Required as u8,
            other => *other as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_level_as_wire_value() {
        assert_eq!(EncryptionLevel::Off.as_wire_value(), 0);
        assert_eq!(EncryptionLevel::On.as_wire_value(), 1);
        assert_eq!(EncryptionLevel::NotSupported.as_wire_value(), 2);
        assert_eq!(EncryptionLevel::Required.as_wire_value(), 3);
        assert_eq!(EncryptionLevel::Strict.as_wire_value(), 3);
    }
}
