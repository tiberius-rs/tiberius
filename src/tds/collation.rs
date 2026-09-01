//! legacy implementation of collations (or codepages rather) for dealing with varchar's with legacy databases
//! references [1] which has some mappings from the katmai (SQL Server 2008) source code and is a TDS driver
//! directly from microsoft
//! [2] is helpful to map CP1234 to the appropriate encoding
//!
//! [1] <https://github.com/Microsoft/mssql-jdbc/blob/eb14f63077c47ef1fc1c690deb8cfab602baeb85/src/main/java/com/microsoft/sqlserver/jdbc/SQLCollation.java>
//! [2] <https://github.com/lifthrasiir/rust-encoding/blob/496823171f15d9b9446b2ec3fb7765f22346256b/src/label.rs#L282>

use encoding_rs::Encoding;
use std::fmt;

use crate::error::Error;

/// The collation of a character column, describing its locale (LCID), sort
/// order and code page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Collation {
    /// LCID ColFlags Version
    info: u32,
    /// Sortid
    sort_id: u8,
}

impl Collation {
    /// Create a new collation from a raw LCID/flags/version word and sort id.
    pub fn new(info: u32, sort_id: u8) -> Self {
        Self { info, sort_id }
    }

    /// return the locale id part of the LCID (the specification here uses ambiguous terms)
    pub fn lcid(&self) -> u16 {
        (self.info & 0xffff) as u16
    }

    /// The sort id of the collation.
    pub fn sort_id(&self) -> u8 {
        self.sort_id
    }

    /// The raw LCID/flags/version word of the collation.
    pub fn info(&self) -> u32 {
        self.info
    }

    /// return an encoding for a given collation
    pub fn encoding(&self) -> crate::Result<&'static Encoding> {
        let res = if self.sort_id == 0 {
            lcid_to_encoding(self.lcid())
        } else {
            sortid_to_encoding(self.sort_id)
        };

        res.ok_or_else(|| {
            Error::Encoding(
                format!(
                    "encoding: unspported encoding (LCID: {:#04x}, sort ID: {})",
                    self.lcid(),
                    self.sort_id(),
                )
                .into(),
            )
        })
    }
}

impl fmt::Display for Collation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.encoding() {
            Ok(encoding) => write!(f, "{}", encoding.name()),
            _ => write!(f, "None"),
        }
    }
}

/// https://github.com/Microsoft/mssql-jdbc/blob/eb14f63077c47ef1fc1c690deb8cfab602baeb85/src/main/java/com/microsoft/sqlserver/jdbc/SQLCollation.java#L102-L310
/// maps an LCID (it's locale part which is only 2 bytes) to a codepage
///
/// generate the code below from source code:
/// 1. (regex)replace: (.*?)\((.*?),(.*?)\) with $2 => $3
/// 2. replace: Encoding.CP(.*?) with encoding::all::WINDOWS_$1
/// 3. replace: Encoding.UNICODE with encoding::all::UTF16_LE
///
/// the unimplemented!() one's are not supported by rust-encoding
pub fn lcid_to_encoding(locale: u16) -> Option<&'static Encoding> {
    match locale {
        0x0401 => Some(encoding_rs::WINDOWS_1256),
        0x0402 => Some(encoding_rs::WINDOWS_1251),
        0x0403 => Some(encoding_rs::WINDOWS_1252),
        // CP950
        0x0404 | 0x0c04 | 0x1404 => Some(encoding_rs::BIG5),
        0x0405 => Some(encoding_rs::WINDOWS_1250),
        0x0406 => Some(encoding_rs::WINDOWS_1252),
        0x0407 => Some(encoding_rs::WINDOWS_1252),
        0x0408 => Some(encoding_rs::WINDOWS_1253),
        0x0409 => Some(encoding_rs::WINDOWS_1252),
        0x040a => Some(encoding_rs::WINDOWS_1252),
        0x040b => Some(encoding_rs::WINDOWS_1252),
        0x040c => Some(encoding_rs::WINDOWS_1252),
        0x040d => Some(encoding_rs::WINDOWS_1255),
        0x040e => Some(encoding_rs::WINDOWS_1250),
        0x040f => Some(encoding_rs::WINDOWS_1252),
        0x0410 => Some(encoding_rs::WINDOWS_1252),
        // CP932
        0x0411 => Some(encoding_rs::SHIFT_JIS),
        0x0412 => Some(encoding_rs::EUC_KR),
        0x0413 => Some(encoding_rs::WINDOWS_1252),
        0x0414 => Some(encoding_rs::WINDOWS_1252),
        0x0415 => Some(encoding_rs::WINDOWS_1250),
        0x0416 => Some(encoding_rs::WINDOWS_1252),
        0x0417 => Some(encoding_rs::WINDOWS_1252),
        0x0418 => Some(encoding_rs::WINDOWS_1250),
        0x0419 => Some(encoding_rs::WINDOWS_1251),
        0x041a => Some(encoding_rs::WINDOWS_1250),
        0x041b => Some(encoding_rs::WINDOWS_1250),
        0x041c => Some(encoding_rs::WINDOWS_1250),
        0x041d => Some(encoding_rs::WINDOWS_1252),
        0x041e => Some(encoding_rs::WINDOWS_874),
        0x041f => Some(encoding_rs::WINDOWS_1254),
        0x0420 => Some(encoding_rs::WINDOWS_1256),
        0x0421 => Some(encoding_rs::WINDOWS_1252),
        0x0422 => Some(encoding_rs::WINDOWS_1251),
        0x0423 => Some(encoding_rs::WINDOWS_1251),
        0x0424 => Some(encoding_rs::WINDOWS_1250),
        0x0425 => Some(encoding_rs::WINDOWS_1257),
        0x0426 => Some(encoding_rs::WINDOWS_1257),
        0x0427 => Some(encoding_rs::WINDOWS_1257),
        0x0428 => Some(encoding_rs::WINDOWS_1251),
        0x0429 => Some(encoding_rs::WINDOWS_1256),
        0x042a => Some(encoding_rs::WINDOWS_1258),
        0x042b => Some(encoding_rs::WINDOWS_1252),
        0x042c => Some(encoding_rs::WINDOWS_1254),
        0x042d => Some(encoding_rs::WINDOWS_1252),
        0x042e => Some(encoding_rs::WINDOWS_1252),
        0x042f => Some(encoding_rs::WINDOWS_1251),
        0x0432 => Some(encoding_rs::WINDOWS_1252),
        0x0434 => Some(encoding_rs::WINDOWS_1252),
        0x0435 => Some(encoding_rs::WINDOWS_1252),
        0x0436 => Some(encoding_rs::WINDOWS_1252),
        0x0437 => Some(encoding_rs::WINDOWS_1252),
        0x0438 => Some(encoding_rs::WINDOWS_1252),
        0x0439 => Some(encoding_rs::UTF_16LE),
        0x043a => Some(encoding_rs::UTF_16LE),
        0x043b => Some(encoding_rs::WINDOWS_1252),
        0x043e => Some(encoding_rs::WINDOWS_1252),
        0x043f => Some(encoding_rs::WINDOWS_1251),
        0x0440 => Some(encoding_rs::WINDOWS_1251),
        0x0441 => Some(encoding_rs::WINDOWS_1252),
        0x0442 => Some(encoding_rs::WINDOWS_1250),
        0x0443 => Some(encoding_rs::WINDOWS_1254),
        0x0444 => Some(encoding_rs::WINDOWS_1251),
        0x0445 => Some(encoding_rs::UTF_16LE),
        0x0446 => Some(encoding_rs::UTF_16LE),
        0x0447 => Some(encoding_rs::UTF_16LE),
        0x0448 => Some(encoding_rs::UTF_16LE),
        0x0449 => Some(encoding_rs::UTF_16LE),
        0x044a => Some(encoding_rs::UTF_16LE),
        0x044b => Some(encoding_rs::UTF_16LE),
        0x044c => Some(encoding_rs::UTF_16LE),
        0x044d => Some(encoding_rs::UTF_16LE),
        0x044e => Some(encoding_rs::UTF_16LE),
        0x044f => Some(encoding_rs::UTF_16LE),
        0x0450 => Some(encoding_rs::WINDOWS_1251),
        0x0451 => Some(encoding_rs::UTF_16LE),
        0x0452 => Some(encoding_rs::WINDOWS_1252),
        0x0453 => Some(encoding_rs::UTF_16LE),
        0x0454 => Some(encoding_rs::UTF_16LE),
        0x0456 => Some(encoding_rs::WINDOWS_1252),
        0x0457 => Some(encoding_rs::UTF_16LE),
        0x045a => Some(encoding_rs::UTF_16LE),
        0x045b => Some(encoding_rs::UTF_16LE),
        0x045d => Some(encoding_rs::WINDOWS_1252),
        0x045e => Some(encoding_rs::WINDOWS_1252),
        0x0461 => Some(encoding_rs::UTF_16LE),
        0x0462 => Some(encoding_rs::WINDOWS_1252),
        0x0463 => Some(encoding_rs::UTF_16LE),
        0x0464 => Some(encoding_rs::WINDOWS_1252),
        0x0465 => Some(encoding_rs::UTF_16LE),
        0x0468 => Some(encoding_rs::WINDOWS_1252),
        0x046a => Some(encoding_rs::WINDOWS_1252),
        0x046b => Some(encoding_rs::WINDOWS_1252),
        0x046c => Some(encoding_rs::WINDOWS_1252),
        0x046d => Some(encoding_rs::WINDOWS_1251),
        0x046e => Some(encoding_rs::WINDOWS_1252),
        0x046f => Some(encoding_rs::WINDOWS_1252),
        0x0470 => Some(encoding_rs::WINDOWS_1252),
        0x0478 => Some(encoding_rs::WINDOWS_1252),
        0x047a => Some(encoding_rs::WINDOWS_1252),
        0x047c => Some(encoding_rs::WINDOWS_1252),
        0x047e => Some(encoding_rs::WINDOWS_1252),
        0x0480 => Some(encoding_rs::WINDOWS_1256),
        0x0481 => Some(encoding_rs::UTF_16LE),
        0x0482 => Some(encoding_rs::WINDOWS_1252),
        0x0483 => Some(encoding_rs::WINDOWS_1252),
        0x0484 => Some(encoding_rs::WINDOWS_1252),
        0x0485 => Some(encoding_rs::WINDOWS_1251),
        0x0486 => Some(encoding_rs::WINDOWS_1252),
        0x0487 => Some(encoding_rs::WINDOWS_1252),
        0x0488 => Some(encoding_rs::WINDOWS_1252),
        0x048c => Some(encoding_rs::WINDOWS_1256),
        0x0801 => Some(encoding_rs::WINDOWS_1256),
        // CP936
        0x0804 | 0x1004 => Some(encoding_rs::GB18030),
        0x0807 => Some(encoding_rs::WINDOWS_1252),
        0x0809 => Some(encoding_rs::WINDOWS_1252),
        0x080a => Some(encoding_rs::WINDOWS_1252),
        0x080c => Some(encoding_rs::WINDOWS_1252),
        0x0810 => Some(encoding_rs::WINDOWS_1252),
        0x0813 => Some(encoding_rs::WINDOWS_1252),
        0x0814 => Some(encoding_rs::WINDOWS_1252),
        0x0816 => Some(encoding_rs::WINDOWS_1252),
        0x081a => Some(encoding_rs::WINDOWS_1250),
        0x081d => Some(encoding_rs::WINDOWS_1252),
        0x0827 => Some(encoding_rs::WINDOWS_1257),
        0x082c => Some(encoding_rs::WINDOWS_1251),
        0x082e => Some(encoding_rs::WINDOWS_1252),
        0x083b => Some(encoding_rs::WINDOWS_1252),
        0x083c => Some(encoding_rs::WINDOWS_1252),
        0x083e => Some(encoding_rs::WINDOWS_1252),
        0x0843 => Some(encoding_rs::WINDOWS_1251),
        0x0845 => Some(encoding_rs::UTF_16LE),
        0x0850 => Some(encoding_rs::WINDOWS_1251),
        0x085d => Some(encoding_rs::WINDOWS_1252),
        0x085f => Some(encoding_rs::WINDOWS_1252),
        0x086b => Some(encoding_rs::WINDOWS_1252),
        0x0c01 => Some(encoding_rs::WINDOWS_1256),
        0x0c07 => Some(encoding_rs::WINDOWS_1252),
        0x0c09 => Some(encoding_rs::WINDOWS_1252),
        0x0c0a => Some(encoding_rs::WINDOWS_1252),
        0x0c0c => Some(encoding_rs::WINDOWS_1252),
        0x0c1a => Some(encoding_rs::WINDOWS_1251),
        0x0c3b => Some(encoding_rs::WINDOWS_1252),
        0x0c6b => Some(encoding_rs::WINDOWS_1252),
        0x1001 => Some(encoding_rs::WINDOWS_1256),
        0x1007 => Some(encoding_rs::WINDOWS_1252),
        0x1009 => Some(encoding_rs::WINDOWS_1252),
        0x100a => Some(encoding_rs::WINDOWS_1252),
        0x100c => Some(encoding_rs::WINDOWS_1252),
        0x101a => Some(encoding_rs::WINDOWS_1250),
        0x103b => Some(encoding_rs::WINDOWS_1252),
        0x1401 => Some(encoding_rs::WINDOWS_1256),
        0x1407 => Some(encoding_rs::WINDOWS_1252),
        0x1409 => Some(encoding_rs::WINDOWS_1252),
        0x140a => Some(encoding_rs::WINDOWS_1252),
        0x140c => Some(encoding_rs::WINDOWS_1252),
        0x141a => Some(encoding_rs::WINDOWS_1250),
        0x143b => Some(encoding_rs::WINDOWS_1252),
        0x1801 => Some(encoding_rs::WINDOWS_1256),
        0x1809 => Some(encoding_rs::WINDOWS_1252),
        0x180a => Some(encoding_rs::WINDOWS_1252),
        0x180c => Some(encoding_rs::WINDOWS_1252),
        0x181a => Some(encoding_rs::WINDOWS_1250),
        0x183b => Some(encoding_rs::WINDOWS_1252),
        0x1c01 => Some(encoding_rs::WINDOWS_1256),
        0x1c09 => Some(encoding_rs::WINDOWS_1252),
        0x1c0a => Some(encoding_rs::WINDOWS_1252),
        0x1c1a => Some(encoding_rs::WINDOWS_1251),
        0x1c3b => Some(encoding_rs::WINDOWS_1252),
        0x2001 => Some(encoding_rs::WINDOWS_1256),
        0x2009 => Some(encoding_rs::WINDOWS_1252),
        0x200a => Some(encoding_rs::WINDOWS_1252),
        0x201a => Some(encoding_rs::WINDOWS_1251),
        0x203b => Some(encoding_rs::WINDOWS_1252),
        0x2401 => Some(encoding_rs::WINDOWS_1256),
        0x2409 => Some(encoding_rs::WINDOWS_1252),
        0x240a => Some(encoding_rs::WINDOWS_1252),
        0x243b => Some(encoding_rs::WINDOWS_1252),
        0x2801 => Some(encoding_rs::WINDOWS_1256),
        0x2809 => Some(encoding_rs::WINDOWS_1252),
        0x280a => Some(encoding_rs::WINDOWS_1252),
        0x2c01 => Some(encoding_rs::WINDOWS_1256),
        0x2c09 => Some(encoding_rs::WINDOWS_1252),
        0x2c0a => Some(encoding_rs::WINDOWS_1252),
        0x3001 => Some(encoding_rs::WINDOWS_1256),
        0x3009 => Some(encoding_rs::WINDOWS_1252),
        0x300a => Some(encoding_rs::WINDOWS_1252),
        0x3401 => Some(encoding_rs::WINDOWS_1256),
        0x3409 => Some(encoding_rs::WINDOWS_1252),
        0x340a => Some(encoding_rs::WINDOWS_1252),
        0x3801 => Some(encoding_rs::WINDOWS_1256),
        0x380a => Some(encoding_rs::WINDOWS_1252),
        0x3c01 => Some(encoding_rs::WINDOWS_1256),
        0x3c0a => Some(encoding_rs::WINDOWS_1252),
        0x4001 => Some(encoding_rs::WINDOWS_1256),
        0x4009 => Some(encoding_rs::WINDOWS_1252),
        0x400a => Some(encoding_rs::WINDOWS_1252),
        0x4409 => Some(encoding_rs::WINDOWS_1252),
        0x440a => Some(encoding_rs::WINDOWS_1252),
        0x4809 => Some(encoding_rs::WINDOWS_1252),
        0x480a => Some(encoding_rs::WINDOWS_1252),
        0x4c0a => Some(encoding_rs::WINDOWS_1252),
        0x500a => Some(encoding_rs::WINDOWS_1252),
        0x540a => Some(encoding_rs::WINDOWS_1252),
        _ => None,
    }
}

/// [1] https://github.com/Microsoft/mssql-jdbc/blob/eb14f63077c47ef1fc1c690deb8cfab602baeb85/src/main/java/com/microsoft/sqlserver/jdbc/SQLCollation.java#L362-L482
/// [2] https://msdn.microsoft.com/de-de/library/ms144250(v=sql.105).aspx
///
/// [2] does only contain 3/4 of the content [1] contains, so the source code is again the better source of information
///
/// generate the code below from source code:
/// 1. (regex)replace .*\((.*?),.*?,(.*?)\) with $1 => $2
/// 2. see above/as above
pub fn sortid_to_encoding(sort_id: u8) -> Option<&'static Encoding> {
    match sort_id {
        // 30 | 31 | 32 | 33 | 34 | 35 => Some(encoding_rs::WINDOWS_437),
        // 40 | 41 | 42 | 43 | 44 | 45 | 49 => Some(encoding_rs::WINDOWS_850),
        50 => Some(encoding_rs::WINDOWS_1252),
        51 => Some(encoding_rs::WINDOWS_1252),
        52 => Some(encoding_rs::WINDOWS_1252),
        53 => Some(encoding_rs::WINDOWS_1252),
        54 => Some(encoding_rs::WINDOWS_1252),
        // 55 | 56 | 57 | 58 | 59 | 60 | 61 => Some(encoding_rs::WINDOWS_850),
        71 => Some(encoding_rs::WINDOWS_1252),
        72 => Some(encoding_rs::WINDOWS_1252),
        73 => Some(encoding_rs::WINDOWS_1252),
        74 => Some(encoding_rs::WINDOWS_1252),
        75 => Some(encoding_rs::WINDOWS_1252),
        80 => Some(encoding_rs::WINDOWS_1250),
        81 => Some(encoding_rs::WINDOWS_1250),
        82 => Some(encoding_rs::WINDOWS_1250),
        83 => Some(encoding_rs::WINDOWS_1250),
        84 => Some(encoding_rs::WINDOWS_1250),
        85 => Some(encoding_rs::WINDOWS_1250),
        86 => Some(encoding_rs::WINDOWS_1250),
        87 => Some(encoding_rs::WINDOWS_1250),
        88 => Some(encoding_rs::WINDOWS_1250),
        89 => Some(encoding_rs::WINDOWS_1250),
        90 => Some(encoding_rs::WINDOWS_1250),
        91 => Some(encoding_rs::WINDOWS_1250),
        92 => Some(encoding_rs::WINDOWS_1250),
        93 => Some(encoding_rs::WINDOWS_1250),
        94 => Some(encoding_rs::WINDOWS_1250),
        95 => Some(encoding_rs::WINDOWS_1250),
        96 => Some(encoding_rs::WINDOWS_1250),
        97 => Some(encoding_rs::WINDOWS_1250),
        98 => Some(encoding_rs::WINDOWS_1250),
        104 => Some(encoding_rs::WINDOWS_1251),
        105 => Some(encoding_rs::WINDOWS_1251),
        106 => Some(encoding_rs::WINDOWS_1251),
        107 => Some(encoding_rs::WINDOWS_1251),
        108 => Some(encoding_rs::WINDOWS_1251),
        112 => Some(encoding_rs::WINDOWS_1253),
        113 => Some(encoding_rs::WINDOWS_1253),
        114 => Some(encoding_rs::WINDOWS_1253),
        120 => Some(encoding_rs::WINDOWS_1253),
        121 => Some(encoding_rs::WINDOWS_1253),
        122 => Some(encoding_rs::WINDOWS_1253),
        124 => Some(encoding_rs::WINDOWS_1253),
        128 => Some(encoding_rs::WINDOWS_1254),
        129 => Some(encoding_rs::WINDOWS_1254),
        130 => Some(encoding_rs::WINDOWS_1254),
        136 => Some(encoding_rs::WINDOWS_1255),
        137 => Some(encoding_rs::WINDOWS_1255),
        138 => Some(encoding_rs::WINDOWS_1255),
        144 => Some(encoding_rs::WINDOWS_1256),
        145 => Some(encoding_rs::WINDOWS_1256),
        146 => Some(encoding_rs::WINDOWS_1256),
        152 => Some(encoding_rs::WINDOWS_1257),
        153 => Some(encoding_rs::WINDOWS_1257),
        154 => Some(encoding_rs::WINDOWS_1257),
        155 => Some(encoding_rs::WINDOWS_1257),
        156 => Some(encoding_rs::WINDOWS_1257),
        157 => Some(encoding_rs::WINDOWS_1257),
        158 => Some(encoding_rs::WINDOWS_1257),
        159 => Some(encoding_rs::WINDOWS_1257),
        160 => Some(encoding_rs::WINDOWS_1257),
        183 => Some(encoding_rs::WINDOWS_1252),
        184 => Some(encoding_rs::WINDOWS_1252),
        185 => Some(encoding_rs::WINDOWS_1252),
        186 => Some(encoding_rs::WINDOWS_1252),
        // CP 932
        192 | 193 | 200 => Some(encoding_rs::SHIFT_JIS),
        194 => Some(encoding_rs::EUC_KR),
        195 => Some(encoding_rs::EUC_KR),
        // CP950
        196 | 197 | 202 => Some(encoding_rs::BIG5),
        // CP936 (GB18030 is an extension of it with more chars), should be backwards-compatible)
        198 | 199 | 203 => Some(encoding_rs::GB18030),
        201 => Some(encoding_rs::BIG5),
        204 => Some(encoding_rs::WINDOWS_874),
        205 => Some(encoding_rs::WINDOWS_874),
        206 => Some(encoding_rs::WINDOWS_874),
        210 => Some(encoding_rs::WINDOWS_1252),
        211 => Some(encoding_rs::WINDOWS_1252),
        212 => Some(encoding_rs::WINDOWS_1252),
        213 => Some(encoding_rs::WINDOWS_1252),
        214 => Some(encoding_rs::WINDOWS_1252),
        215 => Some(encoding_rs::WINDOWS_1252),
        216 => Some(encoding_rs::WINDOWS_1252),
        217 => Some(encoding_rs::WINDOWS_1252),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_split_info_and_sort_id() {
        // info holds LCID in the low 16 bits plus flags/version in the high bits.
        let collation = Collation::new(0x0020_0409, 52);
        assert_eq!(collation.info(), 0x0020_0409);
        assert_eq!(collation.lcid(), 0x0409);
        assert_eq!(collation.sort_id(), 52);
    }

    #[test]
    fn encoding_from_lcid_when_sort_id_zero() {
        // sort_id == 0 -> resolve via the LCID.
        let collation = Collation::new(0x0409, 0);
        let encoding = collation.encoding().expect("known LCID must resolve");
        assert_eq!(encoding, encoding_rs::WINDOWS_1252);
    }

    #[test]
    fn encoding_from_sort_id_when_present() {
        // A non-zero sort_id takes precedence over the LCID.
        let collation = Collation::new(0x0405, 80);
        let encoding = collation.encoding().expect("known sort id must resolve");
        assert_eq!(encoding, encoding_rs::WINDOWS_1250);
    }

    #[test]
    fn encoding_unknown_lcid_errors() {
        let collation = Collation::new(0xFFFF, 0);
        let err = collation.encoding().unwrap_err();
        assert!(matches!(err, Error::Encoding(_)));
    }

    #[test]
    fn encoding_unknown_sort_id_errors() {
        let collation = Collation::new(0x0409, 250);
        assert!(collation.encoding().is_err());
    }

    #[test]
    fn display_uses_encoding_name() {
        let collation = Collation::new(0x0409, 0);
        assert_eq!(format!("{}", collation), encoding_rs::WINDOWS_1252.name());
    }

    #[test]
    fn display_falls_back_to_none_on_unknown() {
        let collation = Collation::new(0xFFFF, 0);
        assert_eq!(format!("{}", collation), "None");
    }

    #[test]
    fn lcid_to_encoding_known_and_unknown() {
        assert_eq!(lcid_to_encoding(0x0401), Some(encoding_rs::WINDOWS_1256));
        assert_eq!(lcid_to_encoding(0x0404), Some(encoding_rs::BIG5));
        assert_eq!(lcid_to_encoding(0x0411), Some(encoding_rs::SHIFT_JIS));
        assert_eq!(lcid_to_encoding(0x0412), Some(encoding_rs::EUC_KR));
        assert_eq!(lcid_to_encoding(0x0804), Some(encoding_rs::GB18030));
        assert_eq!(lcid_to_encoding(0x0439), Some(encoding_rs::UTF_16LE));
        assert_eq!(lcid_to_encoding(0x041e), Some(encoding_rs::WINDOWS_874));
        assert_eq!(lcid_to_encoding(0x0000), None);
    }

    #[test]
    fn sortid_to_encoding_known_and_unknown() {
        assert_eq!(sortid_to_encoding(50), Some(encoding_rs::WINDOWS_1252));
        assert_eq!(sortid_to_encoding(80), Some(encoding_rs::WINDOWS_1250));
        assert_eq!(sortid_to_encoding(104), Some(encoding_rs::WINDOWS_1251));
        assert_eq!(sortid_to_encoding(112), Some(encoding_rs::WINDOWS_1253));
        assert_eq!(sortid_to_encoding(192), Some(encoding_rs::SHIFT_JIS));
        assert_eq!(sortid_to_encoding(194), Some(encoding_rs::EUC_KR));
        assert_eq!(sortid_to_encoding(196), Some(encoding_rs::BIG5));
        assert_eq!(sortid_to_encoding(198), Some(encoding_rs::GB18030));
        assert_eq!(sortid_to_encoding(204), Some(encoding_rs::WINDOWS_874));
        assert_eq!(sortid_to_encoding(0), None);
        assert_eq!(sortid_to_encoding(255), None);
    }

    #[test]
    fn lcid_to_encoding_covers_all_documented_locales() {
        let cases: &[(u16, &encoding_rs::Encoding)] = &[
            (0x0401, encoding_rs::WINDOWS_1256),
            (0x0402, encoding_rs::WINDOWS_1251),
            (0x0403, encoding_rs::WINDOWS_1252),
            (0x0404, encoding_rs::BIG5),
            (0x0c04, encoding_rs::BIG5),
            (0x1404, encoding_rs::BIG5),
            (0x0405, encoding_rs::WINDOWS_1250),
            (0x0406, encoding_rs::WINDOWS_1252),
            (0x0407, encoding_rs::WINDOWS_1252),
            (0x0408, encoding_rs::WINDOWS_1253),
            (0x0409, encoding_rs::WINDOWS_1252),
            (0x040a, encoding_rs::WINDOWS_1252),
            (0x040b, encoding_rs::WINDOWS_1252),
            (0x040c, encoding_rs::WINDOWS_1252),
            (0x040d, encoding_rs::WINDOWS_1255),
            (0x040e, encoding_rs::WINDOWS_1250),
            (0x040f, encoding_rs::WINDOWS_1252),
            (0x0410, encoding_rs::WINDOWS_1252),
            (0x0411, encoding_rs::SHIFT_JIS),
            (0x0412, encoding_rs::EUC_KR),
            (0x0413, encoding_rs::WINDOWS_1252),
            (0x0414, encoding_rs::WINDOWS_1252),
            (0x0415, encoding_rs::WINDOWS_1250),
            (0x0416, encoding_rs::WINDOWS_1252),
            (0x0417, encoding_rs::WINDOWS_1252),
            (0x0418, encoding_rs::WINDOWS_1250),
            (0x0419, encoding_rs::WINDOWS_1251),
            (0x041a, encoding_rs::WINDOWS_1250),
            (0x041b, encoding_rs::WINDOWS_1250),
            (0x041c, encoding_rs::WINDOWS_1250),
            (0x041d, encoding_rs::WINDOWS_1252),
            (0x041e, encoding_rs::WINDOWS_874),
            (0x041f, encoding_rs::WINDOWS_1254),
            (0x0420, encoding_rs::WINDOWS_1256),
            (0x0421, encoding_rs::WINDOWS_1252),
            (0x0422, encoding_rs::WINDOWS_1251),
            (0x0423, encoding_rs::WINDOWS_1251),
            (0x0424, encoding_rs::WINDOWS_1250),
            (0x0425, encoding_rs::WINDOWS_1257),
            (0x0426, encoding_rs::WINDOWS_1257),
            (0x0427, encoding_rs::WINDOWS_1257),
            (0x0428, encoding_rs::WINDOWS_1251),
            (0x0429, encoding_rs::WINDOWS_1256),
            (0x042a, encoding_rs::WINDOWS_1258),
            (0x042b, encoding_rs::WINDOWS_1252),
            (0x042c, encoding_rs::WINDOWS_1254),
            (0x042d, encoding_rs::WINDOWS_1252),
            (0x042e, encoding_rs::WINDOWS_1252),
            (0x042f, encoding_rs::WINDOWS_1251),
            (0x0432, encoding_rs::WINDOWS_1252),
            (0x0434, encoding_rs::WINDOWS_1252),
            (0x0435, encoding_rs::WINDOWS_1252),
            (0x0436, encoding_rs::WINDOWS_1252),
            (0x0437, encoding_rs::WINDOWS_1252),
            (0x0438, encoding_rs::WINDOWS_1252),
            (0x0439, encoding_rs::UTF_16LE),
            (0x043a, encoding_rs::UTF_16LE),
            (0x043b, encoding_rs::WINDOWS_1252),
            (0x043e, encoding_rs::WINDOWS_1252),
            (0x043f, encoding_rs::WINDOWS_1251),
            (0x0440, encoding_rs::WINDOWS_1251),
            (0x0441, encoding_rs::WINDOWS_1252),
            (0x0442, encoding_rs::WINDOWS_1250),
            (0x0443, encoding_rs::WINDOWS_1254),
            (0x0444, encoding_rs::WINDOWS_1251),
            (0x0445, encoding_rs::UTF_16LE),
            (0x0446, encoding_rs::UTF_16LE),
            (0x0447, encoding_rs::UTF_16LE),
            (0x0448, encoding_rs::UTF_16LE),
            (0x0449, encoding_rs::UTF_16LE),
            (0x044a, encoding_rs::UTF_16LE),
            (0x044b, encoding_rs::UTF_16LE),
            (0x044c, encoding_rs::UTF_16LE),
            (0x044d, encoding_rs::UTF_16LE),
            (0x044e, encoding_rs::UTF_16LE),
            (0x044f, encoding_rs::UTF_16LE),
            (0x0450, encoding_rs::WINDOWS_1251),
            (0x0451, encoding_rs::UTF_16LE),
            (0x0452, encoding_rs::WINDOWS_1252),
            (0x0453, encoding_rs::UTF_16LE),
            (0x0454, encoding_rs::UTF_16LE),
            (0x0456, encoding_rs::WINDOWS_1252),
            (0x0457, encoding_rs::UTF_16LE),
            (0x045a, encoding_rs::UTF_16LE),
            (0x045b, encoding_rs::UTF_16LE),
            (0x045d, encoding_rs::WINDOWS_1252),
            (0x045e, encoding_rs::WINDOWS_1252),
            (0x0461, encoding_rs::UTF_16LE),
            (0x0462, encoding_rs::WINDOWS_1252),
            (0x0463, encoding_rs::UTF_16LE),
            (0x0464, encoding_rs::WINDOWS_1252),
            (0x0465, encoding_rs::UTF_16LE),
            (0x0468, encoding_rs::WINDOWS_1252),
            (0x046a, encoding_rs::WINDOWS_1252),
            (0x046b, encoding_rs::WINDOWS_1252),
            (0x046c, encoding_rs::WINDOWS_1252),
            (0x046d, encoding_rs::WINDOWS_1251),
            (0x046e, encoding_rs::WINDOWS_1252),
            (0x046f, encoding_rs::WINDOWS_1252),
            (0x0470, encoding_rs::WINDOWS_1252),
            (0x0478, encoding_rs::WINDOWS_1252),
            (0x047a, encoding_rs::WINDOWS_1252),
            (0x047c, encoding_rs::WINDOWS_1252),
            (0x047e, encoding_rs::WINDOWS_1252),
            (0x0480, encoding_rs::WINDOWS_1256),
            (0x0481, encoding_rs::UTF_16LE),
            (0x0482, encoding_rs::WINDOWS_1252),
            (0x0483, encoding_rs::WINDOWS_1252),
            (0x0484, encoding_rs::WINDOWS_1252),
            (0x0485, encoding_rs::WINDOWS_1251),
            (0x0486, encoding_rs::WINDOWS_1252),
            (0x0487, encoding_rs::WINDOWS_1252),
            (0x0488, encoding_rs::WINDOWS_1252),
            (0x048c, encoding_rs::WINDOWS_1256),
            (0x0801, encoding_rs::WINDOWS_1256),
            (0x0804, encoding_rs::GB18030),
            (0x1004, encoding_rs::GB18030),
            (0x0807, encoding_rs::WINDOWS_1252),
            (0x0809, encoding_rs::WINDOWS_1252),
            (0x080a, encoding_rs::WINDOWS_1252),
            (0x080c, encoding_rs::WINDOWS_1252),
            (0x0810, encoding_rs::WINDOWS_1252),
            (0x0813, encoding_rs::WINDOWS_1252),
            (0x0814, encoding_rs::WINDOWS_1252),
            (0x0816, encoding_rs::WINDOWS_1252),
            (0x081a, encoding_rs::WINDOWS_1250),
            (0x081d, encoding_rs::WINDOWS_1252),
            (0x0827, encoding_rs::WINDOWS_1257),
            (0x082c, encoding_rs::WINDOWS_1251),
            (0x082e, encoding_rs::WINDOWS_1252),
            (0x083b, encoding_rs::WINDOWS_1252),
            (0x083c, encoding_rs::WINDOWS_1252),
            (0x083e, encoding_rs::WINDOWS_1252),
            (0x0843, encoding_rs::WINDOWS_1251),
            (0x0845, encoding_rs::UTF_16LE),
            (0x0850, encoding_rs::WINDOWS_1251),
            (0x085d, encoding_rs::WINDOWS_1252),
            (0x085f, encoding_rs::WINDOWS_1252),
            (0x086b, encoding_rs::WINDOWS_1252),
            (0x0c01, encoding_rs::WINDOWS_1256),
            (0x0c07, encoding_rs::WINDOWS_1252),
            (0x0c09, encoding_rs::WINDOWS_1252),
            (0x0c0a, encoding_rs::WINDOWS_1252),
            (0x0c0c, encoding_rs::WINDOWS_1252),
            (0x0c1a, encoding_rs::WINDOWS_1251),
            (0x0c3b, encoding_rs::WINDOWS_1252),
            (0x0c6b, encoding_rs::WINDOWS_1252),
            (0x1001, encoding_rs::WINDOWS_1256),
            (0x1007, encoding_rs::WINDOWS_1252),
            (0x1009, encoding_rs::WINDOWS_1252),
            (0x100a, encoding_rs::WINDOWS_1252),
            (0x100c, encoding_rs::WINDOWS_1252),
            (0x101a, encoding_rs::WINDOWS_1250),
            (0x103b, encoding_rs::WINDOWS_1252),
            (0x1401, encoding_rs::WINDOWS_1256),
            (0x1407, encoding_rs::WINDOWS_1252),
            (0x1409, encoding_rs::WINDOWS_1252),
            (0x140a, encoding_rs::WINDOWS_1252),
            (0x140c, encoding_rs::WINDOWS_1252),
            (0x141a, encoding_rs::WINDOWS_1250),
            (0x143b, encoding_rs::WINDOWS_1252),
            (0x1801, encoding_rs::WINDOWS_1256),
            (0x1809, encoding_rs::WINDOWS_1252),
            (0x180a, encoding_rs::WINDOWS_1252),
            (0x180c, encoding_rs::WINDOWS_1252),
            (0x181a, encoding_rs::WINDOWS_1250),
            (0x183b, encoding_rs::WINDOWS_1252),
            (0x1c01, encoding_rs::WINDOWS_1256),
            (0x1c09, encoding_rs::WINDOWS_1252),
            (0x1c0a, encoding_rs::WINDOWS_1252),
            (0x1c1a, encoding_rs::WINDOWS_1251),
            (0x1c3b, encoding_rs::WINDOWS_1252),
            (0x2001, encoding_rs::WINDOWS_1256),
            (0x2009, encoding_rs::WINDOWS_1252),
            (0x200a, encoding_rs::WINDOWS_1252),
            (0x201a, encoding_rs::WINDOWS_1251),
            (0x203b, encoding_rs::WINDOWS_1252),
            (0x2401, encoding_rs::WINDOWS_1256),
            (0x2409, encoding_rs::WINDOWS_1252),
            (0x240a, encoding_rs::WINDOWS_1252),
            (0x243b, encoding_rs::WINDOWS_1252),
            (0x2801, encoding_rs::WINDOWS_1256),
            (0x2809, encoding_rs::WINDOWS_1252),
            (0x280a, encoding_rs::WINDOWS_1252),
            (0x2c01, encoding_rs::WINDOWS_1256),
            (0x2c09, encoding_rs::WINDOWS_1252),
            (0x2c0a, encoding_rs::WINDOWS_1252),
            (0x3001, encoding_rs::WINDOWS_1256),
            (0x3009, encoding_rs::WINDOWS_1252),
            (0x300a, encoding_rs::WINDOWS_1252),
            (0x3401, encoding_rs::WINDOWS_1256),
            (0x3409, encoding_rs::WINDOWS_1252),
            (0x340a, encoding_rs::WINDOWS_1252),
            (0x3801, encoding_rs::WINDOWS_1256),
            (0x380a, encoding_rs::WINDOWS_1252),
            (0x3c01, encoding_rs::WINDOWS_1256),
            (0x3c0a, encoding_rs::WINDOWS_1252),
            (0x4001, encoding_rs::WINDOWS_1256),
            (0x4009, encoding_rs::WINDOWS_1252),
            (0x400a, encoding_rs::WINDOWS_1252),
            (0x4409, encoding_rs::WINDOWS_1252),
            (0x440a, encoding_rs::WINDOWS_1252),
            (0x4809, encoding_rs::WINDOWS_1252),
            (0x480a, encoding_rs::WINDOWS_1252),
            (0x4c0a, encoding_rs::WINDOWS_1252),
            (0x500a, encoding_rs::WINDOWS_1252),
            (0x540a, encoding_rs::WINDOWS_1252),
        ];

        for (locale, expected) in cases {
            assert_eq!(
                lcid_to_encoding(*locale),
                Some(*expected),
                "locale {:#06x}",
                locale
            );
        }
    }

    #[test]
    fn sortid_to_encoding_covers_all_documented_sort_ids() {
        let cases: &[(u8, &encoding_rs::Encoding)] = &[
            (50, encoding_rs::WINDOWS_1252),
            (51, encoding_rs::WINDOWS_1252),
            (52, encoding_rs::WINDOWS_1252),
            (53, encoding_rs::WINDOWS_1252),
            (54, encoding_rs::WINDOWS_1252),
            (71, encoding_rs::WINDOWS_1252),
            (72, encoding_rs::WINDOWS_1252),
            (73, encoding_rs::WINDOWS_1252),
            (74, encoding_rs::WINDOWS_1252),
            (75, encoding_rs::WINDOWS_1252),
            (80, encoding_rs::WINDOWS_1250),
            (81, encoding_rs::WINDOWS_1250),
            (82, encoding_rs::WINDOWS_1250),
            (83, encoding_rs::WINDOWS_1250),
            (84, encoding_rs::WINDOWS_1250),
            (85, encoding_rs::WINDOWS_1250),
            (86, encoding_rs::WINDOWS_1250),
            (87, encoding_rs::WINDOWS_1250),
            (88, encoding_rs::WINDOWS_1250),
            (89, encoding_rs::WINDOWS_1250),
            (90, encoding_rs::WINDOWS_1250),
            (91, encoding_rs::WINDOWS_1250),
            (92, encoding_rs::WINDOWS_1250),
            (93, encoding_rs::WINDOWS_1250),
            (94, encoding_rs::WINDOWS_1250),
            (95, encoding_rs::WINDOWS_1250),
            (96, encoding_rs::WINDOWS_1250),
            (97, encoding_rs::WINDOWS_1250),
            (98, encoding_rs::WINDOWS_1250),
            (104, encoding_rs::WINDOWS_1251),
            (105, encoding_rs::WINDOWS_1251),
            (106, encoding_rs::WINDOWS_1251),
            (107, encoding_rs::WINDOWS_1251),
            (108, encoding_rs::WINDOWS_1251),
            (112, encoding_rs::WINDOWS_1253),
            (113, encoding_rs::WINDOWS_1253),
            (114, encoding_rs::WINDOWS_1253),
            (120, encoding_rs::WINDOWS_1253),
            (121, encoding_rs::WINDOWS_1253),
            (122, encoding_rs::WINDOWS_1253),
            (124, encoding_rs::WINDOWS_1253),
            (128, encoding_rs::WINDOWS_1254),
            (129, encoding_rs::WINDOWS_1254),
            (130, encoding_rs::WINDOWS_1254),
            (136, encoding_rs::WINDOWS_1255),
            (137, encoding_rs::WINDOWS_1255),
            (138, encoding_rs::WINDOWS_1255),
            (144, encoding_rs::WINDOWS_1256),
            (145, encoding_rs::WINDOWS_1256),
            (146, encoding_rs::WINDOWS_1256),
            (152, encoding_rs::WINDOWS_1257),
            (153, encoding_rs::WINDOWS_1257),
            (154, encoding_rs::WINDOWS_1257),
            (155, encoding_rs::WINDOWS_1257),
            (156, encoding_rs::WINDOWS_1257),
            (157, encoding_rs::WINDOWS_1257),
            (158, encoding_rs::WINDOWS_1257),
            (159, encoding_rs::WINDOWS_1257),
            (160, encoding_rs::WINDOWS_1257),
            (183, encoding_rs::WINDOWS_1252),
            (184, encoding_rs::WINDOWS_1252),
            (185, encoding_rs::WINDOWS_1252),
            (186, encoding_rs::WINDOWS_1252),
            (192, encoding_rs::SHIFT_JIS),
            (193, encoding_rs::SHIFT_JIS),
            (200, encoding_rs::SHIFT_JIS),
            (194, encoding_rs::EUC_KR),
            (195, encoding_rs::EUC_KR),
            (196, encoding_rs::BIG5),
            (197, encoding_rs::BIG5),
            (202, encoding_rs::BIG5),
            (198, encoding_rs::GB18030),
            (199, encoding_rs::GB18030),
            (203, encoding_rs::GB18030),
            (201, encoding_rs::BIG5),
            (204, encoding_rs::WINDOWS_874),
            (205, encoding_rs::WINDOWS_874),
            (206, encoding_rs::WINDOWS_874),
            (210, encoding_rs::WINDOWS_1252),
            (211, encoding_rs::WINDOWS_1252),
            (212, encoding_rs::WINDOWS_1252),
            (213, encoding_rs::WINDOWS_1252),
            (214, encoding_rs::WINDOWS_1252),
            (215, encoding_rs::WINDOWS_1252),
            (216, encoding_rs::WINDOWS_1252),
            (217, encoding_rs::WINDOWS_1252),
        ];

        for (sort_id, expected) in cases {
            assert_eq!(
                sortid_to_encoding(*sort_id),
                Some(*expected),
                "sort_id {}",
                sort_id
            );
        }
    }

    #[test]
    fn derives_eq_and_copy() {
        let a = Collation::new(0x0409, 0);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, Collation::new(0x0409, 1));
    }
}
