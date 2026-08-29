use super::guid::reorder_bytes;
use super::{Decode, Encode};
use crate::{tds, Error, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};
use tds::EncryptionLevel;
use uuid::Uuid;

/// Client application activity id token used for debugging purposes introduced
/// in TDS 7.4.
#[allow(unused)]
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ActivityId {
    id: Uuid,
    sequence: u32,
}

impl ActivityId {
    /// Creates a new activity id (`TRACEID`, MS-TDS §2.2.6.5) from a client
    /// activity [`Uuid`] and a monotonically increasing sequence number. The
    /// value is emitted in the PRELOGIN packet so a server administrator can
    /// correlate the connection in server-side traces.
    #[allow(dead_code)]
    pub fn new(id: Uuid, sequence: u32) -> Self {
        Self { id, sequence }
    }
}

/// The prelogin packet used to initialize a connection
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PreloginMessage {
    /// [BE] token=0x00
    /// Either the driver version or the version of the SQL server
    pub version: u32,
    pub sub_build: u16,
    /// token=0x01
    pub encryption: EncryptionLevel,
    /// token=0x02
    pub instance_name: Option<String>,
    /// [client] threadid for debugging purposes, token=0x03
    pub thread_id: u32,
    /// token=0x04
    pub mars: bool,
    /// token=0x05
    pub activity_id: Option<ActivityId>,
    /// token=0x06
    pub fed_auth_required: bool,
    pub nonce: Option<[u8; 32]>,
}

impl PreloginMessage {
    pub fn new() -> PreloginMessage {
        let driver_version = crate::get_driver_version();
        PreloginMessage {
            version: driver_version as u32,
            sub_build: (driver_version >> 32) as u16,
            encryption: EncryptionLevel::NotSupported,
            instance_name: None,
            thread_id: 0,
            mars: false,
            activity_id: None,
            fed_auth_required: false,
            nonce: None,
        }
    }

    /// Validates the server's answer to the `INSTOPT` prelogin option
    /// (MS-TDS §2.2.6.5).
    ///
    /// When the client sends an instance name, the server replies with a single
    /// `0x00` byte if the instance the connection landed on is the one that was
    /// requested. Any other payload means the server considers the instance
    /// invalid, in which case this returns a protocol error.
    pub fn validate_instance(&self, requested: Option<&str>) -> Result<()> {
        // Nothing to validate if the client never asked for a named instance.
        if requested.is_none() {
            return Ok(());
        }

        match self.instance_name.as_deref() {
            // `0x00` terminator only -> decoded as `None`: instance is valid.
            None => Ok(()),
            Some(other) => Err(Error::Protocol(
                format!(
                    "server rejected the requested instance {:?} (INSTOPT validity byte was non-zero, got {:?})",
                    requested.unwrap_or_default(),
                    other,
                )
                .into(),
            )),
        }
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    pub fn negotiated_encryption(&self, expected: EncryptionLevel) -> Result<EncryptionLevel> {
        let level = match (expected, self.encryption) {
            (EncryptionLevel::NotSupported, EncryptionLevel::NotSupported) => {
                EncryptionLevel::NotSupported
            }
            (EncryptionLevel::Off, EncryptionLevel::Off) => EncryptionLevel::Off,
            (EncryptionLevel::On, EncryptionLevel::Off)
            | (EncryptionLevel::On, EncryptionLevel::NotSupported) => {
                return Err(Error::Protocol(
                    "Server does not allow the requested encryption level.".into(),
                ))
            }
            // In TDS 8.0 "strict" mode encryption is established before the
            // prelogin, so there is nothing to negotiate here.
            (EncryptionLevel::Strict, _) => EncryptionLevel::Strict,
            (_, _) => EncryptionLevel::On,
        };

        Ok(level)
    }

    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    pub fn negotiated_encryption(&self, _: EncryptionLevel) -> Result<EncryptionLevel> {
        Ok(EncryptionLevel::NotSupported)
    }
}

// prelogin fields
// http://msdn.microsoft.com/en-us/library/dd357559.aspx
const PRELOGIN_VERSION: u8 = 0;
const PRELOGIN_ENCRYPTION: u8 = 1;
const PRELOGIN_INSTOPT: u8 = 2;
const PRELOGIN_THREADID: u8 = 3;
const PRELOGIN_MARS: u8 = 4;
const PRELOGIN_TRACEID: u8 = 5;
const PRELOGIN_FEDAUTHREQUIRED: u8 = 6;
const PRELOGIN_NONCEOPT: u8 = 7;
const PRELOGIN_TERMINATOR: u8 = 0xff;

impl Encode<BytesMut> for PreloginMessage {
    fn encode(self, dst: &mut BytesMut) -> Result<()> {
        let mut fields = Vec::new();
        let mut data_cursor = Cursor::new(Vec::with_capacity(512));

        // version
        fields.push((PRELOGIN_VERSION, 0x04 + 0x02)); // version + subbuild
        data_cursor.write_u32::<BigEndian>(self.version)?;
        data_cursor.write_u16::<BigEndian>(self.sub_build)?;

        // encryption
        fields.push((PRELOGIN_ENCRYPTION, 0x01)); // encryption
        data_cursor.write_u8(self.encryption.as_wire_value())?;

        // instance name (INSTOPT): a null-terminated MBCS string naming the
        // instance the client wants the server to validate. An empty name is
        // encoded as a lone `0x00` terminator.
        let instance = self.instance_name.as_deref().unwrap_or_default();
        let instance_bytes = instance.as_bytes();
        fields.push((PRELOGIN_INSTOPT, (instance_bytes.len() + 1) as u16));
        data_cursor.write_all(instance_bytes)?;
        data_cursor.write_u8(0x00)?; // null terminator

        // threadid
        fields.push((PRELOGIN_THREADID, 0x04)); // thread id
        data_cursor.write_u32::<BigEndian>(self.thread_id)?;

        // MARS
        fields.push((PRELOGIN_MARS, 0x01)); // MARS
        data_cursor.write_u8(self.mars as u8)?;

        // activity id (TRACEID): a client GUID plus a sequence number, emitted
        // only when the client supplies one for server-side trace correlation.
        if let Some(activity_id) = self.activity_id.as_ref() {
            fields.push((PRELOGIN_TRACEID, 0x14)); // 16-byte GUID + 4-byte sequence

            let mut data = *activity_id.id.as_bytes();
            reorder_bytes(&mut data);
            data_cursor.write_all(&data)?;
            data_cursor.write_u32::<LittleEndian>(activity_id.sequence)?;
        }

        // fed auth
        if self.fed_auth_required {
            fields.push((PRELOGIN_FEDAUTHREQUIRED, 0x01));
            data_cursor.write_u8(0x01)?;
        }

        // build the packet-body
        // offset = PL_OPTION_TOKEN + PL_OFFSET + PL_OPTION_LENGTH = 5 bytes + the terminator (0xFF)
        let mut data_offset = (fields.len() * 5 + 1) as u16;

        // write the offset table
        for (token, length) in fields {
            dst.put_u8(token);
            dst.put_u16(data_offset);
            dst.put_u16(length);

            data_offset += length;
        }

        dst.put_u8(PRELOGIN_TERMINATOR);
        dst.extend(data_cursor.into_inner());

        Ok(())
    }
}

impl Decode<BytesMut> for PreloginMessage {
    fn decode(src: &mut BytesMut) -> Result<Self>
    where
        Self: Sized,
    {
        let mut cursor = Cursor::new(src);
        let mut ret = PreloginMessage::new();

        // read all options
        loop {
            let token = cursor.read_u8()?;

            // read until terminator
            if token == 0xff {
                break;
            }

            let offset = cursor.read_u16::<BigEndian>()?;
            let length = cursor.read_u16::<BigEndian>()?;
            let old_pos = cursor.position();

            cursor.set_position(offset as u64);

            // verify whether the server acts in accordance to what we requested
            // and if we can handle on what we seemingly agreed to
            // TODO: support parsing more
            match token {
                // version
                PRELOGIN_VERSION => {
                    ret.version = cursor.read_u32::<BigEndian>()?;
                    ret.sub_build = cursor.read_u16::<BigEndian>()?;
                }
                // encryption
                PRELOGIN_ENCRYPTION => {
                    let encrypt = cursor.read_u8()?;
                    ret.encryption = tds::EncryptionLevel::try_from(encrypt).map_err(|_| {
                        Error::Protocol(format!("invalid encryption value: {}", encrypt).into())
                    })?;
                }
                // instance name
                PRELOGIN_INSTOPT => {
                    let mut bytes = Vec::new();
                    let mut next_byte = cursor.read_u8()?;

                    while next_byte != 0x00 {
                        bytes.push(next_byte);
                        next_byte = cursor.read_u8()?;
                    }

                    if !bytes.is_empty() {
                        ret.instance_name = Some(String::from_utf8_lossy(&bytes).into_owned());
                    }
                }
                PRELOGIN_THREADID => {
                    ret.thread_id = if length == 0 {
                        0
                    } else if length == 4 {
                        cursor.read_u32::<BigEndian>()?
                    } else {
                        return Err(Error::Protocol(
                            format!("prelogin: invalid threadid length: {}", length).into(),
                        ));
                    }
                }
                // mars
                PRELOGIN_MARS => {
                    ret.mars = cursor.read_u8()? != 0;
                }
                // activity id
                PRELOGIN_TRACEID => {
                    // Data is a Guid, 16 bytes and ordered the wrong way around
                    // than Uuid.
                    let mut data = [0u8; 16];

                    cursor.read_exact(&mut data)?;
                    reorder_bytes(&mut data);

                    ret.activity_id = Some(ActivityId {
                        id: Uuid::from_bytes(data),
                        sequence: cursor.read_u32::<LittleEndian>()?,
                    });
                }
                // fed auth
                PRELOGIN_FEDAUTHREQUIRED => {
                    ret.fed_auth_required = cursor.read_u8()? != 0;
                }
                // nonce
                PRELOGIN_NONCEOPT => {
                    let mut data = [0u8; 32];

                    for item in data.iter_mut() {
                        *item = cursor.read_u8()?;
                    }

                    ret.nonce = Some(data);
                }
                _ => {
                    return Err(Error::Protocol(
                        format!("unsupported prelogin token: {}", token).into(),
                    ))
                }
            }

            cursor.set_position(old_pos);
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses the PRELOGIN option-offset table and returns the option tokens in
    /// the order they were emitted, stopping at the terminator.
    fn option_tokens(bytes: &[u8]) -> Vec<u8> {
        let mut tokens = Vec::new();
        let mut pos = 0;

        while pos < bytes.len() {
            let token = bytes[pos];

            if token == PRELOGIN_TERMINATOR {
                break;
            }

            tokens.push(token);
            // token (1) + offset (2) + length (2)
            pos += 5;
        }

        tokens
    }

    /// Reads the raw payload bytes for a given option token from an encoded
    /// PRELOGIN packet using its offset-table entry.
    fn option_payload(bytes: &[u8], token: u8) -> Option<Vec<u8>> {
        let mut pos = 0;

        while pos < bytes.len() && bytes[pos] != PRELOGIN_TERMINATOR {
            if bytes[pos] == token {
                let offset = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
                let length = u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]) as usize;

                return Some(bytes[offset..offset + length].to_vec());
            }

            pos += 5;
        }

        None
    }

    #[test]
    fn prelogin_always_emits_instopt() {
        let mut payload = BytesMut::new();
        PreloginMessage::new()
            .encode(&mut payload)
            .expect("encode should succeed");

        assert!(option_tokens(&payload).contains(&PRELOGIN_INSTOPT));
        // An empty instance name is a single null terminator byte.
        assert_eq!(option_payload(&payload, PRELOGIN_INSTOPT), Some(vec![0x00]));
    }

    #[test]
    fn prelogin_emits_named_instance() {
        let mut payload = BytesMut::new();
        let mut prelogin = PreloginMessage::new();
        prelogin.instance_name = Some("MSSQLServer".to_string());
        prelogin
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        let expected: Vec<u8> = b"MSSQLServer\0".to_vec();
        assert_eq!(option_payload(&payload, PRELOGIN_INSTOPT), Some(expected));

        let decoded = PreloginMessage::decode(&mut payload).expect("decode should succeed");
        assert_eq!(decoded.instance_name.as_deref(), Some("MSSQLServer"));
    }

    #[test]
    fn prelogin_emits_traceid_only_when_present() {
        let mut without = BytesMut::new();
        PreloginMessage::new()
            .encode(&mut without)
            .expect("encode should succeed");
        assert!(!option_tokens(&without).contains(&PRELOGIN_TRACEID));

        let mut with = BytesMut::new();
        let mut prelogin = PreloginMessage::new();
        prelogin.activity_id = Some(ActivityId::new(
            Uuid::parse_str("6f9619ff-8b86-d011-b42d-00c04fc964ff").unwrap(),
            42,
        ));
        prelogin
            .clone()
            .encode(&mut with)
            .expect("encode should succeed");

        assert!(option_tokens(&with).contains(&PRELOGIN_TRACEID));
        // 16-byte GUID + 4-byte sequence.
        assert_eq!(
            option_payload(&with, PRELOGIN_TRACEID).map(|p| p.len()),
            Some(20)
        );

        let decoded = PreloginMessage::decode(&mut with).expect("decode should succeed");
        assert_eq!(decoded.activity_id, prelogin.activity_id);
    }

    #[test]
    fn validate_instance_accepts_valid_response() {
        // Server valid response = lone 0x00 -> decoded as `None`.
        let msg = PreloginMessage::new();
        assert!(msg.validate_instance(Some("MSSQLServer")).is_ok());
        // No requested instance -> nothing to validate.
        assert!(msg.validate_instance(None).is_ok());
    }

    #[test]
    fn validate_instance_rejects_invalid_response() {
        let mut msg = PreloginMessage::new();
        msg.instance_name = Some("otherinstance".to_string());
        assert!(msg.validate_instance(Some("MSSQLServer")).is_err());
    }

    #[test]
    fn prelogin_roundtrip() {
        let mut payload = BytesMut::new();
        let prelogin = PreloginMessage::new();
        prelogin
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        let decoded = PreloginMessage::decode(&mut payload).expect("decode should succeed");

        assert_eq!(prelogin, decoded);
    }

    #[test]
    fn prelogin_with_fedauth_roundtrip() {
        let mut payload = BytesMut::new();
        let mut prelogin = PreloginMessage::new();
        prelogin.fed_auth_required = true;
        prelogin
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        let decoded = PreloginMessage::decode(&mut payload).expect("decode should succeed");

        assert_eq!(prelogin, decoded);
    }

    // #425: a server declining the requested encryption level must yield a
    // catchable protocol error instead of panicking.
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[test]
    fn negotiated_encryption_rejects_declined_level() {
        let mut prelogin = PreloginMessage::new();
        // Server responds with an encryption level the client did not offer /
        // that is weaker than the required `On`.
        prelogin.encryption = EncryptionLevel::Off;

        let result = prelogin.negotiated_encryption(EncryptionLevel::On);

        match result {
            Err(Error::Protocol(_)) => {}
            other => panic!("expected Err(Error::Protocol), got {:?}", other),
        }

        // A matching, valid negotiation still succeeds.
        prelogin.encryption = EncryptionLevel::On;
        assert_eq!(
            prelogin.negotiated_encryption(EncryptionLevel::On).unwrap(),
            EncryptionLevel::On
        );
    }
}
