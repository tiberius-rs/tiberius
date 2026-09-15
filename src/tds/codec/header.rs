use super::{Decode, Encode};
use crate::Error;
use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryFrom;

uint_enum! {
    /// the type of the packet [2.2.3.1.1]#[repr(u32)]
    #[repr(u8)]
    pub enum PacketType {
        SQLBatch = 1,
        /// unused
        PreTDSv7Login = 2,
        Rpc = 3,
        TabularResult = 4,
        AttentionSignal = 6,
        BulkLoad = 7,
        /// Federated Authentication Token
        Fat = 8,
        TransactionManagerReq = 14,
        TDSv7Login = 16,
        Sspi = 17,
        PreLogin = 18,
    }
}

uint_enum! {
    /// the message state [2.2.3.1.2]
    #[repr(u8)]
    pub enum PacketStatus {
        NormalMessage = 0,
        EndOfMessage = 1,
        /// [client to server ONLY] (EndOfMessage also required)
        IgnoreEvent = 3,
        /// [client to server ONLY] [>= TDSv7.1]
        ResetConnection = 0x08,
        /// [client to server ONLY] [>= TDSv7.3]
        ResetConnectionSkipTran = 0x10,
    }
}

/// packet header consisting of 8 bytes [2.2.3.1]
#[derive(Debug, Clone, Copy)]
pub(crate) struct PacketHeader {
    ty: PacketType,
    status: PacketStatus,
    /// [BE] the length of the packet (including the 8 header bytes)
    /// must match the negotiated size sending from client to server [since TDSv7.3] after login
    /// (only if not EndOfMessage)
    length: u16,
    /// [BE] the process ID on the server, for debugging purposes only
    spid: u16,
    /// packet id
    id: u8,
    /// currently unused
    window: u8,
}

impl PacketHeader {
    pub fn new(length: usize, id: u8) -> PacketHeader {
        assert!(length <= u16::MAX as usize);
        PacketHeader {
            ty: PacketType::TDSv7Login,
            status: PacketStatus::ResetConnection,
            length: length as u16,
            spid: 0,
            id,
            window: 0,
        }
    }

    pub fn rpc(id: u8) -> Self {
        Self {
            ty: PacketType::Rpc,
            status: PacketStatus::NormalMessage,
            ..Self::new(0, id)
        }
    }

    pub fn pre_login(id: u8) -> Self {
        Self {
            ty: PacketType::PreLogin,
            status: PacketStatus::EndOfMessage,
            ..Self::new(0, id)
        }
    }

    pub fn login(id: u8) -> Self {
        Self {
            ty: PacketType::TDSv7Login,
            status: PacketStatus::EndOfMessage,
            ..Self::new(0, id)
        }
    }

    // Only the Windows integrated-auth (winauth) login path sends a standalone
    // SSPI packet; every other auth path (including unix GSSAPI) wraps the token
    // in a login packet. Gate the constructor so it compiles only there.
    #[cfg(all(windows, feature = "winauth"))]
    pub fn sspi(id: u8) -> Self {
        Self {
            ty: PacketType::Sspi,
            status: PacketStatus::EndOfMessage,
            ..Self::new(0, id)
        }
    }

    pub fn batch(id: u8) -> Self {
        Self {
            ty: PacketType::SQLBatch,
            status: PacketStatus::NormalMessage,
            ..Self::new(0, id)
        }
    }

    pub fn bulk_load(id: u8) -> Self {
        Self {
            ty: PacketType::BulkLoad,
            status: PacketStatus::NormalMessage,
            ..Self::new(0, id)
        }
    }

    pub fn set_status(&mut self, status: PacketStatus) {
        self.status = status;
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    pub fn set_type(&mut self, ty: PacketType) {
        self.ty = ty;
    }

    pub fn status(&self) -> PacketStatus {
        self.status
    }

    pub fn r#type(&self) -> PacketType {
        self.ty
    }

    pub fn length(&self) -> u16 {
        self.length
    }
}

impl<B> Encode<B> for PacketHeader
where
    B: BufMut,
{
    fn encode(self, dst: &mut B) -> crate::Result<()> {
        dst.put_u8(self.ty as u8);
        dst.put_u8(self.status as u8);
        dst.put_u16(self.length);
        dst.put_u16(self.spid);
        dst.put_u8(self.id);
        dst.put_u8(self.window);

        Ok(())
    }
}

impl Decode<BytesMut> for PacketHeader {
    fn decode(src: &mut BytesMut) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let raw_ty = src.get_u8();

        let ty = PacketType::try_from(raw_ty).map_err(|_| {
            Error::Protocol(format!("header: invalid packet type: {}", raw_ty).into())
        })?;

        let status = PacketStatus::try_from(src.get_u8())
            .map_err(|_| Error::Protocol("header: invalid packet status".into()))?;

        let header = PacketHeader {
            ty,
            status,
            length: src.get_u16(),
            spid: src.get_u16(),
            id: src.get_u8(),
            window: src.get_u8(),
        };

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // --- constructors -----------------------------------------------------

    #[test]
    fn new_sets_defaults() {
        let header = PacketHeader::new(42, 7);
        assert_eq!(header.ty, PacketType::TDSv7Login);
        assert_eq!(header.status, PacketStatus::ResetConnection);
        assert_eq!(header.length, 42);
        assert_eq!(header.length(), 42);
        assert_eq!(header.id, 7);
        assert_eq!(header.spid, 0);
        assert_eq!(header.window, 0);
    }

    #[test]
    fn new_accepts_max_length() {
        let header = PacketHeader::new(u16::MAX as usize, 0);
        assert_eq!(header.length, u16::MAX);
    }

    #[test]
    #[should_panic]
    fn new_rejects_oversized_length() {
        let _ = PacketHeader::new(u16::MAX as usize + 1, 0);
    }

    #[test]
    fn pre_login_constructor() {
        let header = PacketHeader::pre_login(1);
        assert_eq!(header.r#type(), PacketType::PreLogin);
        assert_eq!(header.status(), PacketStatus::EndOfMessage);
        assert_eq!(header.id, 1);
    }

    #[test]
    fn login_constructor() {
        let header = PacketHeader::login(2);
        assert_eq!(header.r#type(), PacketType::TDSv7Login);
        assert_eq!(header.status(), PacketStatus::EndOfMessage);
        assert_eq!(header.id, 2);
    }

    #[test]
    fn rpc_constructor() {
        let header = PacketHeader::rpc(3);
        assert_eq!(header.r#type(), PacketType::Rpc);
        assert_eq!(header.status(), PacketStatus::NormalMessage);
        assert_eq!(header.id, 3);
    }

    #[test]
    fn batch_constructor() {
        let header = PacketHeader::batch(4);
        assert_eq!(header.r#type(), PacketType::SQLBatch);
        assert_eq!(header.status(), PacketStatus::NormalMessage);
        assert_eq!(header.id, 4);
    }

    #[test]
    fn bulk_load_constructor() {
        let header = PacketHeader::bulk_load(5);
        assert_eq!(header.r#type(), PacketType::BulkLoad);
        assert_eq!(header.status(), PacketStatus::NormalMessage);
        assert_eq!(header.id, 5);
    }

    // The `sspi` constructor only exists on the Windows integrated-auth path, so
    // its test must be gated identically to the constructor itself.
    #[cfg(all(windows, feature = "winauth"))]
    #[test]
    fn sspi_constructor() {
        let header = PacketHeader::sspi(9);
        assert_eq!(header.r#type(), PacketType::Sspi);
        assert_eq!(header.status(), PacketStatus::EndOfMessage);
        assert_eq!(header.length(), 0);
        assert_eq!(header.id, 9);
    }

    // --- mutators ---------------------------------------------------------

    #[test]
    fn set_status_updates_status() {
        let mut header = PacketHeader::batch(0);
        assert_eq!(header.status(), PacketStatus::NormalMessage);
        header.set_status(PacketStatus::EndOfMessage);
        assert_eq!(header.status(), PacketStatus::EndOfMessage);
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    #[test]
    fn set_type_updates_type() {
        let mut header = PacketHeader::login(0);
        header.set_type(PacketType::PreLogin);
        assert_eq!(header.r#type(), PacketType::PreLogin);
    }

    // --- encode / decode round-trips -------------------------------------

    fn round_trip(header: PacketHeader) -> PacketHeader {
        let mut buf = BytesMut::new();
        header.encode(&mut buf).expect("encode");
        // The header is exactly 8 bytes on the wire [2.2.3.1].
        assert_eq!(buf.len(), 8);
        PacketHeader::decode(&mut buf).expect("decode")
    }

    fn assert_same(a: PacketHeader, b: PacketHeader) {
        assert_eq!(a.ty, b.ty);
        assert_eq!(a.status, b.status);
        assert_eq!(a.length, b.length);
        assert_eq!(a.spid, b.spid);
        assert_eq!(a.id, b.id);
        assert_eq!(a.window, b.window);
    }

    #[test]
    fn encode_writes_fields_big_endian() {
        let mut header = PacketHeader::new(0x0102, 0xAB);
        header.ty = PacketType::PreLogin;
        header.status = PacketStatus::EndOfMessage;
        header.spid = 0x0304;
        header.window = 0xCD;

        let mut buf = BytesMut::new();
        header.encode(&mut buf).expect("encode");

        assert_eq!(
            &buf[..],
            &[
                PacketType::PreLogin as u8,
                PacketStatus::EndOfMessage as u8,
                0x01,
                0x02, // length, big-endian
                0x03,
                0x04, // spid, big-endian
                0xAB, // id
                0xCD, // window
            ]
        );
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let mut header = PacketHeader::new(1234, 200);
        header.ty = PacketType::TabularResult;
        header.status = PacketStatus::NormalMessage;
        header.spid = 4321;
        header.window = 99;

        assert_same(header, round_trip(header));
    }

    #[test]
    fn round_trip_preserves_end_of_message_flag() {
        let decoded = round_trip(PacketHeader::pre_login(1));
        assert_eq!(decoded.status(), PacketStatus::EndOfMessage);
        assert_eq!(decoded.r#type(), PacketType::PreLogin);
    }

    #[test]
    fn round_trip_all_packet_types() {
        for ty in [
            PacketType::SQLBatch,
            PacketType::Rpc,
            PacketType::TabularResult,
            PacketType::AttentionSignal,
            PacketType::BulkLoad,
            PacketType::Fat,
            PacketType::TransactionManagerReq,
            PacketType::TDSv7Login,
            PacketType::Sspi,
            PacketType::PreLogin,
        ] {
            let mut header = PacketHeader::new(64, 1);
            header.ty = ty;
            assert_eq!(round_trip(header).ty, ty);
        }
    }

    #[test]
    fn round_trip_all_status_flags() {
        for status in [
            PacketStatus::NormalMessage,
            PacketStatus::EndOfMessage,
            PacketStatus::IgnoreEvent,
            PacketStatus::ResetConnection,
            PacketStatus::ResetConnectionSkipTran,
        ] {
            let mut header = PacketHeader::new(8, 0);
            header.status = status;
            assert_eq!(round_trip(header).status, status);
        }
    }

    #[test]
    fn round_trip_length_boundaries() {
        for length in [0usize, 1, 8, 255, 256, u16::MAX as usize] {
            let header = PacketHeader::new(length, 0);
            assert_eq!(round_trip(header).length(), length as u16);
        }
    }

    #[test]
    fn round_trip_packet_id_range() {
        for id in [0u8, 1, 127, 128, 254, 255] {
            let header = PacketHeader::batch(id);
            assert_eq!(round_trip(header).id, id);
        }
    }

    #[test]
    fn decode_rejects_invalid_packet_type() {
        let mut buf = BytesMut::from(&[0xFFu8, 1, 0, 8, 0, 0, 0, 0][..]);
        assert!(PacketHeader::decode(&mut buf).is_err());
    }

    #[test]
    fn decode_rejects_invalid_status() {
        // 0x02 is not a valid PacketStatus.
        let mut buf = BytesMut::from(&[PacketType::SQLBatch as u8, 0x02, 0, 8, 0, 0, 0, 0][..]);
        assert!(PacketHeader::decode(&mut buf).is_err());
    }
}
