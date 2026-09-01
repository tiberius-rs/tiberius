use super::{Decode, Encode, PacketHeader, PacketStatus, HEADER_BYTES};
use bytes::BytesMut;

#[derive(Debug)]
pub struct Packet {
    pub(crate) header: PacketHeader,
    pub(crate) payload: BytesMut,
}

impl Packet {
    pub(crate) fn new(header: PacketHeader, payload: BytesMut) -> Self {
        Self { header, payload }
    }

    pub(crate) fn is_last(&self) -> bool {
        self.header.status() == PacketStatus::EndOfMessage
    }

    pub(crate) fn into_parts(self) -> (PacketHeader, BytesMut) {
        (self.header, self.payload)
    }
}

impl Encode<BytesMut> for Packet {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let size = (self.payload.len() as u16 + HEADER_BYTES as u16).to_be_bytes();

        self.header.encode(dst)?;
        dst.extend(self.payload);

        dst[2] = size[0];
        dst[3] = size[1];

        Ok(())
    }
}

impl Decode<BytesMut> for Packet {
    fn decode(src: &mut BytesMut) -> crate::Result<Self> {
        Ok(Self {
            header: PacketHeader::decode(src)?,
            payload: src.split(),
        })
    }
}

impl Extend<u8> for Packet {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.payload.extend(iter)
    }
}

impl<'a> Extend<&'a u8> for Packet {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.payload.extend(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::PacketHeader;

    #[test]
    fn is_last_reflects_end_of_message_status() {
        let mut packet = Packet::new(PacketHeader::batch(1), BytesMut::new());
        assert!(!packet.is_last());

        packet.header.set_status(PacketStatus::EndOfMessage);
        assert!(packet.is_last());
    }

    #[test]
    fn into_parts_returns_header_and_payload() {
        let payload = BytesMut::from(&b"hello"[..]);
        let packet = Packet::new(PacketHeader::batch(3), payload.clone());

        let (header, parts_payload) = packet.into_parts();
        assert_eq!(header.r#type() as u8, PacketHeader::batch(3).r#type() as u8);
        assert_eq!(parts_payload, payload);
    }

    #[test]
    fn encode_patches_total_length_into_header() {
        let payload = BytesMut::from(&b"abcd"[..]);
        let packet = Packet::new(PacketHeader::batch(1), payload);

        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();

        // 8 header bytes + 4 payload bytes.
        assert_eq!(&buf[2..4], &12u16.to_be_bytes());
        assert_eq!(&buf[8..], b"abcd");
    }

    #[test]
    fn decode_splits_header_and_remaining_payload() {
        let payload = BytesMut::from(&b"xyz"[..]);
        let packet = Packet::new(PacketHeader::batch(1), payload);

        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();

        let decoded = Packet::decode(&mut buf).unwrap();
        assert_eq!(&decoded.payload[..], b"xyz");
        assert!(buf.is_empty());
    }

    #[test]
    fn extend_by_value_and_by_ref_append_to_payload() {
        let mut packet = Packet::new(PacketHeader::batch(1), BytesMut::new());
        packet.extend(vec![1u8, 2, 3]);
        assert_eq!(&packet.payload[..], &[1, 2, 3]);

        let more = [4u8, 5];
        packet.extend(more.iter());
        assert_eq!(&packet.payload[..], &[1, 2, 3, 4, 5]);
    }
}
