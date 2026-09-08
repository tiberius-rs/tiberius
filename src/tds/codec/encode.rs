use super::{Packet, PacketCodec};
use asynchronous_codec::Encoder;
use bytes::{BufMut, BytesMut};

pub(crate) trait Encode<B: BufMut> {
    fn encode(self, dst: &mut B) -> crate::Result<()>;
}

impl Encoder for PacketCodec {
    type Item<'a> = Packet;
    type Error = crate::Error;

    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode(dst)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{PacketHeader, PacketType};

    #[test]
    fn encode_writes_header_and_payload_to_dst() {
        let payload = BytesMut::from(&b"abcd"[..]);
        let packet = Packet::new(PacketHeader::batch(1), payload);

        let mut dst = BytesMut::new();
        let mut codec = PacketCodec;
        codec.encode(packet, &mut dst).expect("encode must succeed");

        // 8-byte header + 4-byte payload; a no-op encode would leave dst empty.
        assert_eq!(dst.len(), 12);
        assert_eq!(dst[0], PacketType::SQLBatch as u8);
        // Total length is patched into the BE length field (bytes 2..4).
        assert_eq!(&dst[2..4], &12u16.to_be_bytes());
        assert_eq!(&dst[8..], b"abcd");
    }
}
