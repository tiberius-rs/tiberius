use super::{Packet, PacketCodec, PacketHeader, HEADER_BYTES};
use crate::Error;
use asynchronous_codec::Decoder;
use bytes::{Buf, BytesMut};
use tracing::{event, Level};

pub trait Decode<B: Buf> {
    fn decode(src: &mut B) -> crate::Result<Self>
    where
        Self: Sized;
}

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < HEADER_BYTES {
            src.reserve(HEADER_BYTES);
            return Ok(None);
        }

        let header = PacketHeader::decode(&mut BytesMut::from(&src[0..HEADER_BYTES]))?;
        let length = header.length() as usize;

        if src.len() < length {
            src.reserve(length);
            return Ok(None);
        }

        event!(
            Level::TRACE,
            "Reading a {:?} ({} bytes)",
            header.r#type(),
            length,
        );

        let header = PacketHeader::decode(src)?;

        if length < HEADER_BYTES {
            return Err(Error::Protocol("Invalid packet length".into()));
        }

        let payload = src.split_to(length - HEADER_BYTES);

        Ok(Some(Packet::new(header, payload)))
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(buf)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(std::io::Error::other("bytes remaining on stream").into())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{Encode, PacketHeader, PacketType};

    // A full SQLBatch packet: 8-byte header + "hello world" payload => length 19.
    fn full_packet_bytes() -> BytesMut {
        let payload = BytesMut::from(&b"hello world"[..]);
        let packet = Packet::new(PacketHeader::batch(1), payload);

        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();
        // Sanity: 8 header + 11 payload.
        assert_eq!(buf.len(), 19);
        buf
    }

    #[test]
    fn decode_partial_header_returns_none() {
        // Fewer than HEADER_BYTES available: we must wait for more bytes and
        // never index into `&src[0..HEADER_BYTES]`.
        let mut src = BytesMut::from(&full_packet_bytes()[0..4]);
        let mut codec = PacketCodec;

        let out = codec.decode(&mut src).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn decode_complete_packet_returns_some() {
        let mut src = full_packet_bytes();
        let mut codec = PacketCodec;

        let packet = codec
            .decode(&mut src)
            .unwrap()
            .expect("a complete packet must decode to Some");

        assert_eq!(packet.header.r#type() as u8, PacketType::SQLBatch as u8);
        // payload length must be `length - HEADER_BYTES` = 19 - 8 = 11.
        assert_eq!(&packet.payload[..], b"hello world");
        assert_eq!(packet.payload.len(), 11);
        // The whole packet is consumed.
        assert!(src.is_empty());
    }

    #[test]
    fn decode_incomplete_body_returns_none() {
        // Full header present (declares length 19) but only part of the body is
        // buffered: must return None rather than splitting past the buffer end.
        let mut src = BytesMut::from(&full_packet_bytes()[0..11]);
        let mut codec = PacketCodec;

        let out = codec.decode(&mut src).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn decode_minimal_packet_exactly_header_bytes() {
        // An empty-payload packet is exactly HEADER_BYTES (8) long with a
        // declared length of 8. This is the boundary for both length checks:
        // `src.len() < HEADER_BYTES` and `length < HEADER_BYTES` must be false.
        let packet = Packet::new(PacketHeader::attention(1), BytesMut::new());
        let mut src = BytesMut::new();
        packet.encode(&mut src).unwrap();
        assert_eq!(src.len(), 8);

        let mut codec = PacketCodec;
        let packet = codec
            .decode(&mut src)
            .unwrap()
            .expect("an 8-byte packet must decode to Some");

        assert_eq!(
            packet.header.r#type() as u8,
            PacketType::AttentionSignal as u8
        );
        assert!(packet.payload.is_empty());
    }

    #[test]
    fn decode_rejects_length_below_header() {
        // Declare a total length smaller than the header itself. We have enough
        // bytes buffered, so we reach the `length < HEADER_BYTES` guard, which
        // must error rather than underflow `length - HEADER_BYTES`.
        let packet = Packet::new(PacketHeader::attention(1), BytesMut::new());
        let mut src = BytesMut::new();
        packet.encode(&mut src).unwrap();
        // Overwrite the BE length field (bytes 2..4) with 5 (< HEADER_BYTES).
        src[2] = 0;
        src[3] = 5;

        let mut codec = PacketCodec;
        let err = codec
            .decode(&mut src)
            .expect_err("length below header must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn decode_eof_returns_some_for_complete_packet() {
        let mut src = full_packet_bytes();
        let mut codec = PacketCodec;

        let packet = codec
            .decode_eof(&mut src)
            .unwrap()
            .expect("decode_eof must yield a complete packet");
        assert_eq!(packet.header.r#type() as u8, PacketType::SQLBatch as u8);
        assert_eq!(&packet.payload[..], b"hello world");
    }

    #[test]
    fn decode_eof_errors_on_trailing_partial_bytes() {
        // A partial packet at EOF (no full frame, buffer not empty) is an error.
        let mut src = BytesMut::from(&full_packet_bytes()[0..4]);
        let mut codec = PacketCodec;

        assert!(codec.decode_eof(&mut src).is_err());
    }
}
