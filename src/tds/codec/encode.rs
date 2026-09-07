use super::{AllHeaderTy, Packet, PacketCodec, ALL_HEADERS_LEN_TX};
use asynchronous_codec::Encoder;
use bytes::{BufMut, BytesMut};

pub(crate) trait Encode<B: BufMut> {
    fn encode(self, dst: &mut B) -> crate::Result<()>;
}

/// Encodes a `B_VARCHAR` (MS-TDS 2.2.5.1.2): a single-byte count of UTF-16 code
/// units followed by the string encoded as little-endian UCS-2.
///
/// The length prefix is a single byte, so a string longer than 255 UTF-16 code
/// units cannot be represented. Truncating the count with `as u8` while still
/// writing every unit would desync the wire, so an over-long string is rejected
/// with an [`Error::Protocol`](crate::Error::Protocol) instead.
pub(crate) fn encode_b_varchar(dst: &mut BytesMut, s: &str) -> crate::Result<()> {
    let units: Vec<u16> = s.encode_utf16().collect();

    if units.len() > u8::MAX as usize {
        return Err(crate::Error::Protocol(
            format!(
                "string is too long for a B_VARCHAR ({} UTF-16 code units, max 255)",
                units.len()
            )
            .into(),
        ));
    }

    dst.put_u8(units.len() as u8);

    for unit in units {
        dst.put_u16_le(unit);
    }

    Ok(())
}

/// Writes the `ALL_HEADERS` block carrying the transaction descriptor that
/// precedes SQLBatch, RPC and Transaction Manager request payloads (MS-TDS
/// 2.2.5.3 / 2.2.5.3.1). The single header is the `TransactionDescriptor`
/// header with an outstanding-request count of 1.
pub(crate) fn encode_all_headers_tx(dst: &mut BytesMut, transaction_desc: [u8; 8]) {
    dst.put_u32_le(ALL_HEADERS_LEN_TX as u32);
    dst.put_u32_le(ALL_HEADERS_LEN_TX as u32 - 4);
    dst.put_u16_le(AllHeaderTy::TransactionDescriptor as u16);
    dst.put_slice(&transaction_desc);
    dst.put_u32_le(1);
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

    #[test]
    fn encode_b_varchar_is_byte_exact() {
        let mut dst = BytesMut::new();
        encode_b_varchar(&mut dst, "Hi").unwrap();

        let mut expected = Vec::new();
        expected.push(2u8); // two UTF-16 code units
        expected.extend_from_slice(&('H' as u16).to_le_bytes());
        expected.extend_from_slice(&('i' as u16).to_le_bytes());

        assert_eq!(&dst[..], &expected[..]);
    }

    #[test]
    fn encode_b_varchar_empty_writes_zero_length() {
        let mut dst = BytesMut::new();
        encode_b_varchar(&mut dst, "").unwrap();
        assert_eq!(&dst[..], &[0u8]);
    }

    // A B_VARCHAR length prefix is a single byte; exactly 255 code units is the
    // boundary of what is representable and must still encode.
    #[test]
    fn encode_b_varchar_accepts_255_units() {
        let name = "a".repeat(255);
        let mut dst = BytesMut::new();
        encode_b_varchar(&mut dst, &name).expect("255-unit string must encode");

        assert_eq!(dst[0], 255);
        assert_eq!(dst.len(), 1 + 255 * 2);
    }

    // 256+ code units cannot fit the u8 count; the encoder must error rather than
    // truncate the count with `as u8` (which would keep writing every unit and
    // desync the wire).
    #[test]
    fn encode_b_varchar_rejects_256_units() {
        let name = "a".repeat(256);
        let mut dst = BytesMut::new();
        let err = encode_b_varchar(&mut dst, &name).unwrap_err();
        assert!(matches!(err, crate::Error::Protocol(_)), "got {err:?}");
    }

    #[test]
    fn encode_all_headers_tx_is_byte_exact() {
        let td = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = BytesMut::new();
        encode_all_headers_tx(&mut dst, td);

        let mut expected = Vec::new();
        expected.extend_from_slice(&22u32.to_le_bytes()); // ALL_HEADERS_LEN_TX
        expected.extend_from_slice(&18u32.to_le_bytes()); // header length (len - 4)
        expected.extend_from_slice(&2u16.to_le_bytes()); // TransactionDescriptor type
        expected.extend_from_slice(&td); // transaction descriptor
        expected.extend_from_slice(&1u32.to_le_bytes()); // outstanding request count

        assert_eq!(&dst[..], &expected[..]);
    }
}
