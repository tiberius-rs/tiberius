use super::{encode_all_headers_tx, Encode};
use bytes::{BufMut, BytesMut};
use std::borrow::Cow;

pub struct BatchRequest<'a> {
    queries: Cow<'a, str>,
    transaction_descriptor: [u8; 8],
}

impl<'a> BatchRequest<'a> {
    pub fn new(queries: impl Into<Cow<'a, str>>, transaction_descriptor: [u8; 8]) -> Self {
        Self {
            queries: queries.into(),
            transaction_descriptor,
        }
    }
}

impl<'a> Encode<BytesMut> for BatchRequest<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        encode_all_headers_tx(dst, self.transaction_descriptor);

        for c in self.queries.encode_utf16() {
            dst.put_u16_le(c);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_is_byte_exact() {
        let td = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let req = BatchRequest::new("Hi", td);

        let mut dst = BytesMut::new();
        req.encode(&mut dst).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&22u32.to_le_bytes()); // ALL_HEADERS_LEN_TX
        expected.extend_from_slice(&18u32.to_le_bytes()); // header length (len - 4)
        expected.extend_from_slice(&2u16.to_le_bytes()); // TransactionDescriptor type
        expected.extend_from_slice(&td); // transaction descriptor
        expected.extend_from_slice(&1u32.to_le_bytes()); // outstanding request count
        expected.extend_from_slice(&('H' as u16).to_le_bytes());
        expected.extend_from_slice(&('i' as u16).to_le_bytes());

        assert_eq!(&dst[..], &expected[..]);
    }
}
