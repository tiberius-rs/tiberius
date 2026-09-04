use crate::{error::Error, sql_read_bytes::SqlReadBytes, ColumnData};
use bytes::BufMut;

/// Encode an `f64` as a money/smallmoney value into `dst`, prefixed with a
/// single length byte (as expected for a nullable `Money`/`Moneyn` column in a
/// bulk-load row). `max_len` is the column's declared length (8 for `money`,
/// 4 for `smallmoney`). Money is stored on the wire as a scaled integer
/// (value * 10_000).
pub(crate) fn encode<B>(dst: &mut B, max_len: usize, val: f64)
where
    B: BufMut,
{
    if max_len == 4 {
        dst.put_u8(4);
        dst.put_i32_le((val * 1e4).round() as i32);
    } else {
        dst.put_u8(8);
        let scaled = (val * 1e4).round() as i64;
        // money is transmitted as two 32-bit words, high word first.
        dst.put_i32_le((scaled >> 32) as i32);
        dst.put_u32_le(scaled as u32);
    }
}

pub(crate) async fn decode<R>(src: &mut R, len: u8) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let res = match len {
        0 => ColumnData::F64(None),
        4 => ColumnData::F64(Some(src.read_i32_le().await? as f64 / 1e4)),
        8 => ColumnData::F64(Some({
            let high = src.read_i32_le().await? as i64;
            let low = src.read_u32_le().await? as f64;

            ((high << 32) as f64 + low) / 1e4
        })),
        _ => {
            return Err(Error::Protocol(
                format!("money: length of {} is invalid", len).into(),
            ))
        }
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reverses the on-wire money representation the same way `decode` does,
    // so we can assert `encode` is the exact inverse without a live server.
    fn decode_bytes(bytes: &[u8]) -> f64 {
        let len = bytes[0];
        match len {
            4 => i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as f64 / 1e4,
            8 => {
                let high = i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as i64;
                let low = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as f64;
                ((high << 32) as f64 + low) / 1e4
            }
            _ => panic!("invalid length"),
        }
    }

    #[test]
    fn encode_smallmoney_roundtrips() {
        let mut buf = Vec::new();
        encode(&mut buf, 4, 1234.5678);
        assert_eq!(buf[0], 4);
        assert_eq!(buf.len(), 5);
        assert_eq!(decode_bytes(&buf), 1234.5678);
    }

    #[test]
    fn encode_money_roundtrips() {
        for val in [0.0, 1.0, -1.0, 1234.5678, -9999.9999, 92233720368.5477] {
            let mut buf = Vec::new();
            encode(&mut buf, 8, val);
            assert_eq!(buf[0], 8);
            assert_eq!(buf.len(), 9);
            assert!((decode_bytes(&buf) - val).abs() < 1e-3, "val={}", val);
        }
    }
}
