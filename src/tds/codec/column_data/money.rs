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
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    // `smallmoney` (len 4) is a single scaled `i32` divided by 1e4. Uses a value
    // that is not a boundary: kills "delete match arm 4" (would fall through to
    // the error arm) and "replace `/` with `%`/`*`" (12345/1e4 = 1.2345, whereas
    // 12345 % 1e4 = 2345.0 and 12345 * 1e4 = 1.2345e8).
    #[tokio::test]
    async fn decode_smallmoney_arm() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(12345);

        let data = decode(&mut buf.into_sql_read_bytes(), 4).await.unwrap();
        match data {
            ColumnData::F64(Some(v)) => assert!((v - 1.2345).abs() < 1e-9, "v={}", v),
            other => panic!("expected F64, got {:?}", other),
        }
    }

    // `money` (len 8) is two 32-bit words: `((high << 32) + low) / 1e4`.
    // high = 1, low = 30000 gives ((1 << 32) + 30000) / 1e4 = 429499.7296.
    // Kills: "delete match arm 8" (error fallthrough); "replace `<<` with `>>`"
    // (1 >> 32 = 0 => 3.0); "replace `+` with `-`/`*`" (subtraction/mult differ);
    // and "replace outer `/` with `%`/`*`" (4294997296 % 1e4 = 7296.0).
    #[tokio::test]
    async fn decode_money_arm() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(1); // high word
        buf.put_u32_le(30000); // low word

        let data = decode(&mut buf.into_sql_read_bytes(), 8).await.unwrap();
        match data {
            ColumnData::F64(Some(v)) => assert!((v - 429499.7296).abs() < 1e-6, "v={}", v),
            other => panic!("expected F64, got {:?}", other),
        }
    }

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

    // A length other than 0/4/8 is an invalid money encoding. Covers 38-42.
    #[tokio::test]
    async fn decode_invalid_length_errors() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        let err = decode(&mut buf.into_sql_read_bytes(), 5).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }

    // The `decode_bytes` test helper panics on an unexpected length prefix.
    // Covers line 99 (the helper's fallthrough arm).
    #[test]
    fn decode_bytes_invalid_length_panics() {
        let result = std::panic::catch_unwind(|| decode_bytes(&[2u8, 0, 0, 0, 0]));
        assert!(result.is_err());
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
