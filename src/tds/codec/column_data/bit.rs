use crate::{error::Error, sql_read_bytes::SqlReadBytes, ColumnData};

pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let recv_len = src.read_u8().await? as usize;

    let res = match recv_len {
        0 => ColumnData::Bit(None),
        1 => ColumnData::Bit(Some(src.read_u8().await? > 0)),
        v => {
            return Err(Error::Protocol(
                format!("bitn: length of {} is invalid", v).into(),
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

    // At the boundary value 0 the comparison must be strictly `> 0`: a stored
    // byte of 0 is `false`. Mutating `>` to `>=` would decode 0 as `true`.
    #[tokio::test]
    async fn decode_zero_byte_is_false() {
        let mut buf = BytesMut::new();
        buf.put_u8(1); // length
        buf.put_u8(0); // value byte

        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::Bit(Some(false)));
    }

    #[tokio::test]
    async fn decode_nonzero_byte_is_true() {
        let mut buf = BytesMut::new();
        buf.put_u8(1); // length
        buf.put_u8(1); // value byte

        let data = decode(&mut buf.into_sql_read_bytes()).await.unwrap();
        assert_eq!(data, ColumnData::Bit(Some(true)));
    }

    // A length prefix other than 0 or 1 is an invalid bit encoding. Covers
    // the error arm at lines 12-16.
    #[tokio::test]
    async fn decode_invalid_length_errors() {
        let mut buf = BytesMut::new();
        buf.put_u8(2); // invalid length

        let err = decode(&mut buf.into_sql_read_bytes()).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }
}
