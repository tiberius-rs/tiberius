use std::borrow::Cow;

use crate::{error::Error, sql_read_bytes::SqlReadBytes, tds::Collation, VarLenType};

pub(crate) async fn decode<R>(
    src: &mut R,
    ty: VarLenType,
    len: usize,
    collation: Option<Collation>,
) -> crate::Result<Option<Cow<'static, str>>>
where
    R: SqlReadBytes + Unpin,
{
    use VarLenType::*;

    let data = super::plp::decode(src, len).await?;

    match (data, ty) {
        // Codepages other than UTF
        (Some(buf), BigChar) | (Some(buf), BigVarChar) => {
            let collation = collation
                .as_ref()
                .ok_or_else(|| Error::Protocol("string column missing collation".into()))?;
            let encoder = collation.encoding()?;

            let s = encoder
                .decode_without_bom_handling_and_without_replacement(buf.as_ref())
                .ok_or_else(|| Error::Encoding("invalid sequence".into()))?
                .to_string();

            Ok(Some(s.into()))
        }
        // UTF-16
        (Some(buf), _) => {
            if buf.len() % 2 != 0 {
                return Err(Error::Protocol("nvarchar: invalid plp length".into()));
            }

            // Decode UTF-16LE straight from the byte pairs, without first
            // collecting an intermediate `Vec<u16>` (one fewer full-buffer
            // allocation + copy per value). Invalid surrogates still error,
            // matching the previous `String::from_utf16` behaviour.
            let s = char::decode_utf16(buf.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
                .collect::<Result<String, _>>()
                .map_err(|_| Error::Protocol("nvarchar: invalid UTF-16 sequence".into()))?;
            Ok(Some(s.into()))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    // A BigVarChar (non-UTF codepage) value with the collation omitted by the
    // server must return a protocol error rather than panicking on `unwrap`.
    #[tokio::test]
    async fn decode_bigvarchar_missing_collation_errors() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(2); // fixed-size PLP length prefix
        buf.put_slice(&[0x41, 0x42]); // "AB" in an 8-bit codepage

        let err = decode(
            &mut buf.into_sql_read_bytes(),
            VarLenType::BigVarChar,
            2,
            None,
        )
        .await
        .expect_err("missing collation must error, not panic");

        match err {
            Error::Protocol(msg) => {
                assert!(
                    msg.contains("missing collation"),
                    "unexpected protocol message: {msg}"
                );
            }
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }
}
