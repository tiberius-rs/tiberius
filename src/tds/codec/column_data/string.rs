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
            // allocation + copy per value).
            let units = buf.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]]));

            // NVARCHAR/NCHAR may be decoded losslessly when the connection opted
            // in (`Config::lossy_utf16_decoding`), replacing invalid surrogates
            // with U+FFFD so legacy rows holding unchecked UCS-2 stay readable.
            // XML (`ty == Xml`, routed here from `xml::decode`) is always strict,
            // regardless of the flag. Either way the `buf.len() % 2` guard above
            // already rejected desynced (odd) lengths.
            if matches!(ty, NChar | NVarchar) && src.context().lossy_utf16() {
                let s: String = char::decode_utf16(units)
                    .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect();
                Ok(Some(s.into()))
            } else {
                // Strict: invalid surrogates error, matching the previous
                // `String::from_utf16` behaviour.
                let s = char::decode_utf16(units)
                    .collect::<Result<String, _>>()
                    .map_err(|_| Error::Protocol("nvarchar: invalid UTF-16 sequence".into()))?;
                Ok(Some(s.into()))
            }
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    // Lossy NVARCHAR decoding replaces an unpaired surrogate with U+FFFD.
    #[tokio::test]
    async fn nvarchar_lossy_replaces_lone_surrogate() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(2); // fixed-size PLP length prefix
        buf.put_u16_le(0xD800); // unpaired high surrogate

        let mut reader = buf.into_sql_read_bytes();
        reader.context_mut().set_lossy_utf16(true);
        let value = decode(&mut reader, VarLenType::NVarchar, 40, None)
            .await
            .expect("lossy nvarchar must decode malformed UTF-16");
        assert_eq!(value.as_deref(), Some("\u{fffd}"));
    }

    // Strict is the default: an unpaired surrogate is a protocol error.
    #[tokio::test]
    async fn nvarchar_strict_rejects_lone_surrogate() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(2);
        buf.put_u16_le(0xD800);

        let err = decode(
            &mut buf.into_sql_read_bytes(),
            VarLenType::NVarchar,
            40,
            None,
        )
        .await
        .expect_err("strict nvarchar must reject malformed UTF-16");
        assert!(matches!(err, Error::Protocol(_)));
    }

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
