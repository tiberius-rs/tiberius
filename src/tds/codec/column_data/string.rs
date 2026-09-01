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
            let collation = collation.as_ref().unwrap();
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
