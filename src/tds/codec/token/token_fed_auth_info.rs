use crate::{Error, SqlReadBytes};
use futures_util::io::AsyncReadExt;

/// Upper bound on the server-declared `TokenLength` before it is used to size an
/// allocation. A `FEDAUTHINFO` token only carries a small handful of URLs/SPNs,
/// so anything beyond a few MiB is malformed; capping avoids a large-allocation
/// DoS from a bogus length. 16 MiB is far above any legitimate token.

/// `FedAuthInfoId` for the STS URL, an Active Directory Security Token Service
/// endpoint that the client contacts to acquire an access token.
const FED_AUTH_INFO_ID_STSURL: u8 = 0x01;

/// `FedAuthInfoId` for the Service Principal Name the token is requested for.
const FED_AUTH_INFO_ID_SPN: u8 = 0x02;

/// A `FEDAUTHINFO` token (`0xEE`), returned by the server during the federated
/// authentication handshake to describe how the client should acquire a
/// federated access token.
///
/// The server sends this token when the client requested a library-driven
/// federated authentication flow (for example, the ADAL/MSAL interactive or
/// integrated Azure Active Directory flows) in the `FEDAUTH` `FeatureExt`
/// option of the login request. The token carries the information elements the
/// client needs to talk to the Active Directory Security Token Service (STS):
/// the STS URL to authenticate against and the Service Principal Name (SPN) the
/// token is requested for.
///
/// See [MS-TDS] §2.2.7.12 (`FEDAUTHINFO`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenFedAuthInfo {
    /// The URL of the Active Directory Security Token Service the client should
    /// authenticate against (`FedAuthInfoId` `STSURL`, `0x01`), if the server
    /// provided one.
    pub sts_url: Option<String>,
    /// The Service Principal Name the federated access token is requested for
    /// (`FedAuthInfoId` `SPN`, `0x02`), if the server provided one.
    pub spn: Option<String>,
}

impl TokenFedAuthInfo {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // TokenLength: the length, in bytes, of the token value that follows,
        // starting at (and including) `CountOfInfoIDs`.
        let token_length = src.read_u32_le().await? as usize;

        if token_length > super::MAX_TOKEN_BODY {
            return Err(Error::Protocol(
                format!("FEDAUTHINFO token length {token_length} exceeds the maximum").into(),
            ));
        }

        let mut body = vec![0u8; token_length];
        src.read_exact(&mut body).await?;

        Self::parse(&body)
    }

    /// Parses the body of a `FEDAUTHINFO` token: the bytes that follow the
    /// `TokenType` and `TokenLength` fields, starting at `CountOfInfoIDs`.
    ///
    /// The information-data offsets carried by each option are measured from the
    /// start of this body (the `CountOfInfoIDs` field), matching the on-the-wire
    /// layout described in [MS-TDS] §2.2.7.12.
    fn parse(body: &[u8]) -> crate::Result<Self> {
        let read_u32 = |buf: &[u8], at: usize| -> crate::Result<u32> {
            buf.get(at..at + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .ok_or_else(|| {
                    Error::Protocol("FEDAUTHINFO token truncated while reading a DWORD".into())
                })
        };

        // CountOfInfoIDs: the number of `FedAuthInfoOpt` options that follow.
        let count = read_u32(body, 0)? as usize;

        let mut info = TokenFedAuthInfo::default();

        for i in 0..count {
            // Each `FedAuthInfoOpt` is 9 bytes: a 1-byte id followed by two DWORDs.
            let opt = 4 + i * 9;

            let id = *body.get(opt).ok_or_else(|| {
                Error::Protocol("FEDAUTHINFO token truncated while reading an option id".into())
            })?;

            let data_len = read_u32(body, opt + 1)? as usize;
            let data_offset = read_u32(body, opt + 5)? as usize;

            let data = body
                .get(data_offset..data_offset + data_len)
                .ok_or_else(|| {
                    Error::Protocol("FEDAUTHINFO token data offset out of bounds".into())
                })?;

            // The info data is a Unicode (UCS-2/UTF-16LE) string, so it must be
            // an even number of bytes.
            if data_len & 1 != 0 {
                return Err(Error::Protocol(
                    "FEDAUTHINFO token data is not valid UTF-16".into(),
                ));
            }

            let mut utf16 = Vec::with_capacity(data_len / 2);
            let mut idx = 0;
            while idx < data_len {
                utf16.push(u16::from_le_bytes([data[idx], data[idx + 1]]));
                idx += 2;
            }

            let value = String::from_utf16(&utf16).map_err(|_| {
                Error::Protocol("FEDAUTHINFO token data is not valid UTF-16".into())
            })?;

            match id {
                FED_AUTH_INFO_ID_STSURL => info.sts_url = Some(value),
                FED_AUTH_INFO_ID_SPN => info.spn = Some(value),
                // Unknown info ids are ignored for forward compatibility, as
                // required by [MS-TDS] §2.2.7.12.
                _ => (),
            }
        }

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn parses_stsurl_and_spn() {
        let sts = utf16le("https://login.microsoftonline.com/");
        let spn = utf16le("https://database.windows.net/");

        // Body layout: CountOfInfoIDs, then two FedAuthInfoOpt, then the data.
        let count: u32 = 2;
        let header_len = 4 + 2 * 9; // count + two options
        let sts_offset = header_len;
        let spn_offset = header_len + sts.len();

        let mut body = Vec::new();
        body.extend_from_slice(&count.to_le_bytes());

        // Option 1: STSURL
        body.push(FED_AUTH_INFO_ID_STSURL);
        body.extend_from_slice(&(sts.len() as u32).to_le_bytes());
        body.extend_from_slice(&(sts_offset as u32).to_le_bytes());

        // Option 2: SPN
        body.push(FED_AUTH_INFO_ID_SPN);
        body.extend_from_slice(&(spn.len() as u32).to_le_bytes());
        body.extend_from_slice(&(spn_offset as u32).to_le_bytes());

        body.extend_from_slice(&sts);
        body.extend_from_slice(&spn);

        let info = TokenFedAuthInfo::parse(&body).unwrap();

        assert_eq!(
            info.sts_url.as_deref(),
            Some("https://login.microsoftonline.com/")
        );
        assert_eq!(info.spn.as_deref(), Some("https://database.windows.net/"));
    }

    #[test]
    fn ignores_unknown_info_id() {
        let count: u32 = 1;
        let mut body = Vec::new();
        body.extend_from_slice(&count.to_le_bytes());
        body.push(0x7F); // unknown id
        body.extend_from_slice(&0u32.to_le_bytes()); // data len
        body.extend_from_slice(&13u32.to_le_bytes()); // offset (past header, no data)

        let info = TokenFedAuthInfo::parse(&body).unwrap();
        assert_eq!(info, TokenFedAuthInfo::default());
    }

    #[test]
    fn rejects_out_of_bounds_offset() {
        let count: u32 = 1;
        let mut body = Vec::new();
        body.extend_from_slice(&count.to_le_bytes());
        body.push(FED_AUTH_INFO_ID_STSURL);
        body.extend_from_slice(&8u32.to_le_bytes()); // data len
        body.extend_from_slice(&1000u32.to_le_bytes()); // bogus offset

        assert!(TokenFedAuthInfo::parse(&body).is_err());
    }

    #[tokio::test]
    async fn decode_reads_length_prefix_and_parses_body() {
        // Exercises the full `decode` path: reading the 4-byte TokenLength, the
        // length bound check, reading the body, and parsing it. A mutation that
        // short-circuits `decode` to `Ok(Default::default())` would drop the
        // parsed STSURL, and a `<` mutation of the length bound check would
        // reject this (well-under-maximum) token outright.
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use bytes::{BufMut, BytesMut};

        let sts = utf16le("https://sts.example/");

        let count: u32 = 1;
        let header_len = 4 + 9; // count + one FedAuthInfoOpt
        let sts_offset = header_len;

        let mut body = Vec::new();
        body.extend_from_slice(&count.to_le_bytes());
        body.push(FED_AUTH_INFO_ID_STSURL);
        body.extend_from_slice(&(sts.len() as u32).to_le_bytes());
        body.extend_from_slice(&(sts_offset as u32).to_le_bytes());
        body.extend_from_slice(&sts);

        let mut buf = BytesMut::new();
        buf.put_u32_le(body.len() as u32); // TokenLength
        buf.put_slice(&body);

        let info = TokenFedAuthInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(info.sts_url.as_deref(), Some("https://sts.example/"));
        assert_eq!(info.spn, None);
    }

    #[tokio::test]
    async fn decode_rejects_oversized_token_length() {
        // A TokenLength above MAX_TOKEN_BODY must be rejected before any body is
        // read (the `token_length > MAX_TOKEN_BODY` guard).
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use bytes::{BufMut, BytesMut};

        let mut buf = BytesMut::new();
        buf.put_u32_le((super::super::MAX_TOKEN_BODY + 1) as u32);

        let err = TokenFedAuthInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect_err("oversized token length must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn parse_rejects_truncated_dword() {
        // A body too short to even read CountOfInfoIDs (a DWORD) trips the
        // `read_u32` truncation guard.
        let err = TokenFedAuthInfo::parse(&[0u8, 0u8]).expect_err("truncated body must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn parse_rejects_missing_option_id() {
        // CountOfInfoIDs claims one option, but the body ends right after the
        // count, so reading the option id is out of bounds.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes());

        let err = TokenFedAuthInfo::parse(&body).expect_err("missing option id must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn parse_rejects_odd_data_length() {
        // A data length that is not a multiple of two cannot be valid UTF-16.
        let count: u32 = 1;
        let header_len = 4 + 9;
        let mut body = Vec::new();
        body.extend_from_slice(&count.to_le_bytes());
        body.push(FED_AUTH_INFO_ID_STSURL);
        body.extend_from_slice(&3u32.to_le_bytes()); // odd data len
        body.extend_from_slice(&(header_len as u32).to_le_bytes()); // offset
        body.extend_from_slice(&[0u8, 0u8, 0u8]); // 3 data bytes

        let err = TokenFedAuthInfo::parse(&body).expect_err("odd data length must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn parse_rejects_invalid_utf16() {
        // Even-length but not valid UTF-16 (a lone high surrogate) must error.
        let count: u32 = 1;
        let header_len = 4 + 9;
        let mut body = Vec::new();
        body.extend_from_slice(&count.to_le_bytes());
        body.push(FED_AUTH_INFO_ID_STSURL);
        body.extend_from_slice(&2u32.to_le_bytes()); // data len
        body.extend_from_slice(&(header_len as u32).to_le_bytes()); // offset
        body.extend_from_slice(&0xD800u16.to_le_bytes()); // lone high surrogate

        let err = TokenFedAuthInfo::parse(&body).expect_err("invalid UTF-16 must error");
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn decode_accepts_token_length_at_maximum() {
        // The length bound check is `token_length > MAX_TOKEN_BODY`, so a token
        // whose length is exactly MAX_TOKEN_BODY must be accepted. `>=` or `==`
        // mutations of the `>` would reject it. The body is a valid, empty
        // (CountOfInfoIDs == 0) token padded out to the maximum length.
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use bytes::{BufMut, BytesMut};

        let token_length = super::super::MAX_TOKEN_BODY;

        let mut buf = BytesMut::new();
        buf.put_u32_le(token_length as u32); // TokenLength == MAX_TOKEN_BODY
        buf.put_slice(&vec![0u8; token_length]); // count = 0, rest padding

        let info = TokenFedAuthInfo::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert_eq!(info, TokenFedAuthInfo::default());
    }
}
