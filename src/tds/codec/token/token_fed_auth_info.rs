use crate::{Error, SqlReadBytes};
use futures_util::io::AsyncReadExt;

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
}
