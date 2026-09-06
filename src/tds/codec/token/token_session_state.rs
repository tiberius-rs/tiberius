use crate::{Error, SqlReadBytes};
use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::io::AsyncReadExt;
use std::io::{Cursor, Read};

/// Upper bound on the server-declared token length before it is used to size an
/// allocation. Session-state payloads are small (a few KiB of recoverable
/// server settings); anything beyond a few MiB is malformed. Capping avoids a
/// large-allocation DoS from a bogus length. 16 MiB is far above any legitimate
/// token.
const MAX_SESSION_STATE_LEN: usize = 16 * 1024 * 1024;

/// A single session state value carried by a [`TokenSessionState`] token.
///
/// Each entry is identified by a `state_id` and carries an opaque, driver
/// server-defined payload. The client is expected to retain these values and
/// replay them when transparently re-establishing a broken connection during
/// session recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStateValue {
    /// The identifier of the state slot (`StateId`).
    pub id: u8,
    /// The opaque state payload (`StateValue`).
    pub value: Vec<u8>,
}

/// The `SESSIONSTATE` token (`0xE4`).
///
/// Sent by the server as part of the connection-resiliency / session-recovery
/// feature (MS-TDS §2.2.7.22). It informs the client about the current session
/// state so that the client can transparently reconnect and restore the
/// session after an idle connection has been broken. Tiberius does not yet
/// initiate transparent reconnects, so the token is decoded and retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSessionState {
    /// Sequence number of this session-state update (`SeqNo`). A value of
    /// `0xFFFFFFFF` indicates that the state cannot be reset and the connection
    /// is not recoverable.
    pub seq_no: u32,
    /// The `Status` byte. Bit 0 (`fRecoverable`) indicates whether the session
    /// is currently in a recoverable state.
    pub status: u8,
    /// The individual state values carried by this token.
    pub states: Vec<SessionStateValue>,
}

impl TokenSessionState {
    /// Whether the session is currently recoverable (`fRecoverable`, bit 0 of
    /// the `Status` byte).
    pub fn is_recoverable(&self) -> bool {
        self.status & 0x01 != 0
    }

    /// Parse the token body (everything following the `TokenType` and `Length`
    /// fields) from an in-memory buffer.
    fn parse(bytes: Vec<u8>) -> crate::Result<Self> {
        let mut buf = Cursor::new(bytes);

        let seq_no = buf.read_u32::<LittleEndian>()?;
        let status = buf.read_u8()?;

        let mut states = Vec::new();

        // The remaining bytes are a sequence of SessionStateData entries that
        // fill exactly the token length. Keep decoding until the buffer is
        // exhausted.
        let total = buf.get_ref().len() as u64;

        while buf.position() < total {
            let id = buf.read_u8()?;

            // StateLen is a single byte, unless it is 0xFF, in which case a
            // 4-byte (LONG) length follows.
            let short_len = buf.read_u8()?;
            let state_len = if short_len == 0xFF {
                buf.read_u32::<LittleEndian>()? as usize
            } else {
                short_len as usize
            };

            let mut value = vec![0u8; state_len];
            buf.read_exact(&mut value)?;

            states.push(SessionStateValue { id, value });
        }

        Ok(TokenSessionState {
            seq_no,
            status,
            states,
        })
    }

    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // Length (ULONG) of the token stream that follows, covering SeqNo,
        // Status and all SessionStateData entries.
        let len = src.read_u32_le().await? as usize;

        if len > MAX_SESSION_STATE_LEN {
            return Err(Error::Protocol(
                format!(
                    "SESSIONSTATE token length {len} exceeds the maximum of {MAX_SESSION_STATE_LEN}"
                )
                .into(),
            ));
        }

        let mut bytes = vec![0u8; len];
        src.read_exact(&mut bytes[0..len]).await?;

        if bytes.len() < 5 {
            return Err(Error::Protocol(
                "SESSIONSTATE token too short to contain SeqNo and Status".into(),
            ));
        }

        Self::parse(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_two_state_values() {
        // SeqNo = 1, Status = 0x01 (fRecoverable), then two SessionStateData
        // entries with short lengths.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes()); // SeqNo
        body.push(0x01); // Status: recoverable

        // State 1: id = 0, len = 3, value = [0xAA, 0xBB, 0xCC]
        body.push(0x00);
        body.push(0x03);
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        // State 2: id = 7, len = 1, value = [0x42]
        body.push(0x07);
        body.push(0x01);
        body.push(0x42);

        let token = TokenSessionState::parse(body).unwrap();

        assert_eq!(token.seq_no, 1);
        assert_eq!(token.status, 0x01);
        assert!(token.is_recoverable());
        assert_eq!(token.states.len(), 2);

        assert_eq!(token.states[0].id, 0);
        assert_eq!(token.states[0].value, vec![0xAA, 0xBB, 0xCC]);

        assert_eq!(token.states[1].id, 7);
        assert_eq!(token.states[1].value, vec![0x42]);
    }

    #[test]
    fn parse_long_state_length() {
        // A single state whose length is encoded with the 0xFF escape followed
        // by a 4-byte length.
        let mut body = Vec::new();
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // SeqNo (not recoverable)
        body.push(0x00); // Status: not recoverable

        body.push(0x02); // StateId
        body.push(0xFF); // long-length escape
        body.extend_from_slice(&300u32.to_le_bytes()); // StateLen = 300
        body.extend_from_slice(&vec![0x5A; 300]);

        let token = TokenSessionState::parse(body).unwrap();

        assert_eq!(token.seq_no, 0xFFFF_FFFF);
        assert!(!token.is_recoverable());
        assert_eq!(token.states.len(), 1);
        assert_eq!(token.states[0].id, 2);
        assert_eq!(token.states[0].value.len(), 300);
        assert!(token.states[0].value.iter().all(|&b| b == 0x5A));
    }

    // A bogus token length beyond the cap must be rejected before it is used to
    // size the body allocation, rather than attempting a multi-GiB allocation.
    #[tokio::test]
    async fn rejects_oversized_token_length() {
        use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
        use bytes::{BufMut, BytesMut};

        let mut buf = BytesMut::new();
        buf.put_u32_le(MAX_SESSION_STATE_LEN as u32 + 1);

        let err = TokenSessionState::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
    }
}
