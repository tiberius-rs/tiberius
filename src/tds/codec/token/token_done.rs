use crate::{tds::codec::Encode, SqlReadBytes, TokenType};
use asynchronous_codec::BytesMut;
use bytes::BufMut;
use enumflags2::{bitflags, BitFlags};
use std::fmt;

#[derive(Debug, Default)]
pub struct TokenDone {
    status: BitFlags<DoneStatus>,
    cur_cmd: u16,
    done_rows: u64,
}

#[bitflags]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoneStatus {
    More = 1, // bit 0 (literal 1: `1 << 0` is shift-invariant)
    Error = 1 << 1,
    Inexact = 1 << 2,
    // reserved
    Count = 1 << 4,
    Attention = 1 << 5,
    // reserved
    RpcInBatch = 1 << 7,
    SrvError = 1 << 8,
}

impl TokenDone {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        // The DONE Status (MS-TDS §2.2.7.6) is a 2-byte bitmask with reserved
        // bits that a server (or a future SQL Server / Azure build) may set.
        // Truncate to the flags we model rather than erroring, matching how
        // COLMETADATA flags are handled.
        let status = BitFlags::from_bits_truncate(src.read_u16_le().await?);

        let cur_cmd = src.read_u16_le().await?;
        let done_row_count_bytes = src.context().version().done_row_count_bytes();

        let done_rows = match done_row_count_bytes {
            8 => src.read_u64_le().await?,
            4 => src.read_u32_le().await? as u64,
            _ => unreachable!(),
        };

        Ok(TokenDone {
            status,
            cur_cmd,
            done_rows,
        })
    }

    pub(crate) fn is_final(&self) -> bool {
        self.status.is_empty()
    }

    /// `true` when the server has set the `DONE_ATTN` status bit, indicating
    /// this DONE token acknowledges a client Attention signal (MS-TDS
    /// section 2.2.7.6).
    pub(crate) fn is_attention(&self) -> bool {
        self.status.contains(DoneStatus::Attention)
    }

    pub(crate) fn rows(&self) -> u64 {
        // The row count is only meaningful when the DONE_COUNT status bit is
        // set (MS-TDS §2.2.7.6); otherwise the field is not a valid count.
        if self.status.contains(DoneStatus::Count) {
            self.done_rows
        } else {
            0
        }
    }
}

impl Encode<BytesMut> for TokenDone {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u8(TokenType::Done as u8);
        dst.put_u16_le(BitFlags::bits(self.status));

        dst.put_u16_le(self.cur_cmd);
        dst.put_u64_le(self.done_rows);

        Ok(())
    }
}

impl fmt::Display for TokenDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.done_rows == 0 {
            write!(f, "Done with status {:?}", self.status)
        } else if self.done_rows == 1 {
            write!(f, "Done with status {:?} (1 row left)", self.status)
        } else {
            write!(
                f,
                "Done with status {:?} ({} rows left)",
                self.status, self.done_rows
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::BytesMut;

    #[tokio::test]
    async fn decode_final_done() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0); // status: empty => final
        buf.put_u16_le(0); // cur_cmd
        buf.put_u64_le(0); // done_rows (SqlServerN => 8 bytes)

        let done = TokenDone::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert!(done.is_final());
        assert_eq!(done.rows(), 0);
        assert!(format!("{}", done).starts_with("Done with status"));
    }

    #[tokio::test]
    async fn decode_with_count_and_rows() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(DoneStatus::Count as u16);
        buf.put_u16_le(0);
        buf.put_u64_le(5);

        let done = TokenDone::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert!(!done.is_final());
        assert_eq!(done.rows(), 5);
        assert!(format!("{}", done).contains("5 rows left"));
    }

    #[tokio::test]
    async fn decode_reads_four_byte_rowcount_on_pre_2005_versions() {
        // Pre-2005 servers encode the DONE rowcount in 4 bytes; the decoder must
        // pick the 4-byte arm from the negotiated version (kills "delete arm 4").
        use crate::sql_read_bytes::SqlReadBytes;
        use crate::tds::codec::login::FeatureLevel;

        let mut buf = BytesMut::new();
        buf.put_u16_le(DoneStatus::Count as u16);
        buf.put_u16_le(0);
        buf.put_u32_le(7); // 4-byte rowcount

        let mut reader = buf.into_sql_read_bytes();
        reader
            .context_mut()
            .set_version(FeatureLevel::SqlServer2000);

        let done = TokenDone::decode(&mut reader).await.unwrap();
        assert_eq!(done.rows(), 7);
    }

    #[tokio::test]
    async fn decode_single_row_display() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(DoneStatus::Count as u16);
        buf.put_u16_le(0);
        buf.put_u64_le(1);

        let done = TokenDone::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        assert!(format!("{}", done).contains("1 row left"));
    }

    #[tokio::test]
    async fn decode_tolerates_reserved_status_bits() {
        let mut buf = BytesMut::new();
        // bit 3 (0b1000 = 8) is reserved/undefined; combined with a real bit
        // (More = 0b1). We tolerate the reserved bit and keep the modeled one.
        buf.put_u16_le(0b1001);
        buf.put_u16_le(0);
        buf.put_u64_le(0);

        let done = TokenDone::decode(&mut buf.into_sql_read_bytes())
            .await
            .expect("reserved status bits must be tolerated");

        assert!(done.status.contains(DoneStatus::More));
    }

    #[tokio::test]
    async fn is_attention_reflects_attention_status_bit() {
        // With the Attention bit set, is_attention() must be true.
        let mut buf = BytesMut::new();
        buf.put_u16_le(DoneStatus::Attention as u16);
        buf.put_u16_le(0);
        buf.put_u64_le(0);

        let done = TokenDone::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();
        assert!(done.is_attention());

        // Without the Attention bit (a different, non-attention bit set),
        // is_attention() must be false.
        let mut buf = BytesMut::new();
        buf.put_u16_le(DoneStatus::More as u16);
        buf.put_u16_le(0);
        buf.put_u64_le(0);

        let done = TokenDone::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();
        assert!(!done.is_attention());
    }

    #[test]
    fn encode_writes_token_type_and_fields() {
        let done = TokenDone::default();
        let mut buf = BytesMut::new();
        done.encode(&mut buf).unwrap();

        assert_eq!(buf[0], TokenType::Done as u8);
        // status(2) + cur_cmd(2) + done_rows(8) after the 1-byte token type
        assert_eq!(buf.len(), 1 + 2 + 2 + 8);
    }
}
