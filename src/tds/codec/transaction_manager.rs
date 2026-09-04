use super::{AllHeaderTy, Encode, ALL_HEADERS_LEN_TX};
use bytes::{BufMut, BytesMut};
use std::borrow::Cow;

uint_enum! {
    /// The request type of a Transaction Manager request, as defined in
    /// MS-TDS 2.2.6.8 (`TM_*` request kinds).
    #[repr(u16)]
    pub enum TransactionManagerRequestType {
        /// Get the address of the Distributed Transaction Coordinator.
        GetDtcAddress = 0,
        /// Import an existing distributed transaction (propagate).
        Propagate = 1,
        /// Begin a new transaction (`TM_BEGIN_XACT`).
        Begin = 5,
        /// Promote a local transaction to a distributed one (`TM_PROMOTE_XACT`).
        Promote = 6,
        /// Commit the active transaction (`TM_COMMIT_XACT`).
        Commit = 7,
        /// Roll back the active transaction (`TM_ROLLBACK_XACT`).
        Rollback = 8,
        /// Create a savepoint in the active transaction (`TM_SAVE_XACT`).
        Save = 9,
    }
}

uint_enum! {
    /// The transaction isolation level requested when beginning a transaction
    /// through a Transaction Manager request (MS-TDS 2.2.6.8).
    #[repr(u8)]
    pub enum IsolationLevel {
        /// Use the server's default isolation level.
        Unspecified = 0x00,
        /// `READ UNCOMMITTED`.
        ReadUncommitted = 0x01,
        /// `READ COMMITTED`.
        ReadCommitted = 0x02,
        /// `REPEATABLE READ`.
        RepeatableRead = 0x03,
        /// `SERIALIZABLE`.
        Serializable = 0x04,
        /// `SNAPSHOT`.
        Snapshot = 0x05,
    }
}

/// A Transaction Manager request (packet type `0x14`, MS-TDS 2.2.6.8).
///
/// These requests let the client begin, commit, roll back or create a
/// savepoint in a transaction directly through the TDS protocol instead of
/// issuing the equivalent T-SQL batch (`BEGIN TRAN`, `COMMIT`, ...).
///
/// Every request carries the current transaction descriptor in the request's
/// `ALL_HEADERS` block so the server can associate it with the correct
/// transaction.
#[derive(Debug, Clone)]
pub struct TransactionManagerRequest<'a> {
    transaction_desc: [u8; 8],
    body: TransactionRequestBody<'a>,
}

#[derive(Debug, Clone)]
enum TransactionRequestBody<'a> {
    Begin {
        isolation_level: IsolationLevel,
        name: Cow<'a, str>,
    },
    Commit {
        name: Cow<'a, str>,
    },
    Rollback {
        name: Cow<'a, str>,
    },
    Save {
        name: Cow<'a, str>,
    },
}

impl<'a> TransactionManagerRequest<'a> {
    /// Build a `TM_BEGIN_XACT` request that begins a new transaction with the
    /// given isolation level. The (usually empty) transaction name is sent as
    /// a `B_VARCHAR`.
    pub fn begin(
        transaction_desc: [u8; 8],
        isolation_level: IsolationLevel,
        name: impl Into<Cow<'a, str>>,
    ) -> Self {
        Self {
            transaction_desc,
            body: TransactionRequestBody::Begin {
                isolation_level,
                name: name.into(),
            },
        }
    }

    /// Build a `TM_COMMIT_XACT` request that commits the active transaction.
    pub fn commit(transaction_desc: [u8; 8], name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            transaction_desc,
            body: TransactionRequestBody::Commit { name: name.into() },
        }
    }

    /// Build a `TM_ROLLBACK_XACT` request that rolls back the active
    /// transaction (or to a savepoint of the given name).
    pub fn rollback(transaction_desc: [u8; 8], name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            transaction_desc,
            body: TransactionRequestBody::Rollback { name: name.into() },
        }
    }

    /// Build a `TM_SAVE_XACT` request that creates a savepoint with the given
    /// name in the active transaction.
    pub fn save(transaction_desc: [u8; 8], name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            transaction_desc,
            body: TransactionRequestBody::Save { name: name.into() },
        }
    }

    fn request_type(&self) -> TransactionManagerRequestType {
        match self.body {
            TransactionRequestBody::Begin { .. } => TransactionManagerRequestType::Begin,
            TransactionRequestBody::Commit { .. } => TransactionManagerRequestType::Commit,
            TransactionRequestBody::Rollback { .. } => TransactionManagerRequestType::Rollback,
            TransactionRequestBody::Save { .. } => TransactionManagerRequestType::Save,
        }
    }
}

/// Encodes a `B_VARCHAR`: a single-byte count of UTF-16 code units followed by
/// the string encoded as little-endian UCS-2 (MS-TDS 2.2.5.1.2).
fn encode_b_varchar(dst: &mut BytesMut, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    dst.put_u8(units.len() as u8);

    for unit in units {
        dst.put_u16_le(unit);
    }
}

impl<'a> Encode<BytesMut> for TransactionManagerRequest<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        // ALL_HEADERS block carrying the transaction descriptor.
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32);
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32 - 4);
        dst.put_u16_le(AllHeaderTy::TransactionDescriptor as u16);
        dst.put_slice(&self.transaction_desc);
        dst.put_u32_le(1);

        // Request type (USHORT).
        dst.put_u16_le(self.request_type() as u16);

        match self.body {
            TransactionRequestBody::Begin {
                isolation_level,
                name,
            } => {
                dst.put_u8(isolation_level as u8);
                encode_b_varchar(dst, &name);
            }
            TransactionRequestBody::Commit { name } | TransactionRequestBody::Rollback { name } => {
                encode_b_varchar(dst, &name);
                // Flags byte: bit 0 (`fBeginXact`) unset — do not begin a new
                // transaction after commit/rollback.
                dst.put_u8(0);
            }
            TransactionRequestBody::Save { name } => {
                encode_b_varchar(dst, &name);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_headers() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(ALL_HEADERS_LEN_TX as u32).to_le_bytes());
        v.extend_from_slice(&(ALL_HEADERS_LEN_TX as u32 - 4).to_le_bytes());
        v.extend_from_slice(&(AllHeaderTy::TransactionDescriptor as u16).to_le_bytes());
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        v.extend_from_slice(&1u32.to_le_bytes());
        v
    }

    #[test]
    fn encodes_begin_request() {
        let desc = [1, 2, 3, 4, 5, 6, 7, 8];
        let req = TransactionManagerRequest::begin(desc, IsolationLevel::ReadCommitted, "");

        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let mut expected = all_headers();
        expected.extend_from_slice(&(TransactionManagerRequestType::Begin as u16).to_le_bytes());
        expected.push(IsolationLevel::ReadCommitted as u8); // isolation level
        expected.push(0); // B_VARCHAR length (empty name)

        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn encodes_begin_request_with_name() {
        let desc = [1, 2, 3, 4, 5, 6, 7, 8];
        let req = TransactionManagerRequest::begin(desc, IsolationLevel::Serializable, "tx");

        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let mut expected = all_headers();
        expected.extend_from_slice(&(TransactionManagerRequestType::Begin as u16).to_le_bytes());
        expected.push(IsolationLevel::Serializable as u8);
        expected.push(2); // two UTF-16 code units
        expected.extend_from_slice(&b't'.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&b'x'.to_le_bytes());
        expected.push(0);

        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn encodes_commit_request() {
        let desc = [1, 2, 3, 4, 5, 6, 7, 8];
        let req = TransactionManagerRequest::commit(desc, "");

        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let mut expected = all_headers();
        expected.extend_from_slice(&(TransactionManagerRequestType::Commit as u16).to_le_bytes());
        expected.push(0); // B_VARCHAR length (empty name)
        expected.push(0); // flags: no new transaction

        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn encodes_rollback_request() {
        let desc = [8, 7, 6, 5, 4, 3, 2, 1];
        let req = TransactionManagerRequest::rollback(desc, "");

        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&(ALL_HEADERS_LEN_TX as u32).to_le_bytes());
        expected.extend_from_slice(&(ALL_HEADERS_LEN_TX as u32 - 4).to_le_bytes());
        expected.extend_from_slice(&(AllHeaderTy::TransactionDescriptor as u16).to_le_bytes());
        expected.extend_from_slice(&desc);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&(TransactionManagerRequestType::Rollback as u16).to_le_bytes());
        expected.push(0); // B_VARCHAR length
        expected.push(0); // flags

        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn encodes_save_request() {
        let desc = [1, 2, 3, 4, 5, 6, 7, 8];
        let req = TransactionManagerRequest::save(desc, "sp1");

        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let mut expected = all_headers();
        expected.extend_from_slice(&(TransactionManagerRequestType::Save as u16).to_le_bytes());
        expected.push(3); // three UTF-16 code units
        for unit in "sp1".encode_utf16() {
            expected.extend_from_slice(&unit.to_le_bytes());
        }

        assert_eq!(&buf[..], &expected[..]);
    }
}
