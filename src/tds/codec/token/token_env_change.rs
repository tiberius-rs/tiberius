use crate::{tds::Collation, Error, SqlReadBytes};
use byteorder::{LittleEndian, ReadBytesExt};
use fmt::Debug;
use futures_util::io::AsyncReadExt;
use std::{
    convert::TryFrom,
    fmt,
    io::{Cursor, Read},
};

uint_enum! {
    #[repr(u8)]
    pub enum EnvChangeTy {
        Database = 1,
        Language = 2,
        CharacterSet = 3,
        PacketSize = 4,
        UnicodeDataSortingLID = 5,
        UnicodeDataSortingCFL = 6,
        SqlCollation = 7,
        /// below here: >= TDSv7.2
        BeginTransaction = 8,
        CommitTransaction = 9,
        RollbackTransaction = 10,
        EnlistDTCTransaction = 11,
        DefectTransaction = 12,
        Rtls = 13,
        PromoteTransaction = 15,
        TransactionManagerAddress = 16,
        TransactionEnded = 17,
        ResetConnection = 18,
        UserName = 19,
        /// below here: TDS v7.4
        Routing = 20,
    }
}

impl fmt::Display for EnvChangeTy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvChangeTy::Database => write!(f, "Database"),
            EnvChangeTy::Language => write!(f, "Language"),
            EnvChangeTy::CharacterSet => write!(f, "CharacterSet"),
            EnvChangeTy::PacketSize => write!(f, "PacketSize"),
            EnvChangeTy::UnicodeDataSortingLID => write!(f, "UnicodeDataSortingLID"),
            EnvChangeTy::UnicodeDataSortingCFL => write!(f, "UnicodeDataSortingCFL"),
            EnvChangeTy::SqlCollation => write!(f, "SqlCollation"),
            EnvChangeTy::BeginTransaction => write!(f, "BeginTransaction"),
            EnvChangeTy::CommitTransaction => write!(f, "CommitTransaction"),
            EnvChangeTy::RollbackTransaction => write!(f, "RollbackTransaction"),
            EnvChangeTy::EnlistDTCTransaction => write!(f, "EnlistDTCTransaction"),
            EnvChangeTy::DefectTransaction => write!(f, "DefectTransaction"),
            EnvChangeTy::Rtls => write!(f, "RTLS"),
            EnvChangeTy::PromoteTransaction => write!(f, "PromoteTransaction"),
            EnvChangeTy::TransactionManagerAddress => write!(f, "TransactionManagerAddress"),
            EnvChangeTy::TransactionEnded => write!(f, "TransactionEnded"),
            EnvChangeTy::ResetConnection => write!(f, "ResetConnection"),
            EnvChangeTy::UserName => write!(f, "UserName"),
            EnvChangeTy::Routing => write!(f, "Routing"),
        }
    }
}

#[derive(Debug)]
pub enum TokenEnvChange {
    Database {
        old: String,
        new: String,
    },
    PacketSize {
        old: u32,
        new: u32,
    },
    SqlCollation {
        old: Option<Collation>,
        new: Option<Collation>,
    },
    BeginTransaction([u8; 8]),
    CommitTransaction,
    RollbackTransaction,
    DefectTransaction,
    Routing {
        host: String,
        port: u16,
    },
    ChangeMirror(String),
    Ignored(EnvChangeTy),
}

impl fmt::Display for TokenEnvChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database { old, new } => {
                write!(f, "Database change from '{}' to '{}'", old, new)
            }
            Self::PacketSize { old, new } => {
                write!(f, "Packet size change from '{}' to '{}'", old, new)
            }
            Self::SqlCollation { old, new } => match (old, new) {
                (Some(old), Some(new)) => write!(f, "SQL collation change from {} to {}", old, new),
                (_, Some(new)) => write!(f, "SQL collation changed to {}", new),
                (_, _) => write!(f, "SQL collation change"),
            },
            Self::BeginTransaction(_) => write!(f, "Begin transaction"),
            Self::CommitTransaction => write!(f, "Commit transaction"),
            Self::RollbackTransaction => write!(f, "Rollback transaction"),
            Self::DefectTransaction => write!(f, "Defect transaction"),
            Self::Routing { host, port } => write!(
                f,
                "Server requested routing to a new address: {}:{}",
                host, port
            ),
            Self::ChangeMirror(ref mirror) => write!(f, "Fallback mirror server: `{}`", mirror),
            Self::Ignored(ty) => write!(f, "Ignored env change: `{}`", ty),
        }
    }
}

impl TokenEnvChange {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let len = src.read_u16_le().await? as usize;

        // We read all the bytes now, due to whatever environment change tokens
        // we read, they might contain padding zeroes in the end we must
        // discard.
        let mut bytes = vec![0; len];
        src.read_exact(&mut bytes[0..len]).await?;

        let mut buf = Cursor::new(bytes);
        let ty_byte = buf.read_u8()?;

        let ty = EnvChangeTy::try_from(ty_byte)
            .map_err(|_| Error::Protocol(format!("invalid envchange type {:x}", ty_byte).into()))?;

        let token = match ty {
            EnvChangeTy::Database => {
                let len = buf.read_u8()? as usize;
                let mut bytes = vec![0; len];

                for item in bytes.iter_mut().take(len) {
                    *item = buf.read_u16::<LittleEndian>()?;
                }

                let new_value = String::from_utf16(&bytes[..])?;

                let len = buf.read_u8()? as usize;
                let mut bytes = vec![0; len];

                for item in bytes.iter_mut().take(len) {
                    *item = buf.read_u16::<LittleEndian>()?;
                }

                let old_value = String::from_utf16(&bytes[..])?;

                TokenEnvChange::Database {
                    new: new_value,
                    old: old_value,
                }
            }
            EnvChangeTy::PacketSize => {
                let len = buf.read_u8()? as usize;
                let mut bytes = vec![0; len];

                for item in bytes.iter_mut().take(len) {
                    *item = buf.read_u16::<LittleEndian>()?;
                }

                let new_value = String::from_utf16(&bytes[..])?;

                let len = buf.read_u8()? as usize;
                let mut bytes = vec![0; len];

                for item in bytes.iter_mut().take(len) {
                    *item = buf.read_u16::<LittleEndian>()?;
                }

                let old_value = String::from_utf16(&bytes[..])?;

                TokenEnvChange::PacketSize {
                    new: new_value.parse()?,
                    old: old_value.parse()?,
                }
            }
            EnvChangeTy::SqlCollation => {
                let len = buf.read_u8()? as usize;
                let mut new_value = vec![0; len];
                buf.read_exact(&mut new_value[0..len])?;

                let new = if len == 5 {
                    let new_sortid = new_value[4];
                    let new_info = u32::from_le_bytes([
                        new_value[0],
                        new_value[1],
                        new_value[2],
                        new_value[3],
                    ]);

                    Some(Collation::new(new_info, new_sortid))
                } else {
                    None
                };

                let len = buf.read_u8()? as usize;
                let mut old_value = vec![0; len];
                buf.read_exact(&mut old_value[0..len])?;

                let old = if len == 5 {
                    let old_sortid = old_value[4];
                    let old_info = u32::from_le_bytes([
                        old_value[0],
                        old_value[1],
                        old_value[2],
                        old_value[3],
                    ]);

                    Some(Collation::new(old_info, old_sortid))
                } else {
                    None
                };

                TokenEnvChange::SqlCollation { new, old }
            }
            EnvChangeTy::BeginTransaction | EnvChangeTy::EnlistDTCTransaction => {
                let len = buf.read_u8()?;
                if len != 8 {
                    return Err(Error::Protocol(
                        format!("ENVCHANGE transaction descriptor length {len}, expected 8").into(),
                    ));
                }

                let mut desc = [0; 8];
                buf.read_exact(&mut desc)?;

                TokenEnvChange::BeginTransaction(desc)
            }

            EnvChangeTy::CommitTransaction => TokenEnvChange::CommitTransaction,
            EnvChangeTy::RollbackTransaction => TokenEnvChange::RollbackTransaction,
            EnvChangeTy::DefectTransaction => TokenEnvChange::DefectTransaction,

            EnvChangeTy::Routing => {
                buf.read_u16::<LittleEndian>()?; // routing data value length
                buf.read_u8()?; // routing protocol, always 0 (tcp)

                let port = buf.read_u16::<LittleEndian>()?;

                let len = buf.read_u16::<LittleEndian>()? as usize; // hostname string length
                let mut bytes = vec![0; len];

                for item in bytes.iter_mut().take(len) {
                    *item = buf.read_u16::<LittleEndian>()?;
                }

                let host = String::from_utf16(&bytes[..])?;

                TokenEnvChange::Routing { host, port }
            }
            EnvChangeTy::Rtls => {
                let len = buf.read_u8()? as usize;
                let mut bytes = vec![0; len];

                for item in bytes.iter_mut().take(len) {
                    *item = buf.read_u16::<LittleEndian>()?;
                }

                let mirror_name = String::from_utf16(&bytes[..])?;

                TokenEnvChange::ChangeMirror(mirror_name)
            }
            ty => TokenEnvChange::Ignored(ty),
        };

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::{EnvChangeTy, TokenEnvChange};
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use byteorder::{LittleEndian, WriteBytesExt};
    use bytes::{BufMut, BytesMut};

    #[test]
    fn database_display_uses_old_then_new() {
        // Fields are stored (new, old); Display must print "from old to new".
        let change = TokenEnvChange::Database {
            new: "newdb".to_string(),
            old: "olddb".to_string(),
        };
        assert_eq!(
            format!("{}", change),
            "Database change from 'olddb' to 'newdb'"
        );
    }

    #[test]
    fn packet_size_display_uses_old_then_new() {
        // Fields are stored (new, old); Display must print "from old to new".
        let change = TokenEnvChange::PacketSize {
            new: 8192,
            old: 4096,
        };
        assert_eq!(
            format!("{}", change),
            "Packet size change from '4096' to '8192'"
        );
    }

    fn write_utf16_str(body: &mut Vec<u8>, s: &str) {
        body.push(s.encode_utf16().count() as u8);
        for unit in s.encode_utf16() {
            body.write_u16::<LittleEndian>(unit).unwrap();
        }
    }

    fn envchange_buf(ty: u8, payload: &[u8]) -> BytesMut {
        let mut body = Vec::new();
        body.push(ty);
        body.extend_from_slice(payload);

        let mut buf = BytesMut::new();
        buf.put_u16_le(body.len() as u16);
        buf.put_slice(&body);
        buf
    }

    #[tokio::test]
    async fn decode_database_roundtrip() {
        let mut payload = Vec::new();
        write_utf16_str(&mut payload, "newdb");
        write_utf16_str(&mut payload, "olddb");

        let buf = envchange_buf(EnvChangeTy::Database as u8, &payload);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::Database(new, old) => {
                assert_eq!(new, "newdb");
                assert_eq!(old, "olddb");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_packet_size_parses_numbers() {
        let mut payload = Vec::new();
        write_utf16_str(&mut payload, "8192");
        write_utf16_str(&mut payload, "4096");

        let buf = envchange_buf(EnvChangeTy::PacketSize as u8, &payload);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::PacketSize(new, old) => {
                assert_eq!(new, 8192);
                assert_eq!(old, 4096);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_sql_collation_with_both_present() {
        let mut payload = Vec::new();
        payload.push(5u8);
        payload.write_u32::<LittleEndian>(13632521).unwrap();
        payload.push(52);
        payload.push(5u8);
        payload.write_u32::<LittleEndian>(13632521).unwrap();
        payload.push(52);

        let buf = envchange_buf(EnvChangeTy::SqlCollation as u8, &payload);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::SqlCollation { old, new } => {
                assert!(old.is_some());
                assert!(new.is_some());
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_sql_collation_none_when_length_not_five() {
        let payload = vec![0u8, 0u8];

        let buf = envchange_buf(EnvChangeTy::SqlCollation as u8, &payload);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::SqlCollation { old, new } => {
                assert!(old.is_none());
                assert!(new.is_none());
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_begin_transaction_reads_descriptor() {
        let mut payload = vec![8u8];
        payload.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let buf = envchange_buf(EnvChangeTy::BeginTransaction as u8, &payload);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::BeginTransaction(desc) => {
                assert_eq!(desc, [1, 2, 3, 4, 5, 6, 7, 8]);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_begin_transaction_wrong_length_errors() {
        let payload = vec![3u8, 1, 2, 3];

        let buf = envchange_buf(EnvChangeTy::BeginTransaction as u8, &payload);
        let err = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap_err();

        assert!(format!("{}", err).contains("expected 8"));
    }

    #[tokio::test]
    async fn decode_commit_rollback_defect_transaction() {
        for (ty, is_match) in [
            (
                EnvChangeTy::CommitTransaction,
                (|t: &TokenEnvChange| matches!(t, TokenEnvChange::CommitTransaction))
                    as fn(&TokenEnvChange) -> bool,
            ),
            (EnvChangeTy::RollbackTransaction, |t: &TokenEnvChange| {
                matches!(t, TokenEnvChange::RollbackTransaction)
            }),
            (EnvChangeTy::DefectTransaction, |t: &TokenEnvChange| {
                matches!(t, TokenEnvChange::DefectTransaction)
            }),
        ] {
            let buf = envchange_buf(ty as u8, &[]);
            let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
                .await
                .unwrap();
            assert!(is_match(&decoded));
        }
    }

    #[tokio::test]
    async fn decode_routing_reads_host_and_port() {
        let mut payload = Vec::new();
        payload.write_u16::<LittleEndian>(0).unwrap(); // routing data value length (unused)
        payload.push(0); // protocol, always 0
        payload.write_u16::<LittleEndian>(1433).unwrap(); // port

        let host = "sql.example.com";
        payload
            .write_u16::<LittleEndian>(host.encode_utf16().count() as u16)
            .unwrap();
        for unit in host.encode_utf16() {
            payload.write_u16::<LittleEndian>(unit).unwrap();
        }

        let buf = envchange_buf(EnvChangeTy::Routing as u8, &payload);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::Routing { host: h, port } => {
                assert_eq!(h, host);
                assert_eq!(port, 1433);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_rtls_yields_change_mirror() {
        let mut payload = Vec::new();
        write_utf16_str(&mut payload, "mirror.example.com");

        let buf = envchange_buf(EnvChangeTy::Rtls as u8, &payload);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::ChangeMirror(name) => {
                assert_eq!(name, "mirror.example.com");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_unhandled_type_is_ignored() {
        let buf = envchange_buf(EnvChangeTy::Language as u8, &[]);
        let decoded = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap();

        match decoded {
            TokenEnvChange::Ignored(EnvChangeTy::Language) => {}
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn decode_invalid_type_byte_errors() {
        let buf = envchange_buf(0x63, &[]);
        let err = TokenEnvChange::decode(&mut buf.into_sql_read_bytes())
            .await
            .unwrap_err();

        assert!(format!("{}", err).contains("invalid envchange type"));
    }

    #[test]
    fn env_change_ty_display_all_variants() {
        let cases: &[(EnvChangeTy, &str)] = &[
            (EnvChangeTy::Database, "Database"),
            (EnvChangeTy::Language, "Language"),
            (EnvChangeTy::CharacterSet, "CharacterSet"),
            (EnvChangeTy::PacketSize, "PacketSize"),
            (EnvChangeTy::UnicodeDataSortingLID, "UnicodeDataSortingLID"),
            (EnvChangeTy::UnicodeDataSortingCFL, "UnicodeDataSortingCFL"),
            (EnvChangeTy::SqlCollation, "SqlCollation"),
            (EnvChangeTy::BeginTransaction, "BeginTransaction"),
            (EnvChangeTy::CommitTransaction, "CommitTransaction"),
            (EnvChangeTy::RollbackTransaction, "RollbackTransaction"),
            (EnvChangeTy::EnlistDTCTransaction, "EnlistDTCTransaction"),
            (EnvChangeTy::DefectTransaction, "DefectTransaction"),
            (EnvChangeTy::Rtls, "RTLS"),
            (EnvChangeTy::PromoteTransaction, "PromoteTransaction"),
            (
                EnvChangeTy::TransactionManagerAddress,
                "TransactionManagerAddress",
            ),
            (EnvChangeTy::TransactionEnded, "TransactionEnded"),
            (EnvChangeTy::ResetConnection, "ResetConnection"),
            (EnvChangeTy::UserName, "UserName"),
            (EnvChangeTy::Routing, "Routing"),
        ];

        for (variant, expected) in cases {
            assert_eq!(format!("{}", variant), *expected);
        }
    }

    #[test]
    fn sql_collation_display_both_and_new_only() {
        use crate::tds::Collation;

        // Both old and new present: "from {old} to {new}".
        let both = TokenEnvChange::SqlCollation {
            old: Some(Collation::new(13632521, 52)),
            new: Some(Collation::new(13632521, 52)),
        };
        assert!(format!("{}", both).starts_with("SQL collation change from "));

        // Only new present: "changed to {new}".
        let new_only = TokenEnvChange::SqlCollation {
            old: None,
            new: Some(Collation::new(13632521, 52)),
        };
        assert!(format!("{}", new_only).starts_with("SQL collation changed to "));
    }

    #[test]
    fn token_env_change_display_variants() {
        assert_eq!(
            format!("{}", TokenEnvChange::CommitTransaction),
            "Commit transaction"
        );
        assert_eq!(
            format!("{}", TokenEnvChange::RollbackTransaction),
            "Rollback transaction"
        );
        assert_eq!(
            format!("{}", TokenEnvChange::DefectTransaction),
            "Defect transaction"
        );
        assert_eq!(
            format!("{}", TokenEnvChange::BeginTransaction([0; 8])),
            "Begin transaction"
        );
        assert_eq!(
            format!(
                "{}",
                TokenEnvChange::Routing {
                    host: "host".into(),
                    port: 1433
                }
            ),
            "Server requested routing to a new address: host:1433"
        );
        assert_eq!(
            format!("{}", TokenEnvChange::ChangeMirror("mirror".into())),
            "Fallback mirror server: `mirror`"
        );
        assert_eq!(
            format!("{}", TokenEnvChange::Ignored(EnvChangeTy::Language)),
            "Ignored env change: `Language`"
        );
        assert_eq!(
            format!(
                "{}",
                TokenEnvChange::SqlCollation {
                    old: None,
                    new: None
                }
            ),
            "SQL collation change"
        );
    }
}
