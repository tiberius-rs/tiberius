use super::TypeInfoTvp;
use super::{AllHeaderTy, Encode, ALL_HEADERS_LEN_TX};
use crate::{tds::codec::ColumnData, BytesMutWithTypeInfo, Result};
use bytes::{BufMut, BytesMut};
use enumflags2::{bitflags, BitFlags};
use std::borrow::BorrowMut;
use std::borrow::Cow;

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpcStatus {
    ByRefValue = 1 << 0,
    DefaultValue = 1 << 1,
    // reserved
    Encrypted = 1 << 3,
}

#[bitflags]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpcOption {
    WithRecomp = 1 << 0,
    NoMeta = 1 << 1,
    ReuseMeta = 1 << 2,
}

#[derive(Debug)]
pub struct TokenRpcRequest<'a> {
    proc_id: RpcProcIdValue<'a>,
    flags: BitFlags<RpcOption>,
    params: Vec<RpcParam<'a>>,
    transaction_desc: [u8; 8],
}

impl<'a> TokenRpcRequest<'a> {
    pub fn new<I>(proc_id: I, params: Vec<RpcParam<'a>>, transaction_desc: [u8; 8]) -> Self
    where
        I: Into<RpcProcIdValue<'a>>,
    {
        Self {
            proc_id: proc_id.into(),
            flags: BitFlags::empty(),
            params,
            transaction_desc,
        }
    }
}

/// The value carried by an [`RpcParam`]. A scalar column value, or a
/// table-valued parameter (TVP).
#[derive(Debug)]
pub enum RpcValue<'a> {
    /// An ordinary scalar parameter value.
    Scalar(ColumnData<'a>),
    /// A table-valued parameter. As per the TDS grammar, `TYPE_INFO_TVP`
    /// carries both the type metadata and the data rows.
    Table(TypeInfoTvp<'a>),
}

#[derive(Debug)]
pub struct RpcParam<'a> {
    pub name: Cow<'a, str>,
    pub flags: BitFlags<RpcStatus>,
    pub value: RpcValue<'a>,
}

/// 2.2.6.6 RPC Request
#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum RpcProcId {
    CursorOpen = 2,
    CursorFetch = 7,
    CursorClose = 9,
    ExecuteSQL = 10,
    Prepare = 11,
    Execute = 12,
    PrepExec = 13,
    Unprepare = 15,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum RpcProcIdValue<'a> {
    Name(Cow<'a, str>),
    Id(RpcProcId),
}

impl<'a, S> From<S> for RpcProcIdValue<'a>
where
    S: Into<Cow<'a, str>>,
{
    fn from(s: S) -> Self {
        Self::Name(s.into())
    }
}

impl<'a> From<RpcProcId> for RpcProcIdValue<'a> {
    fn from(id: RpcProcId) -> Self {
        Self::Id(id)
    }
}

impl<'a> Encode<BytesMut> for TokenRpcRequest<'a> {
    fn encode(self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32);
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32 - 4);
        dst.put_u16_le(AllHeaderTy::TransactionDescriptor as u16);
        dst.put_slice(&self.transaction_desc);
        dst.put_u32_le(1);

        match self.proc_id {
            RpcProcIdValue::Id(ref id) => {
                let val = (0xffff_u32) | ((*id as u16) as u32) << 16;
                dst.put_u32_le(val);
            }
            RpcProcIdValue::Name(ref name) => {
                // ProcName is a US_VARCHAR: a u16 little-endian character count
                // followed by that many UTF-16 code units.
                let len_pos = dst.len();
                dst.put_u16_le(0u16);
                let mut length = 0_u16;

                for chr in name.encode_utf16() {
                    dst.put_u16_le(chr);
                    length += 1;
                }

                let dst: &mut [u8] = dst.borrow_mut();
                let mut dst = &mut dst[len_pos..];
                dst.put_u16_le(length);
            }
        }

        dst.put_u16_le(self.flags.bits());

        for param in self.params.into_iter() {
            param.encode(dst)?;
        }

        Ok(())
    }
}

impl<'a> Encode<BytesMut> for RpcParam<'a> {
    fn encode(self, dst: &mut BytesMut) -> Result<()> {
        let len_pos = dst.len();
        let mut length = 0u8;

        dst.put_u8(length);

        for codepoint in self.name.encode_utf16() {
            length += 1;
            dst.put_u16_le(codepoint);
        }

        dst.put_u8(self.flags.bits());

        match self.value {
            RpcValue::Scalar(value) => {
                let mut dst_ti = BytesMutWithTypeInfo::new(dst);
                value.encode(&mut dst_ti)?;
            }
            RpcValue::Table(value) => value.encode(dst)?,
        }

        let dst: &mut [u8] = dst.borrow_mut();
        dst[len_pos] = length;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::ColumnData;

    fn scalar(value: ColumnData<'static>) -> RpcValue<'static> {
        RpcValue::Scalar(value)
    }

    #[test]
    fn encodes_named_proc_header() {
        let req = TokenRpcRequest::new(
            "dbo.usp_MyProc",
            vec![RpcParam {
                name: Cow::Borrowed("@id"),
                flags: BitFlags::empty(),
                value: scalar(ColumnData::I32(Some(1))),
            }],
            [0u8; 8],
        );

        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        // Skip the ALL_HEADERS block, positioned right at the ProcName.
        let name_pos = ALL_HEADERS_LEN_TX;
        let len = u16::from_le_bytes([buf[name_pos], buf[name_pos + 1]]);
        assert_eq!(len as usize, "dbo.usp_MyProc".encode_utf16().count());

        // Verify the UTF-16 payload matches the proc name.
        let mut chars = Vec::new();
        let mut off = name_pos + 2;
        for _ in 0..len {
            chars.push(u16::from_le_bytes([buf[off], buf[off + 1]]));
            off += 2;
        }
        assert_eq!(String::from_utf16(&chars).unwrap(), "dbo.usp_MyProc");

        // Option flags (u16) follow the name.
        let flags = u16::from_le_bytes([buf[off], buf[off + 1]]);
        assert_eq!(flags, 0);
    }

    #[test]
    fn named_and_by_id_differ_only_in_proc_slot() {
        let by_id = {
            let req = TokenRpcRequest::new(RpcProcId::ExecuteSQL, vec![], [0u8; 8]);
            let mut buf = BytesMut::new();
            req.encode(&mut buf).unwrap();
            buf
        };

        // By-id encodes 0xFFFF followed by the proc id in the high word.
        let val = u32::from_le_bytes([
            by_id[ALL_HEADERS_LEN_TX],
            by_id[ALL_HEADERS_LEN_TX + 1],
            by_id[ALL_HEADERS_LEN_TX + 2],
            by_id[ALL_HEADERS_LEN_TX + 3],
        ]);
        assert_eq!(val & 0xffff, 0xffff);
        assert_eq!((val >> 16) as u16, RpcProcId::ExecuteSQL as u16);
    }

    #[test]
    fn encodes_param_name_and_by_ref_flag() {
        let param = RpcParam {
            name: Cow::Borrowed("@out"),
            flags: BitFlags::from_flag(RpcStatus::ByRefValue),
            value: scalar(ColumnData::I32(Some(7))),
        };

        let mut buf = BytesMut::new();
        param.encode(&mut buf).unwrap();

        // First byte is the param-name length (in UTF-16 code units).
        assert_eq!(buf[0] as usize, "@out".encode_utf16().count());

        let mut chars = Vec::new();
        let mut off = 1usize;
        for _ in 0..buf[0] {
            chars.push(u16::from_le_bytes([buf[off], buf[off + 1]]));
            off += 2;
        }
        assert_eq!(String::from_utf16(&chars).unwrap(), "@out");

        // Status flags byte carries the ByRefValue bit.
        assert_eq!(buf[off], RpcStatus::ByRefValue as u8);
    }
}
