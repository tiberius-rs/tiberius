use crate::sql_read_bytes::SqlReadBytes;

// Decode a partially length-prefixed type.
//
// NOTE: values are read via the packet-aware `read_u8`/`read_u16_le`/`read_u32_le`
// helpers (which transparently span TDS packet boundaries). The generic
// `AsyncReadExt::read_exact` must NOT be used here: a PLP value can span multiple
// packets, and `read_exact` treats a packet-boundary `Ok(0)` as EOF.
pub(crate) async fn decode<R>(src: &mut R, len: usize) -> crate::Result<Option<Vec<u8>>>
where
    R: SqlReadBytes + Unpin,
{
    match len {
        // Fixed size
        len if len < 0xffff => {
            let len = src.read_u16_le().await? as usize;

            match len {
                // NULL
                0xffff => Ok(None),
                _ => {
                    let mut data = Vec::with_capacity(len.min(super::MAX_PREALLOC));

                    for _ in 0..len {
                        data.push(src.read_u8().await?);
                    }

                    Ok(Some(data))
                }
            }
        }
        // Unknown size, length-prefixed blobs
        _ => {
            let len = src.read_u64_le().await?;

            let mut data = match len {
                // NULL
                0xffffffffffffffff => return Ok(None),
                // Unknown size
                0xfffffffffffffffe => Vec::new(),
                // Known size. `len` is an untrusted 64-bit wire value; cap the
                // up-front reservation (avoids memory-exhaustion and the
                // `Vec` capacity-overflow panic for values near u64::MAX).
                _ => Vec::with_capacity((len as usize).min(super::MAX_PREALLOC)),
            };

            let mut chunk_data_left = 0usize;

            loop {
                if chunk_data_left == 0 {
                    // We have no chunk. Start a new one.
                    let chunk_size = src.read_u32_le().await? as usize;

                    if chunk_size == 0 {
                        break; // found a sentinel, we're done
                    }

                    // The number of chunks in an "unknown length" PLP value is
                    // unbounded on the wire. Cap the running total so a hostile
                    // server cannot stream chunks forever and exhaust memory on
                    // a single value.
                    if data.len().saturating_add(chunk_size) > super::MAX_PLP_SIZE {
                        return Err(crate::Error::Protocol(
                            format!(
                                "PLP value exceeds the maximum supported size of {} bytes",
                                super::MAX_PLP_SIZE
                            )
                            .into(),
                        ));
                    }

                    chunk_data_left = chunk_size;
                } else {
                    // Read a byte (packet-aware).
                    let byte = src.read_u8().await?;
                    chunk_data_left -= 1;

                    data.push(byte);
                }
            }

            Ok(Some(data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    // At the boundary `len == 0xffff` the decoder takes the chunked (PLP) branch,
    // reading a `u64` length; the chunked stream decodes to [0xAA, 0xBB, 0xCC].
    #[tokio::test]
    async fn decode_boundary_len_uses_chunked_branch() {
        let mut buf = BytesMut::new();
        buf.put_u64_le(5); // known-size PLP total length
        buf.put_u32_le(3); // chunk size
        buf.put_slice(&[0xAA, 0xBB, 0xCC]);
        buf.put_u32_le(0); // terminating chunk

        let data = decode(&mut buf.into_sql_read_bytes(), 0xffff)
            .await
            .unwrap();
        assert_eq!(data, Some(vec![0xAA, 0xBB, 0xCC]));
    }

    // A chunk whose running total strictly exceeds `MAX_PLP_SIZE` must be
    // rejected with the "exceeds the maximum" protocol error before any chunk
    // data is read.
    #[tokio::test]
    async fn decode_oversized_chunk_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u64_le(10); // known-size marker -> chunked branch bookkeeping
        buf.put_u32_le(u32::MAX); // chunk size well past MAX_PLP_SIZE

        let err = decode(&mut buf.into_sql_read_bytes(), 0x10000)
            .await
            .expect_err("oversized PLP chunk must be rejected");

        match err {
            crate::Error::Protocol(msg) => {
                assert!(
                    msg.contains("exceeds the maximum"),
                    "unexpected protocol message: {msg}"
                );
            }
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }
}
