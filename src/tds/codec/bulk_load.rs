use asynchronous_codec::BytesMut;
use futures_util::io::{AsyncRead, AsyncWrite};
use tracing::{event, Level};

use crate::{
    client::Connection, sql_read_bytes::SqlReadBytes, BytesMutWithDataColumns, ExecuteResult,
};

use super::{
    Encode, MetaDataColumn, PacketHeader, PacketStatus, TokenColMetaData, TokenDone, TokenRow,
    HEADER_BYTES,
};

/// A handler for a bulk insert data flow.
#[derive(Debug)]
pub struct BulkLoadRequest<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    connection: &'a mut Connection<S>,
    packet_id: u8,
    buf: BytesMut,
    columns: Vec<MetaDataColumn<'a>>,
}

impl<'a, S> BulkLoadRequest<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub(crate) fn new(
        connection: &'a mut Connection<S>,
        columns: Vec<MetaDataColumn<'a>>,
    ) -> crate::Result<Self> {
        let packet_id = connection.context_mut().next_packet_id();
        let mut buf = BytesMut::new();

        let cmd = TokenColMetaData {
            columns: columns.clone(),
        };

        cmd.encode(&mut buf)?;

        let this = Self {
            connection,
            packet_id,
            buf,
            columns,
        };

        Ok(this)
    }

    /// Adds a new row to the bulk insert, flushing only when having a full packet of data.
    ///
    /// # Warning
    ///
    /// After the last row, [`finalize`] must be called to flush the buffered
    /// data and for the data to actually be available in the table.
    ///
    /// [`finalize`]: #method.finalize
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is already poisoned by a prior
    /// interrupted write, if the row cannot be encoded (e.g. a value that does
    /// not fit its column), or if flushing the buffered packets to the wire
    /// fails. On an encode failure the buffered bytes for the partial row are
    /// rolled back so the stream stays in sync.
    pub async fn send(&mut self, row: TokenRow<'a>) -> crate::Result<()> {
        // Fail fast if a previous write on this connection was interrupted: the
        // stream is already desynced and buffering/writing more bulk data would
        // corrupt it further.
        self.connection.ensure_not_poisoned()?;

        // `row.encode` can now fail mid-row (e.g. an out-of-range money value).
        // A failure would leave the Row-token byte plus any already-encoded
        // columns in `self.buf`; those partial bytes would be flushed on the next
        // successful `send`/`finalize` and desync the bulk stream. Snapshot the
        // buffer length and roll back on error so the stream stays in sync.
        let start = self.buf.len();

        let mut buf_with_columns = BytesMutWithDataColumns::new(&mut self.buf, &self.columns);
        if let Err(e) = row.encode(&mut buf_with_columns) {
            self.buf.truncate(start);
            return Err(e);
        }

        self.write_packets().await?;

        Ok(())
    }

    /// Ends the bulk load, flushing all pending data to the wire.
    ///
    /// This method must be called after sending all the data to flush all
    /// pending data and to get the server actually to store the rows to the
    /// table.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is already poisoned by a prior
    /// interrupted write, if flushing the remaining packets fails, or if the
    /// server reports an error while committing the bulk load.
    pub async fn finalize(mut self) -> crate::Result<ExecuteResult> {
        // See `send`: never layer a finalize onto an already-desynced stream.
        self.connection.ensure_not_poisoned()?;

        TokenDone::default().encode(&mut self.buf)?;
        self.write_packets().await?;

        let mut header = PacketHeader::bulk_load(self.packet_id);
        header.set_status(PacketStatus::EndOfMessage);

        let data = self.buf.split();

        event!(
            Level::TRACE,
            "Finalizing a bulk insert ({} bytes)",
            data.len() + HEADER_BYTES,
        );

        // Bracket the final end-of-message write with the poison flag, mirroring
        // `Connection::send`: if this future is dropped between the write and a
        // clean flush the message is only partly on the wire and the connection
        // must not be silently reused. A clean flush clears the flag.
        self.connection.poison();
        self.connection.write_to_wire(header, data).await?;
        self.connection.flush_sink().await?;
        self.connection.unpoison();

        ExecuteResult::new(self.connection).await
    }

    async fn write_packets(&mut self) -> crate::Result<()> {
        let packet_size = (self.connection.context().packet_size() as usize) - HEADER_BYTES;

        // Nothing to flush yet: the buffered data still fits in a single packet,
        // so no partial message reaches the wire and there is nothing to guard.
        if self.buf.len() <= packet_size {
            return Ok(());
        }

        // Bracket the multi-packet write with the poison flag, mirroring
        // `Connection::send`: while packets are going out the message is only
        // partly on the wire, so a dropped future must leave the connection
        // poisoned rather than reusable. A clean completion clears it.
        self.connection.poison();

        while self.buf.len() > packet_size {
            let header = PacketHeader::bulk_load(self.packet_id);
            let data = self.buf.split_to(packet_size);

            event!(
                Level::TRACE,
                "Bulk insert packet ({} bytes)",
                data.len() + HEADER_BYTES,
            );

            self.connection.write_to_wire(header, data).await?;
        }

        self.connection.unpoison();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::type_info::VarLenContext;
    use crate::{BaseMetaDataColumn, ColumnData, ColumnFlag, TypeInfo, VarLenType};
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use std::{io, task};

    // A do-nothing stream: writes are swallowed and reads report clean EOF. A
    // single small bulk row fits one packet, so `write_packets` returns without
    // ever touching this stream — the rollback test never needs the wire.
    struct NullIo;

    impl AsyncRead for NullIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    impl AsyncWrite for NullIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // A single nullable `money` (VarLenSized, len 8) column. An out-of-range
    // `F64` value routes through `money::encode`, which rejects it with
    // `Error::BulkInput`, making `TokenRow::encode` fail mid-row.
    fn money_columns() -> Vec<MetaDataColumn<'static>> {
        vec![MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Money, 8, None)),
                table_name: None,
            },
            col_name: Default::default(),
        }]
    }

    // On an encode failure mid-row, `send` must roll the buffer back to the
    // post-COLMETADATA baseline it had right after `new`, so the partial
    // Row-token bytes never leak onto the wire and desync the bulk stream.
    //
    // Red-before-green evidence: commenting out the `self.buf.truncate(start)`
    // line in `send` makes the final length assertion FAIL — the buffer stays
    // longer than the baseline because the Row-token byte and any partial column
    // bytes remain. Restoring the line makes it pass. Verified locally.
    #[tokio::test]
    async fn send_rolls_back_partial_row_on_encode_error() {
        let mut conn = Connection::test_over(NullIo, false);
        let columns = money_columns();

        let mut req = BulkLoadRequest::new(&mut conn, columns).unwrap();

        // The baseline is the COLMETADATA token `new` buffered; the rollback must
        // restore exactly this length.
        let baseline = req.buf.len();

        // `1e18` is far past money's range; `money::encode` returns `BulkInput`.
        let mut bad_row = TokenRow::new();
        bad_row.push(ColumnData::F64(Some(1e18)));

        let err = req
            .send(bad_row)
            .await
            .expect_err("an out-of-range money value must fail to encode");
        assert!(matches!(err, crate::Error::BulkInput(_)), "got {err:?}");

        // The partial Row-token bytes were rolled back: the buffer is exactly the
        // post-COLMETADATA baseline again.
        assert_eq!(
            req.buf.len(),
            baseline,
            "partial row bytes were not rolled back"
        );

        // The stream stayed in sync: a subsequent valid row encodes cleanly and
        // appends onto the untouched baseline.
        let mut good_row = TokenRow::new();
        good_row.push(ColumnData::F64(Some(1.5)));
        req.send(good_row)
            .await
            .expect("a valid row must send after a rolled-back failure");
        assert!(
            req.buf.len() > baseline,
            "a valid row should append to the buffer"
        );
    }
}
