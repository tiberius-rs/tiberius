use crate::tds::codec::TokenSspi;
use crate::{
    client::Connection,
    tds::codec::{
        TokenAltMetaData, TokenAltRow, TokenColInfo, TokenColMetaData, TokenDone, TokenEnvChange,
        TokenError, TokenFeatureExtAck, TokenFedAuthInfo, TokenInfo, TokenLoginAck, TokenOrder,
        TokenReturnValue, TokenRow, TokenSessionState, TokenTabName,
    },
    Error, SqlReadBytes, TokenType,
};
use futures_util::{
    io::{AsyncRead, AsyncWrite},
    stream::{BoxStream, Stream, StreamExt, TryStreamExt},
};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use std::{convert::TryFrom, sync::Arc};
use tracing::{event, Level};

/// Wraps a token stream so each server round-trip is bounded by a deadline.
///
/// The timer only runs while an item is *in flight* — i.e. while the inner
/// stream is `Pending` waiting on the server — and is reset the moment a token
/// is delivered. A slow consumer (which simply stops polling between items)
/// therefore never trips it; only a stalled server does. This backs
/// [`Config::command_timeout`](crate::Config::command_timeout), whose rustdoc
/// documents the exact semantics.
struct RoundTripTimeout<'a> {
    inner: BoxStream<'a, crate::Result<ReceivedToken>>,
    /// `None` disables the bound entirely (unbounded reads).
    timeout: Option<Duration>,
    /// The deadline for the token currently being awaited. Created lazily when
    /// the inner stream first parks on the server and cleared on every delivery,
    /// so it measures per-round-trip stall rather than consumer pace.
    delay: Option<futures_timer::Delay>,
    /// Shared with the owning [`Connection`], which flips it when this deadline
    /// fires so the now-desynced connection is rejected on any subsequent use
    /// (its `flush_stream` would otherwise block forever on the still-pending
    /// previous response). `None` in the combinator's own unit tests, which run
    /// without a connection.
    ///
    /// [`Connection`]: crate::client::Connection
    poison: Option<Arc<AtomicBool>>,
}

impl<'a> RoundTripTimeout<'a> {
    fn new(
        timeout: Option<Duration>,
        poison: Option<Arc<AtomicBool>>,
        inner: BoxStream<'a, crate::Result<ReceivedToken>>,
    ) -> Self {
        Self {
            inner,
            timeout,
            delay: None,
            poison,
        }
    }
}

impl Stream for RoundTripTimeout<'_> {
    type Item = crate::Result<ReceivedToken>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        // Both `inner` (a `BoxStream`) and `Delay` are `Unpin`, so they can be
        // polled through `&mut` without structural pin projection.
        let this = self.get_mut();

        match this.inner.poll_next_unpin(cx) {
            // A token arrived (or the stream ended / errored): reset the deadline
            // so the next round-trip is timed afresh.
            Poll::Ready(item) => {
                this.delay = None;
                Poll::Ready(item)
            }
            Poll::Pending => {
                let Some(timeout) = this.timeout else {
                    // Unbounded: never start a timer.
                    return Poll::Pending;
                };

                let delay = this
                    .delay
                    .get_or_insert_with(|| futures_timer::Delay::new(timeout));

                match Pin::new(delay).poll(cx) {
                    Poll::Ready(()) => {
                        // Clear the fired timer and mark the connection desynced:
                        // the tail of this response is still unread on the wire,
                        // so it must not be reused. Flipping the shared flag makes
                        // `Connection::ensure_not_poisoned` reject the next use
                        // (fast, deterministic) instead of `flush_stream` blocking
                        // forever on the still-pending previous response.
                        this.delay = None;
                        if let Some(poison) = &this.poison {
                            poison.store(true, Ordering::Release);
                        }
                        Poll::Ready(Some(Err(crate::Error::Io {
                            kind: std::io::ErrorKind::TimedOut,
                            message: format!(
                                "the server did not send the next part of the command result \
                                 within {timeout:?} (it may have stalled, or be responding too \
                                 slowly for the configured bound); the connection is now out of \
                                 sync and must be dropped. Adjust the bound with \
                                 `Config::command_timeout`, or pass `None` to wait indefinitely."
                            ),
                        })))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ReceivedToken {
    NewResultset(Arc<TokenColMetaData<'static>>),
    // The ALTMETADATA is stashed in the connection context on decode (see
    // `get_alt_col_metadata`); this payload copy is not otherwise read.
    #[allow(dead_code)]
    NewAltResultset(Arc<TokenAltMetaData<'static>>),
    Row(TokenRow<'static>),
    // COMPUTE-clause rows are decoded and traced but not surfaced through the
    // public result API. TODO(surface): expose ALTROW data to callers.
    #[allow(dead_code)]
    AltRow(TokenAltRow<'static>),
    Done(TokenDone),
    DoneInProc(TokenDone),
    DoneProc(TokenDone),
    ReturnStatus(u32),
    ReturnValue(TokenReturnValue),
    // Parsed and traced but not yet surfaced through the public result API.
    // TODO(surface): expose ordering metadata to callers.
    #[allow(dead_code)]
    Order(TokenOrder),
    // TODO(surface): expose browse-mode column info to callers.
    #[allow(dead_code)]
    ColInfo(TokenColInfo),
    // TODO(surface): expose browse-mode table names to callers.
    #[allow(dead_code)]
    TabName(TokenTabName),
    EnvChange(TokenEnvChange),
    // Informational messages are logged at DEBUG on decode; the payload is not
    // otherwise consumed. TODO(surface): expose INFO messages to callers.
    #[allow(dead_code)]
    Info(TokenInfo),
    // Consumed for its `tds_version` during login (see `get_login_ack`); the
    // remaining fields are retained for debugging but not otherwise read.
    #[allow(dead_code)]
    LoginAck(TokenLoginAck),
    // Consumed by `flush_sspi`, which is only compiled with an integrated-auth
    // backend; without one the payload is decoded but never read.
    #[cfg_attr(
        not(any(windows, feature = "integrated-auth-gssapi", feature = "sspi-rs")),
        allow(dead_code)
    )]
    Sspi(TokenSspi),
    // TODO(surface): act on negotiated feature acknowledgements.
    #[allow(dead_code)]
    FeatureExtAck(TokenFeatureExtAck),
    // Connection-resiliency state; parsed but recovery is not yet implemented.
    #[allow(dead_code)]
    SessionState(TokenSessionState),
    // Federated-auth info; parsed for the AAD flow but not read from this enum.
    #[allow(dead_code)]
    FedAuthInfo(TokenFedAuthInfo),
    Error(TokenError),
}

pub(crate) struct TokenStream<'a, S: AsyncRead + AsyncWrite + Unpin + Send> {
    conn: &'a mut Connection<S>,
    last_error: Option<Error>,
}

impl<'a, S> TokenStream<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub(crate) fn new(conn: &'a mut Connection<S>) -> Self {
        Self {
            conn,
            last_error: None,
        }
    }

    pub(crate) async fn flush_done(self) -> crate::Result<TokenDone> {
        let mut stream = self.try_unfold();
        let mut last_error = None;
        let mut routing = None;

        loop {
            match stream.try_next().await? {
                Some(ReceivedToken::Error(error)) => {
                    if last_error.is_none() {
                        last_error = Some(error);
                    }
                }
                Some(ReceivedToken::Done(token)) => match (last_error, routing) {
                    (Some(error), _) => return Err(Error::Server(error)),
                    (_, Some(routing)) => return Err(routing),
                    (_, _) => return Ok(token),
                },
                Some(ReceivedToken::EnvChange(TokenEnvChange::Routing { host, port })) => {
                    routing = Some(Error::Routing { host, port });
                }
                Some(_) => (),
                None => return Err(crate::Error::Protocol("Never got DONE token.".into())),
            }
        }
    }

    /// Drain the token stream after a client Attention signal has been sent,
    /// discarding every remaining token of the cancelled request until the
    /// acknowledging DONE token (with the `DONE_ATTN` status bit set) is
    /// received, per MS-TDS section 2.2.1.6. Returns that DONE token so the
    /// connection is left clean and ready for reuse.
    pub(crate) async fn flush_done_attention(self) -> crate::Result<TokenDone> {
        let mut stream = self.try_unfold();

        loop {
            match stream.try_next().await? {
                Some(ReceivedToken::Done(token))
                | Some(ReceivedToken::DoneProc(token))
                | Some(ReceivedToken::DoneInProc(token))
                    if token.is_attention() =>
                {
                    return Ok(token);
                }
                Some(_) => (),
                None => {
                    return Err(crate::Error::Protocol(
                        "Never got a DONE token acknowledging the Attention signal.".into(),
                    ))
                }
            }
        }
    }

    #[cfg(any(windows, feature = "integrated-auth-gssapi", feature = "sspi-rs"))]
    pub(crate) async fn flush_sspi(self) -> crate::Result<TokenSspi> {
        let mut stream = self.try_unfold();
        let mut last_error = None;

        loop {
            match stream.try_next().await? {
                Some(ReceivedToken::Error(error)) => {
                    if last_error.is_none() {
                        last_error = Some(error);
                    }
                }
                Some(ReceivedToken::Sspi(token)) => return Ok(token),
                Some(_) => (),
                None => match last_error {
                    Some(err) => return Err(crate::Error::Server(err)),
                    None => return Err(crate::Error::Protocol("Never got SSPI token.".into())),
                },
            }
        }
    }

    async fn get_col_metadata(&mut self) -> crate::Result<ReceivedToken> {
        let meta = Arc::new(TokenColMetaData::decode(self.conn).await?);
        self.conn.context_mut().set_last_meta(meta.clone());

        event!(Level::TRACE, ?meta);

        Ok(ReceivedToken::NewResultset(meta))
    }

    async fn get_alt_col_metadata(&mut self) -> crate::Result<ReceivedToken> {
        let meta = Arc::new(TokenAltMetaData::decode(self.conn).await?);
        self.conn.context_mut().set_alt_meta(meta.clone());

        event!(Level::TRACE, ?meta);

        Ok(ReceivedToken::NewAltResultset(meta))
    }

    async fn get_alt_row(&mut self) -> crate::Result<ReceivedToken> {
        // The id is read first so the matching ALTMETADATA can be looked up
        // before the column values are parsed.
        let id = self.conn.read_u16_le().await?;

        let meta = self.conn.context().alt_meta(id).ok_or_else(|| {
            Error::Protocol(format!("ALTROW for unknown compute id {}", id).into())
        })?;

        let row = TokenAltRow::decode(self.conn, id, &meta).await?;

        event!(Level::TRACE, message = ?row);
        Ok(ReceivedToken::AltRow(row))
    }

    async fn get_row(&mut self) -> crate::Result<ReceivedToken> {
        let return_value = TokenRow::decode(self.conn).await?;

        event!(Level::TRACE, message = ?return_value);
        Ok(ReceivedToken::Row(return_value))
    }

    async fn get_nbc_row(&mut self) -> crate::Result<ReceivedToken> {
        let return_value = TokenRow::decode_nbc(self.conn).await?;

        event!(Level::TRACE, message = ?return_value);
        Ok(ReceivedToken::Row(return_value))
    }

    async fn get_return_value(&mut self) -> crate::Result<ReceivedToken> {
        let return_value = TokenReturnValue::decode(self.conn).await?;
        event!(Level::TRACE, message = ?return_value);
        Ok(ReceivedToken::ReturnValue(return_value))
    }

    async fn get_return_status(&mut self) -> crate::Result<ReceivedToken> {
        let status = self.conn.read_u32_le().await?;
        Ok(ReceivedToken::ReturnStatus(status))
    }

    async fn get_error(&mut self) -> crate::Result<ReceivedToken> {
        let err = TokenError::decode(self.conn).await?;

        if self.last_error.is_none() {
            self.last_error = Some(Error::Server(err.clone()));
        }

        event!(Level::ERROR, message = %err.message, code = err.code);
        Ok(ReceivedToken::Error(err))
    }

    async fn get_order(&mut self) -> crate::Result<ReceivedToken> {
        let order = TokenOrder::decode(self.conn).await?;
        event!(Level::TRACE, message = ?order);
        Ok(ReceivedToken::Order(order))
    }

    async fn get_col_info(&mut self) -> crate::Result<ReceivedToken> {
        let col_info = TokenColInfo::decode(self.conn).await?;
        event!(Level::TRACE, message = ?col_info);
        Ok(ReceivedToken::ColInfo(col_info))
    }

    async fn get_tab_name(&mut self) -> crate::Result<ReceivedToken> {
        let tab_name = TokenTabName::decode(self.conn).await?;
        event!(Level::TRACE, message = ?tab_name);
        Ok(ReceivedToken::TabName(tab_name))
    }

    async fn get_done_value(&mut self) -> crate::Result<ReceivedToken> {
        let done = TokenDone::decode(self.conn).await?;
        event!(Level::TRACE, "{}", done);
        Ok(ReceivedToken::Done(done))
    }

    async fn get_done_proc_value(&mut self) -> crate::Result<ReceivedToken> {
        let done = TokenDone::decode(self.conn).await?;
        event!(Level::TRACE, "{}", done);
        Ok(ReceivedToken::DoneProc(done))
    }

    async fn get_done_in_proc_value(&mut self) -> crate::Result<ReceivedToken> {
        let done = TokenDone::decode(self.conn).await?;
        event!(Level::TRACE, "{}", done);
        Ok(ReceivedToken::DoneInProc(done))
    }

    async fn get_env_change(&mut self) -> crate::Result<ReceivedToken> {
        let change = TokenEnvChange::decode(self.conn).await?;

        match change {
            TokenEnvChange::PacketSize { new: new_size, .. } => {
                // MS-TDS: a negotiated packet size must be within 512..=32767.
                // Reject an out-of-range value from the server: the subsequent
                // `packet_size - HEADER_BYTES` in the send paths would otherwise
                // underflow (debug panic) or, for a value of exactly 8, produce
                // a zero chunk size and spin `split_to(0)` forever.
                if !(512..=32767).contains(&new_size) {
                    return Err(crate::Error::Protocol(
                        format!("server requested an invalid packet size of {new_size}").into(),
                    ));
                }
                self.conn.context_mut().set_packet_size(new_size);
            }
            TokenEnvChange::BeginTransaction(desc) => {
                self.conn.context_mut().set_transaction_descriptor(desc);
            }
            TokenEnvChange::CommitTransaction
            | TokenEnvChange::RollbackTransaction
            | TokenEnvChange::DefectTransaction => {
                self.conn.context_mut().set_transaction_descriptor([0; 8]);
            }
            _ => (),
        }

        event!(Level::DEBUG, "{}", change);

        Ok(ReceivedToken::EnvChange(change))
    }

    async fn get_info(&mut self) -> crate::Result<ReceivedToken> {
        let info = TokenInfo::decode(self.conn).await?;
        event!(Level::DEBUG, "{}", info.message);
        Ok(ReceivedToken::Info(info))
    }

    async fn get_login_ack(&mut self) -> crate::Result<ReceivedToken> {
        let ack = TokenLoginAck::decode(self.conn).await?;
        event!(Level::DEBUG, "{} version {}", ack.prog_name, ack.version);

        // Record the TDS version the server negotiated so version-dependent
        // decoders (DONE rowcount width, ERROR/INFO LineNumber width) use the
        // correct layout instead of the hardcoded default. For a modern server
        // (TDS 7.2+) this resolves to the same widths as the default, so there
        // is no behavior change; it only corrects decoding against pre-2005
        // servers that negotiate an earlier TDS version.
        self.conn.context_mut().set_version(ack.tds_version);

        Ok(ReceivedToken::LoginAck(ack))
    }

    async fn get_feature_ext_ack(&mut self) -> crate::Result<ReceivedToken> {
        let ack = TokenFeatureExtAck::decode(self.conn).await?;
        event!(
            Level::DEBUG,
            "FeatureExtAck with {} features",
            ack.features.len()
        );
        Ok(ReceivedToken::FeatureExtAck(ack))
    }

    async fn get_session_state(&mut self) -> crate::Result<ReceivedToken> {
        let state = TokenSessionState::decode(self.conn).await?;
        event!(
            Level::TRACE,
            "SessionState seq_no={} recoverable={} states={}",
            state.seq_no,
            state.is_recoverable(),
            state.states.len()
        );
        Ok(ReceivedToken::SessionState(state))
    }

    async fn get_fed_auth_info(&mut self) -> crate::Result<ReceivedToken> {
        let info = TokenFedAuthInfo::decode(self.conn).await?;
        event!(Level::TRACE, message = ?info);
        Ok(ReceivedToken::FedAuthInfo(info))
    }

    async fn get_sspi(&mut self) -> crate::Result<ReceivedToken> {
        let sspi = TokenSspi::decode_async(self.conn).await?;
        event!(Level::TRACE, "SSPI response");
        Ok(ReceivedToken::Sspi(sspi))
    }

    pub fn try_unfold(self) -> BoxStream<'a, crate::Result<ReceivedToken>> {
        // Read the per-response command timeout before `self` is moved into the
        // unfold closure. Every command result-read path funnels through here
        // (query/execute/simple_query result streams, the bulk-insert server
        // acknowledgement and column-metadata), so bounding each round-trip once
        // at this choke point covers them all.
        let command_timeout = self.conn.context().command_timeout();
        // Shared handle so the timeout, when it fires, can mark the underlying
        // connection desynced (it is moved into the unfold closure below and is
        // otherwise unreachable from `RoundTripTimeout`).
        let poison = self.conn.command_desync_flag();

        let stream = futures_util::stream::try_unfold(self, |mut this| async move {
            if this.conn.is_eof() {
                match this.last_error {
                    None => return Ok(None),
                    Some(error) => return Err(error),
                }
            }

            let ty_byte = this.conn.read_u8().await?;

            let ty = TokenType::try_from(ty_byte)
                .map_err(|_| Error::Protocol(format!("invalid token type {:x}", ty_byte).into()))?;

            let token = match ty {
                TokenType::ReturnStatus => this.get_return_status().await?,
                TokenType::ColMetaData => this.get_col_metadata().await?,
                TokenType::AltMetaData => this.get_alt_col_metadata().await?,
                TokenType::Row => this.get_row().await?,
                TokenType::AltRow => this.get_alt_row().await?,
                TokenType::NbcRow => this.get_nbc_row().await?,
                TokenType::Done => this.get_done_value().await?,
                TokenType::DoneProc => this.get_done_proc_value().await?,
                TokenType::DoneInProc => this.get_done_in_proc_value().await?,
                TokenType::ReturnValue => this.get_return_value().await?,
                TokenType::Error => this.get_error().await?,
                TokenType::Order => this.get_order().await?,
                TokenType::ColInfo => this.get_col_info().await?,
                TokenType::TabName => this.get_tab_name().await?,
                TokenType::EnvChange => this.get_env_change().await?,
                TokenType::Info => this.get_info().await?,
                TokenType::LoginAck => this.get_login_ack().await?,
                TokenType::Sspi => this.get_sspi().await?,
                TokenType::SessionState => this.get_session_state().await?,
                TokenType::FedAuthInfo => this.get_fed_auth_info().await?,
                TokenType::FeatureExtAck => this.get_feature_ext_ack().await?,
                // NOTE: every `TokenType` variant is handled above. This match
                // is intentionally exhaustive (no wildcard arm) so that adding a
                // new `TokenType` fails to compile until a handler is wired up,
                // rather than silently falling through. Unknown token *bytes*
                // are already rejected by the `TokenType::try_from` above.
            };

            Ok(Some((token, this)))
        });

        Box::pin(RoundTripTimeout::new(
            command_timeout,
            Some(poison),
            Box::pin(stream),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::TokenStream;
    use crate::client::Connection;
    use crate::tds::codec::{Encode, Packet, PacketHeader, PacketStatus};
    use crate::{Error, SqlReadBytes};
    use bytes::BytesMut;
    use futures_util::io::{AsyncRead, AsyncWrite};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    // A mock stream that hands out a fixed byte script to `poll_read` (the raw
    // TDS packet bytes a server would have written) and swallows every write.
    // Once the script is exhausted it reports clean EOF (`Ok(0)`), exactly like
    // a closed connection with no more packets on the wire.
    struct MockStream {
        data: Vec<u8>,
        pos: usize,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let remaining = &self.data[self.pos..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // --- Wire-byte builders -------------------------------------------------
    // Each returns a token exactly as it appears on the wire (leading token-type
    // byte + body), built from the same layouts the decoders parse. See
    // `token_done.rs`, `token_error.rs`, and `token_env_change.rs`.

    fn write_b_varchar(buf: &mut Vec<u8>, s: &str) {
        buf.push(s.encode_utf16().count() as u8);
        for unit in s.encode_utf16() {
            buf.extend_from_slice(&unit.to_le_bytes());
        }
    }

    fn write_us_varchar(buf: &mut Vec<u8>, s: &str) {
        buf.extend_from_slice(&(s.encode_utf16().count() as u16).to_le_bytes());
        for unit in s.encode_utf16() {
            buf.extend_from_slice(&unit.to_le_bytes());
        }
    }

    // DONE token (0xFD): status u16, cur_cmd u16, done_rows u64 (8-byte width
    // for the default TDS 7.2+ context).
    fn done_token(status: u16, cur_cmd: u16, rows: u64) -> Vec<u8> {
        let mut v = vec![0xFDu8];
        v.extend_from_slice(&status.to_le_bytes());
        v.extend_from_slice(&cur_cmd.to_le_bytes());
        v.extend_from_slice(&rows.to_le_bytes());
        v
    }

    // ERROR token (0xAA): u16 length prefix, then the ERROR/INFO body. The
    // default test context is TDS 7.2+, so LineNumber is a 4-byte LONG.
    fn error_token(code: u32, message: &str, server: &str, procedure: &str, line: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&code.to_le_bytes());
        body.push(1); // state
        body.push(16); // class
        write_us_varchar(&mut body, message);
        write_b_varchar(&mut body, server);
        write_b_varchar(&mut body, procedure);
        body.extend_from_slice(&line.to_le_bytes());

        let mut v = vec![0xAAu8];
        v.extend_from_slice(&(body.len() as u16).to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    // ENVCHANGE token (0xE3) of type Routing (20): u16 length prefix over the
    // type byte + payload.
    fn envchange_routing(port: u16, host: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u16.to_le_bytes()); // routing data value length (unused)
        payload.push(0); // protocol, always 0 (tcp)
        payload.extend_from_slice(&port.to_le_bytes());
        payload.extend_from_slice(&(host.encode_utf16().count() as u16).to_le_bytes());
        for unit in host.encode_utf16() {
            payload.extend_from_slice(&unit.to_le_bytes());
        }

        let mut body = vec![20u8];
        body.extend_from_slice(&payload);

        let mut v = vec![0xE3u8];
        v.extend_from_slice(&(body.len() as u16).to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    // ENVCHANGE token (0xE3) of type PacketSize (4): new/old sizes as B_VARCHAR
    // decimal strings that the decoder parses into u32.
    fn envchange_packet_size(new: &str, old: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        write_b_varchar(&mut payload, new);
        write_b_varchar(&mut payload, old);

        let mut body = vec![4u8];
        body.extend_from_slice(&payload);

        let mut v = vec![0xE3u8];
        v.extend_from_slice(&(body.len() as u16).to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    // Wrap a token-stream payload in a single end-of-message TDS packet, framed
    // exactly like `Packet::encode` (8-byte header with the big-endian total
    // length patched into bytes [2..4]). This is what the mock stream serves.
    fn packet_bytes(payload: &[u8]) -> Vec<u8> {
        let mut header = PacketHeader::batch(1);
        header.set_status(PacketStatus::EndOfMessage);
        let packet = Packet::new(header, BytesMut::from(payload));

        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();
        buf.to_vec()
    }

    fn conn_over(payload: &[u8]) -> Connection<MockStream> {
        Connection::test_over(MockStream::new(packet_bytes(payload)), false)
    }

    // --- (a) flush_done precedence -----------------------------------------

    #[tokio::test]
    async fn flush_done_error_beats_routing_beats_done() {
        // [ERROR][ENVCHANGE Routing][DONE]: the ERROR must win over the routing
        // redirect, which in turn would win over a plain DONE. Locks the
        // precedence in `flush_done`'s match on (last_error, routing).
        let mut payload = Vec::new();
        payload.extend_from_slice(&error_token(1205, "boom", "srv", "proc", 7));
        payload.extend_from_slice(&envchange_routing(1433, "other.example.com"));
        payload.extend_from_slice(&done_token(0, 0, 0));

        let mut conn = conn_over(&payload);
        let err = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect_err("an ERROR token must surface as an error, not Ok(DONE)");

        match err {
            Error::Server(e) => assert_eq!(e.code(), 1205),
            other => panic!("expected Error::Server, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn flush_done_routing_beats_done() {
        // [ENVCHANGE Routing][DONE] with no ERROR: the routing redirect wins
        // over a plain DONE.
        let mut payload = Vec::new();
        payload.extend_from_slice(&envchange_routing(1433, "other.example.com"));
        payload.extend_from_slice(&done_token(0, 0, 0));

        let mut conn = conn_over(&payload);
        let err = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect_err("a routing env-change must surface as a Routing error");

        match err {
            Error::Routing { host, port } => {
                assert_eq!(host, "other.example.com");
                assert_eq!(port, 1433);
            }
            other => panic!("expected Error::Routing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn flush_done_plain_done_is_ok() {
        // A lone [DONE] returns Ok(TokenDone).
        let mut conn = conn_over(&done_token(0, 0, 0));
        let done = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect("a plain DONE must succeed");
        assert!(done.is_final());
    }

    // --- (b) get_env_change packet-size bound ------------------------------

    #[tokio::test]
    async fn env_change_packet_size_below_512_is_protocol_error() {
        // A negotiated packet size below the 512..=32767 range must be rejected
        // (would otherwise underflow / spin the send path), not panic.
        let mut conn = conn_over(&envchange_packet_size("8", "4096"));
        let err = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect_err("packet size 8 is below the 512 floor");
        match err {
            Error::Protocol(msg) => assert!(msg.contains("invalid packet size")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn env_change_packet_size_above_32767_is_protocol_error() {
        let mut conn = conn_over(&envchange_packet_size("40000", "4096"));
        let err = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect_err("packet size 40000 is above the 32767 ceiling");
        match err {
            Error::Protocol(msg) => assert!(msg.contains("invalid packet size")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn env_change_packet_size_in_range_is_applied() {
        // A valid packet size (8192) is accepted and stored in the context.
        let mut payload = Vec::new();
        payload.extend_from_slice(&envchange_packet_size("8192", "4096"));
        payload.extend_from_slice(&done_token(0, 0, 0));

        let mut conn = conn_over(&payload);
        TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect("an in-range packet size must be accepted");
        assert_eq!(conn.context().packet_size(), 8192);
    }

    // --- (c) try_unfold dispatch -------------------------------------------

    #[tokio::test]
    async fn unknown_token_type_byte_is_protocol_error() {
        // 0x00 is not a defined token type; `TokenType::try_from` must reject it.
        let mut conn = conn_over(&[0x00u8]);
        let err = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect_err("an unknown token byte must be rejected");
        match err {
            Error::Protocol(msg) => assert!(msg.contains("invalid token type")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn row_before_col_metadata_is_protocol_error() {
        // A ROW token (0xD1) arriving before any COLMETADATA has no cached
        // metadata to parse against and must be a clean protocol error.
        let mut conn = conn_over(&[0xD1u8]);
        let err = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect_err("a ROW before COLMETADATA must error");
        match err {
            Error::Protocol(msg) => assert!(msg.contains("before any COLMETADATA")),
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    // --- (d) command timeout end-to-end -------------------------------------
    //
    // A server that answers with a first packet and then goes silent mid-result
    // must surface a prompt TimedOut error through the whole
    // Connection -> TokenStream -> RoundTripTimeout read path, rather than
    // hanging (command-timeout arm).

    // Frame a token payload into a single *non-final* (NormalMessage) TDS
    // packet, so the connection expects at least one more packet afterwards.
    fn normal_packet_bytes(payload: &[u8]) -> Vec<u8> {
        let mut header = PacketHeader::batch(1);
        header.set_status(PacketStatus::NormalMessage);
        let packet = Packet::new(header, BytesMut::from(payload));

        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();
        buf.to_vec()
    }

    // Serves a fixed script of bytes once, then parks every subsequent read
    // forever — a server that answers and then stalls mid-response. Distinct
    // from `MockStream`, which reports clean EOF once its script is exhausted.
    struct AnswerThenSilent {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for AnswerThenSilent {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.pos >= self.data.len() {
                // Script exhausted: the server has gone silent. Only the command
                // timeout can unblock the reader now.
                return Poll::Pending;
            }
            let remaining = &self.data[self.pos..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for AnswerThenSilent {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn is_timed_out(err: &Error) -> bool {
        matches!(err, Error::Io { kind, .. } if *kind == io::ErrorKind::TimedOut)
    }

    #[tokio::test]
    async fn command_timeout_fires_when_server_stalls_mid_stream() {
        use crate::SqlReadBytes;
        use std::time::{Duration, Instant};

        // First (non-final) packet carries a valid ENVCHANGE but no DONE, then
        // the stream goes silent — so the reader must wait for a packet that
        // never comes.
        let script = normal_packet_bytes(&envchange_packet_size("8192", "4096"));
        let mut conn = Connection::test_over(
            AnswerThenSilent {
                data: script,
                pos: 0,
            },
            false,
        );
        conn.context_mut()
            .set_command_timeout(Some(Duration::from_millis(100)));

        let started = Instant::now();
        let err = TokenStream::new(&mut conn)
            .flush_done()
            .await
            .expect_err("a server that stalls mid-result must not hang the read");

        assert!(
            is_timed_out(&err),
            "expected a TimedOut error, got: {err:?}"
        );
        assert!(
            err.to_string().contains("did not send the next part")
                && err.to_string().contains("out of sync"),
            "command timeout error should be diagnosable, got: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the command timeout must fire promptly, took {:?}",
            started.elapsed()
        );
        // The token that *did* arrive before the stall was still processed.
        assert_eq!(conn.context().packet_size(), 8192);
        // The connection is now desynced (the tail of the timed-out response is
        // still unread): it must be poisoned so a pool cannot silently reuse it
        // and re-hang in `flush_stream` on the still-pending response.
        let reuse = conn.ensure_not_poisoned();
        assert!(
            reuse.is_err(),
            "a command timeout must leave the connection unusable, got: {reuse:?}"
        );
        assert!(
            reuse.unwrap_err().to_string().contains("out of sync"),
            "reuse should be rejected with a command-timeout desync error"
        );
    }

    #[tokio::test]
    async fn no_command_timeout_keeps_waiting_on_a_stalled_server() {
        // With no command timeout configured, a mid-result stall keeps the read
        // pending; an outer guard proves no internal timeout fires.
        let script = normal_packet_bytes(&envchange_packet_size("8192", "4096"));
        let mut conn = Connection::test_over(
            AnswerThenSilent {
                data: script,
                pos: 0,
            },
            false,
        );
        // command_timeout defaults to None on a bare Context.

        let outcome = tokio::time::timeout(std::time::Duration::from_millis(150), async {
            TokenStream::new(&mut conn).flush_done().await
        })
        .await;

        assert!(
            outcome.is_err(),
            "with no command timeout the read should stay pending on the stalled server"
        );
    }
}

// Server-free tests for the `RoundTripTimeout` stream combinator that backs
// `Config::command_timeout`. They assert the per-round-trip semantics directly:
// a stalled server times out promptly, responsive reads pass through, `None`
// disables the bound, and — critically — a slow *consumer* never trips it.
#[cfg(test)]
mod round_trip_timeout_tests {
    use super::{ReceivedToken, RoundTripTimeout};
    use futures_util::stream::{self, BoxStream, StreamExt};
    use std::time::{Duration, Instant};

    fn token() -> ReceivedToken {
        ReceivedToken::ReturnStatus(0)
    }

    fn is_timed_out(err: &crate::Error) -> bool {
        matches!(err, crate::Error::Io { kind, .. } if *kind == std::io::ErrorKind::TimedOut)
    }

    #[tokio::test]
    async fn stalled_server_times_out_promptly() {
        // Inner stream never yields: a server that stops responding mid-result.
        let inner: BoxStream<'static, crate::Result<ReceivedToken>> = stream::pending().boxed();
        let mut s = RoundTripTimeout::new(Some(Duration::from_millis(50)), None, inner);

        let started = Instant::now();
        let item = s.next().await.expect("must yield a timeout error, not end");
        let err = item.expect_err("a stalled server must produce an error");
        assert!(is_timed_out(&err), "expected TimedOut, got: {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must fire promptly, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn responsive_reads_pass_through_under_the_bound() {
        let inner: BoxStream<'static, crate::Result<ReceivedToken>> =
            stream::iter(vec![Ok(token()), Ok(token()), Ok(token())]).boxed();
        let mut s = RoundTripTimeout::new(Some(Duration::from_secs(30)), None, inner);

        let mut count = 0;
        while let Some(item) = s.next().await {
            item.expect("responsive reads must not error");
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn none_timeout_never_injects_a_deadline() {
        // A permanently pending inner stream with no bound must stay pending —
        // the outer guard elapsing proves no internal timeout fired.
        let inner: BoxStream<'static, crate::Result<ReceivedToken>> = stream::pending().boxed();
        let mut s = RoundTripTimeout::new(None, None, inner);

        let outcome = tokio::time::timeout(Duration::from_millis(100), s.next()).await;
        assert!(
            outcome.is_err(),
            "with no bound the stream must keep waiting, not time out"
        );
    }

    #[tokio::test]
    async fn slow_consumer_does_not_trip_the_timeout() {
        // The server answers each round-trip with a genuine `Pending` gap that
        // stays *under* the bound (so the timer really is armed and reset on
        // each delivery), but the consumer then idles far *longer* than the
        // bound between pulls. Because the timer only runs while a read is in
        // flight — never between the consumer's polls — this must NOT time out,
        // proving the bound measures server latency, not consumer pace. Using a
        // real slow server (not an always-ready `stream::iter`) means the
        // `Pending`/timer arm is actually exercised, so the test would fail if
        // the timer wrongly counted consumer idle time.
        let mut s = RoundTripTimeout::new(
            Some(Duration::from_millis(100)),
            None,
            slow_server(Duration::from_millis(30), 3),
        );

        for _ in 0..3 {
            s.next()
                .await
                .expect("item expected")
                .expect("a responsive server must not time out");
            // Idle far longer than the 100ms bound between consuming items.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(s.next().await.is_none(), "stream should end cleanly");
    }

    // An inner stream whose every item is delivered only after a genuine
    // `Pending` gap of `gap`, driven by a real timer. Unlike `stream::iter`
    // (always immediately `Ready`), this forces `RoundTripTimeout` down its
    // `Pending` arm on every round-trip, so the lazy-create / reset-on-delivery
    // logic is actually exercised.
    fn slow_server(
        gap: Duration,
        count: usize,
    ) -> BoxStream<'static, crate::Result<ReceivedToken>> {
        stream::unfold(0usize, move |i| async move {
            if i >= count {
                return None;
            }
            tokio::time::sleep(gap).await;
            Some((Ok(token()), i + 1))
        })
        .boxed()
    }

    #[tokio::test]
    async fn bounds_each_round_trip_not_total_enumeration() {
        // Five genuine round-trips, each 50ms (well under the 200ms bound), for a
        // total enumeration of ~250ms — longer than the bound. A correct
        // per-round-trip timer resets on each delivery and never trips; a broken
        // one that measured total stream lifetime (delay created once, never
        // reset) would fire partway through. All five tokens must arrive.
        let mut s = RoundTripTimeout::new(
            Some(Duration::from_millis(200)),
            None,
            slow_server(Duration::from_millis(50), 5),
        );

        let mut count = 0;
        while let Some(item) = s.next().await {
            item.expect("no round-trip exceeds the bound, so none must time out");
            count += 1;
        }
        assert_eq!(count, 5, "all tokens must be delivered across genuine gaps");
    }

    #[tokio::test]
    async fn deadline_resets_after_delivery_then_a_later_stall_trips() {
        // One token arrives after a short gap (under the bound), then the server
        // goes silent forever. The first item must be delivered (proving the
        // pre-stall token survives), and the *next* poll must arm a fresh timer
        // and trip (proving the deadline re-arms after a delivery rather than
        // being consumed once).
        let inner = stream::unfold(0usize, |i| async move {
            match i {
                0 => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some((Ok(token()), 1usize))
                }
                _ => std::future::pending().await,
            }
        })
        .boxed();
        let mut s = RoundTripTimeout::new(Some(Duration::from_millis(80)), None, inner);

        s.next()
            .await
            .expect("first token expected")
            .expect("the first round-trip is under the bound and must not time out");

        let err = s
            .next()
            .await
            .expect("a second item (the timeout error) is expected")
            .expect_err("the second, stalled round-trip must trip the re-armed deadline");
        assert!(is_timed_out(&err), "expected TimedOut, got: {err:?}");
    }

    #[tokio::test]
    async fn poison_flag_is_flipped_when_the_deadline_fires() {
        // The shared poison handle must be set when the timer fires, so the
        // owning connection can reject reuse.
        let poison = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let inner: BoxStream<'static, crate::Result<ReceivedToken>> = stream::pending().boxed();
        let mut s =
            RoundTripTimeout::new(Some(Duration::from_millis(50)), Some(poison.clone()), inner);

        assert!(!poison.load(std::sync::atomic::Ordering::Acquire));
        let err = s
            .next()
            .await
            .expect("a timeout error is expected")
            .expect_err("a stalled server must produce an error");
        assert!(is_timed_out(&err));
        assert!(
            poison.load(std::sync::atomic::Ordering::Acquire),
            "the poison flag must be set when the command timeout fires"
        );
    }

    #[tokio::test]
    async fn zero_duration_trips_on_the_first_stall() {
        // A zero-duration bound is a degenerate but valid setting: the first time
        // the server is not immediately ready, the deadline is already elapsed,
        // so the read fails fast rather than hanging.
        let inner: BoxStream<'static, crate::Result<ReceivedToken>> = stream::pending().boxed();
        let mut s = RoundTripTimeout::new(Some(Duration::ZERO), None, inner);

        let err = s
            .next()
            .await
            .expect("a timeout error is expected")
            .expect_err("a zero bound must trip on the first stall");
        assert!(is_timed_out(&err), "expected TimedOut, got: {err:?}");
    }
}
