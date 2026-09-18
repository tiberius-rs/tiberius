#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use crate::client::{tls::TlsPreloginWrapper, tls_stream::create_tls_stream};
use crate::{
    client::{tls::MaybeTlsStream, AuthMethod, Config},
    tds::{
        codec::{
            self, Encode, LoginMessage, Packet, PacketCodec, PacketHeader, PacketStatus,
            PreloginMessage, TokenDone,
        },
        stream::TokenStream,
        Context, HEADER_BYTES,
    },
    EncryptionLevel, SqlReadBytes,
};
use asynchronous_codec::Framed;
use bytes::BytesMut;
#[cfg(any(windows, feature = "integrated-auth-gssapi", feature = "sspi-rs"))]
use codec::TokenSspi;
use futures_util::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use futures_util::ready;
use futures_util::sink::SinkExt;
use futures_util::stream::{Stream, TryStream, TryStreamExt};
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
use libgssapi::{
    context::{ClientCtx, CtxFlags},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL},
};
use pretty_hex::*;
use secrecy::ExposeSecret;
#[cfg(all(unix, feature = "sspi-rs"))]
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm,
    SecurityBuffer, Sspi, SspiImpl, Username,
};
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{cmp, fmt::Debug, io, pin::Pin, task};
use task::Poll;
use tracing::{event, Level};
#[cfg(all(windows, feature = "winauth"))]
use winauth::{windows::NtlmSspiBuilder, NextBytes};
use zeroize::{Zeroize, Zeroizing};

/// A `Connection` is an abstraction between the [`Client`] and the server. It
/// can be used as a `Stream` to fetch [`Packet`]s from and to `send` packets
/// splitting them to the negotiated limit automatically.
///
/// `Connection` is not meant to use directly, but as an abstraction layer for
/// the numerous `Stream`s for easy packet handling.
///
/// [`Client`]: struct.Encode.html
/// [`Packet`]: ../protocol/codec/struct.Packet.html
pub(crate) struct Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    transport: Framed<MaybeTlsStream<S>, PacketCodec>,
    flushed: bool,
    context: Context,
    buf: BytesMut,
    /// Set for the duration of a multi-packet write. A message is only partly
    /// on the wire while this is `true`; if the writing future is dropped
    /// (a cancelled `query`/`execute`, a `select!` losing the race, a
    /// `tokio::time::timeout` firing) the flag stays set, so the next write on
    /// the same connection fails cleanly instead of appending a second message
    /// after a half-sent one and silently desyncing the server.
    poisoned: bool,
    /// Set when a `command_timeout` fires mid-response. The tail of the
    /// timed-out response is then still unread on the wire, so the connection is
    /// out of sync with the server and must not be reused. This handle is shared
    /// with the token stream's `RoundTripTimeout`, which flips it when its
    /// deadline elapses; [`ensure_not_poisoned`] rejects every subsequent use so
    /// a pool discards the connection instead of hanging in `flush_stream` on
    /// the still-pending previous response.
    ///
    /// [`ensure_not_poisoned`]: Self::ensure_not_poisoned
    command_desync: Arc<AtomicBool>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Debug for Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("transport", &"Framed<..>")
            .field("flushed", &self.flushed)
            .field("context", &self.context)
            .field("buf", &self.buf.as_ref().hex_dump())
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Connection<S> {
    /// Creates a new connection.
    ///
    /// Note: `tcp_stream` is a connected stream, so some parts of the
    /// [`Config`] need to be handled outside of this method.
    ///
    /// The handshake performed here (prelogin, TLS negotiation and login) is
    /// bounded by [`Config::handshake_timeout`]: if the server accepts the TCP
    /// connection but then stalls mid-handshake (for example a TLS handshake
    /// that never completes), the connect future fails with a
    /// [`std::io::ErrorKind::TimedOut`] error instead of hanging forever. Enable
    /// `tracing` at `DEBUG` to see which stage was last reached.
    pub(crate) async fn connect(config: Config, tcp_stream: S) -> crate::Result<Connection<S>> {
        let handshake_timeout = config.handshake_timeout;
        with_optional_timeout(handshake_timeout, Self::establish(config, tcp_stream)).await
    }

    /// Performs the full connection handshake (prelogin, TLS negotiation and
    /// login) over an already-connected `tcp_stream`.
    ///
    /// Split out from [`connect`](Self::connect) so the whole handshake can be
    /// wrapped in a single [`Config::handshake_timeout`] bound; on its own it
    /// runs unbounded and would block forever if the server stalls.
    async fn establish(config: Config, tcp_stream: S) -> crate::Result<Connection<S>> {
        // Captured before `config` is consumed below and applied to the
        // `Context` only *after* the handshake completes (see the end of this
        // method). Arming it up front would also bound the login-ack/SSPI drain
        // that runs through the same token stream (`flush_done`/`flush_sspi`)
        // during connect, which is wrong: that whole handshake is governed by
        // `handshake_timeout` alone, so `handshake_timeout(None)` must genuinely
        // wait indefinitely regardless of `command_timeout`.
        let command_timeout = config.command_timeout;

        let context = {
            let mut context = Context::new();
            context.set_spn(config.get_host(), config.get_port());
            // Row-decode preference; unrelated to handshake timing, so set it up
            // front alongside the SPN.
            context.set_lossy_utf16(config.lossy_utf16_decoding);
            context
        };

        // In TDS 8.0 "strict" mode the TLS handshake happens *before* the
        // prelogin, so we wrap the stream in TLS up front. In every other mode
        // the connection starts in the clear and TLS (if any) is negotiated
        // during the prelogin.
        #[cfg(any(
            feature = "rustls",
            feature = "native-tls",
            feature = "vendored-openssl"
        ))]
        let transport = match config.encryption {
            EncryptionLevel::Strict => {
                event!(Level::DEBUG, "Performing a TLS handshake (TDS 8.0 strict)");
                let mut pre_login_stream = TlsPreloginWrapper::new(tcp_stream);
                // No prelogin framing is used for the strict handshake; pass the
                // raw TLS bytes straight through.
                pre_login_stream.handshake_complete();
                let stream = create_tls_stream(&config, pre_login_stream).await?;
                event!(Level::DEBUG, "TLS handshake successful");
                Framed::new(MaybeTlsStream::Tls(stream), PacketCodec)
            }
            _ => Framed::new(MaybeTlsStream::Raw(tcp_stream), PacketCodec),
        };

        #[cfg(not(any(
            feature = "rustls",
            feature = "native-tls",
            feature = "vendored-openssl"
        )))]
        let transport = Framed::new(MaybeTlsStream::Raw(tcp_stream), PacketCodec);

        let mut connection = Self {
            transport,
            context,
            flushed: false,
            buf: BytesMut::new(),
            poisoned: false,
            command_desync: Arc::new(AtomicBool::new(false)),
        };

        let fed_auth_required = matches!(config.auth, AuthMethod::AADToken(_));

        event!(Level::DEBUG, "Handshake stage: sending TDS prelogin");
        let prelogin = connection
            .prelogin(
                config.encryption,
                fed_auth_required,
                config.instance_name.clone(),
            )
            .await?;

        let encryption = prelogin.negotiated_encryption(config.encryption)?;
        event!(
            Level::DEBUG,
            "Handshake stage: prelogin complete, negotiated encryption = {:?}",
            encryption
        );

        let connection = connection.tls_handshake(&config, encryption).await?;

        event!(Level::DEBUG, "Handshake stage: sending login");
        let mut connection = connection
            .login(
                config.auth,
                encryption,
                config.database,
                config.host,
                config.application_name,
                config.client_name,
                config.readonly,
                config.packet_size,
                prelogin,
            )
            .await?;

        connection.flush_done().await?;
        event!(Level::DEBUG, "Handshake stage: login complete");

        // The handshake is done; arm the per-response command timeout now so it
        // only ever bounds command result reads, never the handshake above.
        connection
            .context_mut()
            .set_command_timeout(command_timeout);

        Ok(connection)
    }

    /// Flush the incoming token stream until receiving `DONE` token.
    async fn flush_done(&mut self) -> crate::Result<TokenDone> {
        TokenStream::new(self).flush_done().await
    }

    #[cfg(any(windows, feature = "integrated-auth-gssapi", feature = "sspi-rs"))]
    /// Flush the incoming token stream until receiving `SSPI` token.
    async fn flush_sspi(&mut self) -> crate::Result<TokenSspi> {
        TokenStream::new(self).flush_sspi().await
    }

    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    fn post_login_encryption(mut self, encryption: EncryptionLevel) -> Self {
        if let EncryptionLevel::Off = encryption {
            event!(
                Level::WARN,
                "Turning TLS off after a login. All traffic from here on is not encrypted.",
            );

            let Self { transport, .. } = self;
            let tcp = transport.into_inner().into_inner();
            self.transport = Framed::new(MaybeTlsStream::Raw(tcp), PacketCodec);
        }

        self
    }

    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    fn post_login_encryption(self, _: EncryptionLevel) -> Self {
        self
    }

    /// Send an item to the wire. Header should define the item type and item should implement
    /// [`Encode`], defining the byte structure for the wire.
    ///
    /// The `send` will split the packet into multiple packets if bigger than
    /// the negotiated packet size, and handle flushing to the wire in an optimal way.
    ///
    /// [`Encode`]: ../protocol/codec/trait.Encode.html
    pub async fn send<E>(&mut self, mut header: PacketHeader, item: E) -> crate::Result<()>
    where
        E: Sized + Encode<BytesMut>,
    {
        self.ensure_not_poisoned()?;
        self.flushed = false;
        let packet_size = (self.context.packet_size() as usize) - HEADER_BYTES;

        let mut payload = BytesMut::new();
        item.encode(&mut payload)?;

        // Mark the connection poisoned across the multi-packet write; a clean
        // completion clears it below. A future dropped mid-loop leaves it set.
        self.poisoned = true;

        while !payload.is_empty() {
            let writable = cmp::min(payload.len(), packet_size);
            let split_payload = payload.split_to(writable);

            if payload.is_empty() {
                header.set_status(PacketStatus::EndOfMessage);
            } else {
                header.set_status(PacketStatus::NormalMessage);
            }

            event!(
                Level::TRACE,
                "Sending a packet ({} bytes)",
                split_payload.len() + HEADER_BYTES,
            );

            self.write_to_wire(header, split_payload).await?;
        }

        self.flush_sink().await?;
        self.poisoned = false;

        Ok(())
    }

    /// Returns an error if a previous multi-packet write on this connection was
    /// interrupted (e.g. the query/execute future was cancelled), which would
    /// have left a partial message on the wire. The connection cannot be safely
    /// reused in that state and should be dropped.
    pub(crate) fn ensure_not_poisoned(&self) -> crate::Result<()> {
        if self.poisoned {
            return Err(crate::Error::Protocol(
                "connection was left in an inconsistent state by a cancelled write and can no longer be used; open a new connection"
                    .into(),
            ));
        }
        if self.command_desync.load(Ordering::Acquire) {
            return Err(crate::Error::Protocol(
                "connection was left out of sync with the server by a command timeout (the previous response is only partly read) and can no longer be used; open a new connection"
                    .into(),
            ));
        }
        Ok(())
    }

    /// A handle to the command-timeout desync flag, shared with the token stream
    /// so it can mark the connection unusable when a `command_timeout` fires
    /// mid-response. See the `command_desync` field.
    pub(crate) fn command_desync_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.command_desync)
    }

    /// Marks the connection poisoned for the duration of a multi-packet write.
    ///
    /// Exposed to the bulk-load write path (`BulkLoadRequest`), which writes its
    /// messages by calling [`write_to_wire`] directly rather than through
    /// [`send`]. It must bracket those write loops with `poison`/[`unpoison`] so
    /// that a dropped future (cancelled bulk insert, `select!`, `timeout`) leaves
    /// the connection unusable instead of silently reused after a half-sent
    /// message — the same guarantee `send`/`cancel_request` get from their inline
    /// bracketing. This is deliberately *not* folded into `write_to_wire`: that
    /// method is called once per packet inside `send`'s loop, so clearing the
    /// flag there would drop the poison between packets of a multi-packet send
    /// and destroy the very protection `send` relies on.
    ///
    /// [`write_to_wire`]: Self::write_to_wire
    /// [`send`]: Self::send
    /// [`unpoison`]: Self::unpoison
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Clears the poisoned flag after a multi-packet write completes cleanly.
    /// The counterpart to [`poison`](Self::poison); see its docs.
    pub(crate) fn unpoison(&mut self) {
        self.poisoned = false;
    }

    async fn send_sensitive_login(
        &mut self,
        header: PacketHeader,
        mut payload: Zeroizing<Box<[u8]>>,
    ) -> crate::Result<()> {
        self.ensure_not_poisoned()?;
        self.flushed = false;
        let packet_size = (self.context.packet_size() as usize) - HEADER_BYTES;

        // Frame the login into zeroizable packets off the shared `BytesMut`
        // path. Each frame is a `Zeroizing` wiped on drop at the end of its
        // loop iteration, so no explicit call is needed there; `payload` is
        // zeroized right after framing to drop the plaintext copy before the
        // network-write loop's awaits.
        let frames = frame_sensitive_login(header, &payload[..], packet_size)?;
        payload.zeroize();

        // Mark the connection poisoned across the multi-frame write, exactly
        // like `send`/`cancel_request`: if the writing future is dropped
        // mid-loop the login is only partly on the wire and the connection must
        // not be silently reused. A clean flush clears it below.
        self.poisoned = true;

        for frame in frames {
            event!(Level::TRACE, "Sending a packet ({} bytes)", frame.len(),);

            self.transport.write_all(&frame[..]).await?;
        }

        (&mut *self.transport).flush().await?;
        self.poisoned = false;

        Ok(())
    }

    /// Sends a packet of data to the database.
    ///
    /// # Warning
    ///
    /// Please be sure the packet size doesn't exceed the largest allowed size
    /// dictaded by the server.
    pub(crate) async fn write_to_wire(
        &mut self,
        header: PacketHeader,
        data: BytesMut,
    ) -> crate::Result<()> {
        self.flushed = false;

        let packet = Packet::new(header, data);
        self.transport.send(packet).await?;

        Ok(())
    }

    /// Sends all pending packages to the wire.
    pub(crate) async fn flush_sink(&mut self) -> crate::Result<()> {
        self.transport.flush().await
    }

    /// Sends a TDS Attention signal (packet type `0x06`, MS-TDS section
    /// 2.2.1.6) to request cancellation of the request currently in flight on
    /// this connection, then drains the token stream until the acknowledging
    /// DONE token (with the `DONE_ATTN` status bit set) is received.
    ///
    /// The Attention message carries no payload, so it is written to the wire
    /// as a single end-of-message packet. Draining the acknowledgement leaves
    /// the connection clean and ready to be reused for further queries.
    pub(crate) async fn cancel_request(&mut self) -> crate::Result<TokenDone> {
        // Consistency with the other write paths (`send`,
        // `send_sensitive_login`, `flush_stream`): if a previous multi-packet
        // write was interrupted, the connection is already desynced with a
        // partial message sitting on the wire. Appending an Attention packet
        // after that half-sent message would corrupt the stream further and the
        // acknowledging DONE could never be matched, so fail fast instead. A
        // legitimate cancel targets an in-flight request, which means the prior
        // `send` completed and cleared the flag, so this guard never rejects a
        // valid cancellation.
        self.ensure_not_poisoned()?;

        let id = self.context.next_packet_id();
        let header = PacketHeader::attention(id);

        // Mark the connection poisoned across the write, exactly like `send`:
        // the Attention is a single end-of-message packet, but if the writing
        // future is dropped mid-flight the header is only partly on the wire and
        // the connection must not be silently reused. A clean flush clears it.
        self.poisoned = true;

        // Attention has an empty payload; send just the 8-byte header.
        self.write_to_wire(header, BytesMut::new()).await?;
        self.flush_sink().await?;
        self.poisoned = false;

        TokenStream::new(self).flush_done_attention().await
    }

    /// Cleans the packet stream from previous use. It is important to use the
    /// whole stream before using the connection again. Flushing the stream
    /// makes sure we don't have any old data causing undefined behaviour after
    /// previous queries.
    ///
    /// Calling this will slow down the queries if stream is still dirty if all
    /// results are not handled.
    pub async fn flush_stream(&mut self) -> crate::Result<()> {
        // If a previous write was cancelled mid-message the connection is
        // already known-bad; fail fast rather than layering a new request on
        // top of it.
        self.ensure_not_poisoned()?;

        // Discard any partially-consumed packet payload, then drain whole
        // packets up to the end-of-message marker. Truncating `buf` and
        // re-reading on packet boundaries resynchronises the token stream even
        // if a previous result stream was dropped part-way through a value
        // (the lost bytes belonged to a packet we are discarding anyway).
        self.buf.truncate(0);

        if self.flushed {
            return Ok(());
        }

        loop {
            match self.try_next().await {
                Ok(Some(packet)) => {
                    event!(
                        Level::WARN,
                        "Flushing unhandled packet from the wire. Please consume your streams!",
                    );

                    if packet.is_last() {
                        break;
                    }
                }
                Ok(None) => break,
                // The stream could not be drained cleanly (e.g. it was
                // abandoned at an unrecoverable offset). Poison the connection
                // so it is not silently reused in an inconsistent state.
                Err(e) => {
                    self.poisoned = true;
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// True if the underlying stream has no more data and is consumed
    /// completely.
    pub fn is_eof(&self) -> bool {
        self.flushed && self.buf.is_empty()
    }

    /// A message sent by the client to set up context for login. The server
    /// responds to a client PRELOGIN message with a message of packet header
    /// type 0x04 and with the packet data containing a PRELOGIN structure.
    ///
    /// This message stream is also used to wrap the TLS handshake payload if
    /// encryption is needed. In this scenario, where PRELOGIN message is
    /// transporting the TLS handshake payload, the packet data is simply the
    /// raw bytes of the TLS handshake payload.
    async fn prelogin(
        &mut self,
        encryption: EncryptionLevel,
        fed_auth_required: bool,
        instance_name: Option<String>,
    ) -> crate::Result<PreloginMessage> {
        let mut msg = PreloginMessage::new();
        msg.encryption = encryption;
        msg.fed_auth_required = fed_auth_required;
        msg.instance_name = instance_name.clone();

        let id = self.context.next_packet_id();
        self.send(PacketHeader::pre_login(id), msg).await?;

        let response: PreloginMessage = codec::collect_from(self).await?;
        // threadid (should be empty when sent from server to client)
        debug_assert_eq!(response.thread_id, 0);
        // ensure the server accepted the instance we asked it to validate
        response.validate_instance(instance_name.as_deref())?;
        Ok(response)
    }

    /// Defines the login record rules with SQL Server. Authentication with
    /// connection options.
    #[allow(clippy::too_many_arguments)]
    async fn login(
        mut self,
        auth: AuthMethod,
        encryption: EncryptionLevel,
        db: Option<String>,
        server_name: Option<String>,
        application_name: Option<String>,
        client_name: Option<String>,
        readonly: bool,
        packet_size: Option<u32>,
        prelogin: PreloginMessage,
    ) -> crate::Result<Self> {
        let mut login_message = LoginMessage::new();

        if let Some(db) = db {
            login_message.db_name(db);
        }

        if let Some(server_name) = server_name {
            login_message.server_name(server_name);
        }

        if let Some(app_name) = application_name {
            login_message.app_name(app_name);
        }

        if let Some(client_name) = client_name {
            login_message.hostname(client_name);
        }

        login_message.readonly(readonly);

        if let Some(size) = packet_size {
            login_message.packet_size(size);
        }

        match auth {
            #[cfg(all(windows, feature = "winauth"))]
            AuthMethod::Integrated => {
                let mut client = NtlmSspiBuilder::new()
                    .target_spn(self.context.spn())
                    .build()?;

                login_message.integrated_security(client.next_bytes(None)?);

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let sspi_bytes = self.flush_sspi().await?;

                match client.next_bytes(Some(sspi_bytes.as_ref()))? {
                    Some(sspi_response) => {
                        event!(Level::TRACE, sspi_response_len = sspi_response.len());

                        let id = self.context.next_packet_id();
                        let header = PacketHeader::sspi(id);

                        let token = TokenSspi::new(sspi_response);
                        self.send(header, token).await?;
                    }
                    None => {
                        return Err(crate::Error::Protocol(
                            "NTLM handshake produced no response to the server challenge".into(),
                        ))
                    }
                }
            }
            #[cfg(all(unix, feature = "integrated-auth-gssapi"))]
            AuthMethod::Integrated => {
                let mut s = OidSet::new();
                s.add(GSS_MECH_KRB5)?;

                let client_cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&s))?;

                let mut ctx = ClientCtx::new(
                    Some(client_cred),
                    Name::new(self.context.spn().as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))?,
                    CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
                    None,
                );

                let init_token = ctx.step(None, None)?.ok_or_else(|| {
                    crate::Error::Protocol("GSSAPI produced no initial token".into())
                })?;

                login_message.integrated_security(Some(Vec::from(init_token.deref())));

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let auth_bytes = self.flush_sspi().await?;

                let next_token = match ctx.step(Some(auth_bytes.as_ref()), None)? {
                    Some(response) => {
                        event!(Level::TRACE, response_len = response.len());
                        TokenSspi::new(Vec::from(response.deref()))
                    }
                    None => {
                        event!(Level::TRACE, response_len = 0);
                        TokenSspi::new(Vec::new())
                    }
                };

                let id = self.context.next_packet_id();
                let header = PacketHeader::login(id);

                self.send(header, next_token).await?;
            }
            #[cfg(all(unix, feature = "sspi-rs"))]
            AuthMethod::Windows(auth) => {
                let mut ntlm = Ntlm::new();

                let username =
                    Username::new(&auth.user, auth.domain.as_deref()).map_err(sspi::Error::from)?;

                // `auth.password` is a `SecretString`; sspi requires a
                // plaintext `String`, but that single copy is *moved* (not
                // cloned again) into `AuthIdentity.password`, which is
                // `sspi::Secret<String>` — a `#[derive(ZeroizeOnDrop)]` wrapper.
                // The plaintext is therefore wiped when `identity` (and the
                // credentials handle derived from it) is dropped; no
                // un-zeroized copy is left behind. Expose the secret once, for
                // this single `to_string()`, so no extra plaintext lingers
                // here (`auth.password` zeroizes when this arm's `auth`
                // drops).
                let identity = AuthIdentity {
                    username,
                    password: auth.password.expose_secret().to_string().into(),
                };

                let mut creds = ntlm
                    .acquire_credentials_handle()
                    .with_credential_use(CredentialUse::Outbound)
                    .with_auth_data(&identity)
                    .execute(&mut ntlm)?;

                let spn = self.context.spn().to_string();

                // First leg of the NTLM handshake: produce the NEGOTIATE token
                // and ship it in the login packet as integrated security data.
                let mut input = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
                let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

                let mut builder = ntlm
                    .initialize_security_context()
                    .with_credentials_handle(&mut creds.credentials_handle)
                    .with_context_requirements(
                        ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
                    )
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&spn)
                    .with_input(&mut input)
                    .with_output(&mut output);

                ntlm.initialize_security_context_impl(&mut builder)?
                    .resolve_to_result()?;

                login_message.integrated_security(Some(output[0].buffer.clone()));

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);

                // Second leg: consume the server's CHALLENGE token and reply
                // with the AUTHENTICATE token.
                let sspi_bytes = self.flush_sspi().await?;

                let mut input = vec![SecurityBuffer::new(
                    sspi_bytes.as_ref().to_vec(),
                    BufferType::Token,
                )];
                let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

                let mut builder = ntlm
                    .initialize_security_context()
                    .with_credentials_handle(&mut creds.credentials_handle)
                    .with_context_requirements(
                        ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
                    )
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&spn)
                    .with_input(&mut input)
                    .with_output(&mut output);

                ntlm.initialize_security_context_impl(&mut builder)?
                    .resolve_to_result()?;

                event!(Level::TRACE, authenticate_len = output[0].buffer.len());

                let id = self.context.next_packet_id();
                self.send(
                    PacketHeader::login(id),
                    TokenSspi::new(output[0].buffer.clone()),
                )
                .await?;
            }
            #[cfg(all(windows, feature = "winauth"))]
            AuthMethod::Windows(auth) => {
                let spn = self.context.spn().to_string();
                let builder = winauth::NtlmV2ClientBuilder::new().target_spn(spn);
                // `auth.password` is a `SecretString`, but `winauth`
                // 0.0.5's `build` takes the password by value as a plain
                // `String` and neither zeroizes it nor exposes it afterwards, so
                // it cannot be wiped once handed over. Expose it once for a
                // single `to_string()` copy (no additional retained plaintext
                // here) and accept a residual: the plaintext lives inside
                // the `NtlmV2Client` until that value is dropped, un-zeroized.
                // Closing this fully requires zeroize support upstream in
                // `winauth`.
                let mut client = builder.build(
                    auth.domain,
                    auth.user,
                    auth.password.expose_secret().to_string(),
                );

                login_message.integrated_security(client.next_bytes(None)?);

                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;

                self = self.post_login_encryption(encryption);

                let sspi_bytes = self.flush_sspi().await?;

                match client.next_bytes(Some(sspi_bytes.as_ref()))? {
                    Some(sspi_response) => {
                        event!(Level::TRACE, sspi_response_len = sspi_response.len());

                        let id = self.context.next_packet_id();
                        let header = PacketHeader::login(id);

                        let token = TokenSspi::new(sspi_response);
                        self.send(header, token).await?;
                    }
                    None => {
                        return Err(crate::Error::Protocol(
                            "NTLM handshake produced no response to the server challenge".into(),
                        ))
                    }
                }
            }
            AuthMethod::None => {
                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
                self = self.post_login_encryption(encryption);
            }
            AuthMethod::SqlServer(auth) => {
                let (user, mut password) = auth.into_credentials();

                login_message.user_name(user);
                // Expose the password only to hand it to the login message,
                // which stores its own `SecretString` copy.
                login_message.password(password.expose_secret());
                let payload = login_message.encode_to_boxed_slice()?;
                // Wipe the local copy immediately; `login_message` was consumed by
                // `encode_to_boxed_slice` and its `SecretString` password was
                // zeroized on drop there.
                password.zeroize();

                let id = self.context.next_packet_id();
                self.send_sensitive_login(PacketHeader::login(id), payload)
                    .await?;
                self = self.post_login_encryption(encryption);
            }
            AuthMethod::AADToken(token) => {
                // Expose the token only to hand it to the login message; the
                // `SecretString` here is wiped on drop at the end of this arm,
                // and the login message stores its own `SecretString` copy.
                login_message.aad_token(
                    token.expose_secret(),
                    prelogin.fed_auth_required,
                    prelogin.nonce,
                );
                // Encode into a zeroizing buffer and use the sensitive-login
                // path so the bearer token does not linger in freed heap memory.
                let payload = login_message.encode_to_boxed_slice()?;
                let id = self.context.next_packet_id();
                self.send_sensitive_login(PacketHeader::login(id), payload)
                    .await?;
                self = self.post_login_encryption(encryption);
            }
        }

        Ok(self)
    }

    /// Implements the TLS handshake with the SQL Server.
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    async fn tls_handshake(
        self,
        config: &Config,
        encryption: EncryptionLevel,
    ) -> crate::Result<Self> {
        match encryption {
            EncryptionLevel::NotSupported => {
                event!(
                    Level::WARN,
                    "TLS encryption is not enabled. All traffic including the login credentials are not encrypted."
                );

                Ok(self)
            }
            // In strict mode the handshake already happened before the prelogin,
            // so the transport is already a TLS stream. Nothing to do here.
            EncryptionLevel::Strict => {
                event!(
                    Level::TRACE,
                    "Already in a TLS stream (TDS 8.0 strict), skipping handshake."
                );

                Ok(self)
            }
            EncryptionLevel::Off | EncryptionLevel::On | EncryptionLevel::Required => {
                event!(Level::DEBUG, "Performing a TLS handshake");

                let Self {
                    transport,
                    context,
                    command_desync,
                    ..
                } = self;
                let mut stream = match transport.into_inner() {
                    MaybeTlsStream::Raw(tcp) => {
                        create_tls_stream(config, TlsPreloginWrapper::new(tcp)).await?
                    }
                    _ => unreachable!(),
                };

                stream.get_mut().handshake_complete();
                event!(Level::DEBUG, "TLS handshake successful");

                let transport = Framed::new(MaybeTlsStream::Tls(stream), PacketCodec);

                Ok(Self {
                    transport,
                    context,
                    flushed: false,
                    buf: BytesMut::new(),
                    poisoned: false,
                    command_desync,
                })
            }
        }
    }

    /// Implements the TLS handshake with the SQL Server.
    #[cfg(not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )))]
    async fn tls_handshake(self, config: &Config, _: EncryptionLevel) -> crate::Result<Self> {
        check_tls_backend_available(config.encryption)?;

        event!(
            Level::WARN,
            "TLS encryption is not enabled. All traffic including the login credentials are not encrypted."
        );

        Ok(self)
    }

    pub(crate) async fn close(mut self) -> crate::Result<()> {
        self.transport.close().await
    }
}

#[cfg(test)]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Connection<S> {
    /// Builds a `Connection` over a caller-supplied mock `AsyncRead + AsyncWrite`
    /// stream for server-free unit tests, bypassing the prelogin/login handshake.
    ///
    /// The buffer starts empty and `flushed` starts `false`, so the first read
    /// pulls a packet from the mock transport; a default [`Context`] is used and
    /// the `poisoned` flag is caller-controlled. This mirrors the real field
    /// initialization in [`Connection::connect`] and is `#[cfg(test)]` only, so
    /// it never ships. Shared by the poison-guard tests and the `TokenStream`
    /// state-machine tests, which feed it canned TDS-framed bytes.
    pub(crate) fn test_over(io: S, poisoned: bool) -> Connection<S> {
        Connection {
            transport: Framed::new(MaybeTlsStream::Raw(io), PacketCodec),
            flushed: false,
            context: Context::new(),
            buf: BytesMut::new(),
            poisoned,
            command_desync: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Returns an error when the user requested encryption but no TLS backend was
/// compiled in. Without this check, a `Required`/`On` encryption request would
/// silently fall back to an unencrypted connection.
#[cfg(not(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
)))]
fn check_tls_backend_available(encryption: EncryptionLevel) -> crate::Result<()> {
    if let EncryptionLevel::On | EncryptionLevel::Required | EncryptionLevel::Strict = encryption {
        return Err(crate::Error::Tls(
            "TLS encryption was requested but the crate was compiled without a TLS backend. \
             Enable one of the `native-tls`, `rustls` or `vendored-openssl` features."
                .to_string(),
        ));
    }

    Ok(())
}

/// Runs `fut` to completion, but fails with a clear [`crate::Error::Io`] of
/// kind [`io::ErrorKind::TimedOut`] if it does not finish within `timeout`.
///
/// A `None` timeout runs the future unbounded (the pre-0.13 behaviour). The
/// timer comes from `futures-timer`, whose `Delay` is runtime-agnostic, so this
/// works under any executor driving the generic [`Connection::connect`] path —
/// it does not assume tokio or smol. Used to bound the connection handshake so
/// a server that accepts the TCP connection and then stalls yields
/// a diagnosable error instead of an indefinite hang.
async fn with_optional_timeout<F, T>(
    timeout: Option<std::time::Duration>,
    fut: F,
) -> crate::Result<T>
where
    F: std::future::Future<Output = crate::Result<T>>,
{
    match timeout {
        None => fut.await,
        Some(timeout) => {
            // `pin!` makes the future `Unpin` so `select` can take it by value;
            // `Delay` is already `Unpin`. Whichever finishes first wins the
            // race and the loser is dropped.
            let fut = std::pin::pin!(fut);
            match futures_util::future::select(fut, futures_timer::Delay::new(timeout)).await {
                futures_util::future::Either::Left((res, _)) => res,
                futures_util::future::Either::Right(((), _)) => Err(crate::Error::Io {
                    kind: io::ErrorKind::TimedOut,
                    message: format!(
                        "the connection handshake (prelogin, TLS negotiation and login) did not \
                         complete within {timeout:?}; the server accepted the TCP connection but \
                         did not finish the handshake in time (it may have stalled, or be \
                         responding too slowly for the configured bound). Enable `tracing` at \
                         DEBUG to see which stage was last reached, or change the bound with \
                         `Config::handshake_timeout`."
                    ),
                }),
            }
        }
    }
}

/// Frame a login message into one or more login packets, each no larger than
/// `packet_size` payload bytes, ready to write to the wire.
///
/// This is the packetization core of [`Connection::send_sensitive_login`],
/// factored out so it can be unit-tested without a live server. Every packet is
/// an 8-byte header (see [`PacketHeader::encode`]) followed by up to
/// `packet_size` payload bytes, with the big-endian total length written into
/// header bytes `[2..4]` — matching [`Packet::encode`]. All but the final packet
/// carry `NormalMessage`; the final one carries `EndOfMessage`.
///
/// The returned frames are `Zeroizing` so the sensitive login bytes they contain
/// are wiped on drop, keeping them off the shared (non-zeroizing) `BytesMut`
/// path used by the ordinary `send`.
fn frame_sensitive_login(
    mut header: PacketHeader,
    payload: &[u8],
    packet_size: usize,
) -> crate::Result<Vec<Zeroizing<Box<[u8]>>>> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let end = cmp::min(payload.len(), offset + packet_size);

        if end == payload.len() {
            header.set_status(PacketStatus::EndOfMessage);
        } else {
            header.set_status(PacketStatus::NormalMessage);
        }

        // Build the frame at its exact final capacity. `header.encode` is the
        // only fallible (`?`) operation, and it runs BEFORE the sensitive
        // payload bytes are copied in, so the secret never lives in this plain
        // `Vec` across a `?`/`.await`. Once the header (`HEADER_BYTES`) and the
        // chunk (`end - offset`) are written, `len == capacity`, so
        // `into_boxed_slice()` cannot shrink-reallocate and leak an un-zeroized
        // copy. Boxing into `Zeroizing` at push means each finished frame is
        // wiped on drop and can no longer be grown.
        let mut frame = Vec::with_capacity(HEADER_BYTES + end - offset);
        header.encode(&mut frame)?;
        frame.extend_from_slice(&payload[offset..end]);

        let size = (frame.len() as u16).to_be_bytes();
        frame[2] = size[0];
        frame[3] = size[1];

        debug_assert_eq!(
            frame.len(),
            frame.capacity(),
            "login frame buffer would shrink-reallocate when boxed, leaking a copy"
        );
        frames.push(Zeroizing::new(frame.into_boxed_slice()));
        offset = end;
    }

    Ok(frames)
}

#[cfg(test)]
mod sensitive_login_tests {
    use super::frame_sensitive_login;
    use crate::tds::codec::{Decode, Packet, PacketHeader, PacketStatus};
    use crate::tds::HEADER_BYTES;
    use bytes::BytesMut;

    // An oversized login payload must be split into >=2 packets, each framed
    // exactly like `Packet::encode`: an 8-byte header whose `[2..4]` bytes hold
    // the big-endian total length, contiguous payload chunks covering the whole
    // input, `NormalMessage` on every packet but the last and `EndOfMessage` on
    // the final one.
    #[test]
    fn oversized_login_is_split_into_multiple_framed_packets() {
        let packet_size = 16; // payload bytes per packet (excludes the 8-byte header)
        let payload: Vec<u8> = (0..50u16).map(|i| i as u8).collect(); // 50 bytes -> ceil(50/16)=4
        let header = PacketHeader::login(3);

        let frames = frame_sensitive_login(header, &payload, packet_size).unwrap();

        assert!(
            frames.len() >= 2,
            "expected the oversized login to split into >=2 packets, got {}",
            frames.len()
        );
        assert_eq!(
            frames.len(),
            4,
            "50 bytes / 16 per packet should be 4 packets"
        );

        let mut reassembled = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            let is_last = i == frames.len() - 1;

            // Decode the header back off the wire bytes and check framing.
            let mut buf = BytesMut::from(&frame[..]);
            let decoded = PacketHeader::decode(&mut buf).unwrap();

            // Length field ([2..4], big-endian) must equal the whole frame length.
            assert_eq!(
                decoded.length() as usize,
                frame.len(),
                "packet {i} length field must match the framed size"
            );
            // And the raw bytes must match `Packet::encode`'s placement exactly.
            let expected_len = (frame.len() as u16).to_be_bytes();
            assert_eq!([frame[2], frame[3]], expected_len);

            // Payload chunk size: every packet but the last is full.
            let payload_len = frame.len() - HEADER_BYTES;
            if is_last {
                assert_eq!(decoded.status(), PacketStatus::EndOfMessage);
                assert!(payload_len <= packet_size && payload_len > 0);
            } else {
                assert_eq!(decoded.status(), PacketStatus::NormalMessage);
                assert_eq!(payload_len, packet_size);
            }

            reassembled.extend_from_slice(&frame[HEADER_BYTES..]);
        }

        // The concatenated payloads must reconstruct the original login bytes.
        assert_eq!(reassembled, payload);
    }

    // The frames are now `Box<[u8]>` built at exact capacity (len==capacity
    // before `into_boxed_slice`, guarded by a debug_assert in the builder). The
    // total bytes across all frames must therefore be exactly one header per
    // frame plus the whole payload — no slack from over-reserved/realloc'd
    // buffers — which this test enforces.
    #[test]
    fn framed_login_has_no_slack_bytes() {
        let packet_size = 16;
        let payload: Vec<u8> = (0..50u16).map(|i| i as u8).collect();
        let header = PacketHeader::login(5);

        let frames = frame_sensitive_login(header, &payload, packet_size).unwrap();

        let total: usize = frames.iter().map(|f| f.len()).sum();
        assert_eq!(
            total,
            frames.len() * HEADER_BYTES + payload.len(),
            "framed bytes must equal one header per frame plus the exact payload"
        );
    }

    // A cross-check that a single frame produced by `frame_sensitive_login`
    // matches byte-for-byte what `Packet::encode` produces for the same
    // header + payload, when it fits in one packet.
    #[test]
    fn single_packet_frame_matches_packet_encode() {
        use crate::tds::codec::Encode;

        let payload = vec![0xABu8; 10];
        let header = PacketHeader::login(7);

        let frames = frame_sensitive_login(header, &payload, 100).unwrap();
        assert_eq!(frames.len(), 1);

        let mut expected = BytesMut::new();
        let mut eom_header = header;
        eom_header.set_status(PacketStatus::EndOfMessage);
        Packet::new(eom_header, BytesMut::from(&payload[..]))
            .encode(&mut expected)
            .unwrap();

        assert_eq!(&frames[0][..], &expected[..]);
    }
}

#[cfg(all(
    test,
    not(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))
))]
mod tests {
    use super::check_tls_backend_available;
    use crate::EncryptionLevel;

    #[test]
    fn requested_encryption_without_tls_backend_errors() {
        assert!(check_tls_backend_available(EncryptionLevel::Required).is_err());
        assert!(check_tls_backend_available(EncryptionLevel::On).is_err());
    }

    #[test]
    fn no_encryption_without_tls_backend_is_ok() {
        assert!(check_tls_backend_available(EncryptionLevel::Off).is_ok());
        assert!(check_tls_backend_available(EncryptionLevel::NotSupported).is_ok());
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Stream for Connection<S> {
    type Item = crate::Result<Packet>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match ready!(this.transport.try_poll_next_unpin(cx)) {
            Some(Ok(packet)) => {
                this.flushed = packet.is_last();
                Poll::Ready(Some(Ok(packet)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> futures_util::io::AsyncRead for Connection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.get_mut();
        let size = buf.len();

        if this.buf.len() < size {
            while let Some(item) = ready!(Pin::new(&mut this).try_poll_next(cx)) {
                match item {
                    Ok(packet) => {
                        let (_, payload) = packet.into_parts();
                        this.buf.extend(payload);

                        if this.buf.len() >= size {
                            break;
                        }
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            e.to_string(),
                        )))
                    }
                }
            }

            // Got EOF before having all the data.
            if this.buf.len() < size {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "No more packets in the wire",
                )));
            }
        }

        buf.copy_from_slice(this.buf.split_to(size).as_ref());
        Poll::Ready(Ok(size))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SqlReadBytes for Connection<S> {
    /// Hex dump of the current buffer.
    fn debug_buffer(&self) {
        dbg!(self.buf.as_ref().hex_dump());
    }

    /// The current execution context.
    fn context(&self) -> &Context {
        &self.context
    }

    /// A mutable reference to the current execution context.
    fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}

// Server-free tests for the poisoned-connection guard shared by every write
// path, including the Attention/cancel path (see `cancel_request`). These build
// a `Connection` over an in-memory stream that is never actually driven: the
// guard must reject before any I/O happens.
#[cfg(test)]
mod poison_tests {
    use super::*;
    use crate::tds::codec::{BulkLoadRequest, TokenRow};
    use std::pin::Pin;

    /// A stream that swallows writes and reports clean EOF on read. If the
    /// poisoned guard is ever bypassed, `cancel_request` would reach here and
    /// fail with an EOF/IO error instead of the poison `Protocol` error, which
    /// is exactly what the assertions below distinguish.
    struct NullIo;

    impl AsyncRead for NullIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    impl AsyncWrite for NullIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
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

    /// A stream whose writes always fail, simulating a wire error / interrupted
    /// write. Reads report clean EOF.
    struct FailingIo;

    impl AsyncRead for FailingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    impl AsyncWrite for FailingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("wire down")))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("wire down")))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn connection_over<S>(io: S, poisoned: bool) -> Connection<S>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        Connection::test_over(io, poisoned)
    }

    fn poisoned_connection() -> Connection<NullIo> {
        connection_over(NullIo, true)
    }

    fn is_poison_error(err: &crate::Error) -> bool {
        matches!(err, crate::Error::Protocol(msg) if msg.contains("inconsistent state"))
    }

    #[test]
    fn ensure_not_poisoned_reports_poison() {
        let conn = poisoned_connection();
        assert!(is_poison_error(&conn.ensure_not_poisoned().unwrap_err()));
    }

    #[test]
    fn ensure_not_poisoned_ok_when_clean() {
        let mut conn = poisoned_connection();
        conn.poisoned = false;
        assert!(conn.ensure_not_poisoned().is_ok());
    }

    #[tokio::test]
    async fn cancel_request_rejects_poisoned_connection() {
        let mut conn = poisoned_connection();
        let err = conn
            .cancel_request()
            .await
            .expect_err("cancel on a poisoned connection must fail");
        // Must be the poison guard specifically, not an incidental IO/EOF error
        // from reaching the wire — that is what proves the guard is in effect.
        assert!(
            is_poison_error(&err),
            "expected poison Protocol error, got: {err:?}"
        );
        // The guard rejected before touching the wire, so the flag is untouched.
        assert!(conn.poisoned);
    }

    // --- Bulk-load write path (`BulkLoadRequest`) ---------------------------
    // The bulk path writes multi-packet messages via `write_to_wire` directly,
    // so it must get the same poison guarantee as `send`. Empty columns + empty
    // rows keep these server-free: each `send` appends a single Row-token byte
    // to the buffer and a tiny `packet_size` forces the write loop to fire.

    #[tokio::test]
    async fn bulk_send_rejects_poisoned_connection() {
        let mut conn = poisoned_connection();
        let mut bulk = BulkLoadRequest::new(&mut conn, Vec::new()).unwrap();
        let err = bulk
            .send(TokenRow::new())
            .await
            .expect_err("a bulk send on a poisoned connection must fail");
        // Must be the poison guard specifically — not an incidental IO error
        // from reaching the (swallowing) wire — which proves the guard is in
        // effect before any bytes are buffered or written.
        assert!(is_poison_error(&err), "expected poison error, got: {err:?}");
    }

    #[tokio::test]
    async fn bulk_write_clears_poison_on_success() {
        let mut conn = connection_over(NullIo, false);
        // One usable payload byte per packet so buffered Row-token bytes spill
        // into the multi-packet write loop.
        conn.context.set_packet_size(HEADER_BYTES as u32 + 1);

        {
            let mut bulk = BulkLoadRequest::new(&mut conn, Vec::new()).unwrap();
            for _ in 0..8 {
                bulk.send(TokenRow::new())
                    .await
                    .expect("bulk send over a clean wire must succeed");
            }
        }

        // After the bulk writes complete cleanly the connection must be usable.
        assert!(!conn.poisoned);
        assert!(conn.ensure_not_poisoned().is_ok());
    }

    #[tokio::test]
    async fn bulk_write_failure_leaves_connection_poisoned() {
        let mut conn = connection_over(FailingIo, false);
        conn.context.set_packet_size(HEADER_BYTES as u32 + 1);

        {
            let mut bulk = BulkLoadRequest::new(&mut conn, Vec::new()).unwrap();
            let mut result = Ok(());
            for _ in 0..8 {
                result = bulk.send(TokenRow::new()).await;
                if result.is_err() {
                    break;
                }
            }
            assert!(
                result.is_err(),
                "a failing wire must surface an error from the bulk write"
            );
        }

        // The interrupted write must leave the connection poisoned so the next
        // op fails cleanly instead of appending onto a half-sent message.
        assert!(
            conn.poisoned,
            "a failed bulk write must poison the connection"
        );
        assert!(is_poison_error(&conn.ensure_not_poisoned().unwrap_err()));
    }
}

// Server-free tests for the handshake timeout helper (`with_optional_timeout`)
// and its wiring into `Connection::connect`. A future that never completes must
// surface a `TimedOut` error rather than hang, a `None` bound must run
// unbounded, and inner results (both `Ok` and `Err`) must pass through
// untouched when the future wins the race.
#[cfg(test)]
mod timeout_tests {
    use super::*;
    use std::future;
    use std::pin::Pin;
    use std::time::{Duration, Instant};

    fn is_timed_out(err: &crate::Error) -> bool {
        matches!(
            err,
            crate::Error::Io {
                kind: io::ErrorKind::TimedOut,
                ..
            }
        )
    }

    #[tokio::test]
    async fn none_timeout_runs_unbounded_and_returns_inner_ok() {
        let out: crate::Result<u8> =
            with_optional_timeout(None, async { Ok::<_, crate::Error>(7u8) }).await;
        assert_eq!(out.unwrap(), 7);
    }

    #[tokio::test]
    async fn future_completing_before_bound_returns_its_ok() {
        let out: crate::Result<&str> =
            with_optional_timeout(Some(Duration::from_secs(30)), async {
                Ok::<_, crate::Error>("done")
            })
            .await;
        assert_eq!(out.unwrap(), "done");
    }

    #[tokio::test]
    async fn future_completing_before_bound_propagates_its_err() {
        // A fast inner error must be surfaced as-is, not masked as a timeout.
        let out: crate::Result<()> = with_optional_timeout(Some(Duration::from_secs(30)), async {
            Err::<(), _>(crate::Error::Protocol("boom".into()))
        })
        .await;
        let err = out.unwrap_err();
        assert!(
            !is_timed_out(&err),
            "fast inner error must not be a timeout"
        );
        assert!(matches!(err, crate::Error::Protocol(msg) if msg == "boom"));
    }

    #[tokio::test]
    async fn stalled_future_times_out_with_diagnosable_error() {
        let started = Instant::now();
        // A future that never resolves models a server that accepts the TCP
        // connection and then stops responding mid-handshake.
        let never = future::pending::<crate::Result<()>>();
        let out = with_optional_timeout(Some(Duration::from_millis(50)), never).await;

        let err = out.expect_err("a stalled handshake must not hang; it must error");
        assert!(
            is_timed_out(&err),
            "expected a TimedOut error, got: {err:?}"
        );

        let msg = err.to_string();
        assert!(
            msg.contains("did not complete") && msg.contains("handshake"),
            "timeout error should explain the stalled handshake, got: {msg}"
        );
        // The bound is honoured: returns promptly rather than blocking.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timeout should fire promptly, took {:?}",
            started.elapsed()
        );
    }

    // A stream that accepts (swallows) every write but never yields any bytes on
    // read, modelling a server that completes the TCP connection and then goes
    // silent during the prelogin/TLS handshake.
    struct SilentServer;

    impl AsyncRead for SilentServer {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            // Never ready: the read half hangs forever. The handshake timeout,
            // not this stream, is what must unblock the connect future.
            Poll::Pending
        }
    }

    impl AsyncWrite for SilentServer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
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

    #[tokio::test]
    async fn connect_times_out_when_server_stalls_after_tcp() {
        // Full `Connection::connect` wiring: the prelogin is written (swallowed)
        // and then the response read hangs. With a short handshake timeout the
        // connect must return a TimedOut error instead of blocking forever.
        let mut config = Config::new();
        config.host("stalled.example");
        config.handshake_timeout(Some(Duration::from_millis(100)));

        let started = Instant::now();
        let err = Connection::connect(config, SilentServer)
            .await
            .expect_err("a server that stalls after TCP connect must not hang connect");

        assert!(
            is_timed_out(&err),
            "expected a TimedOut error, got: {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "connect should give up promptly, took {:?}",
            started.elapsed()
        );
    }

    // The same stalled-peer
    // scenario, pinned to `EncryptionLevel::NotSupported` so the prelogin read
    // (not a TLS handshake) is what stalls, and a companion test proving that
    // with the bound disabled the connect keeps waiting.
    #[tokio::test]
    async fn connect_honors_handshake_timeout_without_tls() {
        let mut config = Config::new();
        config.host("stalled.example");
        config.encryption(EncryptionLevel::NotSupported);
        config.handshake_timeout(Some(Duration::from_millis(50)));

        let started = Instant::now();
        let err = Connection::connect(config, SilentServer)
            .await
            .expect_err("a stalled handshake must fail rather than hang");

        assert!(is_timed_out(&err), "expected TimedOut, got: {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "connect must fail promptly under the configured timeout"
        );
    }

    #[tokio::test]
    async fn connect_without_handshake_timeout_does_not_time_out() {
        // With the bound disabled the connect future keeps waiting on the
        // stalled read; the outer guard elapsing proves no internal timeout
        // fired.
        let mut config = Config::new();
        config.host("stalled.example");
        config.encryption(EncryptionLevel::NotSupported);
        config.handshake_timeout(None);
        assert_eq!(config.get_handshake_timeout(), None);

        let outcome = tokio::time::timeout(
            Duration::from_millis(100),
            Connection::connect(config, SilentServer),
        )
        .await;
        assert!(
            outcome.is_err(),
            "connect without a handshake timeout should keep waiting on the stalled stream"
        );
    }

    // Serves a canned prelogin response once, then parks every subsequent read
    // forever — a server that completes the prelogin exchange and then stalls
    // while the client waits for the login acknowledgement.
    struct AnswerPreloginThenSilent {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for AnswerPreloginThenSilent {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.pos >= self.data.len() {
                return Poll::Pending;
            }
            let remaining = &self.data[self.pos..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for AnswerPreloginThenSilent {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
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

    // Frame a payload as a single final (EndOfMessage) prelogin packet.
    fn final_prelogin_packet() -> Vec<u8> {
        let mut payload = BytesMut::new();
        PreloginMessage::new()
            .encode(&mut payload)
            .expect("prelogin encode");
        let packet = Packet::new(PacketHeader::pre_login(1), payload);
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).expect("packet encode");
        buf.to_vec()
    }

    #[tokio::test]
    async fn command_timeout_does_not_bound_the_connect_handshake() {
        // `command_timeout` must NOT bound the
        // login-ack drain that runs through the token stream during connect. The
        // whole handshake is governed by `handshake_timeout` alone, so with
        // `handshake_timeout(None)` a server that answers prelogin and then
        // stalls at the login acknowledgement must be waited on indefinitely,
        // even though a short `command_timeout` is configured. Before the fix
        // the 50ms command timeout fired during `flush_done`, so connect would
        // (wrongly) return within the 300ms guard.
        let mut config = Config::new();
        config.host("stalled.example");
        config.encryption(EncryptionLevel::NotSupported);
        config.handshake_timeout(None);
        config.command_timeout(Some(Duration::from_millis(50)));

        let server = AnswerPreloginThenSilent {
            data: final_prelogin_packet(),
            pos: 0,
        };

        let outcome = tokio::time::timeout(
            Duration::from_millis(300),
            Connection::connect(config, server),
        )
        .await;
        assert!(
            outcome.is_err(),
            "command_timeout must not cut off the connect handshake; connect returned {outcome:?}"
        );
    }
}
