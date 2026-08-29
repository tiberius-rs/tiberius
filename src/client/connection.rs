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
#[cfg(any(windows, feature = "integrated-auth-gssapi"))]
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
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
use std::ops::Deref;
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
    /// Creates a new connection
    pub(crate) async fn connect(config: Config, tcp_stream: S) -> crate::Result<Connection<S>> {
        let context = {
            let mut context = Context::new();
            context.set_spn(config.get_host(), config.get_port());
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
        };

        let fed_auth_required = matches!(config.auth, AuthMethod::AADToken(_));

        let prelogin = connection
            .prelogin(
                config.encryption,
                fed_auth_required,
                config.instance_name.clone(),
            )
            .await?;

        let encryption = prelogin.negotiated_encryption(config.encryption)?;

        let connection = connection.tls_handshake(&config, encryption).await?;

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

        Ok(connection)
    }

    /// Flush the incoming token stream until receiving `DONE` token.
    async fn flush_done(&mut self) -> crate::Result<TokenDone> {
        TokenStream::new(self).flush_done().await
    }

    #[cfg(any(windows, feature = "integrated-auth-gssapi"))]
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
        self.flushed = false;
        let packet_size = (self.context.packet_size() as usize) - HEADER_BYTES;

        let mut payload = BytesMut::new();
        item.encode(&mut payload)?;

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

        Ok(())
    }

    async fn send_sensitive_login(
        &mut self,
        header: PacketHeader,
        mut payload: Zeroizing<Vec<u8>>,
    ) -> crate::Result<()> {
        self.flushed = false;
        let packet_size = (self.context.packet_size() as usize) - HEADER_BYTES;

        // Frame the login into zeroizable packets off the shared `BytesMut`
        // path, then write each and wipe it immediately. Both the frames and the
        // source `payload` are `Zeroizing`, so any sensitive bytes are cleared.
        let frames = frame_sensitive_login(header, &payload, packet_size)?;
        payload.zeroize();

        for mut frame in frames {
            event!(Level::TRACE, "Sending a packet ({} bytes)", frame.len(),);

            self.transport.write_all(frame.as_slice()).await?;
            frame.zeroize();
        }

        self.transport.flush().await?;

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

    /// Cleans the packet stream from previous use. It is important to use the
    /// whole stream before using the connection again. Flushing the stream
    /// makes sure we don't have any old data causing undefined behaviour after
    /// previous queries.
    ///
    /// Calling this will slow down the queries if stream is still dirty if all
    /// results are not handled.
    pub async fn flush_stream(&mut self) -> crate::Result<()> {
        self.buf.truncate(0);

        if self.flushed {
            return Ok(());
        }

        while let Some(packet) = self.try_next().await? {
            event!(
                Level::WARN,
                "Flushing unhandled packet from the wire. Please consume your streams!",
            );

            let is_last = packet.is_last();

            if is_last {
                break;
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
                    None => unreachable!(),
                }
            }
            #[cfg(all(unix, feature = "integrated-auth-gssapi"))]
            AuthMethod::Integrated => {
                let mut s = OidSet::new()?;
                s.add(&GSS_MECH_KRB5)?;

                let client_cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&s))?;

                let mut ctx = ClientCtx::new(
                    Some(client_cred),
                    Name::new(self.context.spn().as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?,
                    CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
                    None,
                );

                let init_token = ctx.step(None, None)?;

                login_message.integrated_security(Some(Vec::from(init_token.unwrap().deref())));

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
            #[cfg(all(windows, feature = "winauth"))]
            AuthMethod::Windows(auth) => {
                let spn = self.context.spn().to_string();
                let builder = winauth::NtlmV2ClientBuilder::new().target_spn(spn);
                let mut client = builder.build(auth.domain, auth.user, auth.password);

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
                    None => unreachable!(),
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
                login_message.password(password.as_str());
                let payload = login_message.encode_to_vec()?;
                password.zeroize();

                let id = self.context.next_packet_id();
                self.send_sensitive_login(PacketHeader::login(id), payload)
                    .await?;
                self = self.post_login_encryption(encryption);
            }
            AuthMethod::AADToken(token) => {
                login_message.aad_token(token, prelogin.fed_auth_required, prelogin.nonce);
                let id = self.context.next_packet_id();
                self.send(PacketHeader::login(id), login_message).await?;
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
                    transport, context, ..
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
) -> crate::Result<Vec<Zeroizing<Vec<u8>>>> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let end = cmp::min(payload.len(), offset + packet_size);

        if end == payload.len() {
            header.set_status(PacketStatus::EndOfMessage);
        } else {
            header.set_status(PacketStatus::NormalMessage);
        }

        let mut frame = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + end - offset));
        header.encode(&mut *frame)?;
        frame.extend_from_slice(&payload[offset..end]);

        let size = (frame.len() as u16).to_be_bytes();
        frame[2] = size[0];
        frame[3] = size[1];

        frames.push(frame);
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
