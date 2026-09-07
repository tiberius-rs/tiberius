#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use super::tls_stream::TlsStream;
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use crate::tds::{
    codec::{Decode, Encode, PacketHeader, PacketStatus, PacketType},
    HEADER_BYTES,
};
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use bytes::BytesMut;
use futures_util::io::{AsyncRead, AsyncWrite};
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use futures_util::ready;
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use std::cmp;
use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use tracing::{event, Level};

/// A wrapper to handle either TLS or bare connections.
pub(crate) enum MaybeTlsStream<S: AsyncRead + AsyncWrite + Unpin + Send> {
    Raw(S),
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    Tls(TlsStream<TlsPreloginWrapper<S>>),
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> MaybeTlsStream<S> {
    pub fn into_inner(self) -> S {
        match self {
            Self::Raw(s) => s,
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            Self::Tls(mut tls) => tls.get_mut().stream.take().unwrap(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for MaybeTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for MaybeTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_flush(cx),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_close(cx),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_close(cx),
        }
    }
}

/// On TLS handshake, the server expects to get and sends back normal TDS
/// packets. To use a common TLS library, we must implement a wrapper for
/// packet handling on this stage.
///
/// What it does is it interferes on handshake for TDS packet handling,
/// and when complete, just passes the calls to the underlying connection.
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
pub(crate) struct TlsPreloginWrapper<S> {
    stream: Option<S>,
    pending_handshake: bool,

    header_buf: [u8; HEADER_BYTES],
    header_pos: usize,
    read_remaining: usize,

    wr_buf: Vec<u8>,
    header_written: bool,
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S> TlsPreloginWrapper<S> {
    pub fn new(stream: S) -> Self {
        TlsPreloginWrapper {
            stream: Some(stream),
            pending_handshake: true,

            header_buf: [0u8; HEADER_BYTES],
            header_pos: 0,
            read_remaining: 0,
            wr_buf: vec![0u8; HEADER_BYTES],
            header_written: false,
        }
    }

    pub fn handshake_complete(&mut self) {
        self.pending_handshake = false;
    }
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for TlsPreloginWrapper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Normal operation does not need any extra treatment, we handle packets
        // in the codec.
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_read(cx, buf);
        }

        let inner = self.get_mut();

        // Read the headers separately and do not send them to the Tls
        // connection handling.
        if !inner.header_buf[inner.header_pos..].is_empty() {
            while !inner.header_buf[inner.header_pos..].is_empty() {
                let read = ready!(Pin::new(inner.stream.as_mut().unwrap())
                    .poll_read(cx, &mut inner.header_buf[inner.header_pos..]))?;

                if read == 0 {
                    return Poll::Ready(Ok(0));
                }

                inner.header_pos += read;
            }

            let header = PacketHeader::decode(&mut BytesMut::from(&inner.header_buf[..]))
                .map_err(io::Error::other)?;

            // We only get pre-login packets in the handshake process. This runs
            // before any certificate has been validated, so the bytes are fully
            // untrusted: reject anything unexpected instead of panicking.
            if header.r#type() != PacketType::PreLogin {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected a pre-login packet during the TLS handshake",
                )));
            }

            // And we know from this point on how much data we should expect.
            inner.read_remaining = (header.length() as usize)
                .checked_sub(HEADER_BYTES)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pre-login packet length shorter than its header",
                    )
                })?;

            event!(
                Level::TRACE,
                "Reading packet of {} bytes",
                inner.read_remaining,
            );
        }

        let max_read = cmp::min(inner.read_remaining, buf.len());

        // TLS connector gets whatever we have after the header.
        let read = ready!(
            Pin::new(&mut inner.stream.as_mut().unwrap()).poll_read(cx, &mut buf[..max_read])
        )?;

        inner.read_remaining -= read;

        // All data is read, after this we're expecting a new header.
        if inner.read_remaining == 0 {
            inner.header_pos = 0;
        }

        Poll::Ready(Ok(read))
    }
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for TlsPreloginWrapper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Normal operation does not need any extra treatment, we handle
        // packets in the codec.
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_write(cx, buf);
        }

        // Buffering data.
        self.wr_buf.extend_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.get_mut();

        // If on handshake mode, wraps the data to a TDS packet before sending.
        if inner.pending_handshake && inner.wr_buf.len() > HEADER_BYTES {
            if !inner.header_written {
                let mut header = PacketHeader::new(inner.wr_buf.len(), 0);

                header.set_type(PacketType::PreLogin);
                header.set_status(PacketStatus::EndOfMessage);

                header
                    .encode(&mut &mut inner.wr_buf[0..HEADER_BYTES])
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Could not encode header.")
                    })?;

                inner.header_written = true;
            }

            while !inner.wr_buf.is_empty() {
                event!(
                    Level::TRACE,
                    "Writing a packet of {} bytes",
                    inner.wr_buf.len(),
                );

                let written = ready!(
                    Pin::new(&mut inner.stream.as_mut().unwrap()).poll_write(cx, &inner.wr_buf)
                )?;

                inner.wr_buf.drain(..written);
            }

            inner.wr_buf.resize(HEADER_BYTES, 0);
            inner.header_written = false;
        }

        Pin::new(&mut inner.stream.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream.as_mut().unwrap()).poll_close(cx)
    }
}

#[cfg(all(
    test,
    any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )
))]
mod tests {
    use super::*;
    use futures_util::io::{AsyncRead, AsyncWrite};
    use std::task::{Context, Poll, Waker};

    // A minimal in-memory stream that yields a fixed slice of bytes to the
    // reader. Enough to drive `TlsPreloginWrapper::poll_read` through the
    // prelogin header-parsing branch without a real socket / TLS handshake.
    struct MockStream {
        data: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut task::Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let remaining = &self.data.get_ref()[self.data.position() as usize..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            let pos = self.data.position();
            self.data.set_position(pos + n as u64);
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // An in-memory stream that captures every byte written to it, so the
    // framing produced by `poll_write` + `poll_flush` can be inspected. Reads
    // report clean EOF; they are not exercised by the write-side tests.
    struct CapturingStream {
        written: Vec<u8>,
    }

    impl AsyncRead for CapturingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut task::Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    impl AsyncWrite for CapturingStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // During the handshake, `poll_write` buffers the payload behind an 8-byte
    // header placeholder and `poll_flush` back-fills that header and writes the
    // whole frame to the wire. The result must be exactly one TDS packet:
    // PreLogin type, EndOfMessage status, a total length covering header +
    // payload, followed by the verbatim payload. This locks the wrapper's
    // outbound framing (previously only the read side was tested).
    #[test]
    fn poll_write_then_flush_frames_a_prelogin_packet() {
        let stream = CapturingStream {
            written: Vec::new(),
        };
        let mut wrapper = TlsPreloginWrapper::new(stream);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        // A payload longer than the header, so the `wr_buf.len() > HEADER_BYTES`
        // flush guard fires. Distinctive bytes make an off-by-one obvious.
        let payload: Vec<u8> = (0u8..20).map(|i| 0xA0 ^ i).collect();
        assert!(payload.len() > HEADER_BYTES);

        match Pin::new(&mut wrapper).poll_write(&mut cx, &payload) {
            Poll::Ready(Ok(n)) => assert_eq!(n, payload.len()),
            other => panic!("expected the payload to be accepted, got {other:?}"),
        }

        match Pin::new(&mut wrapper).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected a clean flush, got {other:?}"),
        }

        let written = &wrapper.stream.as_ref().unwrap().written;

        // The frame is header + payload and nothing else.
        assert_eq!(
            written.len(),
            HEADER_BYTES + payload.len(),
            "framed packet must be exactly header + payload bytes"
        );

        // The 8-byte header decodes to a PreLogin end-of-message packet whose
        // declared length matches the whole frame.
        let header = PacketHeader::decode(&mut BytesMut::from(&written[..HEADER_BYTES])).unwrap();
        assert_eq!(header.r#type(), PacketType::PreLogin);
        assert_eq!(header.status(), PacketStatus::EndOfMessage);
        assert_eq!(
            header.length() as usize,
            HEADER_BYTES + payload.len(),
            "header length field must cover header + payload"
        );

        // The payload follows the header verbatim.
        assert_eq!(&written[HEADER_BYTES..], &payload[..]);
    }

    // Drive one `poll_read` over a wrapper fed the given 8-byte header.
    fn poll_header(header: [u8; HEADER_BYTES]) -> Poll<io::Result<usize>> {
        let stream = MockStream {
            data: std::io::Cursor::new(header.to_vec()),
        };
        let mut wrapper = TlsPreloginWrapper::new(stream);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut buf = [0u8; 32];
        Pin::new(&mut wrapper).poll_read(&mut cx, &mut buf)
    }

    // A non-PreLogin packet type during the (unauthenticated) handshake must be
    // rejected with `InvalidData`, not passed through / panicked on.
    #[test]
    fn non_prelogin_packet_type_is_rejected() {
        // ty=SQLBatch(1), status=0, length=20 (BE), spid=0, id=0, window=0
        let header = [1u8, 0, 0, 20, 0, 0, 0, 0];
        match poll_header(header) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("expected InvalidData error, got {other:?}"),
        }
    }

    // A PreLogin header whose declared length is shorter than the 8-byte header
    // must be rejected via the `checked_sub` underflow guard, not panic.
    #[test]
    fn prelogin_length_shorter_than_header_is_rejected() {
        // ty=PreLogin(18), status=0, length=4 (< HEADER_BYTES), rest 0
        let header = [18u8, 0, 0, 4, 0, 0, 0, 0];
        match poll_header(header) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("expected InvalidData error, got {other:?}"),
        }
    }
}
