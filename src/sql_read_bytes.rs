use crate::tds::Context;
use bytes::Buf;
use futures_util::io::AsyncRead;
use pin_project_lite::pin_project;
use std::io::ErrorKind::UnexpectedEof;
use std::{future::Future, io, mem::size_of, pin::Pin, task};
use task::Poll;

macro_rules! varchar_reader {
    ($name:ident, $length_reader:ident) => {
        pin_project! {
            #[doc(hidden)]
            pub struct $name<R> {
                #[pin]
                src: R,
                length: Option<usize>,
                buf: Option<Vec<u16>>,
                read: usize
            }
        }

        #[allow(dead_code)]
        impl<R> $name<R> {
            pub(crate) fn new(src: R) -> Self {
                Self {
                    src,
                    length: None,
                    buf: None,
                    read: 0,
                }
            }
        }

        impl<R> Future for $name<R>
        where
            R: AsyncRead,
        {
            type Output = io::Result<String>;

            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
                let mut me = self.project();

                // We must know the length of the string first.
                while me.length.is_none() {
                    let mut read_len = $length_reader::new(&mut me.src);

                    match Pin::new(&mut read_len).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(length)) => {
                            *me.length = Some(length as usize);
                            *me.buf = Some(Vec::with_capacity(length as usize));
                        }
                    }
                }

                // We've set the length and initialized the buffer
                let len = me.length.unwrap();
                let buf = me.buf.as_mut().unwrap();

                // Everything's read, we can return the string.
                if *me.read == len {
                    let s = String::from_utf16(&buf).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-16 data.")
                    })?;

                    return Poll::Ready(Ok(s));
                }

                // Read the utf-16 data
                while *me.read < len {
                    let mut read_u16 = ReadU16Le::new(&mut me.src);

                    match Pin::new(&mut read_u16).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(n)) => {
                            buf.push(n);
                            *me.read += 1;
                        }
                    }
                }

                // Everything's read, we can return the string.
                let s = String::from_utf16(&buf).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-16 data.")
                })?;

                return Poll::Ready(Ok(s));
            }
        }
    };
}

macro_rules! bytes_reader {
    ($name:ident, $ty:ty, $reader:ident) => {
        bytes_reader!($name, $ty, $reader, size_of::<$ty>());
    };
    ($name:ident, $ty:ty, $reader:ident, $bytes:expr) => {
        pin_project! {
            #[doc(hidden)]
            pub struct $name<R> {
                #[pin]
                src: R,
                buf: [u8; $bytes],
                read: u8,
            }
        }

        #[allow(dead_code)]
        impl<R> $name<R> {
            pub(crate) fn new(src: R) -> Self {
                $name {
                    src,
                    buf: [0; $bytes],
                    read: 0,
                }
            }
        }

        impl<R> Future for $name<R>
        where
            R: AsyncRead,
        {
            type Output = io::Result<$ty>;

            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
                let mut me = self.project();

                if *me.read == $bytes as u8 {
                    return Poll::Ready(Ok(Buf::$reader(&mut &me.buf[..])));
                }

                while *me.read < $bytes as u8 {
                    *me.read += match me
                        .src
                        .as_mut()
                        .poll_read(cx, &mut me.buf[*me.read as usize..])
                    {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(UnexpectedEof.into()));
                        }
                        Poll::Ready(Ok(n)) => n as u8,
                    };
                }

                let num = Buf::$reader(&mut &me.buf[..]);

                Poll::Ready(Ok(num))
            }
        }
    };
}

/// The `SqlReadBytes` trait is used to read bytes from the wire.
// Many of the methods have an `allow(dead_code)` attribute because they are not currently used but they could be anytime in the future.
pub(crate) trait SqlReadBytes: AsyncRead + Unpin {
    // Pretty-print current wire content.
    #[allow(dead_code)]
    fn debug_buffer(&self);

    // The client state.
    fn context(&self) -> &Context;

    // A mutable reference to the SQL client state.
    fn context_mut(&mut self) -> &mut Context;

    // Read a single i8 value.
    #[allow(dead_code)]
    fn read_i8(&mut self) -> ReadI8<&mut Self>
    where
        Self: Unpin,
    {
        ReadI8::new(self)
    }

    // Read a single byte value.
    fn read_u8(&mut self) -> ReadU8<&mut Self>
    where
        Self: Unpin,
    {
        ReadU8::new(self)
    }

    // Read a single big-endian u32 value.
    fn read_u32(&mut self) -> ReadU32Be<&mut Self>
    where
        Self: Unpin,
    {
        ReadU32Be::new(self)
    }

    // Read a single big-endian f32 value.
    #[allow(dead_code)]
    fn read_f32(&mut self) -> ReadF32<&mut Self>
    where
        Self: Unpin,
    {
        ReadF32::new(self)
    }

    // Read a single big-endian f64 value.
    #[allow(dead_code)]
    fn read_f64(&mut self) -> ReadF64<&mut Self>
    where
        Self: Unpin,
    {
        ReadF64::new(self)
    }

    // Read a single f32 value.
    fn read_f32_le(&mut self) -> ReadF32Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadF32Le::new(self)
    }

    // Read a single f64 value.
    fn read_f64_le(&mut self) -> ReadF64Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadF64Le::new(self)
    }

    // Read a single u16 value.
    fn read_u16_le(&mut self) -> ReadU16Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadU16Le::new(self)
    }

    // Read a single u32 value.
    fn read_u32_le(&mut self) -> ReadU32Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadU32Le::new(self)
    }

    // Read a single u64 value.
    fn read_u64_le(&mut self) -> ReadU64Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadU64Le::new(self)
    }

    // Read a single u128 value.
    #[allow(dead_code)]
    fn read_u128_le(&mut self) -> ReadU128Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadU128Le::new(self)
    }

    // Read a single i16 value.
    fn read_i16_le(&mut self) -> ReadI16Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadI16Le::new(self)
    }

    // Read a single i32 value.
    fn read_i32_le(&mut self) -> ReadI32Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadI32Le::new(self)
    }

    // Read a single i64 value.
    fn read_i64_le(&mut self) -> ReadI64Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadI64Le::new(self)
    }

    // Read a single i128 value.
    #[allow(dead_code)]
    fn read_i128_le(&mut self) -> ReadI128Le<&mut Self>
    where
        Self: Unpin,
    {
        ReadI128Le::new(self)
    }

    // A variable-length character stream defined by a length-field of an u8.
    fn read_b_varchar(&mut self) -> ReadBVarchar<&mut Self>
    where
        Self: Unpin,
    {
        ReadBVarchar::new(self)
    }

    // A variable-length character stream defined by a length-field of an u16.
    fn read_us_varchar(&mut self) -> ReadUSVarchar<&mut Self>
    where
        Self: Unpin,
    {
        ReadUSVarchar::new(self)
    }
}

varchar_reader!(ReadBVarchar, ReadU8);
varchar_reader!(ReadUSVarchar, ReadU16Le);

bytes_reader!(ReadI8, i8, get_i8);
bytes_reader!(ReadU8, u8, get_u8);
bytes_reader!(ReadU32Be, u32, get_u32);

bytes_reader!(ReadU16Le, u16, get_u16_le);
bytes_reader!(ReadU32Le, u32, get_u32_le);
bytes_reader!(ReadU64Le, u64, get_u64_le);
bytes_reader!(ReadU128Le, u128, get_u128_le);

bytes_reader!(ReadI16Le, i16, get_i16_le);
bytes_reader!(ReadI32Le, i32, get_i32_le);
bytes_reader!(ReadI64Le, i64, get_i64_le);
bytes_reader!(ReadI128Le, i128, get_i128_le);

bytes_reader!(ReadF32, f32, get_f32);
bytes_reader!(ReadF64, f64, get_f64);

bytes_reader!(ReadF32Le, f32, get_f32_le);
bytes_reader!(ReadF64Le, f64, get_f64_le);

#[cfg(test)]
mod tests {
    use super::test_utils::IntoSqlReadBytes;
    use crate::SqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn read_i8_value() {
        let mut buf = BytesMut::new();
        buf.put_i8(-5);
        assert_eq!(buf.into_sql_read_bytes().read_i8().await.unwrap(), -5);
    }

    #[tokio::test]
    async fn read_u32_big_endian() {
        let mut buf = BytesMut::new();
        buf.put_u32(0x01020304);
        assert_eq!(
            buf.into_sql_read_bytes().read_u32().await.unwrap(),
            0x01020304
        );
    }

    #[tokio::test]
    async fn read_f32_and_f64_big_endian() {
        let mut buf = BytesMut::new();
        buf.put_f32(1.5);
        assert_eq!(buf.into_sql_read_bytes().read_f32().await.unwrap(), 1.5);

        let mut buf = BytesMut::new();
        buf.put_f64(2.5);
        assert_eq!(buf.into_sql_read_bytes().read_f64().await.unwrap(), 2.5);
    }

    #[tokio::test]
    async fn read_f32_and_f64_little_endian() {
        let mut buf = BytesMut::new();
        buf.put_f32_le(1.5);
        assert_eq!(buf.into_sql_read_bytes().read_f32_le().await.unwrap(), 1.5);

        let mut buf = BytesMut::new();
        buf.put_f64_le(2.5);
        assert_eq!(buf.into_sql_read_bytes().read_f64_le().await.unwrap(), 2.5);
    }

    #[tokio::test]
    async fn read_u128_and_i128_le() {
        let mut buf = BytesMut::new();
        buf.put_u128_le(12345);
        assert_eq!(
            buf.into_sql_read_bytes().read_u128_le().await.unwrap(),
            12345
        );

        let mut buf = BytesMut::new();
        buf.put_i128_le(-12345);
        assert_eq!(
            buf.into_sql_read_bytes().read_i128_le().await.unwrap(),
            -12345
        );
    }

    #[tokio::test]
    async fn read_b_varchar_and_us_varchar() {
        let mut buf = BytesMut::new();
        buf.put_u8(2);
        buf.put_u16_le('h' as u16);
        buf.put_u16_le('i' as u16);
        assert_eq!(
            buf.into_sql_read_bytes().read_b_varchar().await.unwrap(),
            "hi"
        );

        let mut buf = BytesMut::new();
        buf.put_u16_le(2);
        buf.put_u16_le('h' as u16);
        buf.put_u16_le('i' as u16);
        assert_eq!(
            buf.into_sql_read_bytes().read_us_varchar().await.unwrap(),
            "hi"
        );
    }

    #[tokio::test]
    async fn context_and_context_mut_accessible() {
        let buf = BytesMut::new();
        let mut reader = buf.into_sql_read_bytes();
        assert_eq!(reader.context().packet_size(), 4096);
        reader.context_mut().set_packet_size(8192);
        assert_eq!(reader.context().packet_size(), 8192);
    }

    // The length prefix cannot be read (empty wire) — exercises the error arm of
    // the varchar length read (`Poll::Ready(Err(..))`).
    #[tokio::test]
    async fn b_varchar_length_read_error() {
        let buf = BytesMut::new();
        assert!(buf.into_sql_read_bytes().read_b_varchar().await.is_err());
    }

    // The length is read but the character payload is truncated — exercises the
    // error arm of the inner u16 read within the varchar loop.
    #[tokio::test]
    async fn b_varchar_data_read_error() {
        let mut buf = BytesMut::new();
        buf.put_u8(1); // announce one u16 char...
        buf.put_u8(0x41); // ...but supply only a single byte
        assert!(buf.into_sql_read_bytes().read_b_varchar().await.is_err());
    }

    // A lone UTF-16 surrogate makes `String::from_utf16` fail — exercises the
    // invalid-UTF-16 error mapping at the end of the varchar reader.
    #[tokio::test]
    async fn b_varchar_invalid_utf16_error() {
        let mut buf = BytesMut::new();
        buf.put_u8(1);
        buf.put_u16_le(0xD800); // unpaired high surrogate
        assert!(buf.into_sql_read_bytes().read_b_varchar().await.is_err());
    }

    // `debug_buffer` for the test reader is a `todo!()`; calling it must panic.
    #[test]
    #[should_panic]
    fn debug_buffer_panics() {
        let reader = BytesMut::new().into_sql_read_bytes();
        reader.debug_buffer();
    }
}

// Tests for the `Poll::Pending` / clean-EOF branches of the readers, which
// require an `AsyncRead` that can return `Pending` / `Ok(0)` on demand and a
// manually driven poll.
#[cfg(test)]
mod poll_branch_tests {
    use crate::tds::Context;
    use crate::SqlReadBytes;
    use bytes::{BufMut, BytesMut};
    use futures_util::io::AsyncRead;
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    enum Then {
        Pending,
        Eof,
    }

    // Hands out `data` while enough bytes remain, then switches to returning
    // either `Poll::Pending` or a clean EOF (`Ok(0)`).
    struct ScriptedReader {
        data: BytesMut,
        then: Then,
        ctx: Context,
    }

    impl ScriptedReader {
        fn new(data: BytesMut, then: Then) -> Self {
            Self {
                data,
                then,
                ctx: Context::new(),
            }
        }
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let size = buf.len();

            if size > 0 && this.data.len() >= size {
                buf.copy_from_slice(this.data.split_to(size).as_ref());
                return Poll::Ready(Ok(size));
            }

            match this.then {
                Then::Pending => Poll::Pending,
                Then::Eof => Poll::Ready(Ok(0)),
            }
        }
    }

    impl SqlReadBytes for ScriptedReader {
        fn debug_buffer(&self) {}
        fn context(&self) -> &Context {
            &self.ctx
        }
        fn context_mut(&mut self) -> &mut Context {
            &mut self.ctx
        }
    }

    fn poll_once<F: Future>(fut: F) -> Poll<F::Output> {
        let waker = std::task::Waker::noop();
        let mut cx = TaskContext::from_waker(waker);
        let mut fut = std::pin::pin!(fut);
        fut.as_mut().poll(&mut cx)
    }

    // The varchar length read yields `Pending` (no bytes available yet).
    #[test]
    fn varchar_length_pending() {
        let mut reader = ScriptedReader::new(BytesMut::new(), Then::Pending);
        assert!(matches!(poll_once(reader.read_b_varchar()), Poll::Pending));
    }

    // The length is read, but the character payload read yields `Pending`.
    #[test]
    fn varchar_data_pending() {
        let mut data = BytesMut::new();
        data.put_u8(1); // length available, character bytes are not
        let mut reader = ScriptedReader::new(data, Then::Pending);
        assert!(matches!(poll_once(reader.read_b_varchar()), Poll::Pending));
    }

    // A fixed-width numeric read yields `Pending` when no bytes are available.
    #[test]
    fn fixed_width_read_pending() {
        let mut reader = ScriptedReader::new(BytesMut::new(), Then::Pending);
        assert!(matches!(poll_once(reader.read_u32_le()), Poll::Pending));
    }

    // A clean EOF (`Ok(0)`) mid-read surfaces as an `UnexpectedEof` error.
    #[test]
    fn fixed_width_read_unexpected_eof() {
        let mut reader = ScriptedReader::new(BytesMut::new(), Then::Eof);
        match poll_once(reader.read_u8()) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::tds::Context;
    use crate::SqlReadBytes;
    use bytes::BytesMut;
    use futures_util::io::AsyncRead;
    use std::io;
    use std::pin::Pin;
    use std::task::Poll;

    // a test util to run decode logic on BytesMut, for testing loop back
    pub(crate) trait IntoSqlReadBytes {
        type T: SqlReadBytes;
        fn into_sql_read_bytes(self) -> Self::T;
    }

    impl IntoSqlReadBytes for BytesMut {
        type T = BytesMutReader;

        fn into_sql_read_bytes(self) -> Self::T {
            BytesMutReader {
                buf: self,
                ctx: Context::new(),
            }
        }
    }

    pub(crate) struct BytesMutReader {
        buf: BytesMut,
        ctx: Context,
    }

    impl AsyncRead for BytesMutReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let size = buf.len();

            // Got EOF before having all the data.
            if this.buf.len() < size {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "No more packets in the wire",
                )));
            }

            buf.copy_from_slice(this.buf.split_to(size).as_ref());
            Poll::Ready(Ok(size))
        }
    }

    impl SqlReadBytes for BytesMutReader {
        fn debug_buffer(&self) {
            todo!()
        }

        fn context(&self) -> &Context {
            &self.ctx
        }

        fn context_mut(&mut self) -> &mut Context {
            &mut self.ctx
        }
    }
}
