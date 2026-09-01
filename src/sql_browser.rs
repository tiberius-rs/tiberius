#[cfg(feature = "sql-browser-tokio")]
mod tokio;

#[cfg(feature = "sql-browser-smol")]
mod smol;

use crate::client::Config;
use async_trait::async_trait;

/// An extension trait to a `TcpStream` to find a port and connecting to a
/// named database instance.
///
/// Only needed on Windows platforms, where the server port is not known and the
/// address is in the form of `hostname\\INSTANCE`.
#[async_trait]
pub trait SqlBrowser {
    /// If the given builder defines a named instance, finds the correct port
    /// and returns a `TcpStream` to be used in the [`Client`]. If instance name
    /// is not defined, connects directly to the given host and port.
    ///
    /// [`Client`]: struct.Client.html
    async fn connect_named(builder: &Config) -> crate::Result<Self>
    where
        Self: Sized + Send + Sync;
}

#[cfg(any(feature = "sql-browser-tokio", feature = "sql-browser-smol"))]
fn get_port_from_sql_browser_reply(
    mut buf: Vec<u8>,
    len: usize,
    instance_name: &str,
) -> crate::Result<u16> {
    const DELIMITER: &[u8] = b"tcp;";

    buf.truncate(len);

    // Built fresh on each failure path so the descriptive context (which
    // instance failed to resolve) is preserved rather than being collapsed into
    // a bare `Error::Utf8`/`Error::ParseInt` by `?`.
    let err = || {
        crate::Error::Conversion(
            format!("Could not resolve SQL browser instance {}", instance_name).into(),
        )
    };

    // The SSRP reply is [SVR_RESP(1 byte)][RESP_SIZE(2 bytes, LE)][data...], so
    // the instance data starts at offset 3. A reply shorter than that 3-byte
    // header is malformed — and SSRP is unauthenticated UDP, so a spoofed or
    // truncated datagram is fully attacker-controlled. Guard it explicitly:
    // `&buf[3..len]` would otherwise panic ("slice index starts at 3 but ends
    // at 1") for a 1- or 2-byte reply.
    if len < 3 {
        return Err(err());
    }

    let rsp = &buf[3..len];

    let port: u16 = rsp
        .windows(DELIMITER.len())
        .rev()
        .position(|window| window == DELIMITER)
        .and_then(|pos| rsp[(rsp.len() - pos)..].split(|item| *item == b';').next())
        .and_then(|val| std::str::from_utf8(val).ok())
        .and_then(|val| val.parse().ok())
        .ok_or_else(err)?;

    Ok(port)
}
