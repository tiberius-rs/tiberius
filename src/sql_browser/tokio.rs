use super::SqlBrowser;
use crate::client::Config;
use async_trait::async_trait;
use futures_util::future::TryFutureExt;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use net::{TcpStream, UdpSocket};
use std::{io, net::SocketAddr};
use tokio::{
    net,
    time::{self, error::Elapsed, Duration},
};
use tracing::Level;

#[async_trait]
impl SqlBrowser for TcpStream {
    /// This method can be used to connect to SQL Server named instances
    /// when on a Windows paltform with the `sql-browser-tokio` feature
    /// enabled. Please see the crate examples for more detailed examples.
    async fn connect_named(builder: &Config) -> crate::Result<Self> {
        let addrs = net::lookup_host(builder.get_addr()).await?;
        let mut first_error = None;

        if builder.multi_subnet_failover {
            let mut futures = addrs
                .map(|addr| connect_addr(builder, addr))
                .collect::<FuturesUnordered<_>>();
            while let Some(connection) = futures.next().await {
                match connection {
                    Ok(connection) => return Ok(connection),
                    Err(error) => first_error.get_or_insert(error),
                };
            }
        } else {
            for addr in addrs {
                match connect_addr(builder, addr).await {
                    Ok(connection) => return Ok(connection),
                    Err(error) => first_error.get_or_insert(error),
                };
            }
        }

        // If we end up here, there was no successful connection.
        Err(first_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Could not resolve server host").into()
        }))
    }
}

async fn connect_addr(builder: &Config, mut addr: SocketAddr) -> crate::Result<TcpStream> {
    if let Some(ref instance_name) = builder.instance_name {
        // First resolve the instance to a port via the
        // SSRP protocol/MS-SQLR protocol [1]
        // [1] https://msdn.microsoft.com/en-us/library/cc219703.aspx

        let local_bind: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        tracing::event!(
            Level::TRACE,
            "Connecting to instance `{}` using SQL Browser in port `{}`",
            instance_name,
            builder.get_port()
        );

        let msg = [&[4u8], instance_name.as_bytes()].concat();
        let mut buf = vec![0u8; 4096];

        let socket = UdpSocket::bind(&local_bind).await?;
        socket.send_to(&msg, &addr).await?;

        let timeout = Duration::from_millis(1000);

        let len = time::timeout(timeout, socket.recv(&mut buf))
            .map_err(|_: Elapsed| {
                crate::error::Error::Conversion(
                    format!(
                        "SQL browser timeout during resolving instance {}. Please check if browser is running in port {} and does the instance exist.",
                        instance_name,
                        builder.get_port(),
                    )
                    .into(),
                )
            })
            .await??;

        let port = super::get_port_from_sql_browser_reply(buf, len, instance_name)?;
        tracing::event!(Level::TRACE, "Found port `{}` from SQL Browser", port);
        addr.set_port(port);
    };

    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
