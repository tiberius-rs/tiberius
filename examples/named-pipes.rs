//! Connecting to SQL Server over a Windows named pipe.
//!
//! SQL Server exposes a named pipe endpoint (by default
//! `\\.\pipe\sql\query` for the default instance). Because a named pipe
//! implements `AsyncRead`/`AsyncWrite`, it can be handed to
//! [`Client::connect`] exactly like a TCP stream once it is wrapped with the
//! `tokio-util` compatibility layer.
//!
//! Named pipes are a Windows-only transport, so the real example is compiled
//! only on Windows; on other platforms `main` panics with an unsupported
//! message. See tiberius issues #131 and #53 for background.

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use tiberius::{AuthMethod, Client, Config};
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio_util::compat::TokioAsyncWriteCompatExt;

    // The default named pipe for a default SQL Server instance. A named
    // instance uses `\\.\pipe\MSSQL$<instance>\sql\query`.
    const PIPE_NAME: &str = r"\\.\pipe\sql\query";

    let mut config = Config::new();
    config.authentication(AuthMethod::Integrated);
    config.trust_cert();

    let pipe = ClientOptions::new().open(PIPE_NAME)?;
    let mut client = Client::connect(config, pipe.compat_write()).await?;

    let stream = client.query("SELECT @P1", &[&1i32]).await?;
    let row = stream.into_row().await?.unwrap();

    println!("{row:?}");
    assert_eq!(Some(1), row.get(0));

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    panic!("Named pipe connections are only supported on Windows.");
}
