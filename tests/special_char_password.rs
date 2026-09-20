//! End-to-end coverage for special-character passwords (issue #313).
//!
//! The unit tests in `src/client/config` prove the connection-string *parser*;
//! these prove the whole path — parse, LOGIN7, real SQL Server authentication —
//! for passwords that contain structural characters. They run only against a
//! live server (the CI integration lanes), like the other files in `tests/`.

use once_cell::sync::Lazy;
use std::env;
use tiberius::{Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

static ADMIN_CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;user=SA;password=<YourStrong@Passw0rd>;TrustServerCertificate=true".to_owned()
    })
});

async fn connect(conn_str: &str) -> anyhow::Result<Client<Compat<TcpStream>>> {
    let config = Config::from_ado_string(conn_str)?;
    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;
    Ok(Client::connect(config, tcp.compat_write()).await?)
}

/// Creates a SQL login + user with `password`, connects as it using
/// `ado_password` (the value exactly as written in the connection string),
/// runs a trivial query, then drops the login. Proves the special-character
/// password survives the whole login handshake, not just parsing.
async fn assert_login_roundtrip(
    tag: &str,
    password: &str,
    ado_password: &str,
) -> anyhow::Result<()> {
    // Unique per (tag, process, wall-clock nanos) so neither the three tests in
    // this binary nor separate runs against a shared server collide on the login
    // name.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let login = format!("tib_pw_{tag}_{}_{nanos}", std::process::id());

    let mut admin = connect(&ADMIN_CONN_STR).await?;

    // CHECK_POLICY=OFF so the test isn't at the mercy of the host's password
    // policy; the passwords used here are still non-trivial. The password is a
    // T-SQL string literal, so a `'` in it would need doubling — none is used.
    let create = format!(
        "IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN [{login}]; \
         CREATE LOGIN [{login}] WITH PASSWORD = '{password}', CHECK_POLICY = OFF;"
    );
    admin.simple_query(create).await?.into_results().await?;

    // Connect as the new login with the password written the way a user would.
    // Built by appending overrides to the admin string: duplicate keys are
    // last-wins, so this swaps the user/password and forces a plaintext login
    // so the test runs identically in the TLS and no-TLS CI lanes (and also
    // exercises last-wins end-to-end).
    let conn_str = format!(
        "{};user={login};password={ado_password};encrypt=DANGER_PLAINTEXT",
        *ADMIN_CONN_STR
    );
    let result: anyhow::Result<()> = async {
        let mut client = connect(&conn_str).await?;
        let row = client
            .query("SELECT @@VERSION", &[])
            .await?
            .into_row()
            .await?;
        anyhow::ensure!(row.is_some(), "login `{login}` should return a row");
        Ok(())
    }
    .await;

    // Best-effort cleanup regardless of the connection result.
    let _ = admin.simple_query(format!("DROP LOGIN [{login}]")).await;

    result
}

#[tokio::test]
async fn base64_equals_password_authenticates() -> anyhow::Result<()> {
    // The #313 case: `=` padding, written unquoted in the connection string.
    assert_login_roundtrip("eqpad", "Ab1!Zm9vYmFy==", "Ab1!Zm9vYmFy==").await
}

#[tokio::test]
async fn semicolon_password_authenticates_when_quoted() -> anyhow::Result<()> {
    // A `;` in the password must be quoted in the connection string.
    assert_login_roundtrip("semi", "Ab1!x;y=z", "'Ab1!x;y=z'").await
}

#[tokio::test]
async fn braced_password_authenticates() -> anyhow::Result<()> {
    // Brace quoting (the tiberius extension) around `;` and `=`.
    assert_login_roundtrip("brace", "Ab1!p;q=r", "{Ab1!p;q=r}").await
}
