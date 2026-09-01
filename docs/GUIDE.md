# Tiberius Guide

A practical tour of the driver. For the full API see [docs.rs](https://docs.rs/tiberius).
Every example imports the crate as `tiberius` (the package is `tiberius`; see
the [README](../README.md#installation)).

- [Connecting](#connecting)
- [Configuration](#configuration)
- [Encryption & TLS](#encryption--tls)
- [Authentication](#authentication)
- [Querying](#querying)
- [Reading rows](#reading-rows)
- [Bulk insert](#bulk-insert)
- [Stored procedures, OUT params & TVPs](#stored-procedures-out-params--tvps)
- [Transactions](#transactions)
- [`IN (…)` lists](#in--lists)
- [Named instances (SQL Browser)](#named-instances-sql-browser)
- [Query cancellation](#query-cancellation)
- [Connection pooling](#connection-pooling)
- [Error handling](#error-handling)

## Connecting

Tiberius is runtime-independent: you create the `TcpStream` and hand it to the
[`Client`].

**Tokio** (wrap the stream with `tokio_util::compat`):

```rust
use tiberius::{Client, Config, AuthMethod};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

# async fn f() -> anyhow::Result<()> {
let mut config = Config::new();
config.host("localhost");
config.port(1433);
config.authentication(AuthMethod::sql_server("SA", "<YourStrong@Passw0rd>"));
config.trust_cert(); // dev only

let tcp = TcpStream::connect(config.get_addr()).await?;
tcp.set_nodelay(true)?;
let mut client = Client::connect(config, tcp.compat_write()).await?;
# Ok(()) }
```

**smol** (pass the stream directly — no compat layer):

```rust,ignore
let tcp = smol::net::TcpStream::connect(config.get_addr()).await?;
tcp.set_nodelay(true)?;
let mut client = tiberius::Client::connect(config, tcp).await?;
```

## Configuration

Build a [`Config`] fluently, or parse a connection string:

```rust,ignore
// ADO.NET
let config = Config::from_ado_string(
    "Server=tcp:localhost,1433;User Id=SA;Password=pw;Encrypt=strict;",
)?;

// JDBC
let config = Config::from_jdbc_string(
    "jdbc:sqlserver://localhost:1433;user=SA;password=pw;encrypt=true",
)?;

// Builder
let config = Config::builder()
    .host("localhost")
    .port(1433)
    .authentication(AuthMethod::sql_server("SA", "pw"))
    .build();
```

## Encryption & TLS

TLS is on by default. Pick a backend via a feature flag (mutually exclusive):
`native-tls` (default), `rustls`, or `vendored-openssl`.

Encryption levels (`Config::encryption`): `NotSupported`, `Off`, `Required`
(default), and **`Strict`** — TDS 8.0, TLS *before* the pre-login, with the
`tds/8.0` ALPN (requires the `tds80` feature; native-tls or rustls).

```rust,ignore
use tiberius::EncryptionLevel;
config.encryption(EncryptionLevel::Strict);
config.hostname_in_certificate("my-sql-host"); // validate against a specific CN/SAN
config.client_certificate("client.pem", "client.key"); // mutual TLS
// or: config.client_certificate_pkcs12("client.pfx", "password");
```

## Authentication

```rust,ignore
// SQL Server login (password buffers are zeroized)
config.authentication(AuthMethod::sql_server("user", "pw"));

// Windows integrated auth: SSPI on Windows (winauth), NTLM on Unix (sspi-rs)
config.authentication(AuthMethod::windows("user", "pw"));

// Kerberos on Unix (integrated-auth-gssapi feature)
config.authentication(AuthMethod::Integrated);

// Azure AD access token
config.authentication(AuthMethod::aad_token(token));
```

## Querying

From the [`Client`] when parameters are known at the call site:

```rust,ignore
// Rows back
let stream = client.query("SELECT @P1, @P2", &[&1i32, &"foo"]).await?;

// Rows affected
let result = client.execute("UPDATE t SET x = @P1 WHERE id = @P2", &[&1i32, &2i32]).await?;
println!("{} rows", result.total());
```

For dynamic or owned parameters, use the [`Query`] object:

```rust,ignore
use tiberius::Query;
let mut select = Query::new("SELECT @P1, @P2");
for p in ["a", "b"] { select.bind(p); }
let stream = select.query(&mut client).await?;
```

## Reading rows

A query returns a stream. Collect it, or take the first row:

```rust,ignore
// All rows of the first result set
let rows = client.query("SELECT id, name FROM users", &[]).await?
    .into_first_result().await?;

for row in rows {
    let id: i32 = row.get("id").unwrap();
    let name: &str = row.get("name").unwrap();
}

// Just the first row
let row = client.query("SELECT 1 AS n", &[]).await?.into_row().await?.unwrap();
let n: i32 = row.get("n").unwrap();
```

Type mappings are available via `FromSql`/`ToSql`, with optional `chrono`,
`time`, `rust_decimal`, `bigdecimal`, and `serde` support behind their features.
`Client::column_metadata()` exposes column type, size, precision/scale,
nullability and identity flags.

## Bulk insert

Efficiently stream many rows into a table:

```rust,ignore
use tiberius::IntoRow;

let mut req = client.bulk_insert("dbo.target").await?;      // all columns
// or a specific column list:
// let mut req = client.bulk_insert_columns("dbo.target", &["foo", "bar"]).await?;

for i in 0..1000i32 {
    req.send(i.into_row()).await?;
}
let res = req.finalize().await?;
println!("{} rows", res.total());
```

## Stored procedures, OUT params & TVPs

Named RPC with input, output and table-valued parameters is supported via the
[`Command`] API. A TVP row type derives `TableValueRow`:

```rust,ignore
use tiberius::TableValueRow;

#[derive(TableValueRow)]
struct Item {
    #[colname = "Id"]   id: i32,
    #[colname = "Name"] name: String,
}
```

## Transactions

Real Transaction Manager requests (not T-SQL batches), with isolation levels:

```rust,ignore
client.begin_transaction().await?;
// ... work ...
client.commit_transaction().await?;
// or client.rollback_transaction().await?;
```

## `IN (…)` lists

Helpers make variable-length `IN` lists and the 2,100-parameter limit ergonomic —
see the `Query` docs on docs.rs for `in_clause`/parameter-expansion helpers.

## Named instances (SQL Browser)

On Windows, a named instance's port is resolved through SQL Browser. Enable
`sql-browser-tokio` or `sql-browser-smol` and use the `SqlBrowser` extension:

```rust,ignore
use tiberius::SqlBrowser;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

config.port(1434);
config.instance_name("INSTANCE");
let tcp = TcpStream::connect_named(&config).await?;
let mut client = Client::connect(config, tcp.compat_write()).await?;
```

## Query cancellation

```rust,ignore
client.cancel_query().await?; // sends a TDS Attention signal
```

## Connection pooling

Pooling is delegated to the async pool crates rather than built in. This keeps
Tiberius runtime-agnostic (a pool has to pick a runtime's timers and tasks) and
lets the connection lifecycle — sizing, health checks, idle reaping — evolve
independently of the driver. Use [`bb8`](https://crates.io/crates/bb8),
[`deadpool`](https://crates.io/crates/deadpool), or
[`mobc`](https://crates.io/crates/mobc) with a small connection manager.

Because Tiberius has no MARS (one in-flight request per connection), a pool is
also the natural way to get concurrency: check out a connection per task.

Here is a minimal [`bb8`](https://crates.io/crates/bb8) manager over Tokio:

```rust,ignore
use bb8::{ManageConnection, Pool};
use tiberius::{Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

struct TiberiusManager {
    config: Config,
}

#[async_trait::async_trait]
impl ManageConnection for TiberiusManager {
    type Connection = Client<Compat<TcpStream>>;
    type Error = tiberius::error::Error;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let tcp = TcpStream::connect(self.config.get_addr()).await?;
        tcp.set_nodelay(true)?;
        Client::connect(self.config.clone(), tcp.compat_write()).await
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        // Cheap round-trip to confirm the connection is still alive.
        conn.simple_query("SELECT 1").await?.into_row().await?;
        Ok(())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = Config::new();
    config.host("localhost");
    config.port(1433);
    config.authentication(tiberius::AuthMethod::sql_server("SA", "<YourStrong@Passw0rd>"));
    config.trust_cert(); // don't do this in production

    let pool = Pool::builder()
        .max_size(16)
        .build(TiberiusManager { config })
        .await?;

    // Check out a connection; it returns to the pool on drop.
    let mut conn = pool.get().await?;
    let row = conn
        .query("SELECT @P1 AS n", &[&1i32])
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(Some(1i32), row.get("n"));
    Ok(())
}
```

The [`deadpool`](https://crates.io/crates/deadpool) and
[`mobc`](https://crates.io/crates/mobc) integrations follow the same shape —
implement their manager trait with the `connect`/`is_valid` logic above.

## Error handling

All fallible calls return `tiberius::Result<T>` (`Err` is [`tiberius::error::Error`]).
Server-side errors surface as `Error::Server(TokenError { .. })` carrying the SQL
Server error code, state, class, message, procedure and line.

[`Client`]: https://docs.rs/tiberius/latest/tiberius/struct.Client.html
[`Config`]: https://docs.rs/tiberius/latest/tiberius/struct.Config.html
[`Query`]: https://docs.rs/tiberius/latest/tiberius/struct.Query.html
[`Command`]: https://docs.rs/tiberius/latest/tiberius/struct.Command.html
[`tiberius::error::Error`]: https://docs.rs/tiberius/latest/tiberius/error/enum.Error.html
