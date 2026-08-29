# Tiberius
[![crates.io](https://meritbadge.herokuapp.com/tiberius)](https://crates.io/crates/tiberius)
[![docs.rs](https://docs.rs/tiberius/badge.svg)](https://docs.rs/tiberius)
[![Cargo tests](https://github.com/prisma/tiberius/actions/workflows/test.yml/badge.svg)](https://github.com/prisma/tiberius/actions/workflows/test.yml)
[![Chat](https://img.shields.io/discord/664092374359605268)](https://discord.gg/xX4xp9x)

A native Microsoft SQL Server (TDS) client for Rust.

### Goals

- A perfect implementation of the TDS protocol.
- Asynchronous network IO.
- Independent of the network protocol.
- Support for latest versions of Linux, Windows and macOS.

Tiberius speaks the TDS protocol directly, so you can talk to **Microsoft SQL
Server** and **Azure SQL** from Rust on Linux, macOS and Windows — with no ODBC,
no FreeTDS, and no C toolchain in the default build. It is not tied to any async
runtime: give it anything implementing `AsyncRead + AsyncWrite` (Tokio or
smol) and it does the rest.

- Connection pooling (use [bb8](https://crates.io/crates/bb8), [mobc](https://crates.io/crates/mobc), [deadpool](https://crates.io/crates/deadpool) or any of the other asynchronous connection pools)
- Query building
- Object-relational mapping

### Supported SQL Server versions

- 🔌 **Runtime-agnostic** — works with Tokio and smol (any `AsyncRead + AsyncWrite`).
- 🔐 **TLS-first, incl. TDS 8.0 "strict"** — `native-tls`, `rustls`, or vendored
  OpenSSL; `hostname_in_certificate`, ALPN `tds/8.0`, and mutual-TLS client
  certificates.
- 🪪 **Every auth method** — SQL logins (password buffers zeroized), Windows
  integrated auth (SSPI on Windows **and NTLM on Linux/macOS without Kerberos**),
  Kerberos/GSSAPI, and Azure AD tokens.
- 🧱 **Rich data access** — typed rows, `chrono`/`time`/`rust_decimal`/`bigdecimal`,
  optional `serde`, streaming results, and column metadata (type, size, scale,
  nullability, identity).
- ⚡ **Real workloads** — bulk insert (whole-table or a column list), stored
  procedures with **named parameters, OUT params and table-valued parameters**,
  transactions, `IN (…)` list helpers, `MultiSubnetFailover`, and query
  cancellation.
- 🛡️ **Secure & audited** — CI enforces `cargo-deny` (zero advisories), and every
  release is cut from a fully green pipeline.

### Feature flags

| Flag                     | Description                                                                                                                      | Default    |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------|------------|
| `tds73`                  | Support for new date and time types in TDS version 7.3. Disable if using version 7.2.                                            | `enabled`  |
| `native-tls`             | Use operating system's TLS libraries for traffic encryption.                                                                     | `enabled`  |
| `rustls`                 | Use the builtin TLS implementation from rustls instead of linking to the operating system implementation for traffic encryption. | `disabled` |
| `vendored-openssl`       | Statically link against OpenSSL instead of dynamically linking to the operating system implementation for traffic encryption.    | `disabled` |
| `chrono`                 | Read and write date and time values using `chrono`'s types. (for greenfield, using time instead of chrono is recommended)        | `disabled` |
| `time`                   | Read and write date and time values using `time` crate types.                                                                    | `disabled` |
| `rust_decimal`           | Read and write `numeric`/`decimal` values using `rust_decimal`'s `Decimal`.                                                      | `disabled` |
| `bigdecimal`             | Read and write `numeric`/`decimal` values using `bigdecimal`'s `BigDecimal`.                                                     | `disabled` |
| `sql-browser-async-std`  | SQL Browser implementation for the `TcpStream` of async-std.                                                                     | `disabled` |
| `sql-browser-tokio`      | SQL Browser implementation for the `TcpStream` of Tokio.                                                                         | `disabled` |
| `sql-browser-smol`       | SQL Browser implementation for the `TcpStream` of smol.                                                                          | `disabled` |
| `integrated-auth-gssapi` | Support for using Integrated Auth via GSSAPI                                                                                     | `disabled` |

### Supported protocols

Tiberius does not rely on any protocol when connecting to an SQL Server instance. Instead the `Client` takes a socket that implements the `AsyncRead` and `AsyncWrite` traits from the [futures-rs](https://crates.io/crates/futures) crate.

Currently there are good async implementations for TCP in the [async-std](https://crates.io/crates/async-std), [Tokio](https://crates.io/crates/tokio) and [Smol](https://crates.io/crates/smol) projects.

To be able to use them together with Tiberius on Windows platforms with SQL Server, you should make sure that the TCP protocol is enabled, as depending on the edition, this may not be the case. Standard and Enterprise editions will have the setting enabled by default, whereas Developer, Express editions and the Windows Internal Database feature of the Windows Server OS don't.
To enable the TCP/IP protocol you may want to use  the [server settings](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/enable-or-disable-a-server-network-protocol) the [command line](https://docs.microsoft.com/en-us/sql/powershell/how-to-enable-tcp-sqlps).
In the official [Docker image](https://hub.docker.com/_/microsoft-mssql-server) TCP is is enabled by default.

Named pipes should work by using the [NamedPipeClient](https://docs.rs/tokio/1.9.0/tokio/net/windows/named_pipe/struct.NamedPipeClient.html) from the latest Tokio versions.

The shared memory protocol is not documented and seems there are no Rust crates implementing it.

### Encryption (TLS/SSL)

Tiberius can be set to use two different implementations of TLS connection encryption. By default it uses `native-tls`, linking to the TLS library provided by the operating system. This is a good practice and in case of security vulnerabilities, upgrading the system libraries fixes the vulnerability in Tiberius without a recompilation. On Linux we link against OpenSSL, on Windows against schannel and on macOS against Security Framework.

Alternatively one can use the `rustls` feature flag to use the Rust native TLS implementation. This way there are no dynamic dependencies to the system. This might be useful in certain installations, but requires a rebuild to update to a new TLS version. For some reasons the Security Framework on macOS does not work with SQL Server TLS settings, and on Apple platforms if needing TLS it is recommended to use `rustls` instead of `native-tls`. The other option is to use the `vendored-openssl` feature flag, that statically links against the latest OpenSSL implementation.

The crate can also be compiled without TLS support, but not with both features enabled at the same time.

Tiberius has three runtime encryption settings:

| Encryption level | Description                                      |
|------------------|--------------------------------------------------|
| `Required`       | All traffic is encrypted. (default)              |
| `Off`            | Only the login procedure is encrypted.           |
| `NotSupported`   | None of the traffic is encrypted.                |

The encryption levels can be set when connecting to the database.

### Integrated Authentication (TrustedConnection) on \*nix

With the `integrated-auth-gssapi` feature enabled, the crate requires the GSSAPI/Kerberos libraries/headers installed:
  * [CentOS](https://pkgs.org/download/krb5-devel)
  * [Arch](https://www.archlinux.org/packages/core/x86_64/krb5/)
  * [Debian](https://tracker.debian.org/pkg/krb5) (you need the -dev packages to build)
  * [Ubuntu](https://packages.ubuntu.com/bionic-updates/libkrb5-dev)
  * NixOS: Run `nix-shell shell.nix` on the repository root.
  * Mac: as of version `0.4.2` the [libgssapi](https://crates.io/crates/libgssapi) crate used for this feature now uses Apple's [GSS Framework](https://developer.apple.com/documentation/gss?language=objc) which ships with MacOS 10.14+.

Additionally, your runtime system will need to be trusted by and configured for the Active Directory domain your SQL Server is part of. In particular, you'll need to be able to get a valid TGT for your identity, via `kinit` or a keytab. This setup varies by environment and OS, but your friendly network/system administrator should be able to help figure out the specifics.

## Redirects

With certain Azure firewall settings, a login might return `Error::Routing { host, port }`. This means the user must create a new `TcpStream` to the given address, and connect again.

A simple connection procedure would then be:

```rust
use tiberius::{Client, Config, AuthMethod, error::Error};
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();

    config.host("0.0.0.0");
    config.port(1433);
    config.authentication(AuthMethod::sql_server("SA", "<Mys3cureP4ssW0rD>"));

    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;

    let client = match Client::connect(config, tcp.compat_write()).await {
        // Connection successful.
        Ok(client) => client,
        // The server wants us to redirect to a different address
        Err(Error::Routing { host, port }) => {
            let mut config = Config::new();

            config.host(&host);
            config.port(port);
            config.authentication(AuthMethod::sql_server("SA", "<Mys3cureP4ssW0rD>"));

            let tcp = TcpStream::connect(config.get_addr()).await?;
            tcp.set_nodelay(true)?;

            // we should not have more than one redirect, so we'll short-circuit here.
            Client::connect(config, tcp.compat_write()).await?
        }
        Err(e) => Err(e)?,
    };

    Ok(())
}
```

Prefer a connection string? `Config::from_ado_string("Server=tcp:localhost,1433;User Id=SA;Password=…;Encrypt=strict;")`
and `Config::from_jdbc_string(…)` are both supported, or build one fluently with
[`ConfigBuilder`](https://docs.rs/tiberius-ng/latest/tiberius/struct.ConfigBuilder.html).

## Feature flags

| Flag | Purpose | Default |
|---|---|:---:|
| `tds73` | TDS 7.3 date/time types (`date`, `time`, `datetime2`, `datetimeoffset`) | ✅ |
| `tds80` | TDS 8.0 support incl. `EncryptionLevel::Strict` (requires a TLS backend) | ✅ |
| `native-tls` | Encryption via the OS TLS stack (schannel / Secure Transport / OpenSSL) | ✅ |
| `rustls` | Pure-Rust TLS via `rustls` (recommended on macOS/Apple) | |
| `vendored-openssl` | Statically-linked OpenSSL | |
| `chrono` / `time` | Date-time values via `chrono` / the `time` crate | |
| `rust_decimal` / `bigdecimal` | `numeric`/`decimal` via `Decimal` / `BigDecimal` | |
| `serde` | `Serialize`/`Deserialize` for result types | |
| `sql-browser-tokio` / `-smol` | Resolve named instances via SQL Browser | |
| `integrated-auth-gssapi` | Kerberos/GSSAPI integrated auth (Unix) | |
| `sspi-rs` | Windows-style NTLM auth on Linux/macOS without Kerberos | |

The three TLS backends are mutually exclusive. See the [docs](https://docs.rs/tiberius-ng)
for the full API.

## Runtimes

Tiberius takes any `AsyncRead + AsyncWrite` socket, so it runs under:

- **Tokio** — wrap the stream with `tokio_util::compat`.
- **smol** — pass the `TcpStream` directly.

Connection pooling is intentionally out of scope — use
[`bb8`](https://crates.io/crates/bb8), [`deadpool`](https://crates.io/crates/deadpool)
or [`mobc`](https://crates.io/crates/mobc).

## Encryption & authentication

Encryption levels: `NotSupported`, `Off`, `Required` (default), and **`Strict`**
(TDS 8.0, TLS before the pre-login). Validate against a specific certificate name
with `Config::hostname_in_certificate(…)`, and present a client certificate for
mutual TLS with `Config::client_certificate(…)`.

Authentication methods: `AuthMethod::sql_server(...)`, `AuthMethod::windows(...)`
(SSPI on Windows, `sspi-rs` NTLM on Unix), `AuthMethod::Integrated` (Kerberos on
Unix with `integrated-auth-gssapi`), and `AuthMethod::aad_token(...)` for Azure AD.

## Compatibility

| SQL Server | Status |
|---|---|
| 2022, 2019, 2017 | Tested in CI (Linux containers) |
| Azure SQL Database / Managed Instance | Supported (`Encrypt=strict` / AAD) |
| Azure SQL Edge | Tested in CI |
| 2016 → 2005 | Supported via the TDS protocol |

Protocol coverage spans **TDS 7.2 through 8.0** — see
[`docs/TDS_COMPATIBILITY.md`](docs/TDS_COMPATIBILITY.md) for the full
message/token/type matrix.

## Testing

Unit tests run with `cargo test`. Integration tests need a live server; the
easiest way is the bundled helper:

```bash
./docker/test-server.sh              # starts SQL Server (docker or podman)
export TIBERIUS_TEST_CONNECTION_STRING="server=tcp:localhost,1433;user=SA;password=<YourStrong@Passw0rd>;TrustServerCertificate=true"
cargo test --features all
```

CI follows the `dev → qa → main` lifecycle:

- **PRs and `dev`** run a fast lane — lint, unit tests, and one integration smoke
  (SQL Server 2022) — so day-to-day iteration stays quick.
- **`qa`** runs the full UAT: the integration suite against SQL Server
  2017 / 2019 / 2022 / 2025 and Azure SQL Edge across every feature combination,
  plus Windows (integrated auth) and macOS builds. A green `qa` means the release
  is ready.
- **`main`** is a fast promotion from an already-green `qa`; tagging `v*` triggers
  the release workflow (verify → publish to crates.io → GitHub release).

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Contributing

Contributions are very welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Target PRs at the `dev` branch. Bugs and
feature requests go in the [issue tracker](https://github.com/MattJackson/tiberius-ng/issues).

## Security

If you have a security issue to report, please contact us at [security@prisma.io](mailto:security@prisma.io?subject=[GitHub]%20Prisma%202%20Security%20Report%20Tiberius)
