# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This is a maintained community fork of [`tiberius`](https://github.com/prisma/tiberius),
published on crates.io under the package name
[`tiberius-ng`](https://crates.io/crates/tiberius-ng). The library name remains
`tiberius`, so `use tiberius::…` code is unaffected. Entries up to and including
version 0.12.3 reflect the history of the upstream project prior to the fork.

## [Unreleased]

We are working through the backlog of open pull requests and issues from
upstream. Additional fixes and features are being integrated and will appear
here as they land.

### Added

- (Backlog) Further community PRs and issue fixes are being triaged and
  integrated; see the [issue tracker](https://github.com/MattJackson/tiberius-ng/issues).

### Fixed

- (Backlog) Outstanding bug reports carried over from upstream are being
  reviewed and resolved.

### Changed

- (Backlog) Ongoing dependency maintenance to keep the crate free of security
  advisories.

## [0.13.0] - 2026-08-29

First release of the actively-maintained community fork, by
[@MattJackson](https://github.com/MattJackson). Published on crates.io as
[`tiberius-ng`](https://crates.io/crates/tiberius-ng); the importable library
name is still `tiberius`, so downstream `use tiberius::…` code is unaffected —
only the dependency line changes:

```toml
tiberius = { package = "tiberius-ng", version = "0.13" }
```

This release clears the security advisories that were blocking adoption, works
through a large backlog of community pull requests (attributed below), fixes
long-standing bug reports, and substantially extends TDS protocol coverage
(TDS 7.1 through 8.0). See [`docs/TDS_COMPATIBILITY.md`](docs/TDS_COMPATIBILITY.md).

### Security

- Upgraded the TLS stack (`tokio-rustls` 0.24 → 0.26, `rustls` 0.21 → 0.23),
  clearing **RUSTSEC-2026-0098/-0099/-0104** and unblocking `cargo audit` /
  `cargo deny`. From upstream #419 by [@jakewimmer](https://github.com/jakewimmer).
  Fixes #417, #428.
- Zeroize SQL authentication password buffers before/after the login exchange.
  From #411 by [@lstkz](https://github.com/lstkz).
- Added a `cargo-deny` supply-chain gate (`deny.toml` + Security-audit workflow)
  and a Codecov coverage workflow; enforced in CI on every push/PR.

### Added — connectivity & protocol

- **TDS 8.0 "strict" encryption** (`EncryptionLevel::Strict`, TLS-before-prelogin
  with the `tds/8.0` ALPN), plus `Config::hostname_in_certificate()` and
  `Config::client_name()`. Adapted from #413 by [@olback](https://github.com/olback).
  Fixes #412, #340, #414, #224.
- **SQL_VARIANT** reading (previously panicked, `todo!()`) and writing — full
  `sql_variant` parameter support, symmetric with the decoder.
- **CLR UDT**, **COLINFO**, **TABNAME**, **FEDAUTHINFO**, **SESSIONSTATE**, and
  **ALTMETADATA/ALTROW** (`COMPUTE BY`) token support.
- **Transaction Manager requests** (begin/commit/rollback) and the **Attention**
  signal for query cancellation.
- **`Client::column_metadata()`** exposing column type/size/precision/scale,
  nullability and identity flags. From #398 by [@etylermoss](https://github.com/etylermoss).
  Fixes #397, #217, #403.
- Emit PRELOGIN INSTOPT/TRACEID options.

### Added — API & types

- Optional **`serde`** feature: `Serialize`/`Deserialize` for the result types.
  From #416 by [@MukundaKatta](https://github.com/MukundaKatta). Fixes #115.
- **`ConfigBuilder`** for ergonomic `Config` construction. From #366 by
  [@LonerDan](https://github.com/LonerDan).
- **IN-list / 2100-parameter helpers.** From #429 by
  [@joelparkerhenderson](https://github.com/joelparkerhenderson). Fixes #157.
- `bulk_insert_columns()` to bulk-insert into a specified column list. From #359
  by [@NTmatter](https://github.com/NTmatter). Fixes #311.
- `packet_size` configuration for the LOGIN7 message. From #400 by
  [@johndauphine](https://github.com/johndauphine).
- `IntoSql` for `rust_decimal::Decimal` (#376 by [@esheppa](https://github.com/esheppa),
  fixes #401); more `ColumnData` conversion traits (#314) and `Row`→`ColumnData`
  / `TokenRow` accessors (#304, #331) by [@LazyDope](https://github.com/LazyDope)
  and [@lpj145](https://github.com/lpj145).
- `docker/test-server.sh` helper and a named-pipes connection example (#430, #132).

### Fixed

- Return an `Error` instead of **panicking** on unexpected server input across
  the TDS decoder, and when the server declines the requested encryption level.
  Fixes #424, #425.
- Bounds-check column indexing so out-of-range `try_get` returns `Err`, not a
  panic (#211); match raw-identifier column names like `r#type` (#382).
- Fix a multiply-overflow panic decoding dates before 1900 (#316).
- Error at connect time when encryption is required but no TLS backend is
  compiled in (#305).
- Correct the swapped old/new values in `EnvChange` `Display` (#418); lower
  chatty per-connection/token logs from `info!` to `debug!` (#281).
- Convert SQL `smallint`/`Intn` into `i32` via `FromSql` (#263); coerce
  `DateTime2` → `datetime` for bulk insert under `tds73` (#298, from
  [@Geo-W](https://github.com/Geo-W); fixes #307, #373); coerce numerics into
  Money/SmallMoney and strings into NText/Text during bulk insert (#358, #352).
- Send the ReadOnly intent flag in LOGIN7 when `ApplicationIntent=ReadOnly` (#348).
- Fix the sign/padding of negative `Numeric` string formatting. From #390 by
  [@zuckschwerdt](https://github.com/zuckschwerdt). Fixes #368.
- Rescale `numeric`/`decimal` parameters to the target column scale (overflow-
  checked scale-up, round-half-away-from-zero scale-down) instead of panicking
  on a scale mismatch.
- Allow querying columns whose names are keywords such as `End` (#388, from
  [@cjordan](https://github.com/cjordan)).
- Improve `QueryStream::into_results` handling of empty results (#385, fixes #380);
  fix a header type for the SSPI response message (#351, from
  [@staticlibs](https://github.com/staticlibs)); correct an `occured` typo in an
  I/O error message (#423, from [@DucMinhNe](https://github.com/DucMinhNe)).

### Changed — tooling & housekeeping

- Rebranded to the maintained fork (`tiberius-ng` 0.13.0); repository, docs.rs,
  badges and metadata now point at
  [MattJackson/tiberius-ng](https://github.com/MattJackson/tiberius-ng).
- Modernized the GitHub Actions workflows (SHA-pinned actions); replaced the
  broken upstream security workflow; added Dependabot, issue/PR templates,
  `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and `SECURITY.md`.
- Restructured CI around the `dev → qa → main` lifecycle: a fast lane on
  PRs/`dev` (lint, unit tests, one integration smoke) and the full UAT matrix on
  `qa` — SQL Server 2017/2019/2022/**2025** and Azure SQL Edge across every
  feature combination, plus Windows and macOS. Added a tag-triggered release
  workflow (verify → publish to crates.io → GitHub release) and Codecov coverage.
- Fixed the docs.rs build (use the `docsrs` cfg instead of a nightly-only `docs`
  feature) and cleared all `clippy -D warnings`.
- Modernized dependencies and added ~90 unit tests, roughly doubling coverage.
- Declared an MSRV of Rust 1.88 (`rust-version`) with a dedicated CI job, and
  added an advisory `cargo-semver-checks` job plus a `cargo-deny` license gate.

### Removed

- **Dropped async-std support.** The discontinued `async-std` runtime
  (RUSTSEC-2025-0052) is no longer a supported runtime: the
  `sql-browser-async-std` feature, its SQL Browser implementation, and the
  async-std example/tests are removed, eliminating `async-std` from the
  dependency graph entirely. Tiberius remains runtime-independent — use **tokio**
  or **smol** (or any `AsyncRead + AsyncWrite` transport). The internal
  dual-runtime test harness now exercises every integration test on tokio **and**
  smol. *Breaking* for downstreams using the `sql-browser-async-std` feature;
  switch to `sql-browser-tokio` or `sql-browser-smol`.

### Notes

- `0.13.0-alpha.1` was published to crates.io to claim the `tiberius-ng`
  package name ahead of this release.
- Deferred to a follow-up: client-certificate (mutual-TLS) authentication
  (upstream #413's client-cert portion), which needs a rebase onto the new TLS
  stack and live-server validation.

## [0.12.3]

## Version 0.12.3
- feat: improve column type accuracy (#347)
- fix: encoding of zero-length values for large varlen columns (#315)
- update tokio_rustls (#306)
- Allow iterating over the cells in a row. (#303)
- Send ReadOnlyIntent when ApplicationIntent=ReadOnly specified (#297)
- Replace encoding with encoding_rs (#285)
- Disable chrono's oldtime feature (#284)

## Version 0.12.2

- Update connection-string crate to 0.2 (#286)

## Version 0.12.1

- fix: bigdecimal conversion overflow (#271)
- Reduce futures crate dependency footprint (#270)

## Version 0.12.0

- BREAKING: Correctly convert DateTimeOffset to/from database (#269)
  Please read the [issue](https://github.com/prisma/tiberius/issues/260)
  carefully before upgrading.

## Version 0.11.8

- feat: improve column type info (#347)

## Version 0.11.7

- chore: Update connection string to 0.2 (#286)

## Version 0.11.6

- fix: bigdecimal conversion overflow (#271)

## Version 0.11.5

- Close connection explicitly (#268)

## Version 0.11.4

- Fix buffer overrun on finalize (#266)
- Correctly parse (local) server name (#259)

## Version 0.11.3

- Cleanup TokenRow public API (#255)
- Fix null values in NBC rows (#253)

## Version 0.11.2

- Fix error ordering (#248)

## Version 0.11.1

- Don't load native roots for trust-all config (#243)
- Propagate errors correctly (#247)

## Version 0.11.0

- BREAKING: bigdecimal crate upgraded to 0.3 major and has to be of
  the same major in other crates using Tiberius.
- Handle negative scale from a BigDecimal (#240)

## Version 0.10.0

- BREAKING: uuid crate upgraded to 1.0 major and has to be of the same
  major in other crates using Tiberius.

## Version 0.9.5

- Add fractional seconds precision for datetime2 (#235)

## Version 0.9.4

- Fix SQL Browser response parsing error (#229)
- Bulk uploads (#227)

## Version 0.9.3

- Enable SSL if using vendored-openssl feature (#225)

## Version 0.9.2

- Allow statically linking against OpenSSL (#222)

## Version 0.9.1

- Support AAD token authentication (#215)

## Version 0.9.0

- (BREAKING) support rustls, switch between native-tls and rustls.
  the feature flag vendored-openssl is gone. instead if needing vendored TLS,
  use feature flag rustls

## Version 0.8.0

- (BREAKING) fix: correctly decode null integers (#209)

## Version 0.7.3

- Fixing an accidentally renamed time module, that would've been a breaking change.

## Version 0.7.2

- Dynamic query interface (#196)
- Support for `time` 0.3.x (#201)
- Additional option to add custom-ca to root certificates (#203, thx @lostiniceland)

## Version 0.7.1

- Support all pre-login tokens

## Version 0.7.0

- Remove async-std from deps if using tokio
- show TokioAsyncWriteCompatExt in Client docs (#183)
- Upgrade to Rust edition 2021 (#180)

## Version 0.6.5

- Constrain UUID features and optionalize winauth dependency (smaller binaries)

## Version 0.6.4

- Use bundled bigint from bigdecimal

## Version 0.6.3

- Bignum/bigint compilation problems fixed.

## Version 0.6.2

- Improvement on waker calls. We used to wake the runtime too often, this should improve performance.

## Version 0.6.1

- SQL Browser for the smol runtime.

## Version 0.6.0

- Refactor stream handling to something more rusty (#166). This is a breaking
  change, if relying on the asynchronous stream handling of QueryResult. Please
  refer to the updated documentation.

## Version 0.5.16

- Allow setting application name per connection (#161)

## Version 0.5.15

- Split column decoding into modules (speeding up TEXT/NTEXT/IMAGE decoding a lot) (#153)

## Version 0.5.14

- Handle collations for CHAR and TEXT values (#153)

## Version 0.5.13

- Add Config parsing for "Integrated Security" (two words)
- Unified bitflag setup
- Correct default ports
- Update to enumflags2 0.7

## Version 0.5.12

- Warnings should not affect metadata fetching (#139)

## Version 0.5.11

- Fixing of all clippy warnings. This might have some performance benefits and
might also fix some weird bugs in environments where we can't guarantee the
evaluation order. (#136)
- Add info of LCID and sort id to colation errors (#138)

## Version 0.5.10

- Remove a rogue `dbg!`

## Version 0.5.9

- Set the `app_name` in LOGIN7 to `tiberius`. This allows connecting to servers
  that expect the value to not be empty (see issue #127).

## Version 0.5.8

- Try out all resolved IP addresses (#124)

## Version 0.5.7

- Set server name in the login packet (#122)

## Version 0.5.6

-  Fix for handling nullable values (#119 #121)

## Version 0.5.5 and 0.4.21

Catastropichal build failures with feature flags fixed.

## Version 0.5.4 and 0.4.20

Removed the tls feature flag to simplify dependencies. This means you will
always get a TLS-enabled build, and can disable it on runtime. This also means
we don't always compile async-std if wanting to use tokio, and so forth.

Fixes certain issues with vendored OpenSSL on macOS platforms too.

## Version 0.5.3

Changed futures-codec2 to asynchronous-codec, due to former was yanked.

## Versions 0.5.2 and 0.4.19

Introducing working TLS support on macOS platforms.

Please read the issue:

https://github.com/prisma/tiberius/issues/65

## Version 0.5.1

Internally upgrade bytes to 1.0. Should have no visible change to the apis.

## Version 0.5.0

If using Tiberius with Tokio and SQL Browser, this PR will upgrade Tokio to 1.0.

0.4 branch will be updated for a short while if needed and until the ecosystem
has completely settled on Tokio 1.0.

## Version 0.4.18

- Allow `databaseName` in connection string to define the database (#108)
- Implement reader functions for standard string data (#107)
- Fix a time conversion error (#106)

## Version 0.4.17

- Fixing error swallowing with `simple_query` and MARS (#105)
- Fixing transaction descriptor reading (#105)
- Fixing envchange token reads (#105)

## Version 0.4.16

- Handle all MARS results properly (#102)

## Version 0.4.14

- Support alternatively `BigNumber` when dealing with numeric values.
- Document feature flags

## Version 0.4.13

- Realizing UTF-16 works just fine with SQL Server. Reverting the UCS2, but
  still keeping the faster writes.

## Version 0.4.12

*SKIP this, go directly to 0.4.13*

- A typo fix in README (#94)
- Faster string writes with better length handling. UCS2 for writes (#95).

## Version 0.4.11

- Allow disabling TLS in connection string (#89)
- Use connection-string for ado.net parsing (#91)
- Handle JDBC connection strings (#92)

## Version 0.4.10

- Handling nullable int values, fix for #78 (#80)
- Reflect tweaks to upstream libgssapi crate (#81)
- Skip default features in libgssapi (for macOS support)
- Handle env change Routing request (#87)

## Version 0.4.9

- BREAKING: `AuthMethod::WindowsIntegrated` renamed to `AuthMethod::Integrated`.
- Use GSSAPI for IntegratedSecurity on Unix platforms
- Fix module docs for examples
- Make `packet_id` wrapping explicit
- Add DNS feature to Tokio

## Version 0.4.8

- BREAKING: `ColumnData::I8(i8)` is now `ColumnData::U8(u8)` due to misunderstanding how `tinyint` works. (#71)
- Skip any received `done_rows` amounts and avoid creating extra resultsets (#67)
- Actually run the chrono tests (#72)
- Fix GUID byte ordering (#69)
- Fix null time/datetime2/datetimeoffset handling (#73)
- Null image data should be `Binary`, not `String`

## Version 0.4.7

- Pass hostname to TLS handshake, allowing usage with AzureSQL using
  `TrustServerCertificate=no`
  ([#62](https://github.com/prisma/tiberius/pull/62))

## Version 0.4.5

- Documenting type conversions and re-exporting chrono types
  ([#60](https://github.com/prisma/tiberius/pull/60))

## Version 0.4.4

- Fixing multi-part table names in `IMAGE`, `TEXT` and `NTEXT` column metadata
  ([#58](https://github.com/prisma/tiberius/pull/58))

## Version 0.4.3

- Starting transactions with `simple_query` now works without crashing
  ([#55](https://github.com/prisma/tiberius/pull/55))

## Version 0.4.2

- Fixing old and wrong `ExecuteResult` docs
- Adding `rows_affected` method to `ExecuteResult`

## Version 0.4.1

- Add all feature flags for docs.rs build

## Version 0.4.0

- A complete rewrite from 0.3.0
- Not bound to Tokio anymore, independent of the runtime
- Support for many more types
- Async/await, futures 0.3
