# TDS Protocol Compatibility

This document tracks `tiberius`'s coverage of the Microsoft Tabular Data
Stream (MS-TDS) protocol. It is a maintained snapshot — code references may
drift; treat the ratings as the source of truth and file an issue for
discrepancies.

Legend: ✅ full · 🟡 partial · ❌ missing · N/A not applicable.

## Protocol-version support

| TDS version | SQL Server | Rating | Notes |
|---|---|---|---|
| **8.0** | 2022 | ✅ Full | TLS-before-prelogin "strict" mode (`EncryptionLevel::Strict`), `tds/8.0` ALPN, and client-certificate (mutual-TLS) login on native-tls + rustls. 8.0 reuses 7.4 tokens over mandatory TLS; the only backend caveat is that opentls cannot advertise ALPN (see below). |
| **7.4** | 2012–2019 | ✅ Full | Login (`FeatureLevel::SqlServerN`), routing ENVCHANGE, `fReadOnlyIntent`, FedAuth prelogin option + FeatureExt, FEATUREEXTACK, FEDAUTHINFO (0xEE), SESSIONSTATE (0xE4). The only deferral is *transparent reconnect* — SESSIONSTATE is decoded and stored, but not yet replayed to silently re-establish a dropped session. |
| **7.3 A/B** | 2008 / R2 | ✅ Full (`tds73`) | date / time / datetime2 / datetimeoffset types, NBCROW. |
| **7.2** | 2005 | ✅ Full | PLP / varchar(max), XML, MARS / transaction-descriptor headers, SQL_VARIANT (read + write), UDT (0xF0) raw-value decode. |
| **7.1** | 2000 | ✅ Full | Collation, UCS-2 strings, `n`-prefixed var-len types, LOGIN7 layout. |
| **7.0** | 7.0 | ❌ None | Legacy fixed non-nullable types unsupported; the client only negotiates 7.4. Not a target. |

There is **no Microsoft "TDS 6.0"** — the Microsoft protocol line is
7.0 → 7.1 → 7.2 → 7.3A → 7.3B → 7.4 → 8.0. Sybase-era TDS 4.2/5.0 predate
MS-TDS and are a separate protocol lineage, out of scope for this driver.
TDS 8.0 has no distinct LOGIN7 version — it reuses 7.4 tokens over mandatory
TLS, so "8.0" is a transport/ALPN distinction.

**Summary:** TDS 7.1 through 8.0 are fully supported. The only remaining
elements are optional and rarely used: transparent session recovery (the
SESSIONSTATE token is decoded and stored, just not replayed on reconnect),
CLR UDT *object* deserialization (raw bytes are surfaced), and `tds/8.0` ALPN
on the opentls backend (an upstream-crate limitation) — none of which any
standard query, bulk-load, RPC, or transaction path depends on.

## Feature matrix

### Client → server messages
| Message | Status |
|---|---|
| PRELOGIN (0x12) | ✅ (VERSION/ENCRYPTION/INSTOPT/THREADID/MARS emitted; server options decoded and INSTOPT validated) |
| LOGIN7 (0x10) | ✅ |
| SQL Batch (0x01) | ✅ |
| RPC request (0x03) | ✅ by-ID procs and named procs, incl. OUT params and table-valued parameters (#328) |
| Bulk load (0x07) | ✅ whole-table and column-list |
| SSPI (0x11) | ✅ |
| FedAuth token | ✅ via LOGIN7 FeatureExt |
| Attention / cancel (0x06) | ✅ (`Client::cancel_query`) |
| Transaction Manager request (0x14) | ✅ (`begin`/`commit`/`rollback` with isolation levels) |

### Server → client tokens
| Token | Status |
|---|---|
| COLMETADATA, ROW, NBCROW, DONE/PROC/INPROC | ✅ |
| ENVCHANGE, ERROR/INFO, LOGINACK | ✅ |
| RETURNVALUE, RETURNSTATUS, ORDER, SSPI | ✅ |
| FEATUREEXTACK | ✅ |
| ALTMETADATA / ALTROW (compute-by) | ✅ |
| COLINFO (0xA5) | ✅ |
| TABNAME (0xA4) | ✅ |
| FEDAUTHINFO (0xEE) | ✅ (STSURL + SPN surfaced for AAD flows) |
| SESSIONSTATE (0xE4) | ✅ decoded + stored (transparent-reconnect replay not yet implemented) |

### Data types
| Type | Status |
|---|---|
| Fixed-len ints/bit/float/money/datetime(4) | ✅ |
| Nullable var-len (Intn/Bitn/Floatn/Guid/Money/Datetimen/Decimaln/Numericn) | ✅ |
| Char/binary + collation, Text/NText/Image | ✅ |
| PLP (max types), XML | ✅ |
| date / time / datetime2 / datetimeoffset (7.3) | ✅ (`tds73`) |
| Numeric / Decimal (incl. automatic scale rescaling of params) | ✅ |
| SQL_VARIANT (0x62) | ✅ read + write |
| UDT (0xF0) | ✅ raw-value decode (surfaced as bytes; CLR object deserialization out of scope) |

### Encryption & auth
| Feature | Status |
|---|---|
| Encryption NotSupported / Off / On / Required | ✅ |
| Strict (TDS 8.0, TLS-first) | ✅ (`tds80`) |
| `tds/8.0` ALPN | 🟡 native-tls + rustls ✅, opentls ❌ (backend cannot advertise ALPN) |
| ENCRYPT_CLIENT_CERT (mutual TLS) | ✅ (`Config::client_certificate` / `client_certificate_pkcs12`) |
| SQL auth (zeroized) | ✅ |
| Windows NTLM/SSPI (Windows `winauth`; Unix `sspi-rs`) | ✅ |
| Kerberos/GSSAPI (Unix `integrated-auth-gssapi`) | ✅ |
| AAD / federated token | ✅ (`AuthMethod::aad_token`) |

## Remaining optional items

None of the following block standard operation; they are tracked for
completeness and would be additive, backward-compatible features:

- **Transparent session recovery** — the SESSIONSTATE token is already decoded
  and stored; replaying it to silently re-establish a dropped connection is the
  remaining step.
- **CLR UDT object deserialization** — UDT values are decoded to raw bytes;
  interpreting them into CLR objects (e.g. `geometry`) is left to the caller.
- **opentls `tds/8.0` ALPN** — verified infeasible with `opentls` 0.2.1's public
  API (no ALPN setter; the wrapped `SslConnector` is private). Use native-tls or
  rustls for TDS 8.0 strict mode. Tracked upstream against the `opentls` crate.
