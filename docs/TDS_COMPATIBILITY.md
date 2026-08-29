# TDS Protocol Compatibility

This document tracks `tiberius-ng`'s coverage of the Microsoft Tabular Data
Stream (MS-TDS) protocol. It is a maintained snapshot — code references may
drift; treat the ratings as the source of truth and file an issue for
discrepancies.

Legend: ✅ full · 🟡 partial · ❌ missing · N/A not applicable.

## Protocol-version support

| TDS version | SQL Server | Rating | Notes |
|---|---|---|---|
| **8.0** | 2022 | 🟡 Partial | TLS-before-prelogin "strict" mode (`EncryptionLevel::Strict`) and `tds/8.0` ALPN on native-tls + rustls. opentls has no ALPN; client-certificate (mutual-TLS) login not implemented. Otherwise 8.0 == 7.4 semantics. |
| **7.4** | 2012–2019 | 🟡 Partial | Login (`FeatureLevel::SqlServerN`), routing ENVCHANGE, `fReadOnlyIntent`, FedAuth prelogin option + FeatureExt, FEATUREEXTACK. Missing: FEDAUTHINFO (0xEE), SESSIONSTATE (0xE4), session recovery. |
| **7.3 A/B** | 2008 / R2 | ✅ Full (`tds73`) | date / time / datetime2 / datetimeoffset types, NBCROW. |
| **7.2** | 2005 | 🟡 Partial | PLP / varchar(max), XML, MARS / transaction-descriptor headers. Missing: SQL_VARIANT, UDT. |
| **7.1** | 2000 | ✅ Full | Collation, UCS-2 strings, `n`-prefixed var-len types, LOGIN7 layout. |
| **7.0** | 7.0 | ❌ None | Legacy fixed non-nullable types unsupported; the client only negotiates 7.4. Not a target. |

There is **no Microsoft "TDS 6.0"** — the Microsoft protocol line is
7.0 → 7.1 → 7.2 → 7.3A → 7.3B → 7.4 → 8.0. Sybase-era TDS 4.2/5.0 predate
MS-TDS and are a separate protocol lineage, out of scope for this driver.
TDS 8.0 has no distinct LOGIN7 version — it reuses 7.4 tokens over mandatory
TLS, so "8.0" is a transport/ALPN distinction.

## Feature matrix

### Client → server messages
| Message | Status |
|---|---|
| PRELOGIN (0x12) | ✅ (INSTOPT/TRACEID/NONCEOPT decoded but not emitted) |
| LOGIN7 (0x10) | ✅ |
| SQL Batch (0x01) | ✅ |
| RPC request (0x03) | 🟡 by-ID procs ✅; named procs (see #328) |
| Bulk load (0x07) | ✅ |
| SSPI (0x11) | ✅ |
| FedAuth token | 🟡 via LOGIN7 FeatureExt only |
| Attention / cancel (0x06) | ❌ |
| Transaction Manager request (0x14) | ❌ (transactions use T-SQL batches) |

### Server → client tokens
| Token | Status |
|---|---|
| COLMETADATA, ROW, NBCROW, DONE/PROC/INPROC | ✅ |
| ENVCHANGE, ERROR/INFO, LOGINACK | ✅ |
| RETURNVALUE, RETURNSTATUS, ORDER, SSPI | ✅ |
| FEATUREEXTACK | 🟡 FEDAUTH only |
| FEDAUTHINFO (0xEE), SESSIONSTATE (0xE4), TABNAME (0xA4) | ❌ |
| COLINFO (0xA5) | 🟡 enum entry, no handler |
| ALTMETADATA / ALTROW (compute-by) | ❌ |

### Data types
| Type | Status |
|---|---|
| Fixed-len ints/bit/float/money/datetime(4) | ✅ |
| Nullable var-len (Intn/Bitn/Floatn/Guid/Money/Datetimen/Decimaln/Numericn) | ✅ |
| Char/binary + collation, Text/NText/Image | ✅ |
| PLP (max types), XML | ✅ |
| date / time / datetime2 / datetimeoffset (7.3) | ✅ (`tds73`) |
| Numeric / Decimal | ✅ |
| SQL_VARIANT (0x62) | ❌ (currently panics on read) |
| UDT (0xF0) | ❌ |

### Encryption & auth
| Feature | Status |
|---|---|
| Encryption NotSupported / Off / On / Required | ✅ |
| Strict (TDS 8.0, TLS-first) | ✅ (`tds80`) |
| `tds/8.0` ALPN | 🟡 native-tls + rustls ✅, opentls ❌ |
| ENCRYPT_CLIENT_CERT (mutual TLS) | ❌ |
| SQL auth (zeroized) | ✅ |
| Windows NTLM/SSPI (Windows `winauth`; Unix `sspi-rs`) | ✅ |
| Kerberos/GSSAPI (Unix `integrated-auth-gssapi`) | ✅ |
| AAD / federated token | 🟡 security-token library only |

## Prioritized gaps to reach "100%"

**High (correctness):**
1. SQL_VARIANT decode — panics today (M)
2. Named-proc RPC + OUT/TVP (addressed by #328) (M)
3. COLINFO (0xA5) handler (S)

**Medium (7.4/8.0 completeness):**
4. FEDAUTHINFO + SESSIONSTATE tokens (M)
5. TABNAME + ALTMETADATA/ALTROW (M)
6. opentls `tds/8.0` ALPN (S)
7. ENCRYPT_CLIENT_CERT mutual-TLS login (M)

**Lower:**
8. Attention signal / query cancellation (M)
9. Transaction Manager requests (0x14) (L)
10. PRELOGIN INSTOPT emission + instance validation (S)
11. UDT type support (L)
