//! In-house ADO.NET-style connection-string tokenizer.
//!
//! Tiberius parses ADO.NET connection strings as a **superset** of the rules
//! documented for .NET's `DbConnectionStringBuilder`:
//!
//! - pairs are separated by `;`; empty pairs (a stray `;`, trailing `;`) are
//!   ignored;
//! - each pair is split on the **first** `=`, so a value may contain further
//!   `=` characters (for example the `=` padding on a base64 password); a `==`
//!   in the key position is a literal `=`;
//! - keys are trimmed and matched case-insensitively;
//! - an unquoted value is trimmed of surrounding whitespace; to keep `;`, a
//!   quote, or leading/trailing spaces, quote the value with `'…'` or `"…"` and
//!   double the enclosing quote to embed it (`"a""b"` → `a"b`);
//! - **extension (not ADO.NET):** `{…}` brace quoting is also accepted; the
//!   value runs to the first `}` and therefore cannot itself contain `}`.
//!
//! Only ASCII input is accepted; build [`Config`] programmatically for anything
//! else.
//!
//! The returned error is a terse reason; the caller wraps it with the escaping
//! hint (see `hinted_conversion_error`), so the messages here stay short.
//!
//! [`Config`]: crate::Config

use std::collections::HashMap;

/// A parsed ADO.NET connection string: a map of lower-cased keys to their
/// unescaped values.
#[derive(Debug)]
pub(crate) struct AdoNetString {
    pairs: HashMap<String, String>,
}

impl AdoNetString {
    /// The parsed key/value pairs (keys lower-cased).
    pub(crate) fn pairs(&self) -> &HashMap<String, String> {
        &self.pairs
    }
}

/// Parses an ADO.NET connection string. On failure returns a terse reason the
/// caller turns into a hinted [`crate::Error`].
pub(crate) fn parse(input: &str) -> Result<AdoNetString, &'static str> {
    // The parser is byte-oriented for a single reason: every character it
    // treats specially (`;`, `=`, `'`, `"`, `{`, `}`, whitespace) is ASCII, and
    // rejecting non-ASCII up front lets the byte index and the char index stay
    // identical without any multi-byte bookkeeping.
    if !input.is_ascii() {
        return Err("the connection string contains non-ASCII characters");
    }

    let b = input.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut pairs = HashMap::new();

    while i < n {
        // Between pairs, skip separators and surrounding whitespace.
        while i < n && (b[i] == b';' || b[i].is_ascii_whitespace()) {
            i += 1;
        }
        if i >= n {
            break;
        }

        // Key: everything up to the first single `=`. A `==` is a literal `=`.
        let mut key = String::new();
        loop {
            if i >= n || b[i] == b';' {
                return Err("key-value pairs must be joined by a `=`");
            }
            if b[i] == b'=' {
                if i + 1 < n && b[i + 1] == b'=' {
                    key.push('=');
                    i += 2;
                    continue;
                }
                i += 1; // consume the separating `=`
                break;
            }
            key.push(b[i] as char);
            i += 1;
        }
        let key = key
            .trim_matches(|c: char| c.is_ascii_whitespace())
            .to_ascii_lowercase();
        if key.is_empty() {
            return Err("a key in the connection string is empty");
        }

        // Value: leading whitespace before the value is not significant.
        while i < n && b[i].is_ascii_whitespace() {
            i += 1;
        }

        let value = if i < n && (b[i] == b'\'' || b[i] == b'"') {
            let quote = b[i];
            i += 1;
            let mut v = String::new();
            loop {
                if i >= n {
                    return Err(if quote == b'\'' {
                        "the connection string has an unclosed single quote"
                    } else {
                        "the connection string has an unclosed double quote"
                    });
                }
                if b[i] == quote {
                    // A doubled quote is a literal quote; a lone quote closes.
                    if i + 1 < n && b[i + 1] == quote {
                        v.push(quote as char);
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                v.push(b[i] as char);
                i += 1;
            }
            skip_trailing(b, &mut i, "unexpected characters after a quoted value")?;
            v
        } else if i < n && b[i] == b'{' {
            i += 1;
            let mut v = String::new();
            loop {
                if i >= n {
                    return Err("the connection string has an unclosed brace `{`");
                }
                if b[i] == b'}' {
                    i += 1;
                    break;
                }
                v.push(b[i] as char);
                i += 1;
            }
            skip_trailing(
                b,
                &mut i,
                "unexpected characters after a `{…}` value; quote with '' or \"\" if the value contains `}`",
            )?;
            v
        } else {
            // Unquoted: runs to the next `;`, with surrounding whitespace
            // trimmed (leading was already skipped above). Trimming uses the
            // same ASCII-whitespace definition as the leading skip so a value
            // is not truncated differently at its two ends.
            let start = i;
            while i < n && b[i] != b';' {
                i += 1;
            }
            input[start..i]
                .trim_end_matches(|c: char| c.is_ascii_whitespace())
                .to_string()
        };

        // Duplicate keys: last one wins, matching ADO.NET.
        pairs.insert(key, value);

        if i < n && b[i] == b';' {
            i += 1;
        }
    }

    Ok(AdoNetString { pairs })
}

/// After a closing quote or brace, only whitespace may precede the next `;` or
/// the end of the string; anything else is reported with `err`.
fn skip_trailing(b: &[u8], i: &mut usize, err: &'static str) -> Result<(), &'static str> {
    while *i < b.len() && b[*i] != b';' {
        if !b[*i].is_ascii_whitespace() {
            return Err(err);
        }
        *i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse;

    /// Parse and return the single value stored under `key`, panicking with the
    /// parser error if parsing failed.
    fn value(s: &str, key: &str) -> Option<String> {
        parse(s)
            .unwrap_or_else(|e| panic!("`{s}` failed to parse: {e}"))
            .pairs()
            .get(key)
            .cloned()
    }

    #[test]
    fn basic_pairs() {
        let p = parse("Server=host;Database=db;User Id=sa;Password=pw").unwrap();
        assert_eq!(p.pairs().get("server").map(String::as_str), Some("host"));
        assert_eq!(p.pairs().get("database").map(String::as_str), Some("db"));
        assert_eq!(p.pairs().get("user id").map(String::as_str), Some("sa"));
        assert_eq!(p.pairs().get("password").map(String::as_str), Some("pw"));
    }

    #[test]
    fn keys_are_lowercased_and_trimmed() {
        assert_eq!(value("  SeRVeR  =host", "server").as_deref(), Some("host"));
        assert_eq!(value("USER ID=sa", "user id").as_deref(), Some("sa"));
    }

    #[test]
    fn splits_each_pair_on_the_first_equals() {
        // A value may contain further `=` (base64 padding etc.); see #313.
        assert_eq!(
            value("Password=ab=cd", "password").as_deref(),
            Some("ab=cd")
        );
        assert_eq!(
            value("Password=Zm9vYmFy==", "password").as_deref(),
            Some("Zm9vYmFy==")
        );
        assert_eq!(value("k=a=b=c=", "k").as_deref(), Some("a=b=c="));
    }

    #[test]
    fn double_equals_in_key_is_a_literal_equals() {
        // `k==v` reads as the key `k=v` with no separator, hence an error; a
        // value that must *start* with `=` has to be quoted instead.
        assert!(parse("k==v").is_err());
        assert_eq!(value("k='=v'", "k").as_deref(), Some("=v"));
        assert_eq!(value("a==b=c", "a=b").as_deref(), Some("c"));
    }

    #[test]
    fn empty_pairs_are_ignored() {
        assert_eq!(value(";;Server=host;;", "server").as_deref(), Some("host"));
        assert_eq!(value("Server=host;", "server").as_deref(), Some("host"));
        assert_eq!(value(";Server=host", "server").as_deref(), Some("host"));
        assert!(parse("").unwrap().pairs().is_empty());
        assert!(parse("   ").unwrap().pairs().is_empty());
        assert!(parse(";;;").unwrap().pairs().is_empty());
    }

    #[test]
    fn whitespace_between_pairs_is_ignored() {
        let p = parse("Server=host ; Database=db").unwrap();
        assert_eq!(p.pairs().get("server").map(String::as_str), Some("host"));
        assert_eq!(p.pairs().get("database").map(String::as_str), Some("db"));
    }

    #[test]
    fn unquoted_values_are_trimmed_both_sides() {
        assert_eq!(value("k=   a b   ", "k").as_deref(), Some("a b"));
        assert_eq!(value("k=", "k").as_deref(), Some(""));
        assert_eq!(value("k=   ", "k").as_deref(), Some(""));
    }

    #[test]
    fn quotes_preserve_surrounding_whitespace() {
        assert_eq!(value("k=' a '", "k").as_deref(), Some(" a "));
        assert_eq!(value("k=\" a \"", "k").as_deref(), Some(" a "));
        assert_eq!(value("k='   '", "k").as_deref(), Some("   "));
    }

    #[test]
    fn quotes_hold_structural_characters() {
        assert_eq!(value("k='a;b=c{d'", "k").as_deref(), Some("a;b=c{d"));
        assert_eq!(value("k=\"a;b=c{d\"", "k").as_deref(), Some("a;b=c{d"));
        // The other quote character is a literal inside.
        assert_eq!(value("k='a\"b'", "k").as_deref(), Some("a\"b"));
        assert_eq!(value("k=\"a'b\"", "k").as_deref(), Some("a'b"));
    }

    #[test]
    fn doubled_quote_embeds_the_quote() {
        assert_eq!(value("k='a''b'", "k").as_deref(), Some("a'b"));
        assert_eq!(value("k=\"a\"\"b\"", "k").as_deref(), Some("a\"b"));
        assert_eq!(value("k=''''", "k").as_deref(), Some("'")); // '' '' -> one '
    }

    #[test]
    fn braces_hold_structural_characters() {
        assert_eq!(value("k={a;b=c}", "k").as_deref(), Some("a;b=c"));
        assert_eq!(value("k={a'b\"c}", "k").as_deref(), Some("a'b\"c"));
    }

    #[test]
    fn brace_cannot_contain_close_brace() {
        // Closes at the first `}`; trailing content is an error, not folded in.
        assert_eq!(
            parse("k={a}b}").unwrap_err(),
            "unexpected characters after a `{…}` value; quote with '' or \"\" if the value contains `}`"
        );
        assert_eq!(value("k={a}", "k").as_deref(), Some("a"));
    }

    #[test]
    fn trailing_junk_after_quote_is_rejected() {
        assert_eq!(
            parse("k='ab'x").unwrap_err(),
            "unexpected characters after a quoted value"
        );
        assert_eq!(
            parse("k=\"ab\"x").unwrap_err(),
            "unexpected characters after a quoted value"
        );
        // Trailing whitespace after a closing quote is fine.
        assert_eq!(value("k='ab'  ;n=1", "k").as_deref(), Some("ab"));
    }

    #[test]
    fn empty_quoted_value() {
        assert_eq!(value("k=''", "k").as_deref(), Some(""));
        assert_eq!(value("k=\"\"", "k").as_deref(), Some(""));
        assert_eq!(value("k={}", "k").as_deref(), Some(""));
    }

    #[test]
    fn ascii_control_bytes_are_not_treated_as_trim_whitespace() {
        // A trailing vertical tab (0x0B) is content, not whitespace: it must be
        // preserved, consistently with the leading-whitespace skip which also
        // ignores 0x0B. (str::trim_end would wrongly strip it.)
        assert_eq!(
            value("k=secret\u{000B}", "k").as_deref(),
            Some("secret\u{000B}")
        );
        // Ordinary ASCII whitespace is still trimmed when unquoted.
        assert_eq!(value("k=secret\t ", "k").as_deref(), Some("secret"));
        // Keys use the same ASCII-whitespace definition: ASCII spaces are
        // trimmed, but a 0x0B is content (kept), consistent with values.
        assert_eq!(value("  k  =v", "k").as_deref(), Some("v"));
        assert_eq!(value("k\u{000B}=v", "k\u{000B}").as_deref(), Some("v"));
    }

    #[test]
    fn duplicate_keys_last_wins() {
        assert_eq!(value("k=a;k=b;k=c", "k").as_deref(), Some("c"));
    }

    #[test]
    fn server_value_passes_through_raw() {
        assert_eq!(
            value("Server=tcp:host.example.com,1433", "server").as_deref(),
            Some("tcp:host.example.com,1433")
        );
        assert_eq!(
            value("Server=host\\instance", "server").as_deref(),
            Some("host\\instance")
        );
    }

    #[test]
    fn error_reasons() {
        assert_eq!(
            parse("=value").unwrap_err(),
            "a key in the connection string is empty"
        );
        assert_eq!(
            parse("k=a;b").unwrap_err(),
            "key-value pairs must be joined by a `=`"
        );
        assert_eq!(
            parse("k='ab").unwrap_err(),
            "the connection string has an unclosed single quote"
        );
        assert_eq!(
            parse("k=\"ab").unwrap_err(),
            "the connection string has an unclosed double quote"
        );
        assert_eq!(
            parse("k={ab").unwrap_err(),
            "the connection string has an unclosed brace `{`"
        );
        assert!(parse("k=café").is_err());
    }

    // Every printable-ASCII character must round-trip verbatim inside single
    // quotes (with `'` doubled) and inside double quotes (with `"` doubled).
    #[test]
    fn exhaustive_ascii_roundtrip_in_quotes() {
        for byte in 0x20u8..=0x7e {
            let c = byte as char;

            let inner = if c == '\'' {
                "a''b".to_string()
            } else {
                format!("a{c}b")
            };
            let expected = format!("a{c}b");
            assert_eq!(
                value(&format!("k='{inner}'"), "k").as_deref(),
                Some(expected.as_str()),
                "char {c:?} (0x{byte:02x}) via single quotes"
            );

            let inner = if c == '"' {
                "a\"\"b".to_string()
            } else {
                format!("a{c}b")
            };
            assert_eq!(
                value(&format!("k=\"{inner}\""), "k").as_deref(),
                Some(expected.as_str()),
                "char {c:?} (0x{byte:02x}) via double quotes"
            );
        }
    }

    // Unquoted values round-trip verbatim for every printable-ASCII character
    // that is not structural in that position (`;`, and a leading `'`/`"`/`{`).
    #[test]
    fn exhaustive_ascii_roundtrip_unquoted_where_legal() {
        for byte in 0x21u8..=0x7e {
            let c = byte as char;
            if c == ';' {
                continue; // separator: cannot appear unquoted
            }
            // Placed after a leading letter so `'`/`"`/`{` are not value-leading.
            let raw = format!("a{c}b");
            assert_eq!(
                value(&format!("k={raw}"), "k").as_deref(),
                Some(raw.as_str()),
                "char {c:?} (0x{byte:02x}) unquoted"
            );
        }
    }
}
