//! Bounded plain-text decoding with whole-stream credential redaction.
//!
//! Separators and control characters are preserved. Redaction occurs before
//! paging; each replacement span is indivisible in canonical byte coordinates.

use std::ops::Range;

use domain::CiDiagnosticCode;

use crate::woodpecker::{Failure, Session};

/// Independent source, decoded and canonical byte limits.
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    /// Maximum downloaded bytes.
    pub raw_bytes: usize,
    /// Maximum UTF-8 bytes after lossy decoding.
    pub decoded_bytes: usize,
    /// Maximum UTF-8 bytes after redaction expansion.
    pub canonical_bytes: usize,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            raw_bytes: 8 * 1024 * 1024,
            decoded_bytes: 8 * 1024 * 1024,
            canonical_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Canonical stream with explicit loss and indivisible replacement boundaries.
#[derive(Debug)]
pub struct CanonicalText {
    /// Complete redacted text, with original separators preserved.
    pub text: String,
    /// Atomic replacement spans in `text`.
    pub redactions: Vec<Range<usize>>,
    /// Invalid source bytes were replaced with Unicode replacement scalars.
    pub lossy: bool,
}
fn limit() -> Failure {
    Failure {
        code: CiDiagnosticCode::LimitExceeded,
        status: None,
        message: "Download decoding or canonicalization limit reached",
    }
}

/// Decode the complete bounded source and redact before selecting any page.
///
/// No JSON/base64 interpretation, splitting, trimming or newline insertion is
/// performed. Longest matching credentials win; replacements are not rescanned.
///
/// # Errors
/// Returns a safe limit failure without partial output on size/deadline excess.
pub fn decode(
    session: &Session,
    raw: &[u8],
    secrets: &[&str],
    limits: DecodeLimits,
) -> Result<CanonicalText, Failure> {
    session.check_deadline()?;
    if raw.len() > limits.raw_bytes {
        return Err(limit());
    }
    // Decode incrementally so lossy expansion cannot allocate beyond the cap.
    let mut decoded = String::new();
    let mut remaining = raw;
    let mut lossy = false;
    while !remaining.is_empty() {
        session.check_deadline()?;
        let (valid, invalid) = match std::str::from_utf8(remaining) {
            Ok(text) => (text, 0),
            Err(error) => (
                std::str::from_utf8(&remaining[..error.valid_up_to()]).map_err(|_| limit())?,
                error
                    .error_len()
                    .unwrap_or(remaining.len() - error.valid_up_to()),
            ),
        };
        if valid.len() > limits.decoded_bytes.saturating_sub(decoded.len()) {
            return Err(limit());
        }
        decoded.push_str(valid);
        remaining = &remaining[valid.len()..];
        if invalid > 0 {
            if 3 > limits.decoded_bytes.saturating_sub(decoded.len()) {
                return Err(limit());
            }
            decoded.push('\u{fffd}');
            lossy = true;
            remaining = &remaining[invalid..];
        }
    }
    let mut policy: Vec<_> = secrets.iter().copied().filter(|s| !s.is_empty()).collect();
    policy.sort_unstable_by_key(|s| std::cmp::Reverse(s.len()));
    policy.dedup();
    let mut canonical = CanonicalText {
        text: String::new(),
        redactions: Vec::new(),
        lossy,
    };
    let mut offset = 0;
    while offset < decoded.len() {
        session.check_deadline()?;
        let suffix = &decoded[offset..];
        let secret = policy.iter().find(|s| suffix.starts_with(**s));
        let (piece, consumed) = if let Some(secret) = secret {
            ("[REDACTED]", secret.len())
        } else {
            let n = suffix.chars().next().map_or(0, char::len_utf8);
            (&suffix[..n], n)
        };
        let end = canonical
            .text
            .len()
            .checked_add(piece.len())
            .ok_or_else(limit)?;
        if end > limits.canonical_bytes {
            return Err(limit());
        }
        if secret.is_some() {
            canonical.redactions.push(canonical.text.len()..end);
        }
        canonical.text.push_str(piece);
        offset = offset.checked_add(consumed).ok_or_else(limit)?;
    }
    session.check_deadline()?;
    Ok(canonical)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::woodpecker::{Origin, StepLogTransportLimits};

    fn session() -> Session {
        Session::for_step_logs(
            Origin::parse("http://example.invalid").expect("origin"),
            None,
            StepLogTransportLimits::default(),
        )
        .expect("session")
    }
    #[tokio::test]
    async fn exact_text_loss_and_longest_redaction() {
        let raw = b" \r\n\x1b[31m\0SECRETend\xff";
        let value = decode(
            &session(),
            raw,
            &["SEC", "SECRET", ""],
            DecodeLimits::default(),
        )
        .expect("decode");
        assert_eq!(value.text, " \r\n\x1b[31m\0[REDACTED]end�");
        assert!(value.lossy);
        assert_eq!(&value.text[value.redactions[0].clone()], "[REDACTED]");
        for raw in [
            b"".as_slice(),
            b"\"eHl6\"",
            b"no final newline",
            "終🙂\r\n".as_bytes(),
        ] {
            let value = decode(&session(), raw, &[], DecodeLimits::default()).expect("decode");
            assert_eq!(value.text.as_bytes(), raw);
            assert!(!value.lossy);
        }
    }
    #[tokio::test]
    async fn independent_caps_are_hard_failures() {
        for (raw, limits) in [
            (
                b"abcd".as_slice(),
                DecodeLimits {
                    raw_bytes: 3,
                    ..DecodeLimits::default()
                },
            ),
            (
                b"\xff",
                DecodeLimits {
                    decoded_bytes: 2,
                    ..DecodeLimits::default()
                },
            ),
            (
                b"x",
                DecodeLimits {
                    canonical_bytes: 9,
                    ..DecodeLimits::default()
                },
            ),
        ] {
            assert_eq!(
                decode(&session(), raw, &["x"], limits)
                    .expect_err("limit")
                    .code,
                CiDiagnosticCode::LimitExceeded
            );
        }
        assert_eq!(
            decode(
                &session(),
                b"x",
                &["x"],
                DecodeLimits {
                    canonical_bytes: 10,
                    ..DecodeLimits::default()
                }
            )
            .expect("exact cap")
            .text,
            "[REDACTED]"
        );
    }
}
