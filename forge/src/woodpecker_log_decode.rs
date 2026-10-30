//! Bounded retained log decoding and cross-record credential canonicalization.
//!
//! Empty and malformed records retain their array positions. UTF-8 decoding is
//! explicitly lossy with a diagnostic. Redaction spans record boundaries and
//! precedes pagination; replacement units must never be split by a paginator.

use std::cell::Cell;
use std::fmt;
use std::ops::Range;

use base64::{Engine, prelude::BASE64_STANDARD};
use domain::{CiDiagnosticCode, CiLogRecordMetadata, CiStepLogDiagnostic};
use serde::de::{self, DeserializeSeed, IgnoredAny, SeqAccess, Visitor};
use serde_json::Value;

use crate::woodpecker::{Failure, Session};

/// Independently injectable CPU/allocation bounds for decoding one snapshot.
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    /// Raw JSON bytes, checked before parsing.
    pub body_bytes: usize,
    /// Maximum array positions, including malformed/empty records.
    pub records: usize,
    /// Maximum cumulative decoded UTF-8 representation bytes.
    pub decoded_bytes: usize,
    /// Maximum canonical output after redaction expansion.
    pub canonical_bytes: usize,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            body_bytes: 8 * 1024 * 1024,
            records: 65_536,
            decoded_bytes: 8 * 1024 * 1024,
            canonical_bytes: 8 * 1024 * 1024,
        }
    }
}

/// One original array position after decoding and credential redaction.
#[derive(Debug)]
pub struct CanonicalRecord {
    /// Whitespace-preserving canonical UTF-8 output.
    pub text: String,
    /// Atomic replacement spans in canonical record byte coordinates.
    pub redactions: Vec<Range<usize>>,
    /// Bounded allowlisted metadata, never traversal order.
    pub metadata: CiLogRecordMetadata,
    /// At most one safe decoding diagnostic for this position.
    pub diagnostic: Option<CiStepLogDiagnostic>,
}

fn fail(code: CiDiagnosticCode, message: &'static str) -> Failure {
    Failure {
        code,
        status: None,
        message,
    }
}
fn limit() -> Failure {
    fail(
        CiDiagnosticCode::LimitExceeded,
        "Retained log decoding limit reached",
    )
}
fn malformed() -> Failure {
    fail(
        CiDiagnosticCode::MalformedResponse,
        "Retained log response is not a JSON array or null",
    )
}
fn diagnostic(index: usize, code: &str, message: &str) -> CiStepLogDiagnostic {
    CiStepLogDiagnostic {
        code: code.into(),
        message: message.into(),
        record_index: Some(index),
        http_status: None,
    }
}

struct LogArray<'a> {
    max: usize,
    exceeded: &'a Cell<bool>,
}
impl<'de> DeserializeSeed<'de> for LogArray<'_> {
    type Value = Vec<Value>;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for LogArray<'_> {
    type Value = Vec<Value>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a retained log array or null")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut records = Vec::new();
        loop {
            if records.len() == self.max {
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.exceeded.set(true);
                    return Err(de::Error::custom("record count exceeds limit"));
                }
                break;
            }
            let Some(record) = seq.next_element::<Value>()? else {
                break;
            };
            records.push(record);
        }
        Ok(records)
    }
}
fn parse_records(raw: &[u8], max: usize) -> Result<Vec<Value>, Failure> {
    let exceeded = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let array = LogArray {
        max,
        exceeded: &exceeded,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| if exceeded.get() { limit() } else { malformed() })?;
    deserializer.end().map_err(|_| malformed())?;
    Ok(array)
}

/// Decode a bounded full response and redact credentials across record edges.
///
/// A null top-level response is explicitly supported as no retained output.
/// A present record UUID must exactly equal the selected step's UUID; absent
/// UUID is allowed by the pinned provider contract. Malformed records produce
/// empty positions with diagnostics instead of vanishing from traversal.
///
/// # Errors
/// Rejects malformed top-level JSON, UUID mismatch, allocation/record limits or
/// the request's shared CPU deadline. Failures establish no navigable snapshot.
#[allow(clippy::too_many_lines)]
pub fn decode(
    session: &Session,
    raw: &[u8],
    step_uuid: Option<&str>,
    secrets: &[&str],
    limits: DecodeLimits,
) -> Result<Vec<CanonicalRecord>, Failure> {
    session.check_deadline()?;
    if raw.len() > limits.body_bytes {
        return Err(limit());
    }
    let array = parse_records(raw, limits.records)?;
    session.check_deadline()?;
    let mut records = Vec::with_capacity(array.len());
    let mut joined = String::new();
    let mut ranges = Vec::with_capacity(array.len());
    for (index, value) in array.into_iter().enumerate() {
        session.check_deadline()?;
        let start = joined.len();
        let mut record = CanonicalRecord {
            text: String::new(),
            redactions: Vec::new(),
            metadata: CiLogRecordMetadata::default(),
            diagnostic: None,
        };
        if let Some(object) = value.as_object() {
            if let Some(uuid) = object.get("step_uuid").filter(|v| !v.is_null())
                && (uuid.as_str().is_none() || uuid.as_str() != step_uuid)
            {
                return Err(fail(
                    CiDiagnosticCode::BindingMismatch,
                    "Retained log record UUID does not match the selected step",
                ));
            }
            record.metadata.time = object.get("time").and_then(Value::as_i64);
            record.metadata.line = object.get("line").and_then(Value::as_i64);
            if let Some(kind) = object.get("type").and_then(Value::as_str) {
                // Never echo arbitrary nested metadata or secret-bearing labels.
                let (safe, clipped) = crate::woodpecker::safe_text(kind, secrets, 64);
                record.metadata.record_type = Some(safe);
                if clipped {
                    record.diagnostic = Some(diagnostic(
                        index,
                        "metadata_limit",
                        "Record type exceeds the metadata bound",
                    ));
                }
            }
            match object.get("data") {
                None | Some(Value::Null) => {}
                Some(Value::String(encoded)) => {
                    // Base64 maximum allocation is checked before decoding.
                    let estimate = encoded.len().checked_add(3).ok_or_else(limit)? / 4;
                    let estimate = estimate.checked_mul(3).ok_or_else(limit)?;
                    // At most two padding bytes can inflate this upper bound.
                    if estimate.saturating_sub(2)
                        > limits.decoded_bytes.saturating_sub(joined.len())
                    {
                        return Err(limit());
                    }
                    match BASE64_STANDARD.decode(encoded) {
                        Ok(bytes) => {
                            let text = String::from_utf8_lossy(&bytes);
                            if matches!(text, std::borrow::Cow::Owned(_)) {
                                record.diagnostic = Some(diagnostic(
                                    index,
                                    "lossy_utf8",
                                    "Invalid UTF-8 uses Unicode replacement characters",
                                ));
                            }
                            if text.len() > limits.decoded_bytes.saturating_sub(joined.len()) {
                                return Err(limit());
                            }
                            joined.push_str(&text);
                        }
                        Err(_) => {
                            record.diagnostic = Some(diagnostic(
                                index,
                                "invalid_base64",
                                "Record data is not valid base64",
                            ));
                        }
                    }
                }
                _ => {
                    record.diagnostic = Some(diagnostic(
                        index,
                        "invalid_data",
                        "Record data must be base64 text or null",
                    ));
                }
            }
        } else {
            record.diagnostic = Some(diagnostic(
                index,
                "invalid_record",
                "Log array entry is not an object",
            ));
        }
        ranges.push(start..joined.len());
        records.push(record);
    }
    canonicalize(
        session,
        &joined,
        &ranges,
        &mut records,
        secrets,
        limits.canonical_bytes,
    )?;
    session.check_deadline()?;
    Ok(records)
}

fn canonicalize(
    session: &Session,
    joined: &str,
    ranges: &[Range<usize>],
    records: &mut [CanonicalRecord],
    secrets: &[&str],
    cap: usize,
) -> Result<(), Failure> {
    let mut secrets: Vec<_> = secrets.iter().copied().filter(|s| !s.is_empty()).collect();
    secrets.sort_unstable_by_key(|s| std::cmp::Reverse(s.len()));
    let mut offset = 0;
    let mut index = 0;
    let mut emitted = 0;
    while offset < joined.len() {
        session.check_deadline()?;
        while ranges.get(index).is_some_and(|r| r.end <= offset) {
            index += 1;
        }
        let Some(record) = records.get_mut(index) else {
            return Err(limit());
        };
        let remaining = &joined[offset..];
        let secret = secrets.iter().find(|s| remaining.starts_with(**s));
        let (piece, consumed) = if let Some(secret) = secret {
            ("[REDACTED]", secret.len())
        } else {
            let n = remaining.chars().next().map_or(0, char::len_utf8);
            (&remaining[..n], n)
        };
        if piece.len() > cap.saturating_sub(emitted) {
            return Err(limit());
        }
        if secret.is_some() {
            record
                .redactions
                .push(record.text.len()..record.text.len() + piece.len());
        }
        record.text.push_str(piece);
        emitted += piece.len();
        offset += consumed;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use serde_json::json;

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
    fn run(
        value: &Value,
        uuid: Option<&str>,
        secrets: &[&str],
        limits: DecodeLimits,
    ) -> Result<Vec<CanonicalRecord>, Failure> {
        decode(
            &session(),
            &serde_json::to_vec(value).expect("json"),
            uuid,
            secrets,
            limits,
        )
    }
    fn data(text: &str) -> Value {
        json!({"data": BASE64_STANDARD.encode(text)})
    }

    #[tokio::test]
    async fn preserves_every_position_and_valid_scalar_with_explicit_diagnostics() {
        let value = json!([{}, {"data":null}, {"data":""}, 7, {"data":7}, {"data":"?"},
            {"data":BASE64_STANDARD.encode([b'a',0xff,b'b'])}, data("\n\t\r\0終🙂  ")]);
        let records = run(&value, None, &[], DecodeLimits::default()).expect("decode");
        assert_eq!(records.len(), 8);
        for record in &records[..6] {
            assert!(record.text.is_empty());
        }
        assert_eq!(
            records[3].diagnostic.as_ref().expect("diagnostic").code,
            "invalid_record"
        );
        assert_eq!(
            records[4].diagnostic.as_ref().expect("diagnostic").code,
            "invalid_data"
        );
        assert_eq!(
            records[5].diagnostic.as_ref().expect("diagnostic").code,
            "invalid_base64"
        );
        assert_eq!(records[6].text, "a�b");
        assert_eq!(
            records[6].diagnostic.as_ref().expect("diagnostic").code,
            "lossy_utf8"
        );
        assert_eq!(records[7].text, "\n\t\r\0終🙂  ");
        for (index, record) in records.iter().enumerate() {
            if let Some(d) = &record.diagnostic {
                assert_eq!(d.record_index, Some(index));
            }
        }
    }

    #[tokio::test]
    async fn secrets_cross_arbitrary_record_edges_before_fragmentation() {
        let secret = "終CI_SECRET🙂";
        for split in secret
            .char_indices()
            .map(|(offset, _)| offset)
            .chain([secret.len()])
        {
            let value = json!([
                data(&format!("before {}", &secret[..split])),
                {},
                data(&format!("{} after", &secret[split..]))
            ]);
            let records = run(&value, None, &[secret], DecodeLimits::default()).expect("decode");
            let text: String = records.iter().map(|r| r.text.as_str()).collect();
            assert_eq!(text, "before [REDACTED] after");
            assert_eq!(records.len(), 3);
            assert!(records[1].text.is_empty());
            let units: Vec<_> = records
                .iter()
                .flat_map(|r| r.redactions.iter().map(|span| &r.text[span.clone()]))
                .collect();
            assert_eq!(units, vec!["[REDACTED]"]);
        }
        let value = json!([data("SE"), data("CR"), data("ET"), data("!")]);
        let records = run(&value, None, &["SECRET"], DecodeLimits::default()).expect("decode");
        assert_eq!(
            records.iter().map(|r| r.text.as_str()).collect::<String>(),
            "[REDACTED]!"
        );
    }

    #[tokio::test]
    async fn top_level_null_empty_and_malformed_are_distinct() {
        for value in [Value::Null, json!([])] {
            assert!(
                run(&value, None, &[], DecodeLimits::default())
                    .expect("empty")
                    .is_empty()
            );
        }
        for raw in [b"{".as_slice(), b"{}", b"42", b"[", b"null garbage"] {
            assert_eq!(
                decode(&session(), raw, None, &[], DecodeLimits::default())
                    .expect_err("malformed")
                    .code,
                CiDiagnosticCode::MalformedResponse
            );
        }
        let deep = format!("{}{}", "[".repeat(130), "]".repeat(130));
        assert_eq!(
            decode(
                &session(),
                deep.as_bytes(),
                None,
                &[],
                DecodeLimits::default()
            )
            .expect_err("depth")
            .code,
            CiDiagnosticCode::MalformedResponse
        );
    }

    #[tokio::test]
    async fn validates_uuid_and_does_not_echo_unknown_metadata() {
        for uuid in [json!("other"), json!(7), json!({})] {
            assert_eq!(
                run(
                    &json!([{"step_uuid":uuid}]),
                    Some("selected"),
                    &[],
                    DecodeLimits::default()
                )
                .expect_err("binding")
                .code,
                CiDiagnosticCode::BindingMismatch
            );
        }
        let value = json!([{"step_uuid":"selected", "time":0, "line":8, "type":"SECRET", "password":"SECRET", "data":""}, {}]);
        let records = run(
            &value,
            Some("selected"),
            &["SECRET"],
            DecodeLimits::default(),
        )
        .expect("decode");
        assert_eq!(records[0].metadata.time, Some(0));
        assert_eq!(records[0].metadata.line, Some(8));
        assert_eq!(
            records[0].metadata.record_type.as_deref(),
            Some("[REDACTED]")
        );
    }

    #[tokio::test]
    async fn limits_are_hard_errors_including_lossy_and_redaction_expansion() {
        for (value, limits) in [
            (
                json!([{}]),
                DecodeLimits {
                    body_bytes: 1,
                    ..DecodeLimits::default()
                },
            ),
            (
                json!([{}, {}]),
                DecodeLimits {
                    records: 1,
                    ..DecodeLimits::default()
                },
            ),
            (
                json!([data("abcd")]),
                DecodeLimits {
                    decoded_bytes: 3,
                    ..DecodeLimits::default()
                },
            ),
            (
                json!([{"data":"/w=="}]),
                DecodeLimits {
                    decoded_bytes: 2,
                    ..DecodeLimits::default()
                },
            ),
            (
                json!([data("x")]),
                DecodeLimits {
                    canonical_bytes: 9,
                    ..DecodeLimits::default()
                },
            ),
        ] {
            assert_eq!(
                run(&value, None, &["x"], limits).expect_err("limit").code,
                CiDiagnosticCode::LimitExceeded
            );
        }
        let records = run(
            &json!([data("ab"), data("cd")]),
            None,
            &[],
            DecodeLimits {
                decoded_bytes: 4,
                canonical_bytes: 4,
                ..DecodeLimits::default()
            },
        )
        .expect("exact limit");
        assert_eq!(
            records.iter().map(|r| r.text.as_str()).collect::<String>(),
            "abcd"
        );
    }
}
