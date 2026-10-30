//! Stateless strict snapshots of bounded, canonical retained step output.
//!
//! Every caller must freshly authorize, select and fetch before constructing a
//! snapshot. Cursors carry digests and positions only; they grant no authority.
//! Re-fetching costs O(retained log size) per page. Any changed raw body or
//! security binding requires an explicit restart, even for an active step.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use domain::{
    CiLogFragment, CiLogPosition, CiLogStart, CiStepLogDiagnostic, CiStepLogIdentity,
    CiStepLogOptions, CiStepLogStatus, RepositoryCiStepLogs, RepositoryRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::woodpecker::{Origin, Session};
use crate::woodpecker_log_decode::CanonicalRecord;

const RESPONSE_CAP: usize = 512 * 1024;
const FRAGMENT_CAP: usize = 256;

/// Safe assembly error; callers retain validated identity in failure envelopes.
#[derive(Debug, PartialEq, Eq)]
pub struct PageError {
    /// Stable error classification, without upstream or cursor text.
    pub status: CiStepLogStatus,
    /// Static explanation suitable for a diagnostic.
    pub message: &'static str,
    /// Minimum budget required for the next indivisible scalar/redaction unit.
    pub minimum_page_bytes: Option<usize>,
}
fn error(status: CiStepLogStatus, message: &'static str) -> PageError {
    PageError {
        status,
        message,
        minimum_page_bytes: None,
    }
}
fn deadline(session: &Session) -> Result<(), PageError> {
    session.check_deadline().map_err(|_| {
        error(
            CiStepLogStatus::RetrievalLimit,
            "Step log deadline exceeded",
        )
    })
}
fn invalid() -> PageError {
    error(
        CiStepLogStatus::InvalidCursor,
        "Invalid snapshot cursor or position",
    )
}
fn digest(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part.len().to_be_bytes());
        hash.update(part);
    }
    BASE64_URL_SAFE_NO_PAD.encode(hash.finalize())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    binding: String,
    snapshot: String,
    position: CiLogPosition,
}

/// A request-local snapshot; never persist or cache across requests.
pub struct Snapshot {
    identity: CiStepLogIdentity,
    binding: String,
    id: String,
    records: Vec<CanonicalRecord>,
}
impl Snapshot {
    /// Bind exact fetched bytes and canonical records to configured authority.
    ///
    /// `records` must come from decoding `raw` with exactly `secrets`. The
    /// origin must be the configured CI origin, never an input URL. Secret
    /// values enter only a non-reversible policy digest, never cursor fields.
    ///
    /// # Errors
    /// Returns a safe assembly/deadline failure.
    pub fn new(
        session: &Session,
        repository: &RepositoryRef,
        origin: &Origin,
        identity: CiStepLogIdentity,
        raw: &[u8],
        records: Vec<CanonicalRecord>,
        secrets: &[&str],
    ) -> Result<Self, PageError> {
        deadline(session)?;
        let mut policy: Vec<_> = secrets.iter().copied().filter(|s| !s.is_empty()).collect();
        policy.sort_unstable();
        policy.dedup();
        let policy_parts: Vec<_> = policy.iter().map(|s| s.as_bytes()).collect();
        let policy_digest = digest(&policy_parts);
        let binding_bytes = serde_json::to_vec(&(
            "strict-snapshot-v1/redaction-v1/lossy-utf8-v1",
            repository,
            origin
                .pipeline_url(
                    identity.selector.provider_repository_id,
                    identity.selector.pipeline_number,
                )
                .map_err(|_| {
                    error(
                        CiStepLogStatus::BindingMismatch,
                        "Invalid configured CI origin",
                    )
                })?,
            &identity,
            policy_digest,
        ))
        .map_err(|_| invalid())?;
        let binding = digest(&[&binding_bytes]);
        let id = digest(&[binding.as_bytes(), raw]);
        deadline(session)?;
        Ok(Self {
            identity,
            binding,
            id,
            records,
        })
    }

    fn cursor(&self, position: CiLogPosition) -> Result<String, PageError> {
        let bytes = serde_json::to_vec(&Cursor {
            version: 1,
            binding: self.binding.clone(),
            snapshot: self.id.clone(),
            position,
        })
        .map_err(|_| invalid())?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }

    fn resume(&self, input: &str) -> Result<CiLogPosition, PageError> {
        if input.is_empty() || input.len() > domain::CI_LOG_MAX_CURSOR_BYTES {
            return Err(invalid());
        }
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| invalid())?;
        let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if cursor.version != 1
            || cursor.binding.len() != 43
            || cursor.snapshot.len() != 43
            || BASE64_URL_SAFE_NO_PAD.decode(&cursor.binding).is_err()
            || BASE64_URL_SAFE_NO_PAD.decode(&cursor.snapshot).is_err()
        {
            return Err(invalid());
        }
        if cursor.binding != self.binding {
            return Err(error(
                CiStepLogStatus::BindingMismatch,
                "Snapshot security or source binding changed",
            ));
        }
        if cursor.snapshot != self.id {
            return Err(error(
                CiStepLogStatus::StaleCursor,
                "Retained snapshot changed; restart explicitly",
            ));
        }
        let p = cursor.position;
        if p.record_index == self.records.len() && p.byte_offset == 0 {
            return Ok(p);
        }
        let r = self.records.get(p.record_index).ok_or_else(invalid)?;
        if !r.text.is_char_boundary(p.byte_offset)
            || (p.byte_offset == r.text.len() && !r.text.is_empty())
            || r.redactions
                .iter()
                .any(|s| s.start < p.byte_offset && p.byte_offset < s.end)
        {
            return Err(invalid());
        }
        Ok(p)
    }

    fn tail(&self, budget: usize) -> CiLogPosition {
        let mut used = 0;
        let mut p = CiLogPosition {
            record_index: self.records.len(),
            byte_offset: 0,
        };
        for (index, r) in self.records.iter().enumerate().rev().take(FRAGMENT_CAP) {
            p.record_index = index;
            p.byte_offset = 0;
            if r.text.len() > budget.saturating_sub(used) {
                let mut offset = r.text.len() - budget.saturating_sub(used);
                while !r.text.is_char_boundary(offset) {
                    offset += 1;
                }
                if let Some(span) = r
                    .redactions
                    .iter()
                    .find(|s| s.start < offset && offset < s.end)
                {
                    offset = span.start;
                }
                p.byte_offset = offset;
                // Avoid a noncanonical end-of-record position for tiny budgets.
                if offset == r.text.len() && offset > 0 {
                    p.byte_offset = r.text.char_indices().next_back().map_or(0, |(i, _)| i);
                }
                break;
            }
            used += r.text.len();
        }
        p
    }

    /// Assemble a progressing bounded page, preserving every emitted position.
    ///
    /// EOF describes this fetched snapshot only. Empty/malformed records count
    /// toward the fragment bound and retain their positions and diagnostics.
    ///
    /// # Errors
    /// Rejects changed snapshots, untrusted positions, impossible page budgets,
    /// deadline exhaustion or a response envelope exceeding the hard cap.
    #[allow(clippy::too_many_lines)]
    pub fn page(
        &self,
        session: &Session,
        options: &CiStepLogOptions,
    ) -> Result<RepositoryCiStepLogs, PageError> {
        deadline(session)?;
        options.validate().map_err(|_| invalid())?;
        let budget = options.budget();
        let start = if let Some(cursor) = &options.cursor {
            self.resume(cursor)?
        } else if options.start == Some(CiLogStart::Tail) {
            self.tail(budget)
        } else {
            CiLogPosition::default()
        };
        let mut page = RepositoryCiStepLogs::unsupported(self.identity.selector.clone());
        page.identity = Some(self.identity.clone());
        page.status = CiStepLogStatus::Available;
        page.snapshot_id = Some(self.id.clone());
        page.position = start;
        page.end_position = start;
        page.beginning_cursor = Some(self.cursor(CiLogPosition::default())?);
        page.provider_step_finished = match self.identity.step_state.as_str() {
            "success" | "failure" | "error" | "killed" | "skipped" | "cancelled" => Some(true),
            "pending" | "running" | "blocked" => Some(false),
            _ => None,
        };
        page.diagnostics.push(CiStepLogDiagnostic {
            code: "not_exposed".into(),
            message: "Historical infrastructure diagnostics are not exposed".into(),
            record_index: None,
            http_status: None,
        });
        let mut remaining = budget;
        while let Some(record) = self.records.get(page.end_position.record_index) {
            deadline(session)?;
            if page.fragments.len() == FRAGMENT_CAP {
                break;
            }
            let p = page.end_position;
            let mut end = p.byte_offset + remaining.min(record.text.len() - p.byte_offset);
            while !record.text.is_char_boundary(end) {
                end -= 1;
            }
            if let Some(span) = record
                .redactions
                .iter()
                .find(|s| s.start < end && end < s.end)
            {
                end = span.start;
            }
            if end == p.byte_offset && end < record.text.len() {
                if !page.fragments.is_empty() {
                    break;
                }
                let minimum = record
                    .redactions
                    .iter()
                    .find(|s| s.start == end)
                    .map_or_else(
                        || record.text[end..].chars().next().map_or(0, char::len_utf8),
                        |s| s.end - s.start,
                    );
                return Err(PageError {
                    status: CiStepLogStatus::InvalidCursor,
                    message: "page_bytes cannot fit the next UTF-8 scalar or redaction unit",
                    minimum_page_bytes: Some(minimum),
                });
            }
            let complete = end == record.text.len();
            page.fragments.push(CiLogFragment {
                position: p,
                text: record.text[p.byte_offset..end].into(),
                record_complete: complete,
                metadata: record.metadata.clone(),
            });
            if let Some(d) = &record.diagnostic {
                page.diagnostics.push(d.clone());
            }
            // Reserve space for final cursors/flags before committing progress.
            // Escaped text and metadata both count toward the wire envelope.
            if serde_json::to_vec(&page).map_err(|_| invalid())?.len() > RESPONSE_CAP - 4096 {
                page.fragments.pop();
                if record.diagnostic.is_some() {
                    page.diagnostics.pop();
                }
                if page.fragments.is_empty() {
                    return Err(error(
                        CiStepLogStatus::RetrievalLimit,
                        "Serialized step log envelope exceeds limit",
                    ));
                }
                break;
            }
            remaining -= end - p.byte_offset;
            page.end_position = if complete {
                CiLogPosition {
                    record_index: p.record_index + 1,
                    byte_offset: 0,
                }
            } else {
                CiLogPosition {
                    record_index: p.record_index,
                    byte_offset: end,
                }
            };
        }
        page.snapshot_complete = page.end_position.record_index == self.records.len();
        page.truncated =
            !page.snapshot_complete || self.records.iter().any(|r| r.diagnostic.is_some());
        if !page.snapshot_complete {
            page.next_cursor = Some(self.cursor(page.end_position)?);
        }
        // All text, identity, diagnostics and cursors count, including JSON escapes.
        let serialized = serde_json::to_vec(&page).map_err(|_| invalid())?;
        if serialized.len() > RESPONSE_CAP {
            return Err(error(
                CiStepLogStatus::RetrievalLimit,
                "Serialized step log response exceeds limit",
            ));
        }
        deadline(session)?;
        Ok(page)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use base64::prelude::BASE64_STANDARD;
    use domain::{CiStepLogSelector, CiTimestamps, ForgeKind};
    use serde_json::json;

    use super::*;
    use crate::woodpecker::StepLogTransportLimits;
    use crate::woodpecker_log_decode::{DecodeLimits, decode};

    fn session() -> Session {
        Session::for_step_logs(
            Origin::parse("http://example.invalid/ci").expect("origin"),
            None,
            StepLogTransportLimits::default(),
        )
        .expect("session")
    }
    fn snapshot(raw: &[u8], secret: &str, commit: &str) -> Snapshot {
        let s = session();
        let identity = CiStepLogIdentity {
            selector: CiStepLogSelector {
                provider: "woodpecker".into(),
                provider_repository_id: 1,
                pipeline_number: 42,
                workflow_id: 7,
                step_id: 9,
            },
            pipeline_id: 500,
            commit: commit.into(),
            reference: None,
            workflow_pid: 1,
            step_uuid: None,
            step_name: "test".into(),
            step_state: "running".into(),
            timestamps: CiTimestamps {
                created: None,
                updated: None,
                started: None,
                finished: None,
            },
        };
        let records = decode(&s, raw, None, &[secret], DecodeLimits::default()).expect("decode");
        Snapshot::new(
            &s,
            &RepositoryRef {
                alias: "fixture".into(),
                forge: ForgeKind::Forgejo,
                host: "forge.example".into(),
                owner: "owner".into(),
                name: "repo".into(),
            },
            &Origin::parse("http://example.invalid/ci").expect("origin"),
            identity,
            raw,
            records,
            &[secret],
        )
        .expect("snapshot")
    }
    fn raw(texts: &[&str]) -> Vec<u8> {
        serde_json::to_vec(
            &texts
                .iter()
                .map(|s| json!({"data":BASE64_STANDARD.encode(s)}))
                .collect::<Vec<_>>(),
        )
        .expect("json")
    }
    fn traverse(s: &Snapshot, cursor: Option<String>, budget: usize) -> String {
        let mut options = CiStepLogOptions {
            cursor,
            page_bytes: Some(budget),
            ..Default::default()
        };
        let mut output = String::new();
        for _ in 0..1000 {
            let p = s.page(&session(), &options).expect("page");
            assert_eq!(p.provider_step_finished, Some(false));
            assert!(p.fragments.len() <= FRAGMENT_CAP);
            for fragment in &p.fragments {
                output.push_str(&fragment.text);
            }
            if p.snapshot_complete {
                assert!(p.next_cursor.is_none());
                return output;
            }
            assert_ne!(p.position, p.end_position);
            options.cursor = p.next_cursor;
        }
        panic!("nonterminating traversal");
    }

    #[tokio::test]
    async fn six_panics_tail_rewind_and_long_records_reconstruct_exactly() {
        let blocks: Vec<_> = (0..6)
            .map(|i| format!("panic {i}: 終🙂\n{}\n", "stack\t".repeat(30)))
            .collect();
        let mut texts = vec!["ordinary output\n".to_string(); 25];
        for (i, block) in blocks.into_iter().enumerate() {
            texts.insert(i * 4, block);
        }
        texts.insert(3, String::new());
        let refs: Vec<_> = texts.iter().map(String::as_str).collect();
        let s = snapshot(&raw(&refs), "", "commit");
        let expected = texts.concat();
        assert_eq!(traverse(&s, None, 31), expected);
        let tail = s
            .page(
                &session(),
                &CiStepLogOptions {
                    start: Some(CiLogStart::Tail),
                    page_bytes: Some(31),
                    ..Default::default()
                },
            )
            .expect("tail");
        assert!(tail.snapshot_complete);
        assert!(tail.position.record_index > 0);
        assert_eq!(traverse(&s, tail.beginning_cursor, 31), expected);
        let options = CiStepLogOptions {
            page_bytes: Some(31),
            ..Default::default()
        };
        assert_eq!(
            s.page(&session(), &options).expect("page"),
            s.page(&session(), &options).expect("replay")
        );
    }

    #[tokio::test]
    async fn mutations_invalidate_without_emitting_mixed_output() {
        let original = snapshot(&raw(&["abcdef", "ghijk"]), "secret", "commit");
        let page = original
            .page(
                &session(),
                &CiStepLogOptions {
                    page_bytes: Some(2),
                    ..Default::default()
                },
            )
            .expect("page");
        let options = CiStepLogOptions {
            cursor: page.next_cursor,
            ..Default::default()
        };
        for data in [
            raw(&["abcdef", "ghijk", "append"]),
            raw(&["rewrite"]),
            raw(&[]),
            b"null".to_vec(),
        ] {
            assert_eq!(
                snapshot(&data, "secret", "commit")
                    .page(&session(), &options)
                    .expect_err("stale")
                    .status,
                CiStepLogStatus::StaleCursor
            );
        }
        for changed in [
            snapshot(&raw(&["abcdef", "ghijk"]), "other", "commit"),
            snapshot(&raw(&["abcdef", "ghijk"]), "secret", "changed"),
        ] {
            assert_eq!(
                changed
                    .page(&session(), &options)
                    .expect_err("binding")
                    .status,
                CiStepLogStatus::BindingMismatch
            );
        }
    }

    #[tokio::test]
    async fn untrusted_cursor_offsets_and_budget_require_exact_units() {
        let s = snapshot(&raw(&["🙂SECRET終"]), "SECRET", "commit");
        let base = s.cursor(CiLogPosition::default()).expect("cursor");
        for position in [
            CiLogPosition {
                record_index: 0,
                byte_offset: 1,
            },
            CiLogPosition {
                record_index: 0,
                byte_offset: 5,
            },
            CiLogPosition {
                record_index: 2,
                byte_offset: 0,
            },
            CiLogPosition {
                record_index: 0,
                byte_offset: 17,
            },
        ] {
            let c = s.cursor(position).expect("encode");
            assert_eq!(
                s.resume(&c).expect_err("offset").status,
                CiStepLogStatus::InvalidCursor
            );
        }
        for input in [
            "?".to_string(),
            "a".repeat(4097),
            BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
        ] {
            assert!(s.resume(&input).is_err());
        }
        let mut c: Cursor =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(base).expect("base64"))
                .expect("cursor");
        c.version = 2;
        assert!(
            s.resume(&BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).expect("json")))
                .is_err()
        );
        let options = CiStepLogOptions {
            page_bytes: Some(3),
            ..Default::default()
        };
        assert_eq!(
            s.page(&session(), &options)
                .expect_err("budget")
                .minimum_page_bytes,
            Some(4)
        );
        let first = s
            .page(
                &session(),
                &CiStepLogOptions {
                    page_bytes: Some(4),
                    ..Default::default()
                },
            )
            .expect("scalar");
        assert_eq!(first.fragments[0].text, "🙂");
        assert_eq!(
            s.page(
                &session(),
                &CiStepLogOptions {
                    cursor: first.next_cursor,
                    page_bytes: Some(9),
                    ..Default::default()
                }
            )
            .expect_err("redaction")
            .minimum_page_bytes,
            Some(10)
        );
        assert_eq!(traverse(&s, None, 10), "🙂[REDACTED]終");
    }

    #[tokio::test]
    async fn empty_records_escape_expansion_and_fragment_bounds_are_finite() {
        for data in [b"[]".as_slice(), b"null"] {
            let p = snapshot(data, "", "commit")
                .page(&session(), &CiStepLogOptions::default())
                .expect("empty");
            assert!(p.snapshot_complete);
            assert!(p.next_cursor.is_none());
        }
        let data = serde_json::to_vec(&vec![json!({"data":7}); 600]).expect("json");
        let s = snapshot(&data, "", "commit");
        let p = s
            .page(&session(), &CiStepLogOptions::default())
            .expect("page");
        assert_eq!(p.fragments.len(), 256);
        assert_eq!(p.end_position.record_index, 256);
        assert!(!p.snapshot_complete);
        assert_eq!(traverse(&s, None, 1), "");
        let controls = "\0".repeat(65536);
        let s = snapshot(&raw(&[&controls]), "", "commit");
        let p = s
            .page(
                &session(),
                &CiStepLogOptions {
                    page_bytes: Some(65536),
                    ..Default::default()
                },
            )
            .expect("escaped");
        assert_eq!(p.fragments[0].text, controls);
        assert!(serde_json::to_vec(&p).expect("json").len() <= RESPONSE_CAP);
    }

    #[tokio::test]
    async fn wire_budget_continues_only_after_emitted_material() {
        let text = "\0".repeat(256);
        let record = json!({"data": BASE64_STANDARD.encode(&text), "type": "\0".repeat(65)});
        let bytes = serde_json::to_vec(&vec![record; 256]).expect("json");
        let s = snapshot(&bytes, "", "commit");
        let first = s
            .page(
                &session(),
                &CiStepLogOptions {
                    page_bytes: Some(65536),
                    ..Default::default()
                },
            )
            .expect("page");
        assert!(!first.snapshot_complete);
        assert!(first.fragments.len() < 256);
        assert_eq!(first.end_position.record_index, first.fragments.len());
        assert!(serde_json::to_vec(&first).expect("json").len() <= RESPONSE_CAP);
        assert_eq!(traverse(&s, None, 65536), text.repeat(256));
    }
}
