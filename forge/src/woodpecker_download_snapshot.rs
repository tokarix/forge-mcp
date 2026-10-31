//! Dedicated strict download snapshots and canonical UTF-8 byte pagination.
//!
//! Callers freshly authorize, select and fetch the entire bounded source on
//! every page. Tokens contain only digests, profile/version and an offset.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use domain::{
    CiLogStart, CiStepLogDownloadDiagnostic, CiStepLogDownloadFragment, CiStepLogDownloadStatus,
    CiStepLogIdentity, CiStepLogOptions, RepositoryCiStepLogDownload, RepositoryRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::woodpecker::{Origin, Session};
use crate::woodpecker_download_decode::CanonicalText;

const PROFILE: &str = "strict-download-snapshot-v1";
const RESPONSE_CAP: usize = 512 * 1024;

/// Safe pagination failure without source text or token contents.
#[derive(Debug)]
pub struct PageError {
    /// Stable public status.
    pub status: CiStepLogDownloadStatus,
    /// Static diagnostic explanation.
    pub message: &'static str,
    /// Next indivisible unit's minimum text budget, if needed.
    pub minimum_page_bytes: Option<usize>,
}
fn error(status: CiStepLogDownloadStatus, message: &'static str) -> PageError {
    PageError {
        status,
        message,
        minimum_page_bytes: None,
    }
}
fn invalid() -> PageError {
    error(
        CiStepLogDownloadStatus::InvalidCursor,
        "Invalid download cursor or byte boundary",
    )
}
fn deadline(session: &Session) -> Result<(), PageError> {
    session.check_deadline().map_err(|_| {
        error(
            CiStepLogDownloadStatus::RetrievalLimit,
            "Download assembly deadline exceeded",
        )
    })
}
fn digest(session: &Session, parts: &[&[u8]]) -> Result<String, PageError> {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part.len().to_be_bytes());
        for chunk in part.chunks(16384) {
            deadline(session)?;
            hash.update(chunk);
        }
    }
    Ok(BASE64_URL_SAFE_NO_PAD.encode(hash.finalize()))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    profile: String,
    version: u8,
    binding: String,
    snapshot: String,
    offset: usize,
}

/// Request-local, uncached canonical download snapshot.
pub struct Snapshot {
    identity: CiStepLogIdentity,
    canonical: CanonicalText,
    binding: String,
    id: String,
}
impl Snapshot {
    /// Bind the exact authority, configured origin/prefix, endpoint, identity,
    /// representation and redaction policy to the complete received raw source.
    ///
    /// # Errors
    /// Rejects invalid origin, serialization or shared deadline exhaustion.
    pub fn new(
        session: &Session,
        repository: &RepositoryRef,
        origin: &Origin,
        identity: CiStepLogIdentity,
        raw: &[u8],
        canonical: CanonicalText,
        secrets: &[&str],
    ) -> Result<Self, PageError> {
        deadline(session)?;
        let mut policy: Vec<_> = secrets.iter().copied().filter(|s| !s.is_empty()).collect();
        policy.sort_unstable();
        policy.dedup();
        let parts: Vec<_> = policy.iter().map(|s| s.as_bytes()).collect();
        let policy = digest(session, &parts)?;
        let binding_bytes = serde_json::to_vec(&(
            PROFILE,
            "woodpecker_step_log_download/plain_text_utf8_v1/redaction-v1/lossy-utf8-v1",
            repository,
            origin
                .pipeline_url(
                    identity.selector.provider_repository_id,
                    identity.selector.pipeline_number,
                )
                .map_err(|_| invalid())?,
            "logs/download",
            &identity,
            policy,
        ))
        .map_err(|_| invalid())?;
        let binding = digest(session, &[&binding_bytes])?;
        let id = digest(session, &[binding.as_bytes(), raw])?;
        Ok(Self {
            identity,
            canonical,
            binding,
            id,
        })
    }
    fn cursor(&self, offset: usize) -> Result<String, PageError> {
        let bytes = serde_json::to_vec(&Cursor {
            profile: PROFILE.into(),
            version: 1,
            binding: self.binding.clone(),
            snapshot: self.id.clone(),
            offset,
        })
        .map_err(|_| invalid())?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }
    fn boundary(&self, offset: usize) -> bool {
        self.canonical.text.is_char_boundary(offset)
            && !self
                .canonical
                .redactions
                .iter()
                .any(|s| s.start < offset && offset < s.end)
    }
    fn resume(&self, input: &str) -> Result<usize, PageError> {
        if input.is_empty() || input.len() > domain::CI_LOG_MAX_CURSOR_BYTES {
            return Err(invalid());
        }
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| invalid())?;
        let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if cursor.profile != PROFILE
            || cursor.version != 1
            || [&cursor.binding, &cursor.snapshot].iter().any(|d| {
                d.len() != 43
                    || BASE64_URL_SAFE_NO_PAD
                        .decode(d.as_bytes())
                        .map_or(true, |b| b.len() != 32)
            })
        {
            return Err(invalid());
        }
        if cursor.binding != self.binding {
            return Err(error(
                CiStepLogDownloadStatus::BindingMismatch,
                "Download authority, identity, origin or policy changed",
            ));
        }
        if cursor.snapshot != self.id {
            return Err(error(
                CiStepLogDownloadStatus::StaleCursor,
                "Download source changed; restart explicitly",
            ));
        }
        if !self.boundary(cursor.offset) {
            return Err(invalid());
        }
        Ok(cursor.offset)
    }
    fn minimum(&self, offset: usize) -> usize {
        self.canonical
            .redactions
            .iter()
            .find(|s| s.start == offset)
            .map_or_else(
                || {
                    self.canonical.text[offset..]
                        .chars()
                        .next()
                        .map_or(0, char::len_utf8)
                },
                |s| s.end - s.start,
            )
    }
    fn start(&self, options: &CiStepLogOptions) -> Result<usize, PageError> {
        let text = &self.canonical.text;
        let budget = options.budget();
        let start = if let Some(cursor) = &options.cursor {
            self.resume(cursor)?
        } else if options.start == Some(CiLogStart::Tail) {
            let mut offset = text.len().saturating_sub(budget);
            while !text.is_char_boundary(offset) {
                offset += 1;
            }
            if let Some(span) = self
                .canonical
                .redactions
                .iter()
                .find(|s| s.start < offset && offset < s.end)
            {
                offset = span.end;
            }
            if offset == text.len() && !text.is_empty() {
                offset = self
                    .canonical
                    .redactions
                    .iter()
                    .find(|s| s.end == offset)
                    .map_or_else(
                        || text.char_indices().next_back().map_or(0, |(i, _)| i),
                        |s| s.start,
                    );
            }
            offset
        } else {
            0
        };
        Ok(start)
    }
    /// Return a text page with exact canonical offsets and same-snapshot rewind.
    ///
    /// One fragment suffices for a plain stream, below the 256-fragment bound.
    /// A maximal text page needs at most 384 KiB after JSON escaping; envelope
    /// room is checked before exposing any advancing offset or cursor.
    ///
    /// # Errors
    /// Rejects mixed/invalid/stale cursors, insufficient scalar/replacement
    /// budgets, envelope limits or shared CPU deadlines. Never restarts silently.
    pub fn page(
        &self,
        session: &Session,
        options: &CiStepLogOptions,
    ) -> Result<RepositoryCiStepLogDownload, PageError> {
        deadline(session)?;
        options.validate().map_err(|_| invalid())?;
        let text = &self.canonical.text;
        let budget = options.budget();
        let start = self.start(options)?;
        deadline(session)?;
        let mut end = start
            .checked_add(budget.min(text.len() - start))
            .ok_or_else(invalid)?;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(span) = self
            .canonical
            .redactions
            .iter()
            .find(|s| s.start < end && end < s.end)
        {
            end = span.start;
        }
        if end == start && end < text.len() {
            return Err(PageError {
                status: CiStepLogDownloadStatus::InvalidCursor,
                message: "page_bytes cannot fit the next UTF-8 scalar or redaction unit",
                minimum_page_bytes: Some(self.minimum(start)),
            });
        }
        let mut page = RepositoryCiStepLogDownload::unsupported(self.identity.selector.clone());
        page.identity = Some(self.identity.clone());
        page.status = CiStepLogDownloadStatus::Available;
        page.snapshot_id = Some(self.id.clone());
        page.position = start;
        page.end_position = end;
        page.beginning_cursor = Some(self.cursor(0)?);
        page.snapshot_complete = end == text.len();
        page.truncated = !page.snapshot_complete || self.canonical.lossy;
        page.provider_step_finished = match self.identity.step_state.as_str() {
            "success" | "failure" | "error" | "killed" | "skipped" | "cancelled" => Some(true),
            "pending" | "running" | "blocked" => Some(false),
            _ => None,
        };
        if !page.snapshot_complete {
            page.next_cursor = Some(self.cursor(end)?);
        }
        if self.canonical.lossy {
            page.diagnostics.push(CiStepLogDownloadDiagnostic {
                code: "lossy_utf8".into(),
                message: "Invalid UTF-8 uses Unicode replacement characters".into(),
                http_status: None,
            });
        }
        if text.is_empty() {
            page.diagnostics.push(CiStepLogDownloadDiagnostic {
                code: "empty_logs".into(),
                message: "The available download is empty; full-output retention remains unknown"
                    .into(),
                http_status: None,
            });
        }
        // Reserve the actual escaped envelope before adding text.
        let overhead = serde_json::to_vec(&page).map_err(|_| invalid())?.len();
        let escaped = serde_json::to_vec(&text[start..end])
            .map_err(|_| invalid())?
            .len();
        if overhead
            .checked_add(escaped)
            .and_then(|n| n.checked_add(128))
            .is_none_or(|n| n > RESPONSE_CAP)
        {
            return Err(error(
                CiStepLogDownloadStatus::RetrievalLimit,
                "Serialized download envelope exceeds limit",
            ));
        }
        if start < end {
            page.fragments.push(CiStepLogDownloadFragment {
                byte_offset: start,
                text: text[start..end].into(),
            });
        }
        if serde_json::to_vec(&page).map_err(|_| invalid())?.len() > RESPONSE_CAP {
            return Err(error(
                CiStepLogDownloadStatus::RetrievalLimit,
                "Serialized download envelope exceeds limit",
            ));
        }
        deadline(session)?;
        Ok(page)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::woodpecker::StepLogTransportLimits;
    use crate::woodpecker_download_decode::{DecodeLimits, decode};
    use domain::{CiStepLogSelector, CiTimestamps, ForgeKind};
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
        let records = decode(&s, raw, &[secret], DecodeLimits::default()).expect("decode");
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

    fn traverse(s: &Snapshot, cursor: Option<String>, budget: usize) -> String {
        let mut options = CiStepLogOptions {
            cursor,
            page_bytes: Some(budget),
            ..Default::default()
        };
        let mut text = String::new();
        let session = session();
        for _ in 0..10000 {
            let page = s.page(&session, &options).expect("page");
            assert_eq!(
                page.output_completeness,
                domain::CiLogOutputCompleteness::Unknown
            );
            assert!(serde_json::to_vec(&page).expect("json").len() <= RESPONSE_CAP);
            let mut offset = page.position;
            for f in page.fragments {
                assert_eq!(f.byte_offset, offset);
                offset += f.text.len();
                text.push_str(&f.text);
            }
            assert_eq!(offset, page.end_position);
            if page.snapshot_complete {
                assert!(page.next_cursor.is_none());
                return text;
            }
            assert!(page.end_position > page.position);
            options.cursor = page.next_cursor;
        }
        panic!("no progress");
    }
    #[tokio::test]
    async fn reconstruction_tail_rewind_and_loss_preserve_bytes() {
        let raw = format!(
            "{}SECRET{}",
            "終🙂\r\n\0\x1b[31m".repeat(200),
            " no final newline"
        );
        let s = snapshot(raw.as_bytes(), "SECRET", "commit");
        let expected = raw.replace("SECRET", "[REDACTED]");
        for budget in [10, 31, 16384, 65536] {
            assert_eq!(traverse(&s, None, budget), expected);
        }
        let tail = s
            .page(
                &session(),
                &CiStepLogOptions {
                    start: Some(CiLogStart::Tail),
                    page_bytes: Some(31),
                    cursor: None,
                },
            )
            .expect("tail");
        assert!(tail.snapshot_complete);
        assert_eq!(traverse(&s, tail.beginning_cursor, 31), expected);
        let lossy = snapshot(b"a\xff", "", "commit")
            .page(&session(), &CiStepLogOptions::default())
            .expect("lossy");
        assert!(lossy.snapshot_complete && lossy.truncated);
        assert!(lossy.diagnostics.iter().any(|d| d.code == "lossy_utf8"));
        let empty = snapshot(b"", "", "commit")
            .page(&session(), &CiStepLogOptions::default())
            .expect("empty");
        assert!(empty.snapshot_complete && !empty.truncated);
        assert!(empty.fragments.is_empty());
        assert!(empty.diagnostics.iter().any(|d| d.code == "empty_logs"));
        let controls = "\0".repeat(65536);
        assert_eq!(
            traverse(&snapshot(controls.as_bytes(), "", "commit"), None, 65536),
            controls
        );
    }
    #[tokio::test]
    async fn source_and_authority_changes_require_explicit_restart() {
        let original = snapshot(b"abcdef", "secret", "commit");
        let token = original.cursor(2).expect("cursor");
        for raw in [b"abcdefx".as_slice(), b"a", b"replace", b""] {
            let s = snapshot(raw, "secret", "commit");
            assert_eq!(
                s.resume(&token).expect_err("stale").status,
                CiStepLogDownloadStatus::StaleCursor
            );
            assert!(s.page(&session(), &CiStepLogOptions::default()).is_ok());
        }
        for s in [
            snapshot(b"abcdef", "changed", "commit"),
            snapshot(b"abcdef", "secret", "changed"),
        ] {
            assert_eq!(
                s.resume(&token).expect_err("binding").status,
                CiStepLogDownloadStatus::BindingMismatch
            );
        }
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(token).expect("base64");
        let serialized = String::from_utf8(decoded).expect("utf8");
        for secret in ["secret", "commit", "abcdef", "http"] {
            assert!(!serialized.contains(secret));
        }
    }
    #[tokio::test]
    async fn rejects_mixed_profiles_versions_offsets_and_tiny_budgets() {
        let s = snapshot("🙂SECRET終".as_bytes(), "SECRET", "commit");
        for offset in [1, 5, 15, usize::MAX] {
            assert!(s.resume(&s.cursor(offset).expect("cursor")).is_err());
        }
        for input in [
            "?".into(),
            "a".repeat(4097),
            BASE64_URL_SAFE_NO_PAD
                .encode(br#"{"version":1,"position":{"record_index":0,"byte_offset":0}}"#),
        ] {
            assert!(s.resume(&input).is_err());
        }
        for field in ["profile", "version", "unknown"] {
            let mut value: serde_json::Value = serde_json::from_slice(
                &BASE64_URL_SAFE_NO_PAD
                    .decode(s.cursor(0).expect("cursor"))
                    .expect("base64"),
            )
            .expect("json");
            value[field] = serde_json::json!(99);
            assert!(
                s.resume(&BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("json")))
                    .is_err()
            );
        }
        for (offset, budget, minimum) in [(0, 3, 4), (4, 9, 10)] {
            assert_eq!(
                s.page(
                    &session(),
                    &CiStepLogOptions {
                        cursor: Some(s.cursor(offset).expect("cursor")),
                        page_bytes: Some(budget),
                        start: None
                    }
                )
                .expect_err("minimum")
                .minimum_page_bytes,
                Some(minimum)
            );
        }
        assert_eq!(traverse(&s, None, 10), "🙂[REDACTED]終");
    }
    #[tokio::test]
    async fn identical_raw_sources_reject_each_others_real_tokens() {
        let download = snapshot(b"[]", "", "commit");
        let session = session();
        let repository = RepositoryRef {
            alias: "fixture".into(),
            forge: ForgeKind::Forgejo,
            host: "forge.example".into(),
            owner: "owner".into(),
            name: "repo".into(),
        };
        let origin = Origin::parse("http://example.invalid/ci").expect("origin");
        let records = crate::woodpecker_log_decode::decode(
            &session,
            b"[]",
            None,
            &[],
            crate::woodpecker_log_decode::DecodeLimits::default(),
        )
        .expect("JSON decode");
        let json = crate::woodpecker_log_snapshot::Snapshot::new(
            &session,
            &repository,
            &origin,
            download.identity.clone(),
            b"[]",
            records,
            &[],
        )
        .expect("JSON snapshot");
        let page = json
            .page(&session, &CiStepLogOptions::default())
            .expect("JSON page");
        assert!(
            download
                .resume(&page.beginning_cursor.expect("JSON cursor"))
                .is_err()
        );
        let options = CiStepLogOptions {
            cursor: Some(download.cursor(0).expect("download cursor")),
            ..Default::default()
        };
        assert_eq!(
            json.page(&session, &options)
                .expect_err("mixed source")
                .status,
            domain::CiStepLogStatus::InvalidCursor
        );
        assert_ne!(page.snapshot_id, Some(download.id.clone()));
        for mutation in 0..5 {
            let mut repository = repository.clone();
            let mut identity = download.identity.clone();
            let mut origin = origin.clone();
            match mutation {
                0 => repository.alias = "other".into(),
                1 => identity.step_uuid = Some("changed".into()),
                2 => identity.selector.workflow_id += 1,
                3 => origin = Origin::parse("http://other.invalid/ci").expect("origin"),
                _ => origin = Origin::parse("http://example.invalid/other-prefix").expect("origin"),
            }
            let canonical = decode(&session, b"[]", &[], DecodeLimits::default()).expect("decode");
            let changed = Snapshot::new(
                &session,
                &repository,
                &origin,
                identity,
                b"[]",
                canonical,
                &[],
            )
            .expect("snapshot");
            assert_eq!(
                changed
                    .resume(&download.cursor(0).expect("cursor"))
                    .expect_err("binding")
                    .status,
                CiStepLogDownloadStatus::BindingMismatch
            );
        }
    }
}
