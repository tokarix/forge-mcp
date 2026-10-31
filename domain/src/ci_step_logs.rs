//! Bounded historical step output contracts.
//!
//! `strict-snapshot-v1` re-fetches the full retained log on every page. Any raw
//! body, source identity, origin or redaction-policy change invalidates traversal.
//! Consumers must explicitly restart; this interface does not follow live logs.
//! Concatenate fragments within each record, then records in array order, without
//! adding separators. Positions measure canonical decoded, redacted UTF-8 bytes.
//! Invalid UTF-8 uses Unicode replacement characters with a record diagnostic.

use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, CiEvidenceKind, CiTimestamps, RepositoryRef};

/// Default canonical text budget per response.
pub const CI_LOG_DEFAULT_PAGE_BYTES: usize = 16 * 1024;
/// Largest accepted canonical text budget per response.
pub const CI_LOG_MAX_PAGE_BYTES: usize = 64 * 1024;
/// Maximum untrusted cursor input size, before decoding.
pub const CI_LOG_MAX_CURSOR_BYTES: usize = 4096;

/// Lookup hints, never evidence that provider identity has been validated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiStepLogSelector {
    /// Initially only `woodpecker` is supported.
    pub provider: String,
    /// Provider repository database ID.
    pub provider_repository_id: u64,
    /// Repository-scoped run number, not pipeline database ID.
    pub pipeline_number: u64,
    /// Workflow database ID, not UI position or workflow pid.
    pub workflow_id: u64,
    /// Step database ID, not runner ID.
    pub step_id: u64,
}
impl CiStepLogSelector {
    /// Check that all IDs fit the provider's positive signed 64-bit IDs.
    #[must_use]
    pub fn valid(&self) -> bool {
        [
            self.provider_repository_id,
            self.pipeline_number,
            self.workflow_id,
            self.step_id,
        ]
        .into_iter()
        .all(|id| id > 0 && i64::try_from(id).is_ok())
    }
}

/// Initial window. Tail always supplies a cursor to rewind the same snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiLogStart {
    /// Traverse from the first record by default.
    #[default]
    Beginning,
    /// Start at the last bounded window of the retained snapshot.
    Tail,
}

/// Bounded page options. Cursor and explicit start are mutually exclusive.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiStepLogOptions {
    /// Opaque untrusted position, reauthorized and revalidated on every request.
    pub cursor: Option<String>,
    /// Applies only to a new snapshot; omission means beginning.
    pub start: Option<CiLogStart>,
    /// Canonical text byte budget (1 through 65,536); default 16,384.
    pub page_bytes: Option<usize>,
}
impl CiStepLogOptions {
    /// Validate input before any provider calls.
    ///
    /// # Errors
    /// Returns a static explanation for invalid options, never cursor contents.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.cursor.is_some() && self.start.is_some() {
            return Err("cursor and start cannot be used together");
        }
        if self
            .cursor
            .as_ref()
            .is_some_and(|c| c.is_empty() || c.len() > CI_LOG_MAX_CURSOR_BYTES)
        {
            return Err("cursor must contain 1 through 4096 bytes");
        }
        if !(1..=CI_LOG_MAX_PAGE_BYTES).contains(&self.budget()) {
            return Err("page_bytes must be between 1 and 65536");
        }
        Ok(())
    }
    /// Effective canonical text byte budget.
    #[must_use]
    pub fn budget(&self) -> usize {
        self.page_bytes.unwrap_or(CI_LOG_DEFAULT_PAGE_BYTES)
    }
}

/// Authorized repository-scoped retained output request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetRepositoryCiStepLogsRequest {
    /// Gateway identity authorizing this read.
    pub agent: AgentIdentity,
    /// Authorized forge repository, independent of provider lookup hints.
    pub repository: RepositoryRef,
    /// Explicit selected child.
    pub selector: CiStepLogSelector,
    /// Snapshot and window selection.
    pub options: CiStepLogOptions,
}

/// Provider identity populated only after repository and child binding succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiStepLogIdentity {
    /// Validated selector.
    pub selector: CiStepLogSelector,
    /// Pipeline database ID, distinct from the run number.
    pub pipeline_id: i64,
    /// Exact source commit; never clipped into a different identity.
    pub commit: String,
    /// Explicitly unknown when not exposed or not safely representable.
    pub reference: Option<String>,
    /// Workflow position used for the step's parent binding.
    pub workflow_pid: i64,
    /// Provider step UUID if exposed.
    pub step_uuid: Option<String>,
    /// Sanitized bounded step name.
    pub step_name: String,
    /// Sanitized provider state; retrieval does not depend on this state.
    pub step_state: String,
    /// Provider step timestamps, when available.
    pub timestamps: CiTimestamps,
}

/// Position in canonical record output; array index is authoritative order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiLogPosition {
    /// Zero-based upstream array position, including empty/malformed records.
    pub record_index: usize,
    /// Byte offset in the decoded and redacted UTF-8 record.
    pub byte_offset: usize,
}

/// Allowlisted provider record metadata; never controls traversal order.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CiLogRecordMetadata {
    /// Provider timestamp, when well typed.
    pub time: Option<i64>,
    /// Provider line number, when well typed.
    pub line: Option<i64>,
    /// Bounded provider record type.
    pub record_type: Option<String>,
}

/// One ordered fragment, including explicit zero-output record positions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiLogFragment {
    /// Start in canonical output.
    pub position: CiLogPosition,
    /// Original whitespace is preserved; no separators are inserted.
    pub text: String,
    /// Whether this fragment reaches the end of this record.
    pub record_complete: bool,
    /// Optional allowlisted provider metadata.
    pub metadata: CiLogRecordMetadata,
}

/// Stable page status, distinguishing ordinary continuation from hard failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogStatus {
    /// A bounded navigable snapshot page, possibly with decoding diagnostics.
    Available,
    /// Hard resource bound; no navigable snapshot or continuation.
    RetrievalLimit,
    /// Cursor is malformed or points outside canonical UTF-8 positions.
    InvalidCursor,
    /// Freshly fetched retained output differs from the cursor snapshot.
    StaleCursor,
    /// Repository, source or child identity does not match.
    BindingMismatch,
    /// Selected provider request failed.
    Unavailable,
    /// Backend or provider capability is unsupported.
    Unsupported,
    /// Top-level provider response is malformed, not an empty log.
    MalformedResponse,
}

/// Bounded, safe diagnostic; upstream error bodies are never messages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiStepLogDiagnostic {
    /// Stable code such as `invalid_base64`, `lossy_utf8` or `not_exposed`.
    pub code: String,
    /// Static safe explanation, never upstream text or cursor content.
    pub message: String,
    /// Affected array position for record decoding failures.
    pub record_index: Option<usize>,
    /// HTTP status if an upstream request failed.
    pub http_status: Option<u16>,
}

/// Selected retained JSON source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogSource {
    /// Retained JSON view; never proof of full output retention.
    WoodpeckerStepLogJson,
}

/// Versioned JSON records with decoded text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogRepresentation {
    /// Retained JSON view; never proof of full output retention.
    JsonRecordsV1,
}

/// Retained historical output never establishes current-head CI or merge success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RepositoryCiStepLogs {
    /// Selected retained source, outside cursor binding.
    pub source: CiStepLogSource,
    /// Selected representation, outside cursor binding.
    pub representation: CiStepLogRepresentation,
    /// Source EOF cannot establish full job-output retention.
    pub output_completeness: crate::CiLogOutputCompleteness,
    /// Always historical, including active retained snapshots.
    pub evidence_kind: CiEvidenceKind,
    /// Echoed request hints, separate from validated identity.
    pub selector: CiStepLogSelector,
    /// Remains absent on binding/selection failures.
    pub identity: Option<CiStepLogIdentity>,
    /// Typed retrieval outcome.
    pub status: CiStepLogStatus,
    /// `strict-snapshot-v1`; changes require an explicit restart.
    pub consistency: String,
    /// Non-reversible digest of raw response and versioned security binding.
    pub snapshot_id: Option<String>,
    /// Fragments in original array order.
    pub fragments: Vec<CiLogFragment>,
    /// Start of this page.
    pub position: CiLogPosition,
    /// First position after actually emitted fragments.
    pub end_position: CiLogPosition,
    /// Null at snapshot EOF and for every hard retrieval failure.
    pub next_cursor: Option<String>,
    /// Rewind within the same snapshot, including a tail-initialized snapshot.
    pub beginning_cursor: Option<String>,
    /// End of the fetched snapshot, independently of possible future appends.
    pub snapshot_complete: bool,
    /// Conservative terminal-state assessment; unknown remains null.
    pub provider_step_finished: Option<bool>,
    /// More snapshot material exists or retrieval/decoding is limited.
    pub truncated: bool,
    /// Bounded safe diagnostics, including unavailable infrastructure evidence.
    pub diagnostics: Vec<CiStepLogDiagnostic>,
}
impl RepositoryCiStepLogs {
    /// Safe retention limitation, independent of cursor and provider state.
    #[must_use]
    pub fn completeness_diagnostic() -> CiStepLogDiagnostic {
        CiStepLogDiagnostic {
            code: "output_completeness_unknown".into(),
            message: "Available source EOF does not establish full job-output retention".into(),
            record_index: None,
            http_status: None,
        }
    }

    /// Explicit unsupported default, with no purported validated identity.
    #[must_use]
    pub fn unsupported(selector: CiStepLogSelector) -> Self {
        Self {
            source: CiStepLogSource::WoodpeckerStepLogJson,
            representation: CiStepLogRepresentation::JsonRecordsV1,
            output_completeness: crate::CiLogOutputCompleteness::Unknown,
            evidence_kind: CiEvidenceKind::Historical,
            selector,
            identity: None,
            status: CiStepLogStatus::Unsupported,
            consistency: "strict-snapshot-v1".into(),
            snapshot_id: None,
            fragments: Vec::new(),
            position: CiLogPosition::default(),
            end_position: CiLogPosition::default(),
            next_cursor: None,
            beginning_cursor: None,
            snapshot_complete: false,
            provider_step_finished: None,
            truncated: true,
            diagnostics: vec![Self::completeness_diagnostic()],
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn selector() -> CiStepLogSelector {
        CiStepLogSelector {
            provider: "woodpecker".into(),
            provider_repository_id: 1,
            pipeline_number: 42,
            workflow_id: 7,
            step_id: 9,
        }
    }

    #[test]
    fn identifiers_require_positive_signed_provider_range() {
        let base = selector();
        assert!(base.valid());
        for id in [0, i64::MAX as u64 + 1, u64::MAX] {
            for field in 0..4 {
                let mut selected = base.clone();
                match field {
                    0 => selected.provider_repository_id = id,
                    1 => selected.pipeline_number = id,
                    2 => selected.workflow_id = id,
                    _ => selected.step_id = id,
                }
                assert!(!selected.valid());
            }
        }
        let mut max = base;
        max.step_id = i64::MAX as u64;
        assert!(max.valid());
    }

    #[test]
    fn options_bound_input_and_preserve_explicit_start_conflict() {
        let default = CiStepLogOptions::default();
        assert_eq!(default.budget(), 16384);
        assert!(default.validate().is_ok());
        for budget in [0, 65537, usize::MAX] {
            assert!(
                CiStepLogOptions {
                    page_bytes: Some(budget),
                    ..default.clone()
                }
                .validate()
                .is_err()
            );
        }
        for budget in [1, 65536] {
            assert!(
                CiStepLogOptions {
                    page_bytes: Some(budget),
                    ..default.clone()
                }
                .validate()
                .is_ok()
            );
        }
        for cursor in [String::new(), "x".repeat(4097)] {
            assert!(
                CiStepLogOptions {
                    cursor: Some(cursor),
                    ..default.clone()
                }
                .validate()
                .is_err()
            );
        }
        let options = CiStepLogOptions {
            cursor: Some("opaque".into()),
            start: Some(CiLogStart::Beginning),
            page_bytes: None,
        };
        assert!(options.validate().is_err());
        assert!(serde_json::from_str::<CiStepLogOptions>(r#"{"start":"live"}"#).is_err());
        assert!(serde_json::from_str::<CiStepLogOptions>(r#"{"offset":1}"#).is_err());
    }

    #[test]
    fn failure_envelope_never_claims_identity_or_snapshot_eof() {
        let response = RepositoryCiStepLogs::unsupported(selector());
        let json = serde_json::to_value(response).expect("serialize");
        assert_eq!(json["evidence_kind"], "historical");
        assert_eq!(json["status"], "unsupported");
        assert_eq!(json["consistency"], "strict-snapshot-v1");
        assert!(json["identity"].is_null());
        assert!(json["next_cursor"].is_null());
        assert!(json["beginning_cursor"].is_null());
        assert_eq!(json["snapshot_complete"], false);
        assert!(json["provider_step_finished"].is_null());
        assert_eq!(json["selector"]["step_id"], 9);
    }
}
