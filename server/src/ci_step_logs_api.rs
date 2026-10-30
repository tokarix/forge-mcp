//! Public retained step-log wire types and explicit domain conversion.

use serde::Serialize;
use utoipa::ToSchema;

use crate::api::{CiTimestampsResult, HistoricalEvidenceKindResult};

/// Lookup hints, never evidence that provider identity has been validated.
#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CiStepLogSelectorResult {
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

/// Provider identity populated only after repository and child binding succeeds.
#[derive(Debug, Serialize, ToSchema)]
pub struct CiStepLogIdentityResult {
    /// Validated selector.
    pub selector: CiStepLogSelectorResult,
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
    pub timestamps: CiTimestampsResult,
}

/// Position in canonical record output; array index is authoritative order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CiLogPositionResult {
    /// Zero-based upstream array position, including empty/malformed records.
    pub record_index: usize,
    /// Byte offset in the decoded and redacted UTF-8 record.
    pub byte_offset: usize,
}

/// Allowlisted provider record metadata; never controls traversal order.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, ToSchema)]
pub struct CiLogRecordMetadataResult {
    /// Provider timestamp, when well typed.
    pub time: Option<i64>,
    /// Provider line number, when well typed.
    pub line: Option<i64>,
    /// Bounded provider record type.
    pub record_type: Option<String>,
}

/// One ordered fragment, including explicit zero-output record positions.
#[derive(Debug, Serialize, ToSchema)]
pub struct CiLogFragmentResult {
    /// Start in canonical output.
    pub position: CiLogPositionResult,
    /// Original whitespace is preserved; no separators are inserted.
    pub text: String,
    /// Whether this fragment reaches the end of this record.
    pub record_complete: bool,
    /// Optional allowlisted provider metadata.
    pub metadata: CiLogRecordMetadataResult,
}

/// Stable page status, distinguishing ordinary continuation from hard failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogStatusResult {
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
#[derive(Debug, Serialize, ToSchema)]
pub struct CiStepLogDiagnosticResult {
    /// Stable code such as `invalid_base64`, `lossy_utf8` or `not_exposed`.
    pub code: String,
    /// Static safe explanation, never upstream text or cursor content.
    pub message: String,
    /// Affected array position for record decoding failures.
    pub record_index: Option<usize>,
    /// HTTP status if an upstream request failed.
    pub http_status: Option<u16>,
}

/// Retained historical output never establishes current-head CI or merge success.
#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryCiStepLogsResult {
    /// Always historical, including active retained snapshots.
    pub evidence_kind: HistoricalEvidenceKindResult,
    /// Echoed request hints, separate from validated identity.
    pub selector: CiStepLogSelectorResult,
    /// Remains absent on binding/selection failures.
    pub identity: Option<CiStepLogIdentityResult>,
    /// Typed retrieval outcome.
    pub status: CiStepLogStatusResult,
    /// `strict-snapshot-v1`; changes require an explicit restart.
    pub consistency: String,
    /// Non-reversible digest of raw response and versioned security binding.
    pub snapshot_id: Option<String>,
    /// Fragments in original array order.
    pub fragments: Vec<CiLogFragmentResult>,
    /// Start of this page.
    pub position: CiLogPositionResult,
    /// First position after actually emitted fragments.
    pub end_position: CiLogPositionResult,
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
    pub diagnostics: Vec<CiStepLogDiagnosticResult>,
}

impl From<domain::CiStepLogSelector> for CiStepLogSelectorResult {
    fn from(value: domain::CiStepLogSelector) -> Self {
        Self {
            provider: value.provider,
            provider_repository_id: value.provider_repository_id,
            pipeline_number: value.pipeline_number,
            workflow_id: value.workflow_id,
            step_id: value.step_id,
        }
    }
}

impl From<domain::CiLogPosition> for CiLogPositionResult {
    fn from(value: domain::CiLogPosition) -> Self {
        Self {
            record_index: value.record_index,
            byte_offset: value.byte_offset,
        }
    }
}

impl From<domain::CiLogRecordMetadata> for CiLogRecordMetadataResult {
    fn from(value: domain::CiLogRecordMetadata) -> Self {
        Self {
            time: value.time,
            line: value.line,
            record_type: value.record_type,
        }
    }
}

impl From<domain::CiStepLogDiagnostic> for CiStepLogDiagnosticResult {
    fn from(value: domain::CiStepLogDiagnostic) -> Self {
        Self {
            code: value.code,
            message: value.message,
            record_index: value.record_index,
            http_status: value.http_status,
        }
    }
}

impl From<domain::CiStepLogIdentity> for CiStepLogIdentityResult {
    fn from(value: domain::CiStepLogIdentity) -> Self {
        Self {
            selector: value.selector.into(),
            pipeline_id: value.pipeline_id,
            commit: value.commit,
            reference: value.reference,
            workflow_pid: value.workflow_pid,
            step_uuid: value.step_uuid,
            step_name: value.step_name,
            step_state: value.step_state,
            timestamps: value.timestamps.into(),
        }
    }
}

impl From<domain::CiLogFragment> for CiLogFragmentResult {
    fn from(value: domain::CiLogFragment) -> Self {
        Self {
            position: value.position.into(),
            text: value.text,
            record_complete: value.record_complete,
            metadata: value.metadata.into(),
        }
    }
}

impl From<domain::RepositoryCiStepLogs> for RepositoryCiStepLogsResult {
    fn from(value: domain::RepositoryCiStepLogs) -> Self {
        Self {
            evidence_kind: HistoricalEvidenceKindResult::Historical,
            selector: value.selector.into(),
            identity: value.identity.map(Into::into),
            status: value.status.into(),
            consistency: value.consistency,
            snapshot_id: value.snapshot_id,
            fragments: value.fragments.into_iter().map(Into::into).collect(),
            position: value.position.into(),
            end_position: value.end_position.into(),
            next_cursor: value.next_cursor,
            beginning_cursor: value.beginning_cursor,
            snapshot_complete: value.snapshot_complete,
            provider_step_finished: value.provider_step_finished,
            truncated: value.truncated,
            diagnostics: value.diagnostics.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<domain::CiStepLogStatus> for CiStepLogStatusResult {
    fn from(value: domain::CiStepLogStatus) -> Self {
        match value {
            domain::CiStepLogStatus::Available => Self::Available,
            domain::CiStepLogStatus::RetrievalLimit => Self::RetrievalLimit,
            domain::CiStepLogStatus::InvalidCursor => Self::InvalidCursor,
            domain::CiStepLogStatus::StaleCursor => Self::StaleCursor,
            domain::CiStepLogStatus::BindingMismatch => Self::BindingMismatch,
            domain::CiStepLogStatus::Unavailable => Self::Unavailable,
            domain::CiStepLogStatus::Unsupported => Self::Unsupported,
            domain::CiStepLogStatus::MalformedResponse => Self::MalformedResponse,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn wire_conversion_preserves_historical_identity_positions_and_output() {
        let selector = domain::CiStepLogSelector {
            provider: "woodpecker".into(),
            provider_repository_id: 29,
            pipeline_number: 173,
            workflow_id: 41,
            step_id: 53,
        };
        let mut page = domain::RepositoryCiStepLogs::unsupported(selector.clone());
        page.status = domain::CiStepLogStatus::Available;
        page.identity = Some(domain::CiStepLogIdentity {
            selector,
            pipeline_id: 987,
            commit: "0123456789abcdef".into(),
            reference: None,
            workflow_pid: 1,
            step_uuid: Some("step-uuid".into()),
            step_name: "test".into(),
            step_state: "running".into(),
            timestamps: domain::CiTimestamps {
                created: None,
                updated: None,
                started: None,
                finished: None,
            },
        });
        page.snapshot_id = Some("snapshot".into());
        page.next_cursor = Some("opaque-next".into());
        page.beginning_cursor = Some("opaque-start".into());
        page.position = domain::CiLogPosition {
            record_index: 4,
            byte_offset: 2,
        };
        page.end_position = domain::CiLogPosition {
            record_index: 4,
            byte_offset: 12,
        };
        page.provider_step_finished = Some(false);
        page.fragments.push(domain::CiLogFragment {
            position: page.position,
            text: "  終\n\t\u{0000}é".into(),
            record_complete: false,
            metadata: domain::CiLogRecordMetadata {
                time: Some(123),
                line: Some(99),
                record_type: Some("stdout".into()),
            },
        });
        page.diagnostics.push(domain::CiStepLogDiagnostic {
            code: "lossy_utf8".into(),
            message: "Invalid UTF-8 replaced".into(),
            record_index: Some(3),
            http_status: None,
        });
        let expected = serde_json::to_value(&page).expect("domain JSON");
        let actual =
            serde_json::to_value(RepositoryCiStepLogsResult::from(page)).expect("wire JSON");
        assert_eq!(actual, expected);
        assert!(actual["identity"]["reference"].is_null());
        assert_eq!(actual["identity"]["pipeline_id"], 987);
        assert_eq!(actual["selector"]["pipeline_number"], 173);
        assert_eq!(actual["snapshot_complete"], false);
    }

    #[test]
    fn every_status_converts_without_erasing_the_failure_kind() {
        for status in [
            domain::CiStepLogStatus::Available,
            domain::CiStepLogStatus::RetrievalLimit,
            domain::CiStepLogStatus::InvalidCursor,
            domain::CiStepLogStatus::StaleCursor,
            domain::CiStepLogStatus::BindingMismatch,
            domain::CiStepLogStatus::Unavailable,
            domain::CiStepLogStatus::Unsupported,
            domain::CiStepLogStatus::MalformedResponse,
        ] {
            assert_eq!(
                serde_json::to_value(status).expect("domain status"),
                serde_json::to_value(CiStepLogStatusResult::from(status)).expect("wire status")
            );
        }
    }

    #[test]
    fn openapi_registers_all_step_log_contracts() {
        let schema = serde_json::to_value(crate::ApiDoc::openapi()).expect("OpenAPI");
        for name in [
            "RepositoryCiStepLogsResult",
            "CiStepLogIdentityResult",
            "CiStepLogSelectorResult",
            "CiLogFragmentResult",
            "CiLogPositionResult",
            "CiLogRecordMetadataResult",
            "CiStepLogStatusResult",
            "CiStepLogDiagnosticResult",
        ] {
            assert!(schema["components"]["schemas"][name].is_object(), "{name}");
        }
        let page = &schema["components"]["schemas"]["RepositoryCiStepLogsResult"]["properties"];
        assert!(page["snapshot_complete"].is_object());
        assert!(page["provider_step_finished"].is_object());
        assert!(page["identity"].is_object());
    }
}
