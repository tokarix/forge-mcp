//! Public bounded download wire types and explicit domain conversion.

use serde::Serialize;
use utoipa::ToSchema;

use crate::api::{CiStepLogIdentityResult, CiStepLogSelectorResult, HistoricalEvidenceKindResult};

/// The selected provider representation; never implies a complete archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogDownloadSourceResult {
    /// Fixed numeric Woodpecker step download endpoint.
    WoodpeckerStepLogDownload,
}

/// Versioned interpretation of downloaded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogDownloadRepresentationResult {
    /// Plain text with lossy UTF-8 replacement and whole-stream redaction.
    PlainTextUtf8V1,
}

/// Full job-output retention cannot be established by either retained view.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiLogOutputCompletenessResult {
    /// Even available-source EOF may omit a terminal result.
    Unknown,
}

/// Stable download outcome, separate from the historical JSON status contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogDownloadStatusResult {
    /// Navigable bounded snapshot, possibly with explicit decoding loss.
    Available,
    /// Hard bound exceeded; no usable snapshot or continuation.
    RetrievalLimit,
    /// Invalid token encoding, profile, version or canonical byte boundary.
    InvalidCursor,
    /// Raw response changed; explicitly restart to establish a new snapshot.
    StaleCursor,
    /// Authorized identity, configured origin or policy changed.
    BindingMismatch,
    /// Provider returned HTTP 401 or 403.
    AuthorizationDenied,
    /// Provider returned 404; source availability and capability are uncertain.
    ResourceNotFound,
    /// Transient provider, network or server failure.
    Unavailable,
    /// Unsupported adapter/configuration or affirmative capability rejection.
    Unsupported,
    /// Invalid representation headers, framing or response body.
    MalformedResponse,
}

/// Ordered text only; no invented record metadata or line numbering.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct CiStepLogDownloadFragmentResult {
    /// Offset in the complete canonical decoded/redacted UTF-8 stream.
    pub byte_offset: usize,
    /// Provider text; no trimming, separator insertion or ANSI removal.
    pub text: String,
}

/// Safe typed download diagnostic without provider bodies or header values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct CiStepLogDownloadDiagnosticResult {
    /// Stable diagnostic code.
    pub code: String,
    /// Safe explanation, never downloaded text, credentials or cursor contents.
    pub message: String,
    /// Upstream status when available.
    pub http_status: Option<u16>,
}
/// Bounded JSON envelope containing a historical plain-text download page.
#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryCiStepLogDownloadResult {
    /// Always historical.
    pub evidence_kind: HistoricalEvidenceKindResult,
    /// Unverified request hints, kept separate from validated identity.
    pub selector: CiStepLogSelectorResult,
    /// Populated only after complete repository/child validation.
    pub identity: Option<CiStepLogIdentityResult>,
    /// Typed retrieval outcome.
    pub status: CiStepLogDownloadStatusResult,
    /// Fixed provider source identifier.
    pub source: CiStepLogDownloadSourceResult,
    /// Fixed plain-text interpretation identifier.
    pub representation: CiStepLogDownloadRepresentationResult,
    /// Always unknown regardless of EOF or provider state.
    pub output_completeness: CiLogOutputCompletenessResult,
    /// `strict-download-snapshot-v1`; tokens never cross representations.
    pub consistency: String,
    /// Digest binding the complete bounded raw source and authorization context.
    pub snapshot_id: Option<String>,
    /// At most 256 ordered fragments within a 512 KiB serialized envelope.
    pub fragments: Vec<CiStepLogDownloadFragmentResult>,
    /// Canonical byte start, after decoding and redaction.
    pub position: usize,
    /// First canonical byte after emitted text.
    pub end_position: usize,
    /// Reauthorized continuation, null at available-source EOF or hard failure.
    pub next_cursor: Option<String>,
    /// Rewind within this same snapshot, including after tail initialization.
    pub beginning_cursor: Option<String>,
    /// The selected available representation ended, not proof of retention.
    pub snapshot_complete: bool,
    /// Independent conservative provider state assessment; null means unknown.
    pub provider_step_finished: Option<bool>,
    /// More source exists, decoding was lossy or retrieval failed a hard bound.
    pub truncated: bool,
    /// Bounded safe explanations including the unconditional retention limit.
    pub diagnostics: Vec<CiStepLogDownloadDiagnosticResult>,
}

impl From<domain::CiStepLogDownloadSource> for CiStepLogDownloadSourceResult {
    fn from(value: domain::CiStepLogDownloadSource) -> Self {
        match value {
            domain::CiStepLogDownloadSource::WoodpeckerStepLogDownload => {
                Self::WoodpeckerStepLogDownload
            }
        }
    }
}

impl From<domain::CiStepLogDownloadRepresentation> for CiStepLogDownloadRepresentationResult {
    fn from(value: domain::CiStepLogDownloadRepresentation) -> Self {
        match value {
            domain::CiStepLogDownloadRepresentation::PlainTextUtf8V1 => Self::PlainTextUtf8V1,
        }
    }
}

impl From<domain::CiLogOutputCompleteness> for CiLogOutputCompletenessResult {
    fn from(value: domain::CiLogOutputCompleteness) -> Self {
        match value {
            domain::CiLogOutputCompleteness::Unknown => Self::Unknown,
        }
    }
}

impl From<domain::CiStepLogDownloadStatus> for CiStepLogDownloadStatusResult {
    fn from(value: domain::CiStepLogDownloadStatus) -> Self {
        match value {
            domain::CiStepLogDownloadStatus::Available => Self::Available,
            domain::CiStepLogDownloadStatus::RetrievalLimit => Self::RetrievalLimit,
            domain::CiStepLogDownloadStatus::InvalidCursor => Self::InvalidCursor,
            domain::CiStepLogDownloadStatus::StaleCursor => Self::StaleCursor,
            domain::CiStepLogDownloadStatus::BindingMismatch => Self::BindingMismatch,
            domain::CiStepLogDownloadStatus::AuthorizationDenied => Self::AuthorizationDenied,
            domain::CiStepLogDownloadStatus::ResourceNotFound => Self::ResourceNotFound,
            domain::CiStepLogDownloadStatus::Unavailable => Self::Unavailable,
            domain::CiStepLogDownloadStatus::Unsupported => Self::Unsupported,
            domain::CiStepLogDownloadStatus::MalformedResponse => Self::MalformedResponse,
        }
    }
}

impl From<domain::CiStepLogDownloadFragment> for CiStepLogDownloadFragmentResult {
    fn from(value: domain::CiStepLogDownloadFragment) -> Self {
        Self {
            byte_offset: value.byte_offset,
            text: value.text,
        }
    }
}

impl From<domain::CiStepLogDownloadDiagnostic> for CiStepLogDownloadDiagnosticResult {
    fn from(value: domain::CiStepLogDownloadDiagnostic) -> Self {
        Self {
            code: value.code,
            message: value.message,
            http_status: value.http_status,
        }
    }
}

impl From<domain::RepositoryCiStepLogDownload> for RepositoryCiStepLogDownloadResult {
    fn from(value: domain::RepositoryCiStepLogDownload) -> Self {
        Self {
            evidence_kind: HistoricalEvidenceKindResult::Historical,
            selector: value.selector.into(),
            identity: value.identity.map(Into::into),
            status: value.status.into(),
            source: value.source.into(),
            representation: value.representation.into(),
            output_completeness: value.output_completeness.into(),
            consistency: value.consistency,
            snapshot_id: value.snapshot_id,
            fragments: value.fragments.into_iter().map(Into::into).collect(),
            position: value.position,
            end_position: value.end_position,
            next_cursor: value.next_cursor,
            beginning_cursor: value.beginning_cursor,
            snapshot_complete: value.snapshot_complete,
            provider_step_finished: value.provider_step_finished,
            truncated: value.truncated,
            diagnostics: value.diagnostics.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    fn selector() -> domain::CiStepLogSelector {
        domain::CiStepLogSelector {
            provider: "woodpecker".into(),
            provider_repository_id: 29,
            pipeline_number: 42,
            workflow_id: 6001,
            step_id: 7001,
        }
    }

    #[test]
    fn download_conversion_keeps_text_offsets_and_failure_semantics() {
        let mut page = domain::RepositoryCiStepLogDownload::unsupported(selector());
        let json = serde_json::to_value(&page).expect("domain");
        assert!(json["identity"].is_null());
        assert!(json["snapshot_id"].is_null());
        assert!(json["next_cursor"].is_null());
        assert!(json["beginning_cursor"].is_null());
        assert_eq!(json["snapshot_complete"], false);
        assert_eq!(json["truncated"], true);
        assert_eq!(json["source"], "woodpecker_step_log_download");
        assert_eq!(json["representation"], "plain_text_utf8_v1");
        assert_eq!(json["consistency"], "strict-download-snapshot-v1");
        assert_eq!(json["output_completeness"], "unknown");
        assert_eq!(
            json["diagnostics"][0]["code"],
            "output_completeness_unknown"
        );
        assert_eq!(
            serde_json::to_value(RepositoryCiStepLogDownloadResult::from(page.clone()))
                .expect("wire"),
            json
        );

        page.status = domain::CiStepLogDownloadStatus::Available;
        page.position = 9;
        page.end_position = 17;
        page.fragments.push(domain::CiStepLogDownloadFragment {
            byte_offset: 9,
            text: "終\r\n\0\u{1b}".into(),
        });
        page.snapshot_complete = true;
        page.provider_step_finished = Some(true);
        let expected = serde_json::to_value(&page).expect("domain");
        let actual =
            serde_json::to_value(RepositoryCiStepLogDownloadResult::from(page)).expect("wire");
        assert_eq!(actual, expected);
        assert_eq!(actual["output_completeness"], "unknown");
        let fragment = actual["fragments"][0].as_object().expect("fragment");
        assert_eq!(fragment.len(), 2);
        assert!(fragment.contains_key("byte_offset"));
        assert!(fragment.contains_key("text"));
    }

    #[test]
    fn download_statuses_preserve_authorization_and_capability_uncertainty() {
        for status in [
            domain::CiStepLogDownloadStatus::Available,
            domain::CiStepLogDownloadStatus::RetrievalLimit,
            domain::CiStepLogDownloadStatus::InvalidCursor,
            domain::CiStepLogDownloadStatus::StaleCursor,
            domain::CiStepLogDownloadStatus::BindingMismatch,
            domain::CiStepLogDownloadStatus::AuthorizationDenied,
            domain::CiStepLogDownloadStatus::ResourceNotFound,
            domain::CiStepLogDownloadStatus::Unavailable,
            domain::CiStepLogDownloadStatus::Unsupported,
            domain::CiStepLogDownloadStatus::MalformedResponse,
        ] {
            assert_eq!(
                serde_json::to_value(status).expect("domain"),
                serde_json::to_value(CiStepLogDownloadStatusResult::from(status)).expect("wire")
            );
        }
    }

    #[test]
    fn download_openapi_has_only_canonical_text_fragment_metadata() {
        let schema = serde_json::to_value(crate::ApiDoc::openapi()).expect("schema");
        let schemas = &schema["components"]["schemas"];
        assert!(schemas["RepositoryCiStepLogDownloadResult"].is_object());
        let fields = schemas["CiStepLogDownloadFragmentResult"]["properties"]
            .as_object()
            .expect("fields");
        assert_eq!(fields.len(), 2);
        assert!(fields.contains_key("byte_offset"));
        assert!(fields.contains_key("text"));
    }
}
