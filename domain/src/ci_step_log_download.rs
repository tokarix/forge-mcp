//! Bounded historical Woodpecker download contracts.
//!
//! This is the provider's plain-text representation, independently fetched and
//! snapshotted. Concatenate text fragments without inserting separators. Offsets
//! measure decoded and redacted UTF-8 bytes, never network bytes or JSON records.
//! Pages default to 16 KiB (1–64 KiB requested), with 4 KiB cursors, at most
//! 256 fragments and a 512 KiB full serialized envelope. Each page reauthorizes
//! and refetches the whole bounded source: O(source size), three requests and
//! 30 seconds including CPU; metadata is 2 MiB each, raw/decoded/canonical text
//! independently 8 MiB each and aggregate fetched bodies 12 MiB.
//! `strict-download-snapshot-v1` cursors cannot mix with JSON cursors. Tail
//! supplies `beginning_cursor` for rewind. Stale/binding failures require an
//! explicit restart. Version-dependent capability and 404 ambiguity remain
//! explicit. Lossy UTF-8 remains truncated at source EOF.
//! Available-source EOF, provider completion and full-output retention are
//! independent facts. A download cannot establish current-head CI qualification.

use serde::Serialize;

use crate::{
    AgentIdentity, CiEvidenceKind, CiStepLogIdentity, CiStepLogOptions, CiStepLogSelector,
    RepositoryRef,
};

/// Authorized request for an already-known exact numeric step selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetRepositoryCiStepLogDownloadRequest {
    /// Gateway identity authorizing this read independently on every page.
    pub agent: AgentIdentity,
    /// Authorized forge repository, separate from provider lookup hints.
    pub repository: RepositoryRef,
    /// Exact selected child; discovery is a separate operation.
    pub selector: CiStepLogSelector,
    /// Beginning/tail or an opaque source-specific cursor; 1–64 KiB budget.
    pub options: CiStepLogOptions,
}

/// The selected provider representation; never implies a complete archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogDownloadSource {
    /// Fixed numeric Woodpecker step download endpoint.
    WoodpeckerStepLogDownload,
}

/// Versioned interpretation of downloaded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogDownloadRepresentation {
    /// Plain text with lossy UTF-8 replacement and whole-stream redaction.
    PlainTextUtf8V1,
}

/// Full job-output retention cannot be established by either retained view.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiLogOutputCompleteness {
    /// Even available-source EOF may omit a terminal result.
    Unknown,
}

/// Stable download outcome, separate from the historical JSON status contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStepLogDownloadStatus {
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiStepLogDownloadFragment {
    /// Offset in the complete canonical decoded/redacted UTF-8 stream.
    pub byte_offset: usize,
    /// Provider text; no trimming, separator insertion or ANSI removal.
    pub text: String,
}

/// Safe typed download diagnostic without provider bodies or header values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiStepLogDownloadDiagnostic {
    /// Stable diagnostic code.
    pub code: String,
    /// Safe explanation, never downloaded text, credentials or cursor contents.
    pub message: String,
    /// Upstream status when available.
    pub http_status: Option<u16>,
}
impl CiStepLogDownloadDiagnostic {
    /// Unconditional limitation, including at available-source EOF.
    #[must_use]
    pub fn output_completeness_unknown() -> Self {
        Self {
            code: "output_completeness_unknown".into(),
            message: "The available representation may omit a terminal result; its end cannot establish full job-output retention or current-head CI qualification".into(),
            http_status: None,
        }
    }
}

/// Bounded JSON envelope containing a historical plain-text download page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RepositoryCiStepLogDownload {
    /// Always historical.
    pub evidence_kind: CiEvidenceKind,
    /// Unverified request hints, kept separate from validated identity.
    pub selector: CiStepLogSelector,
    /// Populated only after complete repository/child validation.
    pub identity: Option<CiStepLogIdentity>,
    /// Typed retrieval outcome.
    pub status: CiStepLogDownloadStatus,
    /// Fixed provider source identifier.
    pub source: CiStepLogDownloadSource,
    /// Fixed plain-text interpretation identifier.
    pub representation: CiStepLogDownloadRepresentation,
    /// Always unknown regardless of EOF or provider state.
    pub output_completeness: CiLogOutputCompleteness,
    /// `strict-download-snapshot-v1`; tokens never cross representations.
    pub consistency: String,
    /// Digest binding the complete bounded raw source and authorization context.
    pub snapshot_id: Option<String>,
    /// At most 256 ordered fragments within a 512 KiB serialized envelope.
    pub fragments: Vec<CiStepLogDownloadFragment>,
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
    pub diagnostics: Vec<CiStepLogDownloadDiagnostic>,
}
impl RepositoryCiStepLogDownload {
    /// Unsupported default without validated identity, snapshot or cursors.
    #[must_use]
    pub fn unsupported(selector: CiStepLogSelector) -> Self {
        Self {
            evidence_kind: CiEvidenceKind::Historical,
            selector,
            identity: None,
            status: CiStepLogDownloadStatus::Unsupported,
            source: CiStepLogDownloadSource::WoodpeckerStepLogDownload,
            representation: CiStepLogDownloadRepresentation::PlainTextUtf8V1,
            output_completeness: CiLogOutputCompleteness::Unknown,
            consistency: "strict-download-snapshot-v1".into(),
            snapshot_id: None,
            fragments: Vec::new(),
            position: 0,
            end_position: 0,
            next_cursor: None,
            beginning_cursor: None,
            snapshot_complete: false,
            provider_step_finished: None,
            truncated: true,
            diagnostics: vec![CiStepLogDownloadDiagnostic::output_completeness_unknown()],
        }
    }
}
