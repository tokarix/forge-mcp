//! HTTP API request and response types.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// POST /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddIssueDependencyBody {
    pub dependency: u64,
    /// Override owner for the dependency issue (cross-repository dependency).
    /// Must be provided together with `dependency_repo` or both omitted.
    #[serde(default)]
    pub dependency_owner: Option<String>,
    /// Override repository for the dependency issue (cross-repository dependency).
    /// Must be provided together with `dependency_owner` or both omitted.
    #[serde(default)]
    pub dependency_repo: Option<String>,
}

/// POST /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/labels
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddIssueLabelBody {
    pub label: String,
}

/// POST /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/comments
#[derive(Debug, Deserialize, ToSchema)]
pub struct CommentBody {
    pub body: String,
}

/// POST /api/v1/repos/{owner}/{repo}/patches
#[derive(Debug, Deserialize, ToSchema)]
pub struct CommitPatchBody {
    pub author_email: Option<String>,
    pub author_name: Option<String>,
    pub base_branch: String,
    pub commit_message: String,
    #[serde(default)]
    pub existing_branch: bool,
    pub new_branch: String,
    pub patch: String,
}

/// Response for POST /patches
#[derive(Debug, Serialize, ToSchema)]
pub struct CommitPatchResult {
    pub branch: String,
    pub commit_sha: String,
}

/// POST /api/v1/repos/{forge}/{owner}/{repo}/rebase
#[derive(Debug, Deserialize, ToSchema)]
pub struct RebaseBranchBody {
    pub base_branch: String,
    pub branch: String,
    pub operations: Vec<RebaseOperationBody>,
}

/// A single rebase operation.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RebaseOperationBody {
    Reword { commit: String, message: String },
    Drop { commit: String },
    Fixup { commit: String, into: String },
    RebaseOnto {},
}

/// Response for POST /rebase
#[derive(Debug, Serialize, ToSchema)]
pub struct RebaseBranchResult {
    pub branch: String,
    pub commit_sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_mapping: Option<Vec<RebaseCommitMapping>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RebaseCommitMapping {
    pub old_commit_sha: String,
    pub new_commit_sha: String,
}

/// POST /api/v1/repos/{owner}/{repo}/pulls
#[derive(Debug, Deserialize, ToSchema)]
pub struct OpenPullBody {
    pub base_branch: String,
    pub body: String,
    pub head_branch: String,
    pub title: String,
}

/// GET /api/v1/repos/{owner}/{repo}/contents/{path}
#[derive(Debug, Deserialize)]
pub struct ContentsQuery {
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
}

/// Response for GET /contents/{path}
#[derive(Debug, Serialize, ToSchema)]
pub struct ContentsResult {
    pub content: String,
    pub git_ref: Option<String>,
    pub path: String,
}

/// GET /api/v1/repos/{owner}/{repo}/pulls
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListPullsQuery {
    pub state: Option<String>,
}

/// POST /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge
#[derive(Debug, Deserialize, ToSchema)]
pub struct ScheduleAutoMergeBody {
    pub delete_branch_after_merge: Option<bool>,
    pub expected_head_sha: String,
    pub merge_style: Option<String>,
}

/// PATCH /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateChangeRequestBody {
    pub body: Option<String>,
    pub title: Option<String>,
}

/// POST /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/reviews
#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitReviewBody {
    pub body: String,
    /// Review event: `APPROVED`, `REQUEST_CHANGES`, or `COMMENT`.
    pub event: String,
}

/// Shared path parameters for repo-scoped endpoints.
#[derive(Debug, Deserialize)]
pub struct RepoPath {
    pub forge: String,
    pub owner: String,
    pub repo: String,
}

/// Path parameters for pull request endpoints.
#[derive(Debug, Deserialize)]
pub struct PullPath {
    pub forge: String,
    pub index: u64,
    pub owner: String,
    pub repo: String,
}

/// Path parameters for issue label endpoints.
#[derive(Debug, Deserialize)]
pub struct IssueLabelPath {
    pub forge: String,
    pub index: u64,
    pub label: String,
    pub owner: String,
    pub repo: String,
}

/// Path parameters for issue dependency endpoints.
#[derive(Debug, Deserialize)]
pub struct IssueDependencyPath {
    pub dependency: u64,
    pub forge: String,
    pub index: u64,
    pub owner: String,
    pub repo: String,
}

/// Query parameters for removing cross-repository issue dependencies.
#[derive(Debug, Deserialize)]
pub struct RemoveIssueDependencyQuery {
    /// Override owner for the dependency issue (cross-repository dependency).
    pub dependency_owner: Option<String>,
    /// Override repository for the dependency issue (cross-repository dependency).
    pub dependency_repo: Option<String>,
}

/// Path parameters for issue endpoints.
#[derive(Debug, Deserialize)]
pub struct IssuePath {
    pub forge: String,
    pub index: u64,
    pub owner: String,
    pub repo: String,
}

/// Path parameters for contents endpoint. The `path` field captures
/// the remainder of the URL path after `/contents/`.
#[derive(Debug, Deserialize)]
pub struct ContentsPath {
    pub forge: String,
    pub owner: String,
    pub path: String,
    pub repo: String,
}

/// Query parameters for listing issues.
#[derive(Debug, Deserialize)]
pub struct ListIssuesQuery {
    pub state: Option<String>,
}

/// Path parameters for forge-scoped endpoints (no owner/repo).
#[derive(Debug, Deserialize)]
pub struct ForgePath {
    pub forge: String,
}

/// Query parameters for listing repositories.
#[derive(Debug, Deserialize)]
pub struct ListRepositoriesQuery {
    pub owner: Option<String>,
    pub q: Option<String>,
}

/// Request body for commenting on an issue.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CommentOnIssueBody {
    pub body: String,
}

/// Request body for creating an issue.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateIssueBody {
    pub body: String,
    pub title: String,
}

/// Request body for updating an issue (close, assign, edit title/body).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateIssueBody {
    pub assignees: Option<Vec<String>>,
    pub body: Option<String>,
    pub message: Option<String>,
    pub state: Option<String>,
    pub title: Option<String>,
}

/// Response for GET /pulls/{index}/ci-details
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangeRequestCiDetailsResult {
    pub head_sha: String,
    pub state: String,
    pub details: Vec<CiCheckDetailResult>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CiCheckDetailResult {
    pub context: String,
    pub description: String,
    pub state: String,
    pub target_url: String,
    pub resolution: CiResolutionResult,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CiResolutionResult {
    Unsupported,
    Error {
        message: String,
    },
    Resolved {
        provider: CiProviderResult,
        pipeline_url: String,
        failed_steps: Vec<CiFailureStepResult>,
        /// Optional validated Woodpecker evidence. Resolved does not mean CI passed.
        #[serde(skip_serializing_if = "Option::is_none")]
        woodpecker: Option<Box<WoodpeckerPipelineEvidenceResult>>,
    },
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiProviderResult {
    GithubActions,
    Woodpecker,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CiFailureStepResult {
    /// Optional provider evidence, independent of log availability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub woodpecker: Option<WoodpeckerStepEvidenceResult>,
    pub name: String,
    pub state: String,
    pub log_excerpt: Option<CiLogExcerptResult>,
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiDiagnosticComponentResult {
    Pipeline,
    Workflow,
    StepLogs,
    Runner,
    Termination,
    Operation,
}

impl From<domain::CiDiagnosticComponent> for CiDiagnosticComponentResult {
    fn from(value: domain::CiDiagnosticComponent) -> Self {
        match value {
            domain::CiDiagnosticComponent::Pipeline => Self::Pipeline,
            domain::CiDiagnosticComponent::Workflow => Self::Workflow,
            domain::CiDiagnosticComponent::StepLogs => Self::StepLogs,
            domain::CiDiagnosticComponent::Runner => Self::Runner,
            domain::CiDiagnosticComponent::Termination => Self::Termination,
            domain::CiDiagnosticComponent::Operation => Self::Operation,
        }
    }
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiDiagnosticCodeResult {
    CredentialMissing,
    AuthorizationDenied,
    Unavailable,
    ResourceNotFound,
    NotExposed,
    MalformedResponse,
    EmptyLogs,
    BindingMismatch,
    LimitExceeded,
}

impl From<domain::CiDiagnosticCode> for CiDiagnosticCodeResult {
    fn from(value: domain::CiDiagnosticCode) -> Self {
        match value {
            domain::CiDiagnosticCode::CredentialMissing => Self::CredentialMissing,
            domain::CiDiagnosticCode::AuthorizationDenied => Self::AuthorizationDenied,
            domain::CiDiagnosticCode::Unavailable => Self::Unavailable,
            domain::CiDiagnosticCode::ResourceNotFound => Self::ResourceNotFound,
            domain::CiDiagnosticCode::NotExposed => Self::NotExposed,
            domain::CiDiagnosticCode::MalformedResponse => Self::MalformedResponse,
            domain::CiDiagnosticCode::EmptyLogs => Self::EmptyLogs,
            domain::CiDiagnosticCode::BindingMismatch => Self::BindingMismatch,
            domain::CiDiagnosticCode::LimitExceeded => Self::LimitExceeded,
        }
    }
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
pub struct CiDiagnosticResult {
    /// Affected provider component.
    pub component: CiDiagnosticComponentResult,
    /// Stable machine-readable diagnostic code.
    pub code: CiDiagnosticCodeResult,
    /// Safe bounded explanation; never an upstream error body.
    pub message: String,
    /// Upstream HTTP status when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Provider pipeline identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline_id: Option<i64>,
    /// Provider workflow identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<i64>,
    /// Provider step identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_id: Option<i64>,
    /// Provider agent identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<i64>,
}

impl From<domain::CiDiagnostic> for CiDiagnosticResult {
    fn from(value: domain::CiDiagnostic) -> Self {
        Self {
            component: value.component.into(),
            code: value.code.into(),
            message: value.message,
            http_status: value.http_status,
            pipeline_id: value.pipeline_id,
            workflow_id: value.workflow_id,
            step_id: value.step_id,
            runner_id: value.runner_id,
        }
    }
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
pub struct CiTimestampsResult {
    /// Provider Unix timestamp in seconds; absence differs from zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    /// Provider Unix timestamp in seconds; absence differs from zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<i64>,
    /// Provider Unix timestamp in seconds; absence differs from zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started: Option<i64>,
    /// Provider Unix timestamp in seconds; absence differs from zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished: Option<i64>,
}

impl From<domain::CiTimestamps> for CiTimestampsResult {
    fn from(value: domain::CiTimestamps) -> Self {
        Self {
            created: value.created,
            updated: value.updated,
            started: value.started,
            finished: value.finished,
        }
    }
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
pub struct WoodpeckerStepEvidenceResult {
    /// Containing workflow identifier.
    pub workflow_id: i64,
    /// Provider step identifier.
    pub id: i64,
    /// Provider step UUID for external log correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Reported exit code; does not establish the exit cause.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    /// Sanitized provider step error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Provider step timestamps.
    pub timestamps: CiTimestampsResult,
    /// Component failures and limitations.
    pub diagnostics: Vec<CiDiagnosticResult>,
}

impl From<domain::WoodpeckerStepEvidence> for WoodpeckerStepEvidenceResult {
    fn from(value: domain::WoodpeckerStepEvidence) -> Self {
        Self {
            workflow_id: value.workflow_id,
            id: value.id,
            uuid: value.uuid,
            exit_code: value.exit_code,
            error: value.error,
            timestamps: value.timestamps.into(),
            diagnostics: value.diagnostics.into_iter().map(Into::into).collect(),
        }
    }
}

/// Validated child metadata for selecting retained output, independent of state.
#[derive(Debug, Serialize, ToSchema)]
pub struct WoodpeckerStepSelectorResult {
    /// Containing workflow database ID (not workflow position).
    pub workflow_id: i64,
    /// Step database ID; names are not identifiers.
    pub id: i64,
    /// Sanitized, bounded provider name.
    pub name: String,
    /// Sanitized, bounded provider state.
    pub state: String,
    /// Retained provider UUID, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Retained provider timestamps.
    pub timestamps: CiTimestampsResult,
}

impl From<domain::WoodpeckerStepSelector> for WoodpeckerStepSelectorResult {
    fn from(value: domain::WoodpeckerStepSelector) -> Self {
        Self {
            workflow_id: value.workflow_id,
            id: value.id,
            name: value.name,
            state: value.state,
            uuid: value.uuid,
            timestamps: value.timestamps.into(),
        }
    }
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
pub struct WoodpeckerWorkflowEvidenceResult {
    /// Provider workflow identifier.
    pub id: i64,
    /// Provider workflow name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Provider workflow state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Sanitized provider workflow error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Referenced agent identifier from the validated workflow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<i64>,
    /// Provider workflow timestamps.
    pub timestamps: CiTimestampsResult,
}

impl From<domain::WoodpeckerWorkflowEvidence> for WoodpeckerWorkflowEvidenceResult {
    fn from(value: domain::WoodpeckerWorkflowEvidence) -> Self {
        Self {
            id: value.id,
            name: value.name,
            state: value.state,
            error: value.error,
            runner_id: value.runner_id,
            timestamps: value.timestamps.into(),
        }
    }
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
pub struct WoodpeckerRunnerEvidenceResult {
    /// Validated referenced agent identifier.
    pub id: i64,
    /// Current observed platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Current observed execution backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Current observed agent version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl From<domain::WoodpeckerRunnerEvidence> for WoodpeckerRunnerEvidenceResult {
    fn from(value: domain::WoodpeckerRunnerEvidence) -> Self {
        Self {
            id: value.id,
            platform: value.platform,
            backend: value.backend,
            version: value.version,
        }
    }
}

/// Typed CI evidence; provider text must be sanitized and bounded before construction.
#[derive(Debug, Serialize, ToSchema)]
pub struct WoodpeckerPipelineEvidenceResult {
    /// Verified Woodpecker repository identifier.
    pub repository_id: i64,
    /// Provider pipeline identifier.
    pub id: i64,
    /// Repository-scoped pipeline number.
    pub number: i64,
    /// Provider pipeline status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Sanitized provider pipeline error messages.
    pub errors: Vec<String>,
    /// Provider pipeline timestamps.
    pub timestamps: CiTimestampsResult,
    /// Workflows, including failures without failed steps.
    pub workflows: Vec<WoodpeckerWorkflowEvidenceResult>,
    /// Validated workflow children, regardless of state.
    pub steps: Vec<WoodpeckerStepSelectorResult>,
    /// Whether all provider-reported workflows and children were inventoried.
    pub steps_complete: bool,
    /// Allowlisted current observations, stored once per runner.
    pub runners: Vec<WoodpeckerRunnerEvidenceResult>,
    /// Component failures and explicit capability limitations.
    pub diagnostics: Vec<CiDiagnosticResult>,
}

impl From<domain::WoodpeckerPipelineEvidence> for WoodpeckerPipelineEvidenceResult {
    fn from(value: domain::WoodpeckerPipelineEvidence) -> Self {
        Self {
            repository_id: value.repository_id,
            id: value.id,
            number: value.number,
            status: value.status,
            errors: value.errors,
            timestamps: value.timestamps.into(),
            workflows: value.workflows.into_iter().map(Into::into).collect(),
            steps: value.steps.into_iter().map(Into::into).collect(),
            steps_complete: value.steps_complete,
            runners: value.runners.into_iter().map(Into::into).collect(),
            diagnostics: value.diagnostics.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CiLogExcerptResult {
    pub lines: Vec<String>,
}

/// Response for GET /api/v1/agent/info
#[derive(Debug, Serialize)]
pub struct AgentInfoResult {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_prefix: Option<String>,
    pub forges: Vec<AgentForgeInfo>,
}

/// A forge instance the agent has access to.
#[derive(Debug, Serialize)]
pub struct AgentForgeInfo {
    pub alias: String,
    #[serde(rename = "type")]
    pub forge_type: String,
    /// Username of the authenticated agent on this forge, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// Query params for GET /api/v1/agent/events
#[derive(Debug, Deserialize)]
pub struct AgentEventsQuery {
    pub subscriber_id: Option<String>,
}

/// A normalized event envelope sent to connected shims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentEventEnvelope {
    pub content: String,
    pub kind: String,
    pub meta: domain::ChannelEventMeta,
}

/// Error response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListBranchesResponse {
    pub branches: Vec<BranchItem>,
    pub truncated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BranchItem {
    pub name: String,
    pub commit_sha: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BranchDetailsResult {
    pub exists: bool,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListBranchesQuery {
    pub prefix: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct GetBranchQuery {
    pub branch: String,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn commit_patch_body_deserializes() {
        let json = serde_json::json!({
            "author_email": "you@example.com",
            "author_name": "Your Name",
            "base_branch": "main",
            "commit_message": "fix typo",
            "new_branch": "agent/fix",
            "patch": "diff..."
        });
        let body: CommitPatchBody = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(body.author_name.as_deref(), Some("Your Name"));
        assert_eq!(body.author_email.as_deref(), Some("you@example.com"));
        assert_eq!(body.base_branch, "main");
        assert_eq!(body.new_branch, "agent/fix");
    }

    #[test]
    fn contents_query_deserializes_with_ref() {
        let json = serde_json::json!({"ref": "main"});
        let query: ContentsQuery = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(query.git_ref.as_deref(), Some("main"));
    }

    #[test]
    fn contents_query_deserializes_without_ref() {
        let json = serde_json::json!({});
        let query: ContentsQuery = serde_json::from_value(json).expect("should deserialize");
        assert!(query.git_ref.is_none());
    }

    #[test]
    fn rebase_body_deserializes_rebase_onto() {
        let json = serde_json::json!({
            "base_branch": "main",
            "branch": "agent/feature",
            "operations": [{"type": "rebase_onto"}]
        });
        let body: RebaseBranchBody = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(body.base_branch, "main");
        assert_eq!(body.branch, "agent/feature");
        assert_eq!(body.operations.len(), 1);
        assert!(matches!(
            body.operations[0],
            RebaseOperationBody::RebaseOnto {}
        ));
    }

    #[test]
    fn error_body_serializes() {
        let body = ErrorBody {
            error: "not found".to_string(),
        };
        let json = serde_json::to_value(&body).expect("should serialize");
        assert_eq!(json["error"], "not found");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod ci_evidence_contract_tests {
    use super::*;

    #[test]
    fn step_evidence_conversion_preserves_failure_and_optional_zero_times() {
        let evidence = domain::WoodpeckerStepEvidence {
            workflow_id: 7,
            id: 9,
            uuid: Some("step-correlation".into()),
            exit_code: Some(255),
            error: None,
            timestamps: domain::CiTimestamps {
                created: None,
                updated: None,
                started: Some(0),
                finished: Some(1_730_000_000),
            },
            diagnostics: vec![domain::CiDiagnostic {
                component: domain::CiDiagnosticComponent::StepLogs,
                code: domain::CiDiagnosticCode::EmptyLogs,
                message: "No log entries available".into(),
                http_status: Some(200),
                pipeline_id: Some(3),
                workflow_id: Some(7),
                step_id: Some(9),
                runner_id: None,
            }],
        };
        let expected = serde_json::to_value(&evidence).expect("domain JSON");
        let mapped = WoodpeckerStepEvidenceResult::from(evidence);
        assert_eq!(serde_json::to_value(&mapped).expect("HTTP JSON"), expected);
        assert_eq!(expected["exit_code"], 255);
        assert_eq!(expected["timestamps"]["started"], 0);
        assert!(expected["timestamps"].get("created").is_none());
        assert_eq!(expected["diagnostics"][0]["code"], "empty_logs");
    }

    #[test]
    fn legacy_resolved_and_step_json_have_no_new_keys() {
        let result = CiResolutionResult::Resolved {
            provider: CiProviderResult::GithubActions,
            pipeline_url: "https://github.example/actions/runs/1".into(),
            failed_steps: vec![CiFailureStepResult {
                name: "test".into(),
                state: "failure".into(),
                log_excerpt: None,
                woodpecker: None,
            }],
            woodpecker: None,
        };
        assert_eq!(
            serde_json::to_value(result).expect("legacy JSON"),
            serde_json::json!({
                "type": "resolved",
                "provider": "github_actions",
                "pipeline_url": "https://github.example/actions/runs/1",
                "failed_steps": [{"name": "test", "state": "failure", "log_excerpt": null}]
            })
        );
    }

    #[test]
    fn evidence_schemas_are_registered() {
        use utoipa::OpenApi;
        let schema = serde_json::to_value(crate::ApiDoc::openapi()).expect("OpenAPI JSON");
        let schemas = &schema["components"]["schemas"];
        for name in [
            "WoodpeckerPipelineEvidenceResult",
            "WoodpeckerStepEvidenceResult",
            "WoodpeckerWorkflowEvidenceResult",
            "WoodpeckerStepSelectorResult",
            "WoodpeckerRunnerEvidenceResult",
            "CiDiagnosticResult",
            "CiDiagnosticCodeResult",
            "RepositoryCiDetailsResult",
            "HistoricalCiSelectorResult",
            "HistoricalCiOutcomeResult",
            "HistoricalEvidenceKindResult",
            "CiDiagnosticComponentResult",
            "CiTimestampsResult",
        ] {
            assert!(schemas.get(name).is_some(), "missing schema {name}");
        }
    }
}

impl From<domain::CiResolution> for CiResolutionResult {
    fn from(value: domain::CiResolution) -> Self {
        match value {
            domain::CiResolution::Unsupported => CiResolutionResult::Unsupported,
            domain::CiResolution::Error { message } => CiResolutionResult::Error { message },
            domain::CiResolution::Resolved {
                woodpecker,
                provider,
                pipeline_url,
                failed_steps,
            } => CiResolutionResult::Resolved {
                woodpecker: woodpecker.map(|e| Box::new((*e).into())),
                provider: match provider {
                    domain::CiProvider::GithubActions => CiProviderResult::GithubActions,
                    domain::CiProvider::Woodpecker => CiProviderResult::Woodpecker,
                },
                pipeline_url,
                failed_steps: failed_steps
                    .into_iter()
                    .map(|s| CiFailureStepResult {
                        woodpecker: s.woodpecker.map(Into::into),
                        name: s.name,
                        state: s.state,
                        log_excerpt: s.log_excerpt.map(|l| CiLogExcerptResult { lines: l.lines }),
                    })
                    .collect(),
            },
        }
    }
}

/// Explicit historical lookup, independent of current checks and merge qualification.
#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryCiDetailsResult {
    pub evidence_kind: HistoricalEvidenceKindResult,
    pub selector: HistoricalCiSelectorResult,
    pub outcome: HistoricalCiOutcomeResult,
}
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalEvidenceKindResult {
    Historical,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct HistoricalCiSelectorResult {
    pub provider: String,
    pub provider_repository_id: u64,
    pub pipeline_number: u64,
}
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HistoricalCiOutcomeResult {
    Unsupported {
        message: String,
    },
    SelectionDiagnostic {
        diagnostic: CiDiagnosticResult,
    },
    Selected {
        commit: String,
        reference: Option<String>,
        evidence: Box<CiResolutionResult>,
    },
}
impl From<domain::RepositoryCiDetails> for RepositoryCiDetailsResult {
    fn from(value: domain::RepositoryCiDetails) -> Self {
        Self {
            evidence_kind: HistoricalEvidenceKindResult::Historical,
            selector: HistoricalCiSelectorResult {
                provider: value.selector.provider,
                provider_repository_id: value.selector.provider_repository_id,
                pipeline_number: value.selector.pipeline_number,
            },
            outcome: match value.outcome {
                domain::HistoricalCiOutcome::Unsupported { message } => {
                    HistoricalCiOutcomeResult::Unsupported { message }
                }
                domain::HistoricalCiOutcome::SelectionDiagnostic { diagnostic } => {
                    HistoricalCiOutcomeResult::SelectionDiagnostic {
                        diagnostic: diagnostic.into(),
                    }
                }
                domain::HistoricalCiOutcome::Selected {
                    commit,
                    reference,
                    evidence,
                } => HistoricalCiOutcomeResult::Selected {
                    commit,
                    reference,
                    evidence: Box::new((*evidence).into()),
                },
            },
        }
    }
}

#[path = "ci_step_logs_api.rs"]
mod ci_step_logs;
pub use ci_step_logs::*;

#[path = "ci_step_log_download_api.rs"]
mod ci_step_log_download;
pub use ci_step_log_download::*;
