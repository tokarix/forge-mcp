//! HTTP API request and response types.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
    Drop { commit: String },
    Fixup { commit: String, into: String },
}

/// Response for POST /rebase
#[derive(Debug, Serialize, ToSchema)]
pub struct RebaseBranchResult {
    pub branch: String,
    pub commit_sha: String,
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
    pub expected_head_sha: String,
    pub merge_style: String,
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

/// Request body for updating an issue (close, assign).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateIssueBody {
    pub assignees: Option<Vec<String>>,
    pub state: Option<String>,
}

/// Response for GET /api/v1/agent/info
#[derive(Debug, Serialize)]
pub struct AgentInfoResult {
    pub agent_id: String,
    pub forges: Vec<AgentForgeInfo>,
}

/// A forge instance the agent has access to.
#[derive(Debug, Serialize)]
pub struct AgentForgeInfo {
    pub alias: String,
    #[serde(rename = "type")]
    pub forge_type: String,
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

#[cfg(test)]
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
    fn error_body_serializes() {
        let body = ErrorBody {
            error: "not found".to_string(),
        };
        let json = serde_json::to_value(&body).expect("should serialize");
        assert_eq!(json["error"], "not found");
    }
}
