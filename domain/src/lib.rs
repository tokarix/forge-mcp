//! Canonical domain types and service traits for forge-mcp.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod diff;
pub mod policy;

#[derive(Clone)]
pub struct ForgeCredential {
    pub token: Option<String>,
}

impl std::fmt::Debug for ForgeCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeCredential")
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ForgeKind {
    Forgejo,
    GitHub,
    GitLab,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeUser {
    pub email: String,
    pub username: String,
}

impl TryFrom<&str> for ForgeKind {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "forgejo" => Ok(Self::Forgejo),
            "github" => Ok(Self::GitHub),
            "gitlab" => Ok(Self::GitLab),
            other => Err(format!("unsupported forge type '{other}'")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryRef {
    pub alias: String,
    pub forge: ForgeKind,
    pub host: String,
    pub name: String,
    pub owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitAuthor {
    pub email: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRepositoryFileRequest {
    pub agent: AgentIdentity,
    pub repository: RepositoryRef,
    pub path: String,
    pub git_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReadRepositoryFileResponse {
    pub repository: RepositoryRef,
    pub path: String,
    pub git_ref: Option<String>,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChangeRequest {
    pub base_branch: String,
    pub body: String,
    pub changed_files_count: Option<u64>,
    pub commit_count: Option<u64>,
    pub head_branch: String,
    pub head_sha: Option<String>,
    pub index: u64,
    pub merge_base_sha: Option<String>,
    pub state: ChangeRequestState,
    pub title: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChannelEvent {
    pub content: String,
    pub meta: ChannelEventMeta,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChannelEventMeta {
    pub action: String,
    pub change_request: Option<u64>,
    pub delivery_id: String,
    pub event_kind: String,
    pub forge_alias: String,
    pub head_sha: Option<String>,
    pub issue: Option<u64>,
    pub issue_comment: Option<u64>,
    pub owner: String,
    pub repo: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChangeRequestDiff {
    pub index: u64,
    pub patch: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ChangeRequestState {
    Closed,
    Merged,
    Open,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChangeRequestComment {
    pub body: String,
    pub id: u64,
    pub index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChangeRequestCommentDetail {
    pub author: String,
    pub body: String,
    pub created_at: String,
    pub id: u64,
    /// "comment" for general comments, "review" for formal reviews.
    pub kind: String,
    /// For reviews: `APPROVED`, `REQUEST_CHANGES`, or `COMMENT`. None for general comments.
    pub review_state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetChangeRequestCommentsRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

pub trait PublishableEvent {
    fn dedupe_key(&self) -> String;
    fn event_name(&self) -> &str;
    fn repository_ref(&self) -> &RepositoryRef;
    fn to_channel_event(&self) -> ChannelEvent;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangeRequestEvent {
    pub action: ChangeRequestEventAction,
    pub delivery_id: String,
    pub head_sha: String,
    pub index: u64,
    pub repository: RepositoryRef,
    pub title: String,
    pub url: String,
}

impl PublishableEvent for ChangeRequestEvent {
    fn dedupe_key(&self) -> String {
        if !self.delivery_id.is_empty() {
            return format!("{}:{}", self.repository.alias, self.delivery_id);
        }
        format!(
            "{}:{}/{}/{}:{}:{}",
            self.repository.alias,
            self.repository.owner,
            self.repository.name,
            self.index,
            self.head_sha,
            self.action.as_str(),
        )
    }

    fn event_name(&self) -> &str {
        "change_request"
    }

    fn repository_ref(&self) -> &RepositoryRef {
        &self.repository
    }

    fn to_channel_event(&self) -> ChannelEvent {
        ChannelEvent {
            content: format!(
                "change_request {} on {}/{}/{}#{} at {}",
                self.action.as_str(),
                self.repository.alias,
                self.repository.owner,
                self.repository.name,
                self.index,
                self.head_sha,
            ),
            meta: ChannelEventMeta {
                action: self.action.as_str().to_string(),
                change_request: Some(self.index),
                delivery_id: self.delivery_id.clone(),
                event_kind: "change_request".to_string(),
                forge_alias: self.repository.alias.clone(),
                head_sha: Some(self.head_sha.clone()),
                issue: None,
                issue_comment: None,
                owner: self.repository.owner.clone(),
                repo: self.repository.name.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestEventAction {
    Opened,
    Reopened,
    #[serde(rename = "synchronize")]
    Synchronized,
}

impl ChangeRequestEventAction {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Reopened => "reopened",
            Self::Synchronized => "synchronize",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChangeRequestReview {
    pub body: String,
    pub event: String,
    pub id: u64,
    pub index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Issue {
    pub assignees: Vec<String>,
    pub body: String,
    pub index: u64,
    pub labels: Vec<String>,
    pub state: String,
    pub title: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueComment {
    pub author: String,
    pub body: String,
    pub created_at: String,
    pub id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueCommentEventAction {
    Created,
}

impl IssueCommentEventAction {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueCommentEvent {
    pub action: IssueCommentEventAction,
    pub body: String,
    pub comment_id: u64,
    pub delivery_id: String,
    pub issue_index: u64,
    pub repository: RepositoryRef,
}

impl PublishableEvent for IssueCommentEvent {
    fn dedupe_key(&self) -> String {
        if !self.delivery_id.is_empty() {
            return format!("{}:{}", self.repository.alias, self.delivery_id);
        }
        format!(
            "{}:{}/{}/{}:issue_comment:{}",
            self.repository.alias,
            self.repository.owner,
            self.repository.name,
            self.issue_index,
            self.comment_id,
        )
    }

    fn event_name(&self) -> &str {
        "issue_comment"
    }

    fn repository_ref(&self) -> &RepositoryRef {
        &self.repository
    }

    fn to_channel_event(&self) -> ChannelEvent {
        ChannelEvent {
            content: format!(
                "issue_comment {} on {}/{}/{}#{}",
                self.action.as_str(),
                self.repository.alias,
                self.repository.owner,
                self.repository.name,
                self.issue_index,
            ),
            meta: ChannelEventMeta {
                action: self.action.as_str().to_string(),
                change_request: None,
                delivery_id: self.delivery_id.clone(),
                event_kind: "issue_comment".to_string(),
                forge_alias: self.repository.alias.clone(),
                head_sha: None,
                issue: Some(self.issue_index),
                issue_comment: Some(self.comment_id),
                owner: self.repository.owner.clone(),
                repo: self.repository.name.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueEvent {
    pub action: IssueEventAction,
    pub delivery_id: String,
    pub index: u64,
    pub repository: RepositoryRef,
    pub title: String,
    pub url: String,
}

impl PublishableEvent for IssueEvent {
    fn dedupe_key(&self) -> String {
        if !self.delivery_id.is_empty() {
            return format!("{}:{}", self.repository.alias, self.delivery_id);
        }
        format!(
            "{}:{}/{}/{}:issue:{}",
            self.repository.alias,
            self.repository.owner,
            self.repository.name,
            self.index,
            self.action.as_str(),
        )
    }

    fn event_name(&self) -> &str {
        "issue"
    }

    fn repository_ref(&self) -> &RepositoryRef {
        &self.repository
    }

    fn to_channel_event(&self) -> ChannelEvent {
        ChannelEvent {
            content: format!(
                "issue {} on {}/{}/{}#{}",
                self.action.as_str(),
                self.repository.alias,
                self.repository.owner,
                self.repository.name,
                self.index,
            ),
            meta: ChannelEventMeta {
                action: self.action.as_str().to_string(),
                change_request: None,
                delivery_id: self.delivery_id.clone(),
                event_kind: "issue".to_string(),
                forge_alias: self.repository.alias.clone(),
                head_sha: None,
                issue: Some(self.index),
                issue_comment: None,
                owner: self.repository.owner.clone(),
                repo: self.repository.name.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueEventAction {
    Closed,
    Opened,
}

impl IssueEventAction {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Opened => "opened",
        }
    }
}

#[derive(Clone, Debug)]
pub enum WebhookEvent {
    ChangeRequest(ChangeRequestEvent),
    Issue(IssueEvent),
    IssueComment(IssueCommentEvent),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignIssueRequest {
    pub agent: AgentIdentity,
    pub assignee: String,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseChangeRequestRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseIssueRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommentOnChangeRequestRequest {
    pub agent: AgentIdentity,
    pub body: String,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommentOnIssueRequest {
    pub agent: AgentIdentity,
    pub body: String,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPatchRequest {
    pub agent: AgentIdentity,
    pub base_branch: String,
    pub commit_author: CommitAuthor,
    pub commit_message: String,
    pub existing_branch: bool,
    pub new_branch: String,
    pub patch: String,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitPatchResponse {
    pub branch: String,
    pub commit_sha: String,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetChangeRequestDiffRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetChangeRequestRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetIssueCommentsRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetIssueRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListChangeRequestsRequest {
    pub agent: AgentIdentity,
    pub repository: RepositoryRef,
    pub state: Option<ChangeRequestState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListIssuesRequest {
    pub agent: AgentIdentity,
    pub repository: RepositoryRef,
    pub state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenChangeRequestRequest {
    pub agent: AgentIdentity,
    pub base_branch: String,
    pub body: String,
    pub head_branch: String,
    pub repository: RepositoryRef,
    pub title: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebaseOperation {
    Fixup { commit: String, into: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebaseBranchRequest {
    pub agent: AgentIdentity,
    pub base_branch: String,
    pub branch: String,
    pub operations: Vec<RebaseOperation>,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RebaseBranchResponse {
    pub branch: String,
    pub commit_sha: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleAutoMergeRequest {
    pub agent: AgentIdentity,
    pub expected_head_sha: String,
    pub index: u64,
    pub merge_style: String,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateChangeRequestRequest {
    pub agent: AgentIdentity,
    pub body: Option<String>,
    pub index: u64,
    pub repository: RepositoryRef,
    pub title: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitChangeRequestReviewRequest {
    pub agent: AgentIdentity,
    pub body: String,
    /// Must be one of: `APPROVED`, `REQUEST_CHANGES`, `COMMENT`.
    pub event: String,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenChangeRequestResponse {
    pub change_request: ChangeRequest,
    pub repository: RepositoryRef,
}

/// Validates that a repository-relative path is safe.
///
/// Rejects empty paths, absolute paths, paths containing `..` components,
/// null bytes, and backslash separators.
///
/// # Errors
///
/// Returns a description of the violation if the path is unsafe.
pub fn validate_repository_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("path must not be empty".to_string());
    }
    if path != path.trim() {
        return Err("path must not have leading or trailing whitespace".to_string());
    }
    if path.starts_with('/') {
        return Err("absolute paths are not allowed".to_string());
    }
    if path.contains('\0') {
        return Err("path must not contain null bytes".to_string());
    }
    if path.contains('\\') {
        return Err("backslash separators are not allowed".to_string());
    }
    for component in path.split('/') {
        if component == ".." {
            return Err("path must not contain '..' components".to_string());
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("audit failure: {0}")]
    Audit(String),
    #[error("git execution failed: {0}")]
    GitExec(String),
    #[error("policy denied: {reasons}")]
    PolicyDenied { reasons: String },
    #[error("upstream forge error: {0}")]
    Upstream(String),
    #[error("validation failed: {0}")]
    Validation(String),
}

#[async_trait]
pub trait RepositoryReadService: Send + Sync {
    /// Retrieves the unified diff for a change request.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn get_change_request_diff(
        &self,
        request: GetChangeRequestDiffRequest,
    ) -> Result<ChangeRequestDiff, ServiceError>;

    /// Retrieves a single change request by index.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn get_change_request(
        &self,
        request: GetChangeRequestRequest,
    ) -> Result<ChangeRequest, ServiceError>;

    /// Retrieves all comments and reviews for a change request.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn get_change_request_comments(
        &self,
        request: GetChangeRequestCommentsRequest,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ServiceError>;

    /// Lists change requests, optionally filtered by state.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn list_change_requests(
        &self,
        request: ListChangeRequestsRequest,
    ) -> Result<Vec<ChangeRequest>, ServiceError>;

    /// Retrieves a single issue by index.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn get_issue(&self, request: GetIssueRequest) -> Result<Issue, ServiceError>;

    /// Retrieves all comments for an issue.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn get_issue_comments(
        &self,
        request: GetIssueCommentsRequest,
    ) -> Result<Vec<IssueComment>, ServiceError>;

    /// Lists issues, optionally filtered by state.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn list_issues(&self, request: ListIssuesRequest) -> Result<Vec<Issue>, ServiceError>;

    /// Reads a single text file from a repository through the control plane.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails, the upstream forge request fails,
    /// or audit recording fails.
    async fn read_repository_file(
        &self,
        request: ReadRepositoryFileRequest,
    ) -> Result<ReadRepositoryFileResponse, ServiceError>;
}

#[async_trait]
pub trait RepositoryWriteService: Send + Sync {
    /// Assigns an issue to a user.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn assign_issue(
        &self,
        request: AssignIssueRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError>;

    /// Closes a change request after verifying branch-scope policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the branch prefix check fails, the upstream forge
    /// request fails, or audit recording fails.
    async fn close_change_request(
        &self,
        request: CloseChangeRequestRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ServiceError>;

    /// Posts a general comment on a change request.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn comment_on_change_request(
        &self,
        request: CommentOnChangeRequestRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ServiceError>;

    /// Closes an issue.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn close_issue(
        &self,
        request: CloseIssueRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError>;

    /// Posts a comment on an issue.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream forge request fails or audit
    /// recording fails.
    async fn comment_on_issue(
        &self,
        request: CommentOnIssueRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<IssueComment, ServiceError>;

    /// Applies a patch to a new branch and pushes it.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, policy, git execution, or audit fails.
    async fn commit_patch(
        &self,
        request: CommitPatchRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<CommitPatchResponse, ServiceError>;

    /// Opens a change request (pull request) on the forge.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, the upstream forge request, or audit fails.
    async fn open_change_request(
        &self,
        request: OpenChangeRequestRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<OpenChangeRequestResponse, ServiceError>;

    /// Rebases a branch using the given operations (e.g. fixup).
    ///
    /// Performs a full clone, validates operations, runs interactive rebase,
    /// verifies tree integrity, and force-pushes with lease.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, git execution, or audit fails.
    async fn rebase_branch(
        &self,
        request: RebaseBranchRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<RebaseBranchResponse, ServiceError>;

    /// Schedules a pull request for automatic merge when all branch
    /// protection requirements are met.
    ///
    /// # Errors
    ///
    /// Returns an error if the head SHA does not match, the merge style is
    /// invalid, the upstream forge request fails, or audit recording fails.
    async fn schedule_auto_merge(
        &self,
        request: ScheduleAutoMergeRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<(), ServiceError>;

    /// Submits a formal review on a change request.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails, the upstream forge request fails,
    /// or audit recording fails.
    async fn submit_change_request_review(
        &self,
        request: SubmitChangeRequestReviewRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestReview, ServiceError>;

    /// Updates a change request's title and/or body.
    ///
    /// # Errors
    ///
    /// Returns an error if neither title nor body is provided, the upstream
    /// forge request fails, or audit recording fails.
    async fn update_change_request(
        &self,
        request: UpdateChangeRequestRequest,
        authorized: policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ServiceError>;
}

#[cfg(test)]
mod tests {
    use super::validate_repository_path;
    use super::{ChangeRequest, ChangeRequestEventAction, ChangeRequestState, ForgeCredential};

    #[test]
    fn forge_credential_debug_redacts_token() {
        let cred = ForgeCredential {
            token: Some("secret-token".to_string()),
        };
        let debug = format!("{cred:?}");
        assert!(!debug.contains("secret-token"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn forge_credential_debug_none_token() {
        let cred = ForgeCredential { token: None };
        let debug = format!("{cred:?}");
        assert!(debug.contains("None"));
    }

    #[test]
    fn change_request_serializes_to_json() {
        let cr = ChangeRequest {
            base_branch: "main".to_string(),
            body: "fix".to_string(),
            changed_files_count: None,
            commit_count: None,
            head_branch: "agent/fix".to_string(),
            head_sha: None,
            index: 1,
            merge_base_sha: None,
            state: ChangeRequestState::Open,
            title: "Fix".to_string(),
            url: "https://example.com/pulls/1".to_string(),
        };
        let json = serde_json::to_value(&cr).expect("should serialize");
        assert_eq!(json["index"], 1);
        assert_eq!(json["state"], "Open");
    }

    #[test]
    fn change_request_event_action_round_trips_synchronize() {
        let json = serde_json::to_string(&ChangeRequestEventAction::Synchronized)
            .expect("should serialize");
        assert_eq!(json, "\"synchronize\"");

        let parsed: ChangeRequestEventAction =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed, ChangeRequestEventAction::Synchronized);
    }

    #[test]
    fn accepts_simple_relative_path() {
        assert!(validate_repository_path("README.md").is_ok());
    }

    #[test]
    fn accepts_nested_path() {
        assert!(validate_repository_path("src/main.rs").is_ok());
    }

    #[test]
    fn rejects_empty_path() {
        assert!(validate_repository_path("").is_err());
    }

    #[test]
    fn rejects_leading_or_trailing_whitespace() {
        assert!(validate_repository_path("   ").is_err());
        assert!(validate_repository_path(" README.md").is_err());
        assert!(validate_repository_path("README.md ").is_err());
    }

    #[test]
    fn rejects_absolute_path() {
        assert!(validate_repository_path("/etc/passwd").is_err());
    }

    #[test]
    fn rejects_dotdot_traversal() {
        assert!(validate_repository_path("../secret").is_err());
        assert!(validate_repository_path("src/../../etc/passwd").is_err());
        assert!(validate_repository_path("foo/..").is_err());
    }

    #[test]
    fn rejects_null_bytes() {
        assert!(validate_repository_path("foo\0bar").is_err());
    }

    #[test]
    fn rejects_backslash_separators() {
        assert!(validate_repository_path("src\\main.rs").is_err());
    }

    #[test]
    fn allows_dotfiles_and_single_dot() {
        assert!(validate_repository_path(".gitignore").is_ok());
        assert!(validate_repository_path("src/.hidden").is_ok());
        assert!(validate_repository_path("./src/main.rs").is_ok());
    }

    #[test]
    fn issue_event_to_channel_event_sets_meta_fields() {
        use super::{ForgeKind, IssueEvent, IssueEventAction, PublishableEvent, RepositoryRef};
        let event = IssueEvent {
            action: IssueEventAction::Opened,
            delivery_id: "delivery-1".to_string(),
            index: 42,
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            title: "Bug report".to_string(),
            url: "https://forge.example/org/repo/issues/42".to_string(),
        };
        let channel = event.to_channel_event();
        assert_eq!(channel.meta.event_kind, "issue");
        assert_eq!(channel.meta.issue, Some(42));
        assert_eq!(channel.meta.change_request, None);
        assert_eq!(channel.meta.head_sha, None);
        assert_eq!(channel.meta.issue_comment, None);
    }

    #[test]
    fn issue_comment_event_to_channel_event_sets_meta_fields() {
        use super::{
            ForgeKind, IssueCommentEvent, IssueCommentEventAction, PublishableEvent, RepositoryRef,
        };
        let event = IssueCommentEvent {
            action: IssueCommentEventAction::Created,
            body: "looks good".to_string(),
            comment_id: 99,
            delivery_id: "delivery-2".to_string(),
            issue_index: 42,
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
        };
        let channel = event.to_channel_event();
        assert_eq!(channel.meta.event_kind, "issue_comment");
        assert_eq!(channel.meta.issue, Some(42));
        assert_eq!(channel.meta.issue_comment, Some(99));
        assert_eq!(channel.meta.change_request, None);
    }
}
