//! Forge adapter traits and the Phase 1 Forgejo implementation.

use std::sync::Once;

use async_trait::async_trait;
use base64::Engine;
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestEvent,
    ChangeRequestEventAction, ChangeRequestReview, ChangeRequestState, ForgeCredential, ForgeUser,
    ReadRepositoryFileResponse, RepositoryMergeSettings, RepositoryRef,
};
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;

static INSTALL_RING_PROVIDER: Once = Once::new();

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("upstream request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unexpected upstream status {status}: {body}")]
    UnexpectedStatus { status: StatusCode, body: String },
    #[error("invalid response payload: {0}")]
    InvalidPayload(String),
}

#[derive(Debug, Error)]
pub enum ForgeWebhookError {
    #[error("invalid webhook payload: {0}")]
    InvalidPayload(String),
    #[error("invalid webhook signature")]
    InvalidSignature,
    #[error("missing webhook header '{0}'")]
    MissingHeader(String),
}

#[async_trait]
pub trait ForgeAdapter: Send + Sync {
    /// Retrieves the authenticated user's identity from the forge.
    async fn get_authenticated_user(
        &self,
        credential: &ForgeCredential,
    ) -> Result<ForgeUser, ForgeError>;

    /// Assigns an issue to a user.
    async fn assign_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        assignee: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Closes a change request (pull request) on the forge.
    async fn close_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Closes an issue.
    async fn close_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Posts a comment on an issue.
    async fn comment_on_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueComment, ForgeError>;

    /// Posts a general comment on a change request.
    async fn comment_on_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ForgeError>;

    /// Creates a change request (pull request) on the forge.
    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Creates a new issue.
    async fn create_issue(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Returns the set of merge style strings the repository allows.
    async fn get_allowed_merge_styles(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Vec<String>, ForgeError>;

    /// Gets all comments and reviews for a change request.
    async fn get_change_request_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError>;

    /// Gets a single change request by index.
    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Gets the unified diff for a change request.
    async fn get_change_request_diff(
        &self,
        repository: &RepositoryRef,
        index: u64,
    ) -> Result<String, ForgeError>;

    /// Returns the repository's default merge style, if configured.
    async fn get_default_merge_style(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Option<String>, ForgeError>;

    /// Returns the repository's merge-related settings.
    async fn get_repository_merge_settings(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<RepositoryMergeSettings, ForgeError>;

    /// Gets a single issue by index.
    async fn get_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Gets all comments for an issue.
    async fn get_issue_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::IssueComment>, ForgeError>;

    /// Lists change requests for a repository.
    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
    ) -> Result<Vec<ChangeRequest>, ForgeError>;

    /// Lists issues for a repository.
    async fn list_issues(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Issue>, ForgeError>;

    /// Schedules a pull request for automatic merge when all branch
    /// protection requirements are met.
    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        head_commit_id: &str,
        delete_branch_after_merge: Option<bool>,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError>;

    /// Reads a single file from the backing forge.
    ///
    /// # Errors
    ///
    /// Returns an error if the forge is unsupported, the upstream request
    /// fails, or the response payload cannot be decoded into UTF-8 text.
    async fn read_repository_file(
        &self,
        repository: &RepositoryRef,
        path: &str,
        git_ref: Option<&str>,
    ) -> Result<ReadRepositoryFileResponse, ForgeError>;

    /// Submits a formal review on a change request.
    async fn submit_change_request_review(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        event: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestReview, ForgeError>;

    /// Updates a change request's title and/or body.
    async fn update_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Updates an issue's title and/or body.
    async fn update_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;
}

pub trait ForgeWebhookAdapter: Send + Sync {
    /// Verifies a forge webhook signature and converts a supported payload into
    /// a normalized webhook event.
    ///
    /// # Errors
    ///
    /// Returns an error if the required webhook headers are missing, the
    /// signature is invalid, or the payload cannot be parsed.
    fn verify_and_parse_webhook_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError>;
}

#[derive(Clone)]
pub struct ForgejoConfig {
    pub base_url: String,
    pub token: Option<String>,
}

impl std::fmt::Debug for ForgejoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgejoConfig")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ForgejoAdapter {
    client: reqwest::Client,
    config: ForgejoConfig,
}

impl ForgejoAdapter {
    #[must_use]
    pub fn new(config: ForgejoConfig) -> Self {
        INSTALL_RING_PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    async fn get_repository_merge_settings_response(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<ForgejoRepoResponse, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoAuthUser {
    email: String,
    login: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoContentsResponse {
    content: Option<String>,
    encoding: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullBranch {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullRequest {
    base: ForgejoPullBranch,
    body: Option<String>,
    changed_files: Option<u64>,
    head: ForgejoPullBranch,
    html_url: String,
    merge_base: Option<String>,
    merged: bool,
    number: u64,
    state: String,
    title: String,
}

impl ForgejoPullRequest {
    fn into_change_request(self) -> ChangeRequest {
        let state = if self.merged {
            ChangeRequestState::Merged
        } else {
            match self.state.as_str() {
                "open" => ChangeRequestState::Open,
                _ => ChangeRequestState::Closed,
            }
        };
        ChangeRequest {
            base_branch: self.base.ref_name,
            body: self.body.unwrap_or_default(),
            changed_files_count: self.changed_files,
            commit_count: None,
            head_branch: self.head.ref_name,
            head_sha: Some(self.head.sha),
            index: self.number,
            merge_base_sha: self.merge_base,
            state,
            title: self.title,
            url: self.html_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoCommentResponse {
    body: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct ForgejoReviewResponse {
    body: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct ForgejoCommentUser {
    login: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoIssueComment {
    body: String,
    created_at: String,
    id: u64,
    user: ForgejoCommentUser,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullReview {
    body: Option<String>,
    id: u64,
    state: String,
    submitted_at: Option<String>,
    user: ForgejoCommentUser,
}

#[derive(Debug, Deserialize)]
struct ForgejoIssueResponse {
    assignees: Option<Vec<ForgejoCommentUser>>,
    body: Option<String>,
    html_url: String,
    labels: Option<Vec<ForgejoLabelResponse>>,
    number: u64,
    state: String,
    title: String,
}

impl ForgejoIssueResponse {
    fn into_issue(self) -> domain::Issue {
        domain::Issue {
            assignees: self
                .assignees
                .unwrap_or_default()
                .into_iter()
                .map(|u| u.login)
                .collect(),
            body: self.body.unwrap_or_default(),
            index: self.number,
            labels: self
                .labels
                .unwrap_or_default()
                .into_iter()
                .map(|l| l.name)
                .collect(),
            state: self.state,
            title: self.title,
            url: self.html_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoIssueCommentResponse {
    body: String,
    created_at: String,
    id: u64,
    user: ForgejoCommentUser,
}

impl ForgejoIssueCommentResponse {
    fn into_issue_comment(self) -> domain::IssueComment {
        domain::IssueComment {
            author: self.user.login,
            body: self.body,
            created_at: self.created_at,
            id: self.id,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoLabelResponse {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoRepoResponse {
    allow_fast_forward_only_merge: Option<bool>,
    allow_merge_commits: Option<bool>,
    allow_rebase: Option<bool>,
    allow_rebase_explicit: Option<bool>,
    allow_squash_merge: Option<bool>,
    default_delete_branch_after_merge: Option<bool>,
    default_merge_style: Option<String>,
}

impl ForgejoRepoResponse {
    fn allowed_merge_styles(&self) -> Vec<String> {
        let mut styles = Vec::new();
        if self.allow_merge_commits.unwrap_or(false) {
            styles.push("merge".to_string());
        }
        if self.allow_rebase.unwrap_or(false) {
            styles.push("rebase".to_string());
        }
        if self.allow_rebase_explicit.unwrap_or(false) {
            styles.push("rebase-merge".to_string());
        }
        if self.allow_squash_merge.unwrap_or(false) {
            styles.push("squash".to_string());
        }
        if self.allow_fast_forward_only_merge.unwrap_or(false) {
            styles.push("fast-forward-only".to_string());
        }
        styles
    }

    fn normalized_default_merge_style(&self) -> Option<String> {
        self.default_merge_style.clone().filter(|s| !s.is_empty())
    }

    fn into_repository_merge_settings(self) -> RepositoryMergeSettings {
        RepositoryMergeSettings {
            allowed_styles: self.allowed_merge_styles(),
            default_delete_branch_after_merge: self.default_delete_branch_after_merge,
            default_merge_style: self.normalized_default_merge_style(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WebhookEventType {
    IssueComment,
    Issues,
    PullRequest,
    PullRequestReview,
    Unknown(String),
}

impl WebhookEventType {
    fn parse(value: &str) -> Self {
        match value {
            "issue_comment" => Self::IssueComment,
            "issues" => Self::Issues,
            "pull_request" => Self::PullRequest,
            "pull_request_approved"
            | "pull_request_comment"
            | "pull_request_rejected"
            | "pull_request_review" => Self::PullRequestReview,
            other => Self::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookComment {
    body: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookIssue {
    html_url: String,
    number: Option<u64>,
    title: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookIssueCommentPayload {
    action: String,
    comment: ForgejoWebhookComment,
    issue: ForgejoWebhookIssue,
    repository: ForgejoWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookIssueEventPayload {
    action: String,
    issue: ForgejoWebhookIssue,
    number: Option<u64>,
    repository: ForgejoWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookOwner {
    login: Option<String>,
    username: Option<String>,
}

impl ForgejoWebhookOwner {
    fn into_owner(self) -> Result<String, ForgeWebhookError> {
        self.login.or(self.username).ok_or_else(|| {
            ForgeWebhookError::InvalidPayload("repository owner missing".to_string())
        })
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookRepository {
    name: String,
    owner: ForgejoWebhookOwner,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookPullRequest {
    head: ForgejoPullBranch,
    html_url: String,
    number: Option<u64>,
    title: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookPullRequestEventPayload {
    action: String,
    number: Option<u64>,
    pull_request: ForgejoWebhookPullRequest,
    repository: ForgejoWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookPullRequestReviewEventPayload {
    action: String,
    pull_request: ForgejoWebhookPullRequest,
    repository: ForgejoWebhookRepository,
    review: ForgejoWebhookReview,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookReview {
    #[serde(alias = "content")]
    body: Option<String>,
    id: Option<u64>,
    #[serde(rename = "type")]
    review_type: String,
}

#[async_trait]
impl ForgeAdapter for ForgejoAdapter {
    async fn get_authenticated_user(
        &self,
        credential: &ForgeCredential,
    ) -> Result<ForgeUser, ForgeError> {
        let url = format!("{}/api/v1/user", self.config.base_url.trim_end_matches('/'),);

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let user: ForgejoAuthUser = response.json().await?;
        Ok(ForgeUser {
            email: user.email,
            username: user.login,
        })
    }

    async fn assign_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        assignee: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.patch(&url).json(&serde_json::json!({
            "assignees": [assignee]
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn close_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .patch(&url)
            .json(&serde_json::json!({"state": "closed"}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn close_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.patch(&url).json(&serde_json::json!({
            "state": "closed"
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn comment_on_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueComment, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "body": body
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let resp_body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus {
                status,
                body: resp_body,
            });
        }

        let comment: ForgejoIssueCommentResponse = response.json().await?;
        Ok(comment.into_issue_comment())
    }

    async fn comment_on_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"body": body}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let comment: ForgejoCommentResponse = response.json().await?;
        Ok(ChangeRequestComment {
            body: comment.body,
            id: comment.id,
            index,
        })
    }

    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "base": base_branch,
            "body": body,
            "head": head_branch,
            "title": title,
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn create_issue(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "title": title,
            "body": body
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let resp_body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus {
                status,
                body: resp_body,
            });
        }

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_allowed_merge_styles(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Vec<String>, ForgeError> {
        let repo = self
            .get_repository_merge_settings_response(repository, credential)
            .await?;
        Ok(repo.allowed_merge_styles())
    }

    async fn get_change_request_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // Fetch issue comments (general comments on the PR)
        let comments_url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );
        let mut comments_req = self.client.get(&comments_url);
        if let Some(token) = effective_token {
            comments_req = comments_req.bearer_auth(token);
        }
        let comments_response = comments_req.send().await?;
        let status = comments_response.status();
        if !status.is_success() {
            let body = comments_response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }
        let issue_comments: Vec<ForgejoIssueComment> = comments_response.json().await?;

        // Fetch pull request reviews
        let reviews_url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}/reviews",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );
        let mut reviews_req = self.client.get(&reviews_url);
        if let Some(token) = effective_token {
            reviews_req = reviews_req.bearer_auth(token);
        }
        let reviews_response = reviews_req.send().await?;
        let status = reviews_response.status();
        if !status.is_success() {
            let body = reviews_response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }
        let reviews: Vec<ForgejoPullReview> = reviews_response.json().await?;

        // Merge comments and non-PENDING reviews, sort chronologically
        let mut result: Vec<ChangeRequestCommentDetail> = Vec::new();

        for c in issue_comments {
            result.push(ChangeRequestCommentDetail {
                author: c.user.login,
                body: c.body,
                created_at: c.created_at,
                id: c.id,
                kind: "comment".to_string(),
                review_state: None,
            });
        }

        for r in reviews {
            let Some(submitted_at) = r.submitted_at else {
                continue; // Skip PENDING reviews
            };
            result.push(ChangeRequestCommentDetail {
                author: r.user.login,
                body: r.body.unwrap_or_default(),
                created_at: submitted_at,
                id: r.id,
                kind: "review".to_string(),
                review_state: Some(r.state),
            });
        }

        result.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(result)
    }

    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn get_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_issue_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::IssueComment>, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let comments: Vec<ForgejoIssueCommentResponse> = response.json().await?;
        Ok(comments
            .into_iter()
            .map(ForgejoIssueCommentResponse::into_issue_comment)
            .collect())
    }

    async fn get_change_request_diff(
        &self,
        repository: &RepositoryRef,
        index: u64,
    ) -> Result<String, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}.diff",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        response
            .text()
            .await
            .map_err(|e| ForgeError::InvalidPayload(format!("failed to read diff body: {e}")))
    }

    async fn get_default_merge_style(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Option<String>, ForgeError> {
        let repo = self
            .get_repository_merge_settings_response(repository, credential)
            .await?;
        Ok(repo.normalized_default_merge_style())
    }

    async fn get_repository_merge_settings(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<RepositoryMergeSettings, ForgeError> {
        let repo = self
            .get_repository_merge_settings_response(repository, credential)
            .await?;
        Ok(repo.into_repository_merge_settings())
    }

    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
    ) -> Result<Vec<ChangeRequest>, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let state_str = state.map(|s| match s {
            ChangeRequestState::Closed | ChangeRequestState::Merged => "closed",
            ChangeRequestState::Open => "open",
        });

        let mut request = self.client.get(&url);
        if let Some(state_str) = state_str {
            request = request.query(&[("state", state_str)]);
        }
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let prs: Vec<ForgejoPullRequest> = response.json().await?;
        Ok(prs
            .into_iter()
            .map(ForgejoPullRequest::into_change_request)
            .collect())
    }

    async fn list_issues(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Issue>, ForgeError> {
        let mut url = format!(
            "{}/api/v1/repos/{}/{}/issues?type=issues",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );
        if let Some(state) = state {
            url.push_str(&format!("&state={state}"));
        }

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let issues: Vec<ForgejoIssueResponse> = response.json().await?;
        Ok(issues
            .into_iter()
            .map(ForgejoIssueResponse::into_issue)
            .collect())
    }

    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        head_commit_id: &str,
        delete_branch_after_merge: Option<bool>,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}/merge",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut body = serde_json::Map::new();
        body.insert("do".to_string(), serde_json::json!(merge_style));
        body.insert(
            "head_commit_id".to_string(),
            serde_json::json!(head_commit_id),
        );
        body.insert(
            "merge_when_checks_succeed".to_string(),
            serde_json::json!(true),
        );
        if let Some(delete_branch_after_merge) = delete_branch_after_merge {
            body.insert(
                "delete_branch_after_merge".to_string(),
                serde_json::json!(delete_branch_after_merge),
            );
        }
        let mut request = self.client.post(&url).json(&body);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            // Forgejo returns 409 when auto-merge is already scheduled.
            // Treat this specific case as success; surface other 409s as errors.
            if status == reqwest::StatusCode::CONFLICT
                && body.contains("already scheduled to auto merge")
            {
                return Ok(());
            }
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        Ok(())
    }

    /// Reads a repository file through the Forgejo contents API.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, or the response body cannot
    /// be decoded as base64 UTF-8 content.
    async fn read_repository_file(
        &self,
        repository: &RepositoryRef,
        path: &str,
        git_ref: Option<&str>,
    ) -> Result<ReadRepositoryFileResponse, ForgeError> {
        let encoded_path = path.trim_start_matches('/').replace('/', "%2F");
        let url = format!(
            "{}/api/v1/repos/{}/{}/contents/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            encoded_path
        );

        let mut request = self.client.get(url);
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }
        if let Some(reference) = git_ref {
            request = request.query(&[("ref", reference)]);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let payload: ForgejoContentsResponse = response.json().await?;
        let Some(encoded) = payload.content else {
            return Err(ForgeError::InvalidPayload(
                "content field missing; the requested path may not be a file".to_string(),
            ));
        };

        let encoding = payload.encoding.unwrap_or_else(|| "base64".to_string());
        if encoding != "base64" {
            return Err(ForgeError::InvalidPayload(format!(
                "unsupported content encoding: {encoding}"
            )));
        }

        let cleaned = encoded.replace('\n', "");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(cleaned)
            .map_err(|e| ForgeError::InvalidPayload(format!("base64 decode failed: {e}")))?;
        let content = String::from_utf8(bytes)
            .map_err(|e| ForgeError::InvalidPayload(format!("utf8 decode failed: {e}")))?;

        Ok(ReadRepositoryFileResponse {
            repository: repository.clone(),
            path: payload.path,
            git_ref: git_ref.map(ToOwned::to_owned),
            content,
        })
    }

    async fn submit_change_request_review(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        event: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestReview, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}/reviews",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"body": body, "event": event}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let resp_body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus {
                status,
                body: resp_body,
            });
        }

        let review: ForgejoReviewResponse = response.json().await?;
        Ok(ChangeRequestReview {
            body: review.body,
            event: event.to_string(),
            id: review.id,
            index,
        })
    }

    async fn update_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut json_body = serde_json::Map::new();
        if let Some(title) = title {
            json_body.insert(
                "title".to_string(),
                serde_json::Value::String(title.to_string()),
            );
        }
        if let Some(body) = body {
            json_body.insert(
                "body".to_string(),
                serde_json::Value::String(body.to_string()),
            );
        }

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .patch(&url)
            .json(&serde_json::Value::Object(json_body));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let resp_body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus {
                status,
                body: resp_body,
            });
        }

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn update_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut json_body = serde_json::Map::new();
        if let Some(title) = title {
            json_body.insert(
                "title".to_string(),
                serde_json::Value::String(title.to_string()),
            );
        }
        if let Some(body) = body {
            json_body.insert(
                "body".to_string(),
                serde_json::Value::String(body.to_string()),
            );
        }

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .patch(&url)
            .json(&serde_json::Value::Object(json_body));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let resp_body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus {
                status,
                body: resp_body,
            });
        }

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }
}

impl ForgeWebhookAdapter for ForgejoAdapter {
    fn verify_and_parse_webhook_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
        verify_forgejo_signature(headers, body, secret)?;

        let event_header = header_value(headers, &["x-forgejo-event", "x-gitea-event"])
            .ok_or_else(|| ForgeWebhookError::MissingHeader("x-forgejo-event".to_string()))?;
        let event_type = WebhookEventType::parse(event_header);
        let delivery_id = header_value(headers, &["x-forgejo-delivery", "x-gitea-delivery"])
            .unwrap_or_default()
            .to_string();

        match event_type {
            WebhookEventType::PullRequest => {
                let payload: ForgejoWebhookPullRequestEventPayload =
                    serde_json::from_slice(body)
                        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

                let action = match payload.action.as_str() {
                    "opened" => ChangeRequestEventAction::Opened,
                    "reopened" => ChangeRequestEventAction::Reopened,
                    "synchronize" | "synchronized" => ChangeRequestEventAction::Synchronized,
                    _ => return Ok(None),
                };

                let owner = payload.repository.owner.into_owner()?;
                let index = payload
                    .number
                    .or(payload.pull_request.number)
                    .ok_or_else(|| {
                        ForgeWebhookError::InvalidPayload("pull request number missing".to_string())
                    })?;

                Ok(Some(domain::WebhookEvent::ChangeRequest(
                    ChangeRequestEvent {
                        action,
                        delivery_id,
                        head_sha: payload.pull_request.head.sha,
                        index,
                        repository: RepositoryRef {
                            alias: forge_alias.to_string(),
                            forge: forge_kind,
                            host: host.to_string(),
                            name: payload.repository.name,
                            owner,
                        },
                        title: payload.pull_request.title,
                        url: payload.pull_request.html_url,
                    },
                )))
            }
            WebhookEventType::Issues => {
                let payload: ForgejoWebhookIssueEventPayload = serde_json::from_slice(body)
                    .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

                let action = match payload.action.as_str() {
                    "closed" => domain::IssueEventAction::Closed,
                    "opened" => domain::IssueEventAction::Opened,
                    _ => return Ok(None),
                };

                let owner = payload.repository.owner.into_owner()?;
                let index = payload.number.or(payload.issue.number).ok_or_else(|| {
                    ForgeWebhookError::InvalidPayload("issue number missing".to_string())
                })?;

                Ok(Some(domain::WebhookEvent::Issue(domain::IssueEvent {
                    action,
                    delivery_id,
                    index,
                    repository: RepositoryRef {
                        alias: forge_alias.to_string(),
                        forge: forge_kind,
                        host: host.to_string(),
                        name: payload.repository.name,
                        owner,
                    },
                    title: payload.issue.title,
                    url: payload.issue.html_url,
                })))
            }
            WebhookEventType::IssueComment => {
                let payload: ForgejoWebhookIssueCommentPayload = serde_json::from_slice(body)
                    .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

                let action = match payload.action.as_str() {
                    "created" => domain::IssueCommentEventAction::Created,
                    _ => return Ok(None),
                };

                let owner = payload.repository.owner.into_owner()?;
                let issue_index = payload.issue.number.ok_or_else(|| {
                    ForgeWebhookError::InvalidPayload("issue number missing".to_string())
                })?;

                Ok(Some(domain::WebhookEvent::IssueComment(
                    domain::IssueCommentEvent {
                        action,
                        body: payload.comment.body,
                        comment_id: payload.comment.id,
                        delivery_id,
                        issue_index,
                        repository: RepositoryRef {
                            alias: forge_alias.to_string(),
                            forge: forge_kind,
                            host: host.to_string(),
                            name: payload.repository.name,
                            owner,
                        },
                    },
                )))
            }
            WebhookEventType::PullRequestReview => {
                let payload: ForgejoWebhookPullRequestReviewEventPayload =
                    serde_json::from_slice(body)
                        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

                let action = match payload.action.as_str() {
                    "reviewed" | "submitted" => domain::PullRequestReviewEventAction::Submitted,
                    _ => return Ok(None),
                };

                // Skip pending reviews — they are incomplete drafts.
                let review_state = match payload.review.review_type.as_str() {
                    "pull_request_review_approved" => domain::ReviewState::Approved,
                    "pull_request_review_rejected" => domain::ReviewState::RequestChanges,
                    "pull_request_review_comment" => domain::ReviewState::Comment,
                    _ => return Ok(None),
                };

                let owner = payload.repository.owner.into_owner()?;
                let index = payload.pull_request.number.ok_or_else(|| {
                    ForgeWebhookError::InvalidPayload("pull request number missing".to_string())
                })?;

                Ok(Some(domain::WebhookEvent::PullRequestReview(
                    domain::PullRequestReviewEvent {
                        action,
                        delivery_id,
                        head_sha: payload.pull_request.head.sha,
                        index,
                        repository: RepositoryRef {
                            alias: forge_alias.to_string(),
                            forge: forge_kind,
                            host: host.to_string(),
                            name: payload.repository.name,
                            owner,
                        },
                        review_body: payload.review.body.unwrap_or_default(),
                        review_id: payload.review.id.unwrap_or(0),
                        review_state,
                        title: payload.pull_request.title,
                        url: payload.pull_request.html_url,
                    },
                )))
            }
            WebhookEventType::Unknown(name) => {
                tracing::debug!(event_type = %name, "ignoring unhandled webhook event type");
                Ok(None)
            }
        }
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ForgeWebhookError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || (trimmed.len() & 1) != 0 {
        return Err(ForgeWebhookError::InvalidSignature);
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let chars: Vec<char> = trimmed.chars().collect();
    for pair in chars.chunks(2) {
        let high = pair[0]
            .to_digit(16)
            .ok_or(ForgeWebhookError::InvalidSignature)?;
        let low = pair[1]
            .to_digit(16)
            .ok_or(ForgeWebhookError::InvalidSignature)?;
        let combined = (high << 4) | low;
        let combined = u8::try_from(combined).map_err(|_| ForgeWebhookError::InvalidSignature)?;
        bytes.push(combined);
    }
    Ok(bytes)
}

fn header_value<'a>(headers: &'a [(String, String)], names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn verify_forgejo_signature(
    headers: &[(String, String)],
    body: &[u8],
    secret: &str,
) -> Result<(), ForgeWebhookError> {
    let signature = header_value(headers, &["x-forgejo-signature", "x-gitea-signature"])
        .ok_or_else(|| ForgeWebhookError::MissingHeader("x-forgejo-signature".to_string()))?;
    let signature = decode_hex(signature)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| ForgeWebhookError::InvalidPayload(format!("invalid secret: {e}")))?;
    mac.update(body);
    mac.verify_slice(&signature)
        .map_err(|_| ForgeWebhookError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use domain::ForgeCredential;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn test_adapter(base_url: &str) -> ForgejoAdapter {
        ForgejoAdapter::new(ForgejoConfig {
            base_url: base_url.to_string(),
            token: Some("test-token".to_string()),
        })
    }

    fn test_repo() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: domain::ForgeKind::Forgejo,
            host: "https://forge.example".to_string(),
            name: "repo".to_string(),
            owner: "org".to_string(),
        }
    }

    #[tokio::test]
    async fn schedule_auto_merge_sends_correct_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", Some(true), &cred)
            .await
            .unwrap();

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["do"], "rebase");
        assert_eq!(body["merge_when_checks_succeed"], true);
        assert_eq!(body["head_commit_id"], "abc123sha");
        assert_eq!(body["delete_branch_after_merge"], true);
    }

    #[tokio::test]
    async fn schedule_auto_merge_omits_delete_branch_flag_when_unspecified() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await
            .unwrap();

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["do"], "rebase");
        assert_eq!(body["merge_when_checks_succeed"], true);
        assert_eq!(body["head_commit_id"], "abc123sha");
        assert!(body.get("delete_branch_after_merge").is_none());
    }

    #[tokio::test]
    async fn schedule_auto_merge_succeeds_on_already_scheduled_409() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "message": "pull request is already scheduled to auto merge when checks succeed [pull_id: 78]"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn schedule_auto_merge_errors_on_unrelated_409() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "message": "some other conflict"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        let err = result.unwrap_err();
        match err {
            ForgeError::UnexpectedStatus { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::CONFLICT);
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_allowed_merge_styles_returns_enabled_styles() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_fast_forward_only_merge": false,
                "allow_merge_commits": false,
                "allow_rebase": true,
                "allow_rebase_explicit": false,
                "allow_squash_merge": true,
                "default_merge_style": "rebase",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let styles = adapter
            .get_allowed_merge_styles(&test_repo(), &cred)
            .await
            .unwrap();

        assert!(styles.contains(&"rebase".to_string()));
        assert!(styles.contains(&"squash".to_string()));
        assert!(!styles.contains(&"merge".to_string()));
        assert!(!styles.contains(&"rebase-merge".to_string()));
        assert!(!styles.contains(&"fast-forward-only".to_string()));
    }

    #[tokio::test]
    async fn get_allowed_merge_styles_includes_rebase_merge() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_fast_forward_only_merge": false,
                "allow_merge_commits": false,
                "allow_rebase": false,
                "allow_rebase_explicit": true,
                "allow_squash_merge": false,
                "default_merge_style": "rebase-merge",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let styles = adapter
            .get_allowed_merge_styles(&test_repo(), &cred)
            .await
            .unwrap();

        assert_eq!(styles, vec!["rebase-merge"]);
    }

    #[tokio::test]
    async fn get_allowed_merge_styles_includes_fast_forward_only() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_fast_forward_only_merge": true,
                "allow_merge_commits": false,
                "allow_rebase": true,
                "allow_rebase_explicit": false,
                "allow_squash_merge": false,
                "default_merge_style": "rebase",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let styles = adapter
            .get_allowed_merge_styles(&test_repo(), &cred)
            .await
            .unwrap();

        assert_eq!(styles, vec!["rebase", "fast-forward-only"]);
    }

    #[tokio::test]
    async fn get_default_merge_style_returns_style() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true, "allow_rebase_explicit": true, "allow_squash_merge": true,
                "default_merge_style": "squash", "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_default_merge_style(&test_repo(), &cred)
            .await
            .unwrap();
        assert_eq!(result, Some("squash".to_string()));
    }

    #[tokio::test]
    async fn get_default_merge_style_returns_none_when_missing() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true, "allow_rebase_explicit": true, "allow_squash_merge": true,
                "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_default_merge_style(&test_repo(), &cred)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_default_merge_style_returns_none_when_empty() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true, "allow_rebase_explicit": true, "allow_squash_merge": true,
                "default_merge_style": "", "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_default_merge_style(&test_repo(), &cred)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_repository_merge_settings_returns_delete_branch_default() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true,
                "allow_rebase": true,
                "allow_rebase_explicit": false,
                "allow_squash_merge": false,
                "default_delete_branch_after_merge": true,
                "default_merge_style": "rebase",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_repository_merge_settings(&test_repo(), &cred)
            .await
            .unwrap();
        assert_eq!(
            result.allowed_styles,
            vec!["merge".to_string(), "rebase".to_string()]
        );
        assert_eq!(result.default_delete_branch_after_merge, Some(true));
        assert_eq!(result.default_merge_style, Some("rebase".to_string()));
    }

    #[tokio::test]
    async fn get_comments_merges_and_sorts_chronologically() {
        let mock = MockServer::start().await;

        // Issue comments endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/issues/\d+/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": 10,
                    "body": "second comment",
                    "created_at": "2026-03-18T12:00:00Z",
                    "user": { "login": "alice" }
                },
                {
                    "id": 5,
                    "body": "first comment",
                    "created_at": "2026-03-18T10:00:00Z",
                    "user": { "login": "bob" }
                }
            ])))
            .mount(&mock)
            .await;

        // Reviews endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": 20,
                    "body": "approved",
                    "state": "APPROVED",
                    "submitted_at": "2026-03-18T11:00:00Z",
                    "user": { "login": "carol" }
                },
                {
                    "id": 30,
                    "body": null,
                    "state": "PENDING",
                    "submitted_at": null,
                    "user": { "login": "dave" }
                }
            ])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_change_request_comments(&test_repo(), 1, &cred)
            .await
            .unwrap();

        // PENDING review should be filtered out
        assert_eq!(result.len(), 3);

        // Should be sorted chronologically
        assert_eq!(result[0].author, "bob");
        assert_eq!(result[0].created_at, "2026-03-18T10:00:00Z");
        assert_eq!(result[0].kind, "comment");
        assert!(result[0].review_state.is_none());

        assert_eq!(result[1].author, "carol");
        assert_eq!(result[1].created_at, "2026-03-18T11:00:00Z");
        assert_eq!(result[1].kind, "review");
        assert_eq!(result[1].review_state.as_deref(), Some("APPROVED"));

        assert_eq!(result[2].author, "alice");
        assert_eq!(result[2].created_at, "2026-03-18T12:00:00Z");
        assert_eq!(result[2].kind, "comment");
    }

    fn sign_payload(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("valid HMAC key");
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        let mut signature = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut signature, "{byte:02x}").expect("writing to String cannot fail");
        }
        signature
    }

    #[test]
    fn forgejo_webhook_parses_supported_change_request_event() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "synchronize",
            "number": 24,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "5e4e9ed3d19c2d7114eb7da1453913a3ab4f56ca"
                },
                "html_url": "https://forge.example/org/repo/pulls/24",
                "title": "Fix channel events"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            ("x-forgejo-delivery".to_string(), "delivery-123".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::ChangeRequest(e) => e,
            other => panic!("expected ChangeRequest, got {other:?}"),
        };
        assert_eq!(event.action, ChangeRequestEventAction::Synchronized);
        assert_eq!(event.delivery_id, "delivery-123");
        assert_eq!(event.index, 24);
        assert_eq!(event.repository.alias, "internal");
        assert_eq!(event.repository.owner, "org");
        assert_eq!(event.repository.name, "repo");
        assert_eq!(event.head_sha, "5e4e9ed3d19c2d7114eb7da1453913a3ab4f56ca");
    }

    #[test]
    fn forgejo_webhook_parses_synchronized_action_variant() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "synchronized",
            "number": 10,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "def456"
                },
                "html_url": "https://forge.example/org/repo/pulls/10",
                "title": "Update"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            ("x-forgejo-delivery".to_string(), "delivery-456".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::ChangeRequest(e) => e,
            other => panic!("expected ChangeRequest, got {other:?}"),
        };
        assert_eq!(event.action, ChangeRequestEventAction::Synchronized);
        assert_eq!(event.index, 10);
    }

    #[test]
    fn forgejo_webhook_parses_pull_request_review_approved() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "abc123def456"
                },
                "html_url": "https://forge.example/org/repo/pulls/7",
                "number": 7,
                "title": "Fix typo"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "Looks good!",
                "id": 42,
                "type": "pull_request_review_approved"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_review".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-789".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(
            event.action,
            domain::PullRequestReviewEventAction::Submitted
        );
        assert_eq!(event.delivery_id, "delivery-789");
        assert_eq!(event.head_sha, "abc123def456");
        assert_eq!(event.index, 7);
        assert_eq!(event.repository.alias, "internal");
        assert_eq!(event.repository.owner, "org");
        assert_eq!(event.repository.name, "repo");
        assert_eq!(event.review_body, "Looks good!");
        assert_eq!(event.review_id, 42);
        assert_eq!(event.review_state, domain::ReviewState::Approved);
        assert_eq!(event.title, "Fix typo");
    }

    #[test]
    fn forgejo_webhook_parses_pull_request_review_request_changes() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "deadbeef"
                },
                "html_url": "https://forge.example/org/repo/pulls/8",
                "number": 8,
                "title": "Add feature"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "Needs work",
                "id": 43,
                "type": "pull_request_review_rejected"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_review".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-790".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(event.review_state, domain::ReviewState::RequestChanges);
    }

    #[test]
    fn forgejo_webhook_parses_per_action_review_payload() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "reviewed",
            "number": 8,
            "pull_request": {
                "head": {
                    "ref": "agent/claude/cargo-fmt",
                    "sha": "ec64af23c42c"
                },
                "html_url": "https://forge.example/org/repo/pulls/8",
                "number": 8,
                "title": "ci: fix lint failures"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "type": "pull_request_review_approved",
                "content": ""
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_approved".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-792".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(event.review_state, domain::ReviewState::Approved);
        assert_eq!(event.review_body, "");
        assert_eq!(event.review_id, 0);
        assert_eq!(event.index, 8);
    }

    #[test]
    fn forgejo_webhook_ignores_pending_review() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "abc123"
                },
                "html_url": "https://forge.example/org/repo/pulls/9",
                "number": 9,
                "title": "WIP"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "",
                "id": 44,
                "type": "pending"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_review".to_string(),
            ),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let result = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("payload should parse");
        assert!(result.is_none());
    }

    #[test]
    fn forgejo_webhook_parses_pull_request_approved_event_type() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "abc123def456"
                },
                "html_url": "https://forge.example/org/repo/pulls/7",
                "number": 7,
                "title": "Fix typo"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "Looks good!",
                "id": 42,
                "type": "pull_request_review_approved"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_approved".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-791".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(event.review_state, domain::ReviewState::Approved);
    }

    #[test]
    fn forgejo_webhook_rejects_invalid_signature() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "opened",
            "number": 24,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "abc123"
                },
                "html_url": "https://forge.example/org/repo/pulls/24",
                "title": "Fix channel events"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        }))
        .expect("valid JSON");
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            (
                "x-forgejo-signature".to_string(),
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            ),
        ];

        let error = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect_err("signature should be rejected");
        assert!(matches!(error, ForgeWebhookError::InvalidSignature));
    }

    #[test]
    fn forgejo_webhook_ignores_unsupported_action() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "edited",
            "number": 24,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "abc123"
                },
                "html_url": "https://forge.example/org/repo/pulls/24",
                "title": "Fix channel events"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        }))
        .expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let result = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("payload should parse");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn create_issue_sends_correct_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "number": 42,
                "title": "Bug report",
                "body": "Something is broken",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/42",
                "labels": [{"name": "bug"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .create_issue(&test_repo(), "Bug report", "Something is broken", &cred)
            .await
            .unwrap();

        assert_eq!(issue.index, 42);
        assert_eq!(issue.title, "Bug report");
        assert_eq!(issue.body, "Something is broken");
        assert_eq!(issue.state, "open");
        assert_eq!(issue.labels, vec!["bug"]);

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let req_body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(req_body["title"], "Bug report");
        assert_eq!(req_body["body"], "Something is broken");
    }
}
