//! Forge adapter traits and the Phase 1 Forgejo implementation.

use std::fmt::Write;
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
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;

pub mod gitlab;

static INSTALL_RING_PROVIDER: Once = Once::new();

fn install_ring_provider() {
    INSTALL_RING_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("upstream request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("repository not found (upstream returned {status})")]
    NotFound { status: StatusCode },
    #[error(
        "repository may have moved or been renamed (upstream returned {status} redirect to {location})"
    )]
    Redirect {
        status: StatusCode,
        location: String,
    },
    #[error("unexpected upstream status {status}: {body}")]
    UnexpectedStatus { status: StatusCode, body: String },
    #[error("operation not supported: {0}")]
    Unsupported(String),
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
    /// Adds a dependency on another issue.
    async fn add_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Adds a label to an issue, creating the label on the repo if it does
    /// not already exist.
    async fn add_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

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

    /// Creates a commit status on the given SHA.
    async fn create_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        context: &str,
        description: &str,
        state: &str,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError>;

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
        credential: &ForgeCredential,
    ) -> Result<String, ForgeError>;

    /// Returns the combined CI/check status for the given commit SHA.
    async fn get_combined_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::CombinedCommitStatus, ForgeError>;

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

    /// Gets the dependency relationships for an issue.
    async fn get_issue_dependencies(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueDependencies, ForgeError>;

    /// Lists change requests for a repository.
    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequest>, ForgeError>;

    /// Lists issues for a repository.
    async fn list_issues(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Issue>, ForgeError>;

    /// Lists repositories on the forge, optionally filtered by owner and/or
    /// search query.
    async fn list_repositories(
        &self,
        owner: Option<&str>,
        query: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError>;

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

    /// Removes a dependency relationship from an issue.
    async fn remove_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Removes a label from an issue.
    async fn remove_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

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
        credential: &ForgeCredential,
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
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(config: ForgejoConfig) -> Result<Self, ForgeError> {
        install_ring_provider();

        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(Policy::none())
                .build()?,
            config,
        })
    }

    /// Checks the HTTP response status and returns a descriptive error for
    /// non-success codes.  Recognises redirects (3xx) and not-found (404) to
    /// provide actionable messages instead of the generic "error decoding
    /// response body" that occurs when the caller tries to parse a non-JSON
    /// body.
    async fn check_response(response: reqwest::Response) -> Result<reqwest::Response, ForgeError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<unknown>")
                .to_string();
            tracing::warn!(
                %status,
                %location,
                url = %response.url(),
                "upstream returned redirect — repository may have moved or been renamed",
            );
            return Err(ForgeError::Redirect { status, location });
        }

        if status == StatusCode::NOT_FOUND {
            tracing::warn!(
                %status,
                url = %response.url(),
                "upstream returned 404 — repository or resource not found",
            );
            return Err(ForgeError::NotFound { status });
        }

        let url = response.url().clone();
        let body = response.text().await.unwrap_or_default();
        tracing::warn!(
            %status,
            %url,
            body_len = body.len(),
            body_preview = %&body[..body.len().min(512)],
            "unexpected upstream status",
        );
        Err(ForgeError::UnexpectedStatus { status, body })
    }

    /// Fetches the raw Forgejo issue response (including internal `id`).
    async fn fetch_issue_raw(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ForgejoIssueResponse, ForgeError> {
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

        let response = Self::check_response(request.send().await?).await?;
        Ok(response.json().await?)
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

        let response = Self::check_response(request.send().await?).await?;

        response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))
    }

    /// Lists repo labels and returns the ID for a label matching `name`, or
    /// `None` if no such label exists.
    async fn find_label_id(
        &self,
        repository: &RepositoryRef,
        name: &str,
        token: Option<&str>,
    ) -> Result<Option<u64>, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/labels",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.get(&url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let labels: Vec<ForgejoLabelResponse> = response.json().await?;
        Ok(labels.into_iter().find(|l| l.name == name).map(|l| l.id))
    }

    /// Finds a repo label by name, creating it if it does not exist. Returns
    /// the label's numeric ID.
    async fn find_or_create_label(
        &self,
        repository: &RepositoryRef,
        name: &str,
        token: Option<&str>,
    ) -> Result<u64, ForgeError> {
        if let Some(id) = self.find_label_id(repository, name, token).await? {
            return Ok(id);
        }

        // Create the label with a default colour.
        let url = format!(
            "{}/api/v1/repos/{}/{}/labels",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.post(&url).json(&serde_json::json!({
            "color": "#0075ca",
            "name": name,
        }));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let label: ForgejoLabelResponse = response.json().await?;
        Ok(label.id)
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoAuthUser {
    email: String,
    login: String,
}

/// Forgejo combined commit status response from
/// `GET /api/v1/repos/{owner}/{repo}/commits/{ref}/status`.
#[derive(Debug, Deserialize)]
struct ForgejoCombinedStatusResponse {
    sha: String,
    state: String,
    statuses: Option<Vec<ForgejoCommitStatusResponse>>,
    total_count: u64,
}

/// A single commit status entry in the Forgejo response.
#[derive(Debug, Deserialize)]
struct ForgejoCommitStatusResponse {
    context: String,
    description: Option<String>,
    status: String,
    target_url: Option<String>,
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
    commit_id: Option<String>,
    #[serde(default)]
    dismissed: bool,
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
    /// Forgejo internal database ID (not the visible issue number).
    id: u64,
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
    id: u64,
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

/// Forgejo repo search result wrapper from `GET /api/v1/repos/search`.
#[derive(Debug, Deserialize)]
struct ForgejoRepoSearchResponse {
    data: Vec<ForgejoRepoSearchEntry>,
    ok: bool,
}

/// A single repository in a Forgejo search result.
#[derive(Debug, Deserialize)]
struct ForgejoRepoSearchEntry {
    description: Option<String>,
    full_name: String,
    html_url: String,
    name: String,
    owner: Option<ForgejoRepoSearchOwner>,
}

#[derive(Debug, Deserialize)]
struct ForgejoRepoSearchOwner {
    login: String,
}

/// Forgejo user lookup response from `GET /api/v1/users/{username}`.
#[derive(Debug, Deserialize)]
struct ForgejoUserResponse {
    id: u64,
}

impl ForgejoRepoSearchEntry {
    fn into_repository(self) -> domain::Repository {
        domain::Repository {
            description: self.description.unwrap_or_default(),
            full_name: self.full_name,
            name: self.name,
            owner: self.owner.map(|o| o.login).unwrap_or_default(),
            url: self.html_url,
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
    async fn add_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        // Forgejo's dependency API expects the internal database ID, not the
        // visible issue number.  Fetch the dependency issue first.
        let dep_issue = self
            .fetch_issue_raw(repository, dependency, credential)
            .await?;

        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/dependencies",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"dependsOn": dep_issue.id}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        self.get_issue(repository, index, credential).await
    }

    async fn add_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let base = self.config.base_url.trim_end_matches('/');
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // 1. Find or create the label to get its numeric ID.
        let label_id = self
            .find_or_create_label(repository, label, effective_token)
            .await?;

        // 2. Add the label to the issue.
        let url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/labels",
            repository.owner, repository.name,
        );
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"labels": [label_id]}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        // 3. Return the full updated issue.
        self.get_issue(repository, index, credential).await
    }

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn create_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        context: &str,
        description: &str,
        state: &str,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/statuses/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            sha,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "context": context,
            "description": description,
            "state": state,
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        Ok(())
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

        let response = Self::check_response(request.send().await?).await?;

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

    async fn get_combined_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::CombinedCommitStatus, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/commits/{}/status",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            sha,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let combined: ForgejoCombinedStatusResponse = response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))?;

        let state = parse_commit_status_state(&combined.state);
        let statuses = combined
            .statuses
            .unwrap_or_default()
            .into_iter()
            .map(|s| domain::CommitStatus {
                context: s.context,
                description: s.description.unwrap_or_default(),
                state: parse_commit_status_state(&s.status),
                target_url: s.target_url.unwrap_or_default(),
            })
            .collect();

        Ok(domain::CombinedCommitStatus {
            head_sha: combined.sha,
            state,
            statuses,
            total_count: combined.total_count,
        })
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
        let comments_response = Self::check_response(comments_req.send().await?).await?;
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
        let reviews_response = Self::check_response(reviews_req.send().await?).await?;
        let reviews: Vec<ForgejoPullReview> = reviews_response.json().await?;

        // Merge comments and non-PENDING reviews, sort chronologically
        let mut result: Vec<ChangeRequestCommentDetail> = Vec::new();

        for c in issue_comments {
            result.push(ChangeRequestCommentDetail {
                author: c.user.login,
                body: c.body,
                commit_id: None,
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
            let review_state = if r.dismissed {
                "DISMISSED".to_string()
            } else {
                r.state
            };
            result.push(ChangeRequestCommentDetail {
                author: r.user.login,
                body: r.body.unwrap_or_default(),
                commit_id: r.commit_id,
                created_at: submitted_at,
                id: r.id,
                kind: "review".to_string(),
                review_state: Some(review_state),
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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

        let comments: Vec<ForgejoIssueCommentResponse> = response.json().await?;
        Ok(comments
            .into_iter()
            .map(ForgejoIssueCommentResponse::into_issue_comment)
            .collect())
    }

    async fn get_issue_dependencies(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueDependencies, ForgeError> {
        let base = self.config.base_url.trim_end_matches('/');
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // Fetch issues that this issue depends on.
        let deps_url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/dependencies",
            repository.owner, repository.name,
        );
        let mut request = self.client.get(&deps_url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }
        let response = Self::check_response(request.send().await?).await?;
        let depends_on: Vec<ForgejoIssueResponse> = response.json().await?;

        // Fetch issues that are blocked by this issue.
        let blocks_url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/blocks",
            repository.owner, repository.name,
        );
        let mut request = self.client.get(&blocks_url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }
        let response = Self::check_response(request.send().await?).await?;
        let blocks: Vec<ForgejoIssueResponse> = response.json().await?;

        Ok(domain::IssueDependencies {
            blocks: blocks
                .into_iter()
                .map(ForgejoIssueResponse::into_issue)
                .collect(),
            depends_on: depends_on
                .into_iter()
                .map(ForgejoIssueResponse::into_issue)
                .collect(),
        })
    }

    async fn get_change_request_diff(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<String, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}.diff",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

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
        credential: &ForgeCredential,
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

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(state_str) = state_str {
            request = request.query(&[("state", state_str)]);
        }
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

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
            let _ = write!(url, "&state={state}");
        }

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let issues: Vec<ForgejoIssueResponse> = response.json().await?;
        Ok(issues
            .into_iter()
            .map(ForgejoIssueResponse::into_issue)
            .collect())
    }

    async fn list_repositories(
        &self,
        owner: Option<&str>,
        query: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError> {
        const PAGE_SIZE: usize = 50;

        // If owner is specified, resolve to UID for server-side filtering.
        // Try /users/{owner} first, then fall back to /orgs/{owner} so that
        // organization-owned namespaces are also supported.
        let uid = if let Some(owner_name) = owner {
            let base = self.config.base_url.trim_end_matches('/');
            let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

            // Try user endpoint first.
            let user_url = format!("{base}/api/v1/users/{owner_name}");
            let mut req = self.client.get(&user_url);
            if let Some(token) = effective_token {
                req = req.bearer_auth(token);
            }
            let resp = req.send().await?;

            if resp.status() == StatusCode::NOT_FOUND {
                // Not a user — try organization endpoint.
                let org_url = format!("{base}/api/v1/orgs/{owner_name}");
                let mut req = self.client.get(&org_url);
                if let Some(token) = effective_token {
                    req = req.bearer_auth(token);
                }
                let resp = req.send().await?;
                if resp.status() == StatusCode::NOT_FOUND {
                    return Ok(Vec::new());
                }
                let resp = Self::check_response(resp).await?;
                let org: ForgejoUserResponse = resp.json().await?;
                Some(org.id)
            } else {
                let resp = Self::check_response(resp).await?;
                let user: ForgejoUserResponse = resp.json().await?;
                Some(user.id)
            }
        } else {
            None
        };

        let mut all_repos = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut url = format!(
                "{}/api/v1/repos/search?limit={PAGE_SIZE}&page={page}",
                self.config.base_url.trim_end_matches('/'),
            );
            if let Some(uid) = uid {
                let _ = write!(url, "&uid={uid}&exclusive=true");
            }
            if let Some(q) = query {
                let _ = write!(url, "&q={}", urlencoding::encode(q));
            }

            let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
            let mut req = self.client.get(&url);
            if let Some(token) = effective_token {
                req = req.bearer_auth(token);
            }

            let resp = Self::check_response(req.send().await?).await?;
            let search: ForgejoRepoSearchResponse = resp.json().await?;
            if !search.ok {
                return Err(ForgeError::InvalidPayload(
                    "Forgejo repo search returned ok=false".to_string(),
                ));
            }

            let count = search.data.len();
            all_repos.extend(
                search
                    .data
                    .into_iter()
                    .map(ForgejoRepoSearchEntry::into_repository),
            );

            if count < PAGE_SIZE {
                break;
            }
            page += 1;
        }

        Ok(all_repos)
    }

    async fn remove_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        // Forgejo's dependency API expects the internal database ID, not the
        // visible issue number.  Fetch the dependency issue first.
        let dep_issue = self
            .fetch_issue_raw(repository, dependency, credential)
            .await?;

        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/dependencies",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .delete(&url)
            .json(&serde_json::json!({"dependsOn": dep_issue.id}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        self.get_issue(repository, index, credential).await
    }

    async fn remove_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let base = self.config.base_url.trim_end_matches('/');
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // 1. Find the label ID by name.
        let label_id = self
            .find_label_id(repository, label, effective_token)
            .await?
            .ok_or_else(|| ForgeError::InvalidPayload(format!("label '{label}' not found")))?;

        // 2. Remove the label from the issue.
        let url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/labels/{label_id}",
            repository.owner, repository.name,
        );
        let mut request = self.client.delete(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        // 3. Return the full updated issue.
        self.get_issue(repository, index, credential).await
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
            // Forgejo may also return 500 when the duplicate-key DB constraint
            // fires (UQE_pull_auto_merge_pull_id). Treat this as a no-op too.
            if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
                && (body.contains("UQE_pull_auto_merge_pull_id") || body.contains("duplicate key"))
            {
                tracing::debug!("schedule_auto_merge: ignoring 500 duplicate-key response",);
                return Ok(());
            }
            if status.is_redirection() {
                let location = "<unknown>".to_string();
                tracing::warn!(
                    %status,
                    %location,
                    "upstream returned redirect — repository may have moved or been renamed",
                );
                return Err(ForgeError::Redirect { status, location });
            }
            if status == StatusCode::NOT_FOUND {
                tracing::warn!(
                    %status,
                    "upstream returned 404 — repository or resource not found",
                );
                return Err(ForgeError::NotFound { status });
            }
            tracing::warn!(
                %status,
                body_len = body.len(),
                body_preview = %&body[..body.len().min(512)],
                "unexpected upstream status",
            );
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
        credential: &ForgeCredential,
    ) -> Result<ReadRepositoryFileResponse, ForgeError> {
        let encoded_path = path.trim_start_matches('/').replace('/', "%2F");
        let url = format!(
            "{}/api/v1/repos/{}/{}/contents/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            encoded_path
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }
        if let Some(reference) = git_ref {
            request = request.query(&[("ref", reference)]);
        }

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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

        let response = Self::check_response(request.send().await?).await?;

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
                parse_pull_request_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::Issues => {
                parse_issue_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::IssueComment => {
                parse_issue_comment_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::PullRequestReview => {
                parse_pull_request_review_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::Unknown(name) => {
                tracing::debug!(event_type = %name, "ignoring unhandled webhook event type");
                Ok(None)
            }
        }
    }
}

fn parse_pull_request_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookPullRequestEventPayload = serde_json::from_slice(body)
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

fn parse_issue_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookIssueEventPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.action.as_str() {
        "closed" => domain::IssueEventAction::Closed,
        "opened" => domain::IssueEventAction::Opened,
        _ => return Ok(None),
    };

    let owner = payload.repository.owner.into_owner()?;
    let index = payload
        .number
        .or(payload.issue.number)
        .ok_or_else(|| ForgeWebhookError::InvalidPayload("issue number missing".to_string()))?;

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

fn parse_issue_comment_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookIssueCommentPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.action.as_str() {
        "created" => domain::IssueCommentEventAction::Created,
        _ => return Ok(None),
    };

    let owner = payload.repository.owner.into_owner()?;
    let issue_index = payload
        .issue
        .number
        .ok_or_else(|| ForgeWebhookError::InvalidPayload("issue number missing".to_string()))?;

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

fn parse_pull_request_review_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookPullRequestReviewEventPayload = serde_json::from_slice(body)
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

fn parse_commit_status_state(s: &str) -> domain::CommitStatusState {
    match s {
        "error" => domain::CommitStatusState::Error,
        "failure" => domain::CommitStatusState::Failure,
        "success" => domain::CommitStatusState::Success,
        "warning" => domain::CommitStatusState::Warning,
        // Forgejo may return "pending" or an empty string when there are no
        // statuses, so the fallback covers both.
        _ => domain::CommitStatusState::Pending,
    }
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
#[allow(clippy::expect_used, clippy::panic)]
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
        .expect("build forgejo adapter")
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
    async fn create_commit_status_sends_correct_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/statuses/.+"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .create_commit_status(
                &test_repo(),
                "abc123sha",
                "forge-mcp/auto-merge",
                "auto-merge scheduled",
                "success",
                &cred,
            )
            .await
            .expect("create commit status");

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["context"], "forge-mcp/auto-merge");
        assert_eq!(body["description"], "auto-merge scheduled");
        assert_eq!(body["state"], "success");
    }

    #[tokio::test]
    async fn create_commit_status_uses_correct_url() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/org/repo/statuses/abc123sha"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .create_commit_status(
                &test_repo(),
                "abc123sha",
                "ci/test",
                "all good",
                "success",
                &cred,
            )
            .await
            .expect("create commit status");

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn create_commit_status_propagates_error_on_failure() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/statuses/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .create_commit_status(
                &test_repo(),
                "abc123sha",
                "ci/test",
                "test",
                "success",
                &cred,
            )
            .await;

        assert!(result.is_err());
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
            .expect("schedule auto merge");

        let requests = mock.received_requests().await.expect("received requests");
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
            .expect("schedule auto merge");

        let requests = mock.received_requests().await.expect("received requests");
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

        let err = result.expect_err("should fail with conflict");
        match err {
            ForgeError::UnexpectedStatus { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::CONFLICT);
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn schedule_auto_merge_succeeds_on_duplicate_key_500() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(500).set_body_string(
                "duplicate key value violates unique constraint \"UQE_pull_auto_merge_pull_id\"",
            ))
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
    async fn schedule_auto_merge_errors_on_unrelated_500() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        let err = result.expect_err("should fail with unexpected status");
        match err {
            ForgeError::UnexpectedStatus { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
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
            .expect("get allowed merge styles");

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
            .expect("get allowed merge styles");

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
            .expect("get allowed merge styles");

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
            .expect("get default merge style");
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
            .expect("get default merge style");
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
            .expect("get default merge style");
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
            .expect("get repository merge settings");
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
                    "commit_id": "abc123def456",
                    "state": "APPROVED",
                    "submitted_at": "2026-03-18T11:00:00Z",
                    "user": { "login": "carol" }
                },
                {
                    "id": 25,
                    "body": "needs work",
                    "commit_id": "def789abc012",
                    "dismissed": true,
                    "state": "REQUEST_CHANGES",
                    "submitted_at": "2026-03-18T11:30:00Z",
                    "user": { "login": "eve" }
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
            .expect("get change request comments");

        // PENDING review should be filtered out
        assert_eq!(result.len(), 4);

        // Should be sorted chronologically
        assert_eq!(result[0].author, "bob");
        assert_eq!(result[0].created_at, "2026-03-18T10:00:00Z");
        assert_eq!(result[0].kind, "comment");
        assert!(result[0].commit_id.is_none());
        assert!(result[0].review_state.is_none());

        assert_eq!(result[1].author, "carol");
        assert_eq!(result[1].created_at, "2026-03-18T11:00:00Z");
        assert_eq!(result[1].kind, "review");
        assert_eq!(result[1].commit_id.as_deref(), Some("abc123def456"));
        assert_eq!(result[1].review_state.as_deref(), Some("APPROVED"));

        // Dismissed review should have review_state DISMISSED
        assert_eq!(result[2].author, "eve");
        assert_eq!(result[2].created_at, "2026-03-18T11:30:00Z");
        assert_eq!(result[2].kind, "review");
        assert_eq!(result[2].commit_id.as_deref(), Some("def789abc012"));
        assert_eq!(result[2].review_state.as_deref(), Some("DISMISSED"));

        assert_eq!(result[3].author, "alice");
        assert_eq!(result[3].created_at, "2026-03-18T12:00:00Z");
        assert_eq!(result[3].kind, "comment");
        assert!(result[3].commit_id.is_none());
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
                "id": 100,
                "number": 42,
                "title": "Bug report",
                "body": "Something is broken",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/42",
                "labels": [{"id": 1, "name": "bug"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .create_issue(&test_repo(), "Bug report", "Something is broken", &cred)
            .await
            .expect("create issue");

        assert_eq!(issue.index, 42);
        assert_eq!(issue.title, "Bug report");
        assert_eq!(issue.body, "Something is broken");
        assert_eq!(issue.state, "open");
        assert_eq!(issue.labels, vec!["bug"]);

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let req_body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(req_body["title"], "Bug report");
        assert_eq!(req_body["body"], "Something is broken");
    }

    #[tokio::test]
    async fn add_issue_label_creates_label_when_missing() {
        let mock = MockServer::start().await;

        // 1. GET labels returns empty (label doesn't exist).
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;

        // 2. POST to create the label.
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 7,
                "name": "needs-input",
            })))
            .mount(&mock)
            .await;

        // 3. POST to add label to issue.
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 7, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 4. GET issue to return full state.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 101,
                "number": 1,
                "title": "Test issue",
                "body": "",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/1",
                "labels": [{"id": 7, "name": "needs-input"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .add_issue_label(&test_repo(), 1, "needs-input", &cred)
            .await
            .expect("add issue label");

        assert_eq!(issue.labels, vec!["needs-input"]);

        let requests = mock.received_requests().await.expect("received requests");
        // GET labels, POST create label, POST add label, GET issue
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].method.as_str(), "GET");
        assert_eq!(requests[1].method.as_str(), "POST");
        let create_body: serde_json::Value =
            serde_json::from_slice(&requests[1].body).expect("valid JSON");
        assert_eq!(create_body["name"], "needs-input");
    }

    #[tokio::test]
    async fn add_issue_label_reuses_existing_label() {
        let mock = MockServer::start().await;

        // 1. GET labels returns the label (already exists).
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 3, "name": "bug"},
                {"id": 5, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 2. POST to add label to issue.
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 5, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 3. GET issue.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 102,
                "number": 2,
                "title": "Test",
                "body": "",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/2",
                "labels": [{"id": 5, "name": "needs-input"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .add_issue_label(&test_repo(), 2, "needs-input", &cred)
            .await
            .expect("add issue label");

        assert_eq!(issue.labels, vec!["needs-input"]);

        let requests = mock.received_requests().await.expect("received requests");
        // GET labels, POST add label, GET issue (no create — label existed)
        assert_eq!(requests.len(), 3);
        let add_body: serde_json::Value =
            serde_json::from_slice(&requests[1].body).expect("valid JSON");
        assert_eq!(add_body["labels"], serde_json::json!([5]));
    }

    #[tokio::test]
    async fn remove_issue_label_deletes_by_id() {
        let mock = MockServer::start().await;

        // 1. GET labels to find the label ID.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 3, "name": "bug"},
                {"id": 5, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 2. DELETE label from issue.
        Mock::given(method("DELETE"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+/labels/\d+$"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock)
            .await;

        // 3. GET issue.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 103,
                "number": 1,
                "title": "Test",
                "body": "",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/1",
                "labels": [{"id": 3, "name": "bug"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .remove_issue_label(&test_repo(), 1, "needs-input", &cred)
            .await
            .expect("remove issue label");

        assert_eq!(issue.labels, vec!["bug"]);

        let requests = mock.received_requests().await.expect("received requests");
        // GET labels, DELETE label, GET issue
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].method.as_str(), "DELETE");
        assert!(requests[1].url.path().ends_with("/labels/5"));
    }

    #[tokio::test]
    async fn remove_issue_label_errors_when_label_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .remove_issue_label(&test_repo(), 1, "nonexistent", &cred)
            .await;

        assert!(result.is_err());
        let err = result
            .expect_err("should fail with label not found")
            .to_string();
        assert!(
            err.contains("not found"),
            "expected 'not found' in error: {err}"
        );
    }

    #[tokio::test]
    async fn get_combined_commit_status_returns_success() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/commits/abc123/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "abc123",
                "state": "success",
                "statuses": [
                    {
                        "context": "ci/woodpecker",
                        "description": "build passed",
                        "status": "success",
                        "target_url": "https://ci.example/1"
                    }
                ],
                "total_count": 1
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_combined_commit_status(&test_repo(), "abc123", &cred)
            .await
            .expect("get combined commit status");

        assert_eq!(result.head_sha, "abc123");
        assert_eq!(result.state, domain::CommitStatusState::Success);
        assert_eq!(result.total_count, 1);
        assert_eq!(result.statuses.len(), 1);
        assert_eq!(result.statuses[0].context, "ci/woodpecker");
        assert_eq!(result.statuses[0].state, domain::CommitStatusState::Success);
    }

    #[tokio::test]
    async fn get_combined_commit_status_handles_empty_statuses() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/commits/def456/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "def456",
                "state": "",
                "statuses": null,
                "total_count": 0
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_combined_commit_status(&test_repo(), "def456", &cred)
            .await
            .expect("get combined commit status");

        assert_eq!(result.head_sha, "def456");
        assert_eq!(result.state, domain::CommitStatusState::Pending);
        assert_eq!(result.total_count, 0);
        assert!(result.statuses.is_empty());
    }

    #[tokio::test]
    async fn get_combined_commit_status_propagates_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/commits/.+/status"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_combined_commit_status(&test_repo(), "abc123", &cred)
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn parse_commit_status_state_known_values() {
        assert_eq!(
            parse_commit_status_state("success"),
            domain::CommitStatusState::Success
        );
        assert_eq!(
            parse_commit_status_state("failure"),
            domain::CommitStatusState::Failure
        );
        assert_eq!(
            parse_commit_status_state("pending"),
            domain::CommitStatusState::Pending
        );
        assert_eq!(
            parse_commit_status_state("error"),
            domain::CommitStatusState::Error
        );
        assert_eq!(
            parse_commit_status_state("warning"),
            domain::CommitStatusState::Warning
        );
    }

    #[test]
    fn parse_commit_status_state_unknown_defaults_to_pending() {
        assert_eq!(
            parse_commit_status_state(""),
            domain::CommitStatusState::Pending
        );
        assert_eq!(
            parse_commit_status_state("unknown"),
            domain::CommitStatusState::Pending
        );
    }

    #[tokio::test]
    async fn check_response_returns_redirect_on_301() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(
                ResponseTemplate::new(301)
                    .insert_header("Location", "https://forge.example/new-org/repo"),
            )
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with redirect");
        match err {
            ForgeError::Redirect { status, location } => {
                assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
                assert_eq!(location, "https://forge.example/new-org/repo");
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_not_found_on_404() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "The target couldn't be found."
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_unexpected_status_on_500() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with unexpected status");
        match err {
            ForgeError::UnexpectedStatus { status, body } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert!(body.contains("internal server error"));
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_redirect_error_message_mentions_moved() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "https://forge.example/new-org/repo"),
            )
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with redirect");
        let msg = err.to_string();
        assert!(
            msg.contains("moved or been renamed"),
            "error message should mention moved/renamed, got: {msg}"
        );
        assert!(
            msg.contains("302"),
            "error message should contain status code, got: {msg}"
        );
    }

    #[tokio::test]
    async fn check_response_not_found_error_message() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with not found");
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "error message should mention not found, got: {msg}"
        );
    }
}
