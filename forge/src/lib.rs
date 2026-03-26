//! Forge adapter traits and the Phase 1 Forgejo implementation.

use std::sync::Once;

use async_trait::async_trait;
use base64::Engine;
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestEvent,
    ChangeRequestEventAction, ChangeRequestReview, ChangeRequestState, ForgeCredential, ForgeUser,
    ReadRepositoryFileResponse, RepositoryRef,
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

    /// Closes a change request (pull request) on the forge.
    async fn close_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

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

    /// Lists change requests for a repository.
    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
    ) -> Result<Vec<ChangeRequest>, ForgeError>;

    /// Schedules a pull request for automatic merge when all branch
    /// protection requirements are met.
    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        head_commit_id: &str,
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
}

pub trait ForgeWebhookAdapter: Send + Sync {
    /// Verifies a forge webhook signature and converts a supported payload into
    /// a normalized change-request event.
    ///
    /// # Errors
    ///
    /// Returns an error if the required webhook headers are missing, the
    /// signature is invalid, or the payload cannot be parsed.
    fn verify_and_parse_change_request_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<ChangeRequestEvent>, ForgeWebhookError>;
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

    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        head_commit_id: &str,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}/merge",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "do": merge_style,
            "head_commit_id": head_commit_id,
            "merge_when_checks_succeed": true,
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
}

impl ForgeWebhookAdapter for ForgejoAdapter {
    fn verify_and_parse_change_request_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<ChangeRequestEvent>, ForgeWebhookError> {
        verify_forgejo_signature(headers, body, secret)?;

        let event = header_value(headers, &["x-forgejo-event", "x-gitea-event"])
            .ok_or_else(|| ForgeWebhookError::MissingHeader("x-forgejo-event".to_string()))?;
        if event != "pull_request" {
            return Ok(None);
        }

        let payload: ForgejoWebhookPullRequestEventPayload = serde_json::from_slice(body)
            .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

        let action = match payload.action.as_str() {
            "opened" => ChangeRequestEventAction::Opened,
            "reopened" => ChangeRequestEventAction::Reopened,
            "synchronize" => ChangeRequestEventAction::Synchronized,
            _ => return Ok(None),
        };

        let owner = payload.repository.owner.into_owner()?;
        let index = payload
            .number
            .or(payload.pull_request.number)
            .ok_or_else(|| {
                ForgeWebhookError::InvalidPayload("pull request number missing".to_string())
            })?;
        let delivery_id = header_value(headers, &["x-forgejo-delivery", "x-gitea-delivery"])
            .unwrap_or_default()
            .to_string();

        Ok(Some(ChangeRequestEvent {
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
        }))
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
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", &cred)
            .await
            .unwrap();

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["do"], "rebase");
        assert_eq!(body["merge_when_checks_succeed"], true);
        assert_eq!(body["head_commit_id"], "abc123sha");
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
            .verify_and_parse_change_request_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        assert_eq!(event.action, ChangeRequestEventAction::Synchronized);
        assert_eq!(event.delivery_id, "delivery-123");
        assert_eq!(event.index, 24);
        assert_eq!(event.repository.alias, "internal");
        assert_eq!(event.repository.owner, "org");
        assert_eq!(event.repository.name, "repo");
        assert_eq!(event.head_sha, "5e4e9ed3d19c2d7114eb7da1453913a3ab4f56ca");
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
            .verify_and_parse_change_request_event(
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
            .verify_and_parse_change_request_event(
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
}
