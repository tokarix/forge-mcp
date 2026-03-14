//! Forge adapter traits and the Phase 1 Forgejo implementation.

use std::sync::Once;

use async_trait::async_trait;
use base64::Engine;
use domain::{ChangeRequest, ChangeRequestState, ReadRepositoryFileResponse, RepositoryRef};
use reqwest::StatusCode;
use serde::Deserialize;
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

#[async_trait]
pub trait ForgeAdapter: Send + Sync {
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

    /// Creates a change request (pull request) on the forge.
    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Lists change requests for a repository.
    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
    ) -> Result<Vec<ChangeRequest>, ForgeError>;

    /// Gets a single change request by index.
    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
    ) -> Result<ChangeRequest, ForgeError>;
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
struct ForgejoContentsResponse {
    content: Option<String>,
    encoding: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullBranch {
    #[serde(rename = "ref")]
    ref_name: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullRequest {
    base: ForgejoPullBranch,
    body: Option<String>,
    head: ForgejoPullBranch,
    html_url: String,
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
            head_branch: self.head.ref_name,
            index: self.number,
            state,
            title: self.title,
            url: self.html_url,
        }
    }
}

#[async_trait]
impl ForgeAdapter for ForgejoAdapter {
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

    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.post(&url).json(&serde_json::json!({
            "base": base_branch,
            "body": body,
            "head": head_branch,
            "title": title,
        }));
        if let Some(token) = &self.config.token {
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

    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
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

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }
}
