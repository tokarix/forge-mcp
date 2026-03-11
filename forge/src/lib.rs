//! Forge adapter traits and the Phase 1 Forgejo implementation.

use async_trait::async_trait;
use base64::Engine;
use domain::{ReadRepositoryFileResponse, RepositoryRef};
use reqwest::StatusCode;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("unsupported forge for this adapter: {0:?}")]
    UnsupportedForge(domain::ForgeKind),
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

#[async_trait]
impl ForgeAdapter for ForgejoAdapter {
    /// Reads a repository file through the Forgejo contents API.
    ///
    /// # Errors
    ///
    /// Returns an error if the forge kind is not Forgejo, the HTTP request
    /// fails, or the response body cannot be decoded as base64 UTF-8 content.
    async fn read_repository_file(
        &self,
        repository: &RepositoryRef,
        path: &str,
        git_ref: Option<&str>,
    ) -> Result<ReadRepositoryFileResponse, ForgeError> {
        if repository.forge != domain::ForgeKind::Forgejo {
            return Err(ForgeError::UnsupportedForge(repository.forge.clone()));
        }

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
}
