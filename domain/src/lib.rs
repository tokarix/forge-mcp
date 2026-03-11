//! Canonical domain types and service traits for forge-mcp.

use async_trait::async_trait;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForgeKind {
    Forgejo,
    GitHub,
    GitLab,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryRef {
    pub forge: ForgeKind,
    pub host: String,
    pub owner: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRepositoryFileRequest {
    pub agent: AgentIdentity,
    pub repository: RepositoryRef,
    pub path: String,
    pub git_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRepositoryFileResponse {
    pub repository: RepositoryRef,
    pub path: String,
    pub git_ref: Option<String>,
    pub content: String,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("upstream forge error: {0}")]
    Upstream(String),
    #[error("audit failure: {0}")]
    Audit(String),
}

#[async_trait]
pub trait RepositoryReadService: Send + Sync {
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
