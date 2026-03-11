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

#[cfg(test)]
mod tests {
    use super::validate_repository_path;

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
}
