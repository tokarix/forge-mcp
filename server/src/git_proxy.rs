//! Git smart HTTP proxy — read-only streaming proxy for git-upload-pack.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::result_large_err
)]

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use serde::Deserialize;

use crate::api::ErrorBody;
use crate::auth::{ResolvedAgent, extract_bearer_token};
use crate::handlers::AppState;
use crate::registry::ForgeInstance;

#[derive(Debug, Deserialize)]
pub struct GitRepoPath {
    pub forge: String,
    pub owner: String,
    /// Repository name, possibly with `.git` suffix.
    pub repo: String,
}

impl GitRepoPath {
    /// Returns the repo name without the `.git` suffix.
    fn repo_name(&self) -> &str {
        self.repo.strip_suffix(".git").unwrap_or(&self.repo)
    }
}

#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    pub service: Option<String>,
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::to_string(&ErrorBody {
        error: message.to_string(),
    })
    .unwrap_or_else(|_| format!("{{\"error\":\"{message}\"}}"));
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Authenticate, authorize, and resolve the forge instance for a git proxy
/// request.
fn resolve_agent_and_forge<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    path: &GitRepoPath,
    repo_name: &str,
) -> Result<(&'a ResolvedAgent, &'a ForgeInstance), Response> {
    let Some(token) = extract_bearer_token(headers) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing Authorization header",
        ));
    };
    let Some(agent) = state.agent_registry.resolve(token) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid bearer token",
        ));
    };

    if !agent
        .policy_config
        .is_repo_allowed(&path.forge, &path.owner, repo_name)
    {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            &format!(
                "agent '{}' is not authorized for repository '{}/{}/{}'",
                agent.identity.agent_id, path.forge, path.owner, repo_name
            ),
        ));
    }

    let Some(forge) = state.forge_registry.get(&path.forge) else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            &format!("unknown forge '{}'", path.forge),
        ));
    };

    Ok((agent, forge))
}

/// Records an audit event for a git proxy request.
async fn audit_git_read(
    state: &AppState,
    agent: &ResolvedAgent,
    path: &GitRepoPath,
    repo_name: &str,
    forge: &ForgeInstance,
    target: &str,
) -> Result<(), Response> {
    state
        .audit_sink
        .record(audit::AuditRecord {
            action: "git_read".to_string(),
            agent: agent.identity.clone(),
            repository: domain::RepositoryRef {
                alias: path.forge.clone(),
                forge: domain::ForgeKind::Forgejo,
                host: forge.base_url.clone(),
                name: repo_name.to_string(),
                owner: path.owner.clone(),
            },
            target: target.to_string(),
        })
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("audit failure: {e}"),
            )
        })
}

/// `GET /git/{forge}/{owner}/{repo}.git/info/refs?service=git-upload-pack`
pub async fn info_refs(
    State(state): State<AppState>,
    Path(path): Path<GitRepoPath>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response {
    let service = match query.service.as_deref() {
        Some("git-upload-pack") => "git-upload-pack",
        Some("git-receive-pack") => {
            return error_response(
                StatusCode::FORBIDDEN,
                "git push is not supported through the proxy; use the commit_patch MCP tool",
            );
        }
        Some(other) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("unsupported git service: {other}"),
            );
        }
        None => {
            return error_response(StatusCode::BAD_REQUEST, "missing service query parameter");
        }
    };

    let repo_name = path.repo_name();
    let (agent, forge) = match resolve_agent_and_forge(&state, &headers, &path, repo_name) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if let Err(resp) = audit_git_read(&state, agent, &path, repo_name, forge, "info/refs").await {
        return resp;
    }

    // Build upstream URL
    let upstream_url = format!(
        "{}/{}/{}.git/info/refs?service={service}",
        forge.base_url.trim_end_matches('/'),
        path.owner,
        repo_name,
    );

    // Proxy request — use HTTP Basic auth for git smart HTTP transport
    let mut upstream_req = forge.client.get(&upstream_url);
    if let Some(ref token) = forge.token {
        upstream_req = upstream_req.basic_auth(&forge.git_auth_user, Some(token));
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            );
        }
    };

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/x-git-upload-pack-advertisement"));

    let body = Body::from_stream(upstream_resp.bytes_stream());

    Response::builder()
        .status(status.as_u16())
        .header("content-type", content_type)
        .body(body)
        .unwrap()
}

/// `POST /git/{forge}/{owner}/{repo}.git/git-upload-pack`
pub async fn upload_pack(
    State(state): State<AppState>,
    Path(path): Path<GitRepoPath>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let repo_name = path.repo_name();
    let (agent, forge) = match resolve_agent_and_forge(&state, &headers, &path, repo_name) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if let Err(resp) =
        audit_git_read(&state, agent, &path, repo_name, forge, "git-upload-pack").await
    {
        return resp;
    }

    // Build upstream URL
    let upstream_url = format!(
        "{}/{}/{}.git/git-upload-pack",
        forge.base_url.trim_end_matches('/'),
        path.owner,
        repo_name,
    );

    // Stream request body to upstream
    let body_stream = body.into_data_stream();
    let reqwest_body = reqwest::Body::wrap_stream(body_stream);

    // Use HTTP Basic auth for git smart HTTP transport
    let mut upstream_req = forge
        .client
        .post(&upstream_url)
        .header("content-type", "application/x-git-upload-pack-request")
        .body(reqwest_body);
    if let Some(ref token) = forge.token {
        upstream_req = upstream_req.basic_auth(&forge.git_auth_user, Some(token));
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            );
        }
    };

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/x-git-upload-pack-result"));

    let body = Body::from_stream(upstream_resp.bytes_stream());

    Response::builder()
        .status(status.as_u16())
        .header("content-type", content_type)
        .body(body)
        .unwrap()
}

/// `POST /git/{forge}/{owner}/{repo}.git/git-receive-pack` — always rejected
pub async fn receive_pack_rejected() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "git push is not supported through the proxy; use the commit_patch MCP tool",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_strips_git_suffix() {
        let path = GitRepoPath {
            forge: "internal".to_string(),
            owner: "org".to_string(),
            repo: "repo.git".to_string(),
        };
        assert_eq!(path.repo_name(), "repo");
    }

    #[test]
    fn repo_name_without_suffix() {
        let path = GitRepoPath {
            forge: "internal".to_string(),
            owner: "org".to_string(),
            repo: "repo".to_string(),
        };
        assert_eq!(path.repo_name(), "repo");
    }
}
