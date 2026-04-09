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
use crate::auth::{ResolvedAgent, extract_token};
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

/// Builds an upstream git URL using safe path-segment encoding.
///
/// Constructs `{base_url}/{owner}/{repo}.git/{suffix_segments...}` using
/// `reqwest::Url::path_segments_mut()` to prevent path injection from
/// user-controlled owner/repo values.
fn build_upstream_url(
    base_url: &str,
    owner: &str,
    repo_name: &str,
    suffix_segments: &[&str],
) -> Result<reqwest::Url, String> {
    let mut url =
        reqwest::Url::parse(base_url).map_err(|e| format!("invalid forge base URL: {e}"))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| "forge base URL cannot-be-a-base".to_string())?;
        segments.push(owner);
        segments.push(&format!("{repo_name}.git"));
        for s in suffix_segments {
            segments.push(s);
        }
    }
    Ok(url)
}

/// Returns a 401 response with `WWW-Authenticate: Basic` so that git
/// clients know to retry with credentials.
fn auth_challenge(message: &str) -> Response {
    let body = serde_json::to_string(&ErrorBody {
        error: message.to_string(),
    })
    .unwrap_or_else(|_| format!("{{\"error\":\"{message}\"}}"));
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        "www-authenticate",
        HeaderValue::from_static("Basic realm=\"forge-mcp\""),
    );
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::to_string(&ErrorBody {
        error: message.to_string(),
    })
    .unwrap_or_else(|_| format!("{{\"error\":\"{message}\"}}"));
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}

/// Authenticate, authorize, and resolve the forge instance for a git proxy
/// request.
fn resolve_agent_and_forge<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    path: &GitRepoPath,
    repo_name: &str,
) -> Result<(&'a ResolvedAgent, &'a ForgeInstance), Response> {
    let Some(token) = extract_token(headers) else {
        return Err(auth_challenge("missing Authorization header"));
    };
    let Some(agent) = state.agent_registry.resolve(&token) else {
        return Err(auth_challenge("invalid token"));
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
                forge: forge.forge_kind.clone(),
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

    // Build upstream URL using Url builder to prevent path injection
    let upstream_url =
        build_upstream_url(&forge.base_url, &path.owner, repo_name, &["info", "refs"]).map(
            |mut u| {
                u.query_pairs_mut().append_pair("service", service);
                u
            },
        );
    let upstream_url = match upstream_url {
        Ok(u) => u,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
    };

    // Proxy request — use HTTP Basic auth for git smart HTTP transport
    let mut upstream_req = forge.client.get(upstream_url);
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

    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert("content-type", content_type);
    response
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

    // Build upstream URL using Url builder to prevent path injection
    let upstream_url = build_upstream_url(
        &forge.base_url,
        &path.owner,
        repo_name,
        &["git-upload-pack"],
    );
    let upstream_url = match upstream_url {
        Ok(u) => u,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
    };

    // Stream request body to upstream
    let body_stream = body.into_data_stream();
    let reqwest_body = reqwest::Body::wrap_stream(body_stream);

    // Use HTTP Basic auth for git smart HTTP transport.
    // Forward Content-Encoding so Forgejo can decompress gzip request bodies
    // that git clients send for large fetches.
    let mut upstream_req = forge
        .client
        .post(upstream_url)
        .header("content-type", "application/x-git-upload-pack-request")
        .body(reqwest_body);
    if let Some(encoding) = headers.get("content-encoding") {
        upstream_req = upstream_req.header("content-encoding", encoding);
    }
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

    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert("content-type", content_type);
    response
}

/// `POST /git/{forge}/{owner}/{repo}.git/git-receive-pack` — always rejected
pub async fn receive_pack_rejected() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "git push is not supported through the proxy; use the commit_patch MCP tool",
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::todo, clippy::unimplemented)]
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

    #[test]
    fn build_upstream_url_encodes_reserved_characters() {
        let url = build_upstream_url("https://forge.example", "org", "repo", &["info", "refs"])
            .expect("valid upstream URL");
        assert_eq!(url.as_str(), "https://forge.example/org/repo.git/info/refs");
    }

    #[test]
    fn build_upstream_url_encodes_path_traversal() {
        let url = build_upstream_url(
            "https://forge.example",
            "org/../admin",
            "repo",
            &["info", "refs"],
        )
        .expect("valid upstream URL with path traversal");
        // The "/" and ".." within the owner are percent-encoded as a single segment,
        // not resolved as path traversal
        assert!(url.as_str().contains("org%2F..%2Fadmin"));
    }

    #[test]
    fn build_upstream_url_encodes_query_injection() {
        let url = build_upstream_url(
            "https://forge.example",
            "org",
            "repo?evil=1#frag",
            &["git-upload-pack"],
        )
        .expect("valid upstream URL with query injection");
        // Query and fragment characters are percent-encoded within the path segment
        assert!(url.as_str().contains("%3F"));
        assert!(url.as_str().contains("%23"));
        // No raw query or fragment was injected
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use domain::{
        ChangeRequest, ChangeRequestCommentDetail, ChangeRequestState, CommitPatchResponse,
        GetChangeRequestCommentsRequest, GetChangeRequestRequest, ListChangeRequestsRequest,
        OpenChangeRequestResponse, ReadRepositoryFileResponse, ServiceError,
    };
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex, query_param},
    };

    use crate::auth::AgentRegistry;
    use crate::config::AgentPolicyConfig;

    struct FakeForgeAdapter;

    impl forge::ForgeWebhookAdapter for FakeForgeAdapter {
        fn verify_and_parse_webhook_event(
            &self,
            _headers: &[(String, String)],
            _body: &[u8],
            _forge_alias: &str,
            _forge_kind: domain::ForgeKind,
            _host: &str,
            _secret: &str,
        ) -> Result<Option<domain::WebhookEvent>, forge::ForgeWebhookError> {
            unimplemented!()
        }
    }

    #[async_trait::async_trait]
    impl forge::ForgeAdapter for FakeForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn add_issue_label(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn assign_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn close_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn comment_on_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueComment, forge::ForgeError> {
            unimplemented!()
        }
        async fn create_commit_status(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<(), forge::ForgeError> {
            unimplemented!()
        }
        async fn create_issue(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_issue_comments(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_issue_dependencies(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueDependencies, forge::ForgeError> {
            unimplemented!()
        }
        async fn list_issues(
            &self,
            _: &domain::RepositoryRef,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::Issue>, forge::ForgeError> {
            unimplemented!()
        }
        async fn remove_issue_dependency(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn remove_issue_label(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_authenticated_user(
            &self,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ForgeUser, forge::ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }
        async fn close_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            unimplemented!()
        }
        async fn comment_on_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, forge::ForgeError> {
            unimplemented!()
        }
        async fn create_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_change_request_comments(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::ChangeRequestCommentDetail>, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_combined_commit_status(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &domain::RepositoryRef,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<String>, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_change_request_diff(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
        ) -> Result<String, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_default_merge_style(
            &self,
            _: &domain::RepositoryRef,
            _: &domain::ForgeCredential,
        ) -> Result<Option<String>, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_repository_merge_settings(
            &self,
            _: &domain::RepositoryRef,
            _: &domain::ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, forge::ForgeError> {
            unimplemented!()
        }
        async fn list_change_requests(
            &self,
            _: &domain::RepositoryRef,
            _: Option<&domain::ChangeRequestState>,
        ) -> Result<Vec<domain::ChangeRequest>, forge::ForgeError> {
            unimplemented!()
        }
        async fn read_repository_file(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, forge::ForgeError> {
            unimplemented!()
        }
        async fn schedule_auto_merge(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: Option<bool>,
            _: &domain::ForgeCredential,
        ) -> Result<(), forge::ForgeError> {
            unimplemented!()
        }
        async fn submit_change_request_review(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, forge::ForgeError> {
            unimplemented!()
        }
        async fn update_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            unimplemented!()
        }

        async fn update_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            unimplemented!()
        }
    }

    struct FakeReadService;

    #[async_trait::async_trait]
    impl domain::RepositoryReadService for FakeReadService {
        async fn get_issue(
            &self,
            _: domain::GetIssueRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            todo!()
        }
        async fn get_issue_comments(
            &self,
            _: domain::GetIssueCommentsRequest,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ServiceError> {
            todo!()
        }
        async fn get_issue_dependencies(
            &self,
            _: domain::GetIssueDependenciesRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueDependencies, ServiceError> {
            todo!()
        }
        async fn list_issues(
            &self,
            _: domain::ListIssuesRequest,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ServiceError> {
            todo!()
        }

        async fn read_repository_file(
            &self,
            request: domain::ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Ok(ReadRepositoryFileResponse {
                content: "file-content".to_string(),
                git_ref: request.git_ref,
                path: request.path,
                repository: request.repository,
            })
        }

        async fn get_change_request_checks(
            &self,
            _request: domain::GetChangeRequestChecksRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ServiceError> {
            unimplemented!()
        }

        async fn get_change_request_comments(
            &self,
            _request: GetChangeRequestCommentsRequest,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ServiceError> {
            unimplemented!()
        }

        async fn get_change_request_diff(
            &self,
            _request: domain::GetChangeRequestDiffRequest,
        ) -> Result<domain::ChangeRequestDiff, ServiceError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _request: ListChangeRequestsRequest,
        ) -> Result<Vec<ChangeRequest>, ServiceError> {
            Ok(vec![])
        }

        async fn get_change_request(
            &self,
            request: GetChangeRequestRequest,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ServiceError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: "body".to_string(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                index: request.index,
                merge_base_sha: None,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: "https://example.com/pulls/1".to_string(),
            })
        }
    }

    struct FakeWriteService;

    #[async_trait::async_trait]
    impl domain::RepositoryWriteService for FakeWriteService {
        async fn add_issue_dependency(
            &self,
            _: domain::AddIssueDependencyRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, domain::ServiceError> {
            unimplemented!()
        }
        async fn add_issue_label(
            &self,
            _: domain::AddIssueLabelRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, domain::ServiceError> {
            unimplemented!()
        }
        async fn assign_issue(
            &self,
            _: domain::AssignIssueRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            todo!()
        }
        async fn close_issue(
            &self,
            _: domain::CloseIssueRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            todo!()
        }
        async fn comment_on_issue(
            &self,
            _: domain::CommentOnIssueRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueComment, ServiceError> {
            todo!()
        }

        async fn close_change_request(
            &self,
            _request: domain::CloseChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ServiceError> {
            unimplemented!()
        }

        async fn comment_on_change_request(
            &self,
            _request: domain::CommentOnChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ServiceError> {
            unimplemented!()
        }

        async fn commit_patch(
            &self,
            request: domain::CommitPatchRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<CommitPatchResponse, ServiceError> {
            Ok(CommitPatchResponse {
                branch: request.new_branch.clone(),
                commit_sha: "abc123".to_string(),
                repository: request.repository,
            })
        }

        async fn create_issue(
            &self,
            _: domain::CreateIssueRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            unimplemented!()
        }

        async fn open_change_request(
            &self,
            request: domain::OpenChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<OpenChangeRequestResponse, ServiceError> {
            Ok(OpenChangeRequestResponse {
                change_request: ChangeRequest {
                    base_branch: "main".to_string(),
                    body: "body".to_string(),
                    changed_files_count: None,
                    commit_count: None,
                    head_branch: "agent/fix".to_string(),
                    head_sha: None,
                    index: 1,
                    merge_base_sha: None,
                    state: ChangeRequestState::Open,
                    title: "Fix".to_string(),
                    url: "https://example.com/pulls/1".to_string(),
                },
                repository: request.repository,
            })
        }

        async fn rebase_branch(
            &self,
            _request: domain::RebaseBranchRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::RebaseBranchResponse, ServiceError> {
            unimplemented!()
        }

        async fn remove_issue_dependency(
            &self,
            _: domain::RemoveIssueDependencyRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, domain::ServiceError> {
            unimplemented!()
        }
        async fn remove_issue_label(
            &self,
            _: domain::RemoveIssueLabelRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, domain::ServiceError> {
            unimplemented!()
        }

        async fn schedule_auto_merge(
            &self,
            _request: domain::ScheduleAutoMergeRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ServiceError> {
            unimplemented!()
        }

        async fn submit_change_request_review(
            &self,
            _request: domain::SubmitChangeRequestReviewRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ServiceError> {
            unimplemented!()
        }

        async fn update_change_request(
            &self,
            _request: domain::UpdateChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequest, ServiceError> {
            unimplemented!()
        }

        async fn update_issue(
            &self,
            _request: domain::UpdateIssueRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            unimplemented!()
        }
    }

    fn test_forge_instance(base_url: &str) -> crate::registry::ForgeInstance {
        crate::registry::ForgeInstance {
            adapter: Arc::new(FakeForgeAdapter),
            alias: "test-forge".to_string(),
            base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            forge_kind: domain::ForgeKind::Forgejo,
            forge_type: "forgejo".to_string(),
            git_auth_user: String::new(),
            read_service: Arc::new(FakeReadService),
            token: Some("upstream-token".to_string()),
            webhook: None,
            webhook_adapter: Arc::new(FakeForgeAdapter),
            write_service: Arc::new(FakeWriteService),
        }
    }

    fn test_state_with_forge(base_url: &str) -> (AppState, Arc<audit::InMemoryAuditSink>) {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/*".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let audit_sink = Arc::new(audit::InMemoryAuditSink::new());

        let mut forges = std::collections::HashMap::new();
        forges.insert("test-forge".to_string(), test_forge_instance(base_url));

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::clone(&audit_sink) as Arc<dyn audit::AuditSink>,
            auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
                crate::events::EventBus::new(),
                Arc::new(crate::registry::ForgeRegistry::new(
                    std::collections::HashMap::new(),
                )),
            )),
            event_bus: crate::events::EventBus::new(),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        };
        (state, audit_sink)
    }

    fn git_proxy_router(state: AppState) -> axum::Router {
        crate::build_router(state, false)
    }

    #[tokio::test]
    async fn info_refs_proxies_to_upstream() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/org/repo\.git/info/refs"))
            .and(query_param("service", "git-upload-pack"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"001e# service=git-upload-pack\n" as &[u8])
                    .insert_header(
                        "content-type",
                        "application/x-git-upload-pack-advertisement",
                    ),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let (state, audit_sink) = test_state_with_forge(&mock_server.uri());
        let app = git_proxy_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/git/test-forge/org/repo.git/info/refs?service=git-upload-pack")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .expect("content-type header"),
            "application/x-git-upload-pack-advertisement"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        assert_eq!(body.as_ref(), b"001e# service=git-upload-pack\n");

        let records = audit_sink.records().expect("should have audit records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "git_read");
        assert_eq!(records[0].target, "info/refs");
        assert_eq!(records[0].agent.agent_id, "codex");
    }

    #[tokio::test]
    async fn upload_pack_forwards_content_encoding() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/org/repo\.git/git-upload-pack"))
            .and(wiremock::matchers::header("content-encoding", "gzip"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"0008NAK\n" as &[u8])
                    .insert_header("content-type", "application/x-git-upload-pack-result"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let (state, _) = test_state_with_forge(&mock_server.uri());
        let app = git_proxy_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/git/test-forge/org/repo.git/git-upload-pack")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/x-git-upload-pack-request")
                    .header("content-encoding", "gzip")
                    .body(Body::from(b"\x1f\x8b\x08\x00" as &[u8]))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn receive_pack_rejected_returns_403() {
        let mock_server = MockServer::start().await;
        let (state, _) = test_state_with_forge(&mock_server.uri());
        let app = git_proxy_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/git/test-forge/org/repo.git/git-receive-pack")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn info_refs_rejects_receive_pack_service() {
        let mock_server = MockServer::start().await;
        let (state, _) = test_state_with_forge(&mock_server.uri());
        let app = git_proxy_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/git/test-forge/org/repo.git/info/refs?service=git-receive-pack")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn info_refs_rejects_unauthorized() {
        let mock_server = MockServer::start().await;
        let (state, _) = test_state_with_forge(&mock_server.uri());
        let app = git_proxy_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/git/test-forge/org/repo.git/info/refs?service=git-upload-pack")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn info_refs_rejects_disallowed_repo() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/allowed-only".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let mock_server = MockServer::start().await;
        let audit_sink = Arc::new(audit::InMemoryAuditSink::new());

        let mut forges = std::collections::HashMap::new();
        forges.insert(
            "test-forge".to_string(),
            test_forge_instance(&mock_server.uri()),
        );

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::clone(&audit_sink) as Arc<dyn audit::AuditSink>,
            auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
                crate::events::EventBus::new(),
                Arc::new(crate::registry::ForgeRegistry::new(
                    std::collections::HashMap::new(),
                )),
            )),
            event_bus: crate::events::EventBus::new(),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        };
        let app = git_proxy_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/git/test-forge/org/secret-repo.git/info/refs?service=git-upload-pack")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
