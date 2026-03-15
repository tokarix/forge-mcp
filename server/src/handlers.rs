//! Axum route handlers for the REST API.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use domain::{
    AgentIdentity, CommitPatchRequest, ForgeKind, GetChangeRequestRequest,
    ListChangeRequestsRequest, OpenChangeRequestRequest, ReadRepositoryFileRequest, RepositoryRef,
    ServiceError,
};

use crate::api::{
    CommitPatchBody, CommitPatchResult, ContentsPath, ContentsQuery, ContentsResult, ErrorBody,
    ListPullsQuery, OpenPullBody, PullPath, RepoPath,
};
use crate::auth::{AgentRegistry, extract_bearer_token};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub agent_registry: AgentRegistry,
    pub audit_sink: Arc<dyn audit::AuditSink>,
    pub forge_registry: Arc<crate::registry::ForgeRegistry>,
}

fn resolve_forge<'a>(
    registry: &'a crate::registry::ForgeRegistry,
    alias: &str,
) -> Result<&'a crate::registry::ForgeInstance, (StatusCode, Json<ErrorBody>)> {
    registry.get(alias).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: format!("unknown forge alias '{alias}'"),
            }),
        )
    })
}

/// Maps a `ServiceError` to an HTTP status code and error body.
#[allow(clippy::needless_pass_by_value)]
fn map_service_error(err: ServiceError) -> (StatusCode, Json<ErrorBody>) {
    let (status, message) = match &err {
        ServiceError::Audit(_) | ServiceError::GitExec(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
        ServiceError::PolicyDenied { .. } | ServiceError::Validation(_) => {
            (StatusCode::BAD_REQUEST, err.to_string())
        }
        ServiceError::Upstream(_) => (StatusCode::BAD_GATEWAY, err.to_string()),
    };
    (status, Json(ErrorBody { error: message }))
}

/// Resolves bearer token to agent identity or returns 401.
/// Also checks repository authorization (403 if not allowed).
fn resolve_agent(
    headers: &HeaderMap,
    registry: &AgentRegistry,
    forge_alias: &str,
    owner: &str,
    repo: &str,
) -> Result<(AgentIdentity, domain::policy::PolicyConfig), (StatusCode, Json<ErrorBody>)> {
    let token = extract_bearer_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing or invalid Authorization header".to_string(),
            }),
        )
    })?;
    let agent = registry.resolve(token).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid bearer token".to_string(),
            }),
        )
    })?;

    // Check repository authorization
    if !agent
        .policy_config
        .is_repo_allowed(forge_alias, owner, repo)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: format!(
                    "agent '{}' is not authorized for repository '{owner}/{repo}'",
                    agent.identity.agent_id
                ),
            }),
        ));
    }

    Ok((agent.identity.clone(), agent.policy.clone()))
}

fn repo_ref(
    forge_alias: &str,
    owner: &str,
    repo: &str,
    forge: &crate::registry::ForgeInstance,
) -> RepositoryRef {
    RepositoryRef {
        alias: forge_alias.to_string(),
        forge: ForgeKind::Forgejo, // TODO: derive from config type field
        host: forge.base_url.clone(),
        name: repo.to_string(),
        owner: owner.to_string(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/contents/{path}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("path" = String, Path, description = "File path"),
        ("ref" = Option<String>, Query, description = "Git ref"),
    ),
    responses(
        (status = 200, description = "File contents", body = ContentsResult),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/contents/{path}
pub async fn get_contents(
    State(state): State<AppState>,
    Path(path): Path<ContentsPath>,
    Query(query): Query<ContentsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let (identity, _policy) = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .read_repository_file(ReadRepositoryFileRequest {
            agent: identity,
            git_ref: query.git_ref.clone(),
            path: path.path.clone(),
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(ContentsResult {
        content: result.content,
        git_ref: result.git_ref,
        path: result.path,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "Change request details"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}
pub async fn get_pull(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let (identity, _policy) = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_change_request(GetChangeRequestRequest {
            agent: identity,
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(
        serde_json::to_value(&result).expect("serializable"),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("state" = Option<String>, Query, description = "State filter: open, closed, merged"),
    ),
    responses(
        (status = 200, description = "List of change requests"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls
pub async fn list_pulls(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    Query(query): Query<ListPullsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let (identity, _policy) = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let state_filter = query.state.as_deref().map(|s| match s {
        "closed" => domain::ChangeRequestState::Closed,
        "merged" => domain::ChangeRequestState::Merged,
        _ => domain::ChangeRequestState::Open,
    });

    let result = forge
        .read_service
        .list_change_requests(ListChangeRequestsRequest {
            agent: identity,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            state: state_filter,
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(
        serde_json::to_value(&result).expect("serializable"),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/patches",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = CommitPatchBody,
    responses(
        (status = 201, description = "Patch committed", body = CommitPatchResult),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/patches
pub async fn post_patches(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<CommitPatchBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let (identity, policy) = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    // Per-agent policy check
    let diff_result = domain::diff::validate_diff(&body.patch)
        .map_err(|e| map_service_error(ServiceError::Validation(e.to_string())))?;

    let touched_paths: Vec<String> = diff_result
        .files
        .iter()
        .flat_map(|f| {
            let mut paths = vec![f.path.clone()];
            if let Some(ref source) = f.source_path {
                paths.push(source.clone());
            }
            paths
        })
        .collect();

    let policy_context = domain::policy::PolicyContext {
        action: "commit_patch".to_string(),
        agent: identity.clone(),
        repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        target_branch: body.new_branch.clone(),
        touched_paths,
    };
    let decision = domain::policy::evaluate(&policy, &policy_context)
        .map_err(|e| map_service_error(ServiceError::Validation(e.to_string())))?;
    if !decision.is_allowed() {
        return Err(map_service_error(ServiceError::PolicyDenied {
            reasons: decision.reasons.join("; "),
        }));
    }

    let authorized = domain::policy::AuthorizedWrite { policy };

    let result = forge
        .write_service
        .commit_patch(
            CommitPatchRequest {
                agent: identity,
                base_branch: body.base_branch,
                commit_message: body.commit_message,
                new_branch: body.new_branch,
                patch: body.patch,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((
        StatusCode::CREATED,
        Json(CommitPatchResult {
            branch: result.branch,
            commit_sha: result.commit_sha,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = OpenPullBody,
    responses(
        (status = 201, description = "Change request created"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/pulls
pub async fn post_pulls(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<OpenPullBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let (identity, policy) = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    // Per-agent branch prefix check for the head branch
    let policy_context = domain::policy::PolicyContext {
        action: "open_change_request".to_string(),
        agent: identity.clone(),
        repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        target_branch: body.head_branch.clone(),
        touched_paths: vec![],
    };
    let decision = domain::policy::evaluate(&policy, &policy_context)
        .map_err(|e| map_service_error(ServiceError::Validation(e.to_string())))?;
    if !decision.is_allowed() {
        return Err(map_service_error(ServiceError::PolicyDenied {
            reasons: decision.reasons.join("; "),
        }));
    }

    let authorized = domain::policy::AuthorizedWrite { policy };

    let result = forge
        .write_service
        .open_change_request(
            OpenChangeRequestRequest {
                agent: identity,
                base_branch: body.base_branch,
                body: body.body,
                head_branch: body.head_branch,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                title: body.title,
            },
            authorized,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((
        StatusCode::CREATED,
        Json(serde_json::to_value(&result.change_request).expect("serializable")),
    ))
}

/// GET /api/v1/agent/info
pub async fn agent_info(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let token = extract_bearer_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing or invalid Authorization header".to_string(),
            }),
        )
    })?;
    let agent = state.agent_registry.resolve(token).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid bearer token".to_string(),
            }),
        )
    })?;

    // Audit
    state
        .audit_sink
        .record(audit::AuditRecord {
            action: "agent_info".to_string(),
            agent: agent.identity.clone(),
            repository: RepositoryRef {
                alias: String::new(),
                forge: ForgeKind::Forgejo,
                host: String::new(),
                name: String::new(),
                owner: String::new(),
            },
            target: "self".to_string(),
        })
        .await
        .map_err(|e| map_service_error(ServiceError::Audit(e.to_string())))?;

    // Determine accessible forges
    let allowed = agent.policy_config.allowed_forge_aliases();
    let mut forges: Vec<crate::api::AgentForgeInfo> = Vec::new();
    for alias in state.forge_registry.aliases() {
        let visible = match &allowed {
            crate::config::AllowedForges::All => true,
            crate::config::AllowedForges::Specific(set) => set.contains(alias),
        };
        if visible && let Some(instance) = state.forge_registry.get(alias) {
            forges.push(crate::api::AgentForgeInfo {
                alias: alias.clone(),
                forge_type: instance.forge_type.clone(),
            });
        }
    }
    forges.sort_by(|a, b| a.alias.cmp(&b.alias));

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(crate::api::AgentInfoResult {
        agent_id: agent.identity.agent_id.clone(),
        forges,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use domain::{
        ChangeRequest, ChangeRequestState, CommitPatchResponse, GetChangeRequestRequest,
        ListChangeRequestsRequest, OpenChangeRequestResponse, ReadRepositoryFileResponse,
        ServiceError,
    };
    use tower::ServiceExt;

    use crate::auth::AgentRegistry;
    use crate::config::AgentPolicyConfig;

    use super::*;

    struct FakeForgeAdapter;

    #[async_trait::async_trait]
    impl forge::ForgeAdapter for FakeForgeAdapter {
        async fn read_repository_file(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, forge::ForgeError> {
            unimplemented!()
        }
        async fn create_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            unimplemented!()
        }
        async fn list_change_requests(
            &self,
            _: &domain::RepositoryRef,
            _: Option<&domain::ChangeRequestState>,
        ) -> Result<Vec<domain::ChangeRequest>, forge::ForgeError> {
            unimplemented!()
        }
        async fn get_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            unimplemented!()
        }
    }

    struct FakeReadService;

    #[async_trait::async_trait]
    impl domain::RepositoryReadService for FakeReadService {
        async fn read_repository_file(
            &self,
            request: ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Ok(ReadRepositoryFileResponse {
                content: "file-content".to_string(),
                git_ref: request.git_ref,
                path: request.path,
                repository: request.repository,
            })
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
        ) -> Result<ChangeRequest, ServiceError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: "body".to_string(),
                head_branch: "agent/fix".to_string(),
                index: request.index,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: "https://example.com/pulls/1".to_string(),
            })
        }
    }

    struct FakeWriteService;

    #[async_trait::async_trait]
    impl domain::RepositoryWriteService for FakeWriteService {
        async fn commit_patch(
            &self,
            request: CommitPatchRequest,
            _authorized: domain::policy::AuthorizedWrite,
        ) -> Result<CommitPatchResponse, ServiceError> {
            Ok(CommitPatchResponse {
                branch: request.new_branch.clone(),
                commit_sha: "abc123".to_string(),
                repository: request.repository,
            })
        }

        async fn open_change_request(
            &self,
            request: OpenChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
        ) -> Result<OpenChangeRequestResponse, ServiceError> {
            Ok(OpenChangeRequestResponse {
                change_request: ChangeRequest {
                    base_branch: "main".to_string(),
                    body: "body".to_string(),
                    head_branch: "agent/fix".to_string(),
                    index: 1,
                    state: ChangeRequestState::Open,
                    title: "Fix".to_string(),
                    url: "https://example.com/pulls/1".to_string(),
                },
                repository: request.repository,
            })
        }
    }

    fn test_state() -> AppState {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/repo".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let mut forges = std::collections::HashMap::new();
        forges.insert(
            "test-forge".to_string(),
            crate::registry::ForgeInstance {
                adapter: Arc::new(FakeForgeAdapter),
                alias: "test-forge".to_string(),
                base_url: "https://forge.example".to_string(),
                client: reqwest::Client::new(),
                forge_type: "forgejo".to_string(),
                git_auth_user: String::new(),
                read_service: Arc::new(FakeReadService),
                token: None,
                write_service: Arc::new(FakeWriteService),
            },
        );

        AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        }
    }

    #[tokio::test]
    async fn docs_route_absent_when_disabled() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/docs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_contents_returns_file() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/contents/README.md")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["content"], "file-content");
        assert_eq!(json["path"], "README.md");
    }

    #[tokio::test]
    async fn returns_401_without_token() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/contents/README.md")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn returns_403_for_unauthorized_repo() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/allowed-repo".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let mut forges = std::collections::HashMap::new();
        forges.insert(
            "test-forge".to_string(),
            crate::registry::ForgeInstance {
                adapter: Arc::new(FakeForgeAdapter),
                alias: "test-forge".to_string(),
                base_url: "https://forge.example".to_string(),
                client: reqwest::Client::new(),
                forge_type: "forgejo".to_string(),
                git_auth_user: String::new(),
                read_service: Arc::new(FakeReadService),
                token: None,
                write_service: Arc::new(FakeWriteService),
            },
        );

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        };
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/secret-repo/contents/README.md")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_401_with_bad_token() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/contents/README.md")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_patches_returns_201() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({
            "base_branch": "main",
            "commit_message": "fix",
            "new_branch": "agent/fix",
            "patch": "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n # Hello\n+World\n"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/patches")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["branch"], "agent/fix");
        assert_eq!(json["commit_sha"], "abc123");
    }

    #[tokio::test]
    async fn list_pulls_returns_array() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/pulls")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().expect("should be array").is_empty());
    }

    #[tokio::test]
    async fn post_pulls_returns_201() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({
            "base_branch": "main",
            "body": "Fix description",
            "head_branch": "agent/fix",
            "title": "Fix bug"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/pulls")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["index"], 1);
        assert_eq!(json["state"], "Open");
    }

    #[tokio::test]
    async fn get_pull_returns_change_request() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/pulls/1")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["index"], 1);
    }

    #[tokio::test]
    async fn post_patches_rejects_wrong_branch_per_agent_policy() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/repo".to_string()],
                branch_prefix: Some("agent/codex/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let mut forges = std::collections::HashMap::new();
        forges.insert(
            "test-forge".to_string(),
            crate::registry::ForgeInstance {
                adapter: Arc::new(FakeForgeAdapter),
                alias: "test-forge".to_string(),
                base_url: "https://forge.example".to_string(),
                client: reqwest::Client::new(),
                forge_type: "forgejo".to_string(),
                git_auth_user: String::new(),
                read_service: Arc::new(FakeReadService),
                token: None,
                write_service: Arc::new(FakeWriteService),
            },
        );

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        };
        let app = crate::build_router(state, false);

        let body = serde_json::json!({
            "base_branch": "main",
            "commit_message": "fix",
            "new_branch": "agent/claude/fix",
            "patch": "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n # Hello\n+World\n"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/patches")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("does not start with")
        );
    }

    #[tokio::test]
    async fn returns_404_for_unknown_forge() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/nonexistent/org/repo/contents/README.md")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn agent_info_returns_accessible_forges() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agent/info")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["agent_id"], "codex");
        let forges = json["forges"].as_array().unwrap();
        assert_eq!(forges.len(), 1);
        assert_eq!(forges[0]["alias"], "test-forge");
        assert_eq!(forges[0]["type"], "forgejo");
    }

    #[tokio::test]
    async fn agent_info_returns_401_without_token() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agent/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_info_filters_inaccessible_forges() {
        // Agent only has access to "test-forge/org/allowed-repo", not "other-forge"
        let configs = vec![crate::config::AgentConfig {
            agent_id: "restricted".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/repo".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "restricted-token".to_string(),
        }];

        let mut forges = std::collections::HashMap::new();
        forges.insert(
            "test-forge".to_string(),
            crate::registry::ForgeInstance {
                adapter: Arc::new(FakeForgeAdapter),
                alias: "test-forge".to_string(),
                base_url: "https://forge.example".to_string(),
                client: reqwest::Client::new(),
                forge_type: "forgejo".to_string(),
                git_auth_user: String::new(),
                read_service: Arc::new(FakeReadService),
                token: None,
                write_service: Arc::new(FakeWriteService),
            },
        );
        forges.insert(
            "other-forge".to_string(),
            crate::registry::ForgeInstance {
                adapter: Arc::new(FakeForgeAdapter),
                alias: "other-forge".to_string(),
                base_url: "https://other.example".to_string(),
                client: reqwest::Client::new(),
                forge_type: "forgejo".to_string(),
                git_auth_user: String::new(),
                read_service: Arc::new(FakeReadService),
                token: None,
                write_service: Arc::new(FakeWriteService),
            },
        );

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        };

        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agent/info")
                    .header("authorization", "Bearer restricted-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let forges = json["forges"].as_array().unwrap();
        // Only test-forge should be visible, not other-forge
        assert_eq!(forges.len(), 1);
        assert_eq!(forges[0]["alias"], "test-forge");
    }

    #[tokio::test]
    async fn agent_info_records_audit() {
        let audit_sink = Arc::new(audit::InMemoryAuditSink::new());
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["*".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::clone(&audit_sink) as Arc<dyn audit::AuditSink>,
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(
                std::collections::HashMap::new(),
            )),
        };

        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agent/info")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let records = audit_sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "agent_info");
        assert_eq!(records[0].target, "self");
    }
}
