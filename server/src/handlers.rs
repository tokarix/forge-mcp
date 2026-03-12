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
    ListChangeRequestsRequest, OpenChangeRequestRequest, ReadRepositoryFileRequest,
    RepositoryReadService, RepositoryRef, RepositoryWriteService, ServiceError,
};

use crate::api::{
    CommitPatchBody, CommitPatchResult, ContentsPath, ContentsQuery, ContentsResult, ErrorBody,
    ListPullsQuery, OpenPullBody, PullPath, RepoPath,
};
use crate::auth::AgentRegistry;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub agent_registry: AgentRegistry,
    pub forgejo_base_url: String,
    pub read_service: Arc<dyn RepositoryReadService>,
    pub write_service: Arc<dyn RepositoryWriteService>,
}

/// Extracts the bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
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
    if !agent.policy_config.is_repo_allowed(owner, repo) {
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

fn repo_ref(owner: &str, repo: &str, base_url: &str) -> RepositoryRef {
    RepositoryRef {
        forge: ForgeKind::Forgejo,
        host: base_url.to_string(),
        name: repo.to_string(),
        owner: owner.to_string(),
    }
}

/// GET /api/v1/repos/{owner}/{repo}/contents/{path}
pub async fn get_contents(
    State(state): State<AppState>,
    Path(path): Path<ContentsPath>,
    Query(query): Query<ContentsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (identity, _policy) =
        resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .read_service
        .read_repository_file(ReadRepositoryFileRequest {
            agent: identity,
            git_ref: query.git_ref.clone(),
            path: path.path.clone(),
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(ContentsResult {
        content: result.content,
        git_ref: result.git_ref,
        path: result.path,
    }))
}

/// GET /api/v1/repos/{owner}/{repo}/pulls/{index}
pub async fn get_pull(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (identity, _policy) =
        resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .read_service
        .get_change_request(GetChangeRequestRequest {
            agent: identity,
            index: path.index,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(
        serde_json::to_value(&result).expect("serializable"),
    ))
}

/// GET /api/v1/repos/{owner}/{repo}/pulls
pub async fn list_pulls(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    Query(query): Query<ListPullsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (identity, _policy) =
        resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let state_filter = query.state.as_deref().map(|s| match s {
        "closed" => domain::ChangeRequestState::Closed,
        "merged" => domain::ChangeRequestState::Merged,
        _ => domain::ChangeRequestState::Open,
    });

    let result = state
        .read_service
        .list_change_requests(ListChangeRequestsRequest {
            agent: identity,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
            state: state_filter,
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(
        serde_json::to_value(&result).expect("serializable"),
    ))
}

/// POST /api/v1/repos/{owner}/{repo}/patches
pub async fn post_patches(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<CommitPatchBody>,
) -> impl IntoResponse {
    let (identity, _policy) =
        resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .write_service
        .commit_patch(CommitPatchRequest {
            agent: identity,
            base_branch: body.base_branch,
            commit_message: body.commit_message,
            new_branch: body.new_branch,
            patch: body.patch,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
        })
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

/// POST /api/v1/repos/{owner}/{repo}/pulls
pub async fn post_pulls(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<OpenPullBody>,
) -> impl IntoResponse {
    let (identity, _policy) =
        resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .write_service
        .open_change_request(OpenChangeRequestRequest {
            agent: identity,
            base_branch: body.base_branch,
            body: body.body,
            head_branch: body.head_branch,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
            title: body.title,
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((
        StatusCode::CREATED,
        Json(serde_json::to_value(&result.change_request).expect("serializable")),
    ))
}
