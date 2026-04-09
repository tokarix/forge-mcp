//! Axum route handlers for the REST API.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
};
use domain::{
    CloseChangeRequestRequest, CommentOnChangeRequestRequest, CommitPatchRequest, ForgeKind,
    GetChangeRequestChecksRequest, GetChangeRequestCommentsRequest, GetChangeRequestRequest,
    ListChangeRequestsRequest, OpenChangeRequestRequest, PublishableEvent,
    ReadRepositoryFileRequest, RebaseBranchRequest, RepositoryRef, ScheduleAutoMergeRequest,
    ServiceError, SubmitChangeRequestReviewRequest, UpdateChangeRequestRequest,
};

use crate::api::AgentEventsQuery;
use crate::api::{
    AddIssueDependencyBody, AddIssueLabelBody, CommentBody, CommentOnIssueBody, CommitPatchBody,
    CommitPatchResult, ContentsPath, ContentsQuery, ContentsResult, CreateIssueBody, ErrorBody,
    IssueDependencyPath, IssueLabelPath, IssuePath, ListIssuesQuery, ListPullsQuery, OpenPullBody,
    PullPath, RebaseBranchBody, RebaseBranchResult, RebaseOperationBody, RepoPath,
    ScheduleAutoMergeBody, SubmitReviewBody, UpdateChangeRequestBody, UpdateIssueBody,
};
use crate::auth::{AgentRegistry, extract_bearer_token};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub agent_registry: AgentRegistry,
    pub audit_sink: Arc<dyn audit::AuditSink>,
    pub auto_merge_service: Arc<crate::auto_merge::AutoMergeService>,
    pub event_bus: crate::events::EventBus,
    pub forge_registry: Arc<crate::registry::ForgeRegistry>,
}

#[derive(Debug, serde::Deserialize)]
pub struct WebhookPath {
    pub forge: String,
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

fn resolve_authenticated_agent<'a>(
    headers: &HeaderMap,
    registry: &'a AgentRegistry,
) -> Result<&'a crate::auth::ResolvedAgent, (StatusCode, Json<ErrorBody>)> {
    let token = extract_bearer_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing or invalid Authorization header".to_string(),
            }),
        )
    })?;

    registry.resolve(token).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid bearer token".to_string(),
            }),
        )
    })
}

/// Serializes a value to a `serde_json::Value`, mapping errors to 500.
fn to_json_value<T: serde::Serialize>(
    value: &T,
) -> Result<serde_json::Value, (StatusCode, Json<ErrorBody>)> {
    serde_json::to_value(value).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("serialization failed: {e}"),
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
fn resolve_agent<'a>(
    headers: &HeaderMap,
    registry: &'a AgentRegistry,
    forge_alias: &str,
    owner: &str,
    repo: &str,
) -> Result<&'a crate::auth::ResolvedAgent, (StatusCode, Json<ErrorBody>)> {
    let agent = resolve_authenticated_agent(headers, registry)?;

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

    Ok(agent)
}

/// Resolves the effective forge credential for an agent + forge combination.
///
/// Prefers the agent's per-forge identity token, falls back to the forge's
/// configured token.
fn resolve_credential(
    agent: &crate::auth::ResolvedAgent,
    forge_alias: &str,
    forge: &crate::registry::ForgeInstance,
) -> domain::ForgeCredential {
    let token = agent
        .forge_identities
        .get(forge_alias)
        .map(|id| id.token.clone())
        .or_else(|| forge.token.clone());
    domain::ForgeCredential { token }
}

fn resolve_commit_author(
    agent: &crate::auth::ResolvedAgent,
    body: &CommitPatchBody,
) -> Result<domain::CommitAuthor, ServiceError> {
    match (&body.author_name, &body.author_email) {
        (Some(name), Some(email)) => {
            let name = name.trim();
            let email = email.trim();
            if name.is_empty() || email.is_empty() {
                return Err(ServiceError::Validation(
                    "author_name and author_email must be non-empty when provided".to_string(),
                ));
            }
            Ok(domain::CommitAuthor {
                email: email.to_string(),
                name: name.to_string(),
            })
        }
        (None, None) => Ok(domain::CommitAuthor {
            email: format!("{}@forge-mcp", agent.identity.agent_id),
            name: agent.identity.agent_id.clone(),
        }),
        _ => Err(ServiceError::Validation(
            "author_name and author_email must be provided together".to_string(),
        )),
    }
}

fn repo_ref(
    forge_alias: &str,
    owner: &str,
    repo: &str,
    forge: &crate::registry::ForgeInstance,
) -> RepositoryRef {
    RepositoryRef {
        alias: forge_alias.to_string(),
        forge: forge.forge_kind.clone(),
        host: forge.base_url.clone(),
        name: repo.to_string(),
        owner: owner.to_string(),
    }
}

fn map_webhook_error(err: &forge::ForgeWebhookError) -> (StatusCode, Json<ErrorBody>) {
    let status = match err {
        forge::ForgeWebhookError::InvalidSignature | forge::ForgeWebhookError::MissingHeader(_) => {
            StatusCode::UNAUTHORIZED
        }
        forge::ForgeWebhookError::InvalidPayload(_) => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(ErrorBody {
            error: err.to_string(),
        }),
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/agent/events",
    params(
        ("subscriber_id" = Option<String>, Query, description = "Stable subscriber identifier for reconnects"),
    ),
    responses(
        (status = 200, description = "Server-sent events for normalized channel notifications"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/agent/events
pub async fn agent_events(
    State(state): State<AppState>,
    Query(query): Query<AgentEventsQuery>,
    headers: HeaderMap,
) -> Result<
    Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>>,
    (StatusCode, Json<ErrorBody>),
> {
    let agent = resolve_authenticated_agent(&headers, &state.agent_registry)?;
    let subscriber_id = query
        .subscriber_id
        .unwrap_or_else(|| format!("{}-{}", agent.identity.agent_id, agent.identity.session_id));
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);

    let receiver = state.event_bus.subscribe(
        agent.identity.agent_id.clone(),
        agent.policy_config.clone(),
        subscriber_id,
        last_event_id.as_deref(),
    );
    let stream = ReceiverStream::new(receiver).map(|queued| {
        Ok::<Event, std::convert::Infallible>(
            Event::default()
                .event(queued.event_name)
                .id(queued.id)
                .data(queued.data),
        )
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

/// POST /api/v1/forges/{forge}/webhook
pub async fn post_webhook(
    State(state): State<AppState>,
    Path(path): Path<WebhookPath>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let webhook = forge.webhook.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: format!("webhooks are not configured for forge '{}'", path.forge),
            }),
        )
    })?;
    let normalized_headers: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();

    let event = forge
        .webhook_adapter
        .verify_and_parse_webhook_event(
            &normalized_headers,
            body.as_ref(),
            &forge.alias,
            forge.forge_kind.clone(),
            &forge.base_url,
            &webhook.secret,
        )
        .map_err(|error| map_webhook_error(&error))?;

    if let Some(event) = event {
        let channel_event = match &event {
            domain::WebhookEvent::ChangeRequest(e) => e.to_channel_event(),
            domain::WebhookEvent::Issue(e) => e.to_channel_event(),
            domain::WebhookEvent::IssueComment(e) => e.to_channel_event(),
            domain::WebhookEvent::PullRequestReview(e) => e.to_channel_event(),
        };

        let publish_result = match &event {
            domain::WebhookEvent::ChangeRequest(e) => state.event_bus.publish(e),
            domain::WebhookEvent::Issue(e) => state.event_bus.publish(e),
            domain::WebhookEvent::IssueComment(e) => state.event_bus.publish(e),
            domain::WebhookEvent::PullRequestReview(e) => state.event_bus.publish(e),
        };
        let status = publish_result
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody { error })))?;

        tracing::info!(
            forge = %path.forge,
            event_kind = %channel_event.meta.event_kind,
            action = %channel_event.meta.action,
            owner = %channel_event.meta.owner,
            repo = %channel_event.meta.repo,
            delivery_id = %channel_event.meta.delivery_id,
            status = ?status,
            "webhook accepted",
        );

        if let domain::WebhookEvent::PullRequestReview(ref review) = event
            && matches!(status, crate::events::PublishStatus::Enqueued { .. })
            && review.review_state == domain::ReviewState::Approved
        {
            let service = state.auto_merge_service.clone();
            let review = review.clone();
            tokio::spawn(async move {
                service.handle_review(review).await;
            });
        }
    }

    Ok::<_, (StatusCode, Json<ErrorBody>)>(StatusCode::ACCEPTED)
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
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .read_repository_file(ReadRepositoryFileRequest {
            agent: agent.identity.clone(),
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
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/diff",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "Unified diff for the change request"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/diff
pub async fn get_pull_diff(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_change_request_diff(domain::GetChangeRequestDiffRequest {
            agent: agent.identity.clone(),
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
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
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_change_request(GetChangeRequestRequest {
            agent: agent.identity.clone(),
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/checks",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "Combined CI/check status for the PR head"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/checks
pub async fn get_pull_checks(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_change_request_checks(GetChangeRequestChecksRequest {
            agent: agent.identity.clone(),
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
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
    let agent = resolve_agent(
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
            agent: agent.identity.clone(),
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            state: state_filter,
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
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
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let identity = agent.identity.clone();
    let policy = agent.policy.clone();
    let commit_author = resolve_commit_author(agent, &body).map_err(map_service_error)?;

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
                commit_author,
                commit_message: body.commit_message,
                existing_branch: body.existing_branch,
                new_branch: body.new_branch,
                patch: body.patch,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
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
    path = "/api/v1/repos/{forge}/{owner}/{repo}/rebase",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = RebaseBranchBody,
    responses(
        (status = 200, description = "Branch rebased", body = RebaseBranchResult),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/rebase
pub async fn post_rebase(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<RebaseBranchBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let identity = agent.identity.clone();
    let policy = agent.policy.clone();

    // Per-agent branch prefix check
    let policy_context = domain::policy::PolicyContext {
        action: "rebase_branch".to_string(),
        agent: identity.clone(),
        repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        target_branch: body.branch.clone(),
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

    let operations: Vec<domain::RebaseOperation> = body
        .operations
        .into_iter()
        .map(|op| match op {
            RebaseOperationBody::Drop { commit } => domain::RebaseOperation::Drop { commit },
            RebaseOperationBody::Fixup { commit, into } => {
                domain::RebaseOperation::Fixup { commit, into }
            }
            RebaseOperationBody::RebaseOnto {} => domain::RebaseOperation::RebaseOnto,
        })
        .collect();

    let result = forge
        .write_service
        .rebase_branch(
            RebaseBranchRequest {
                agent: identity,
                base_branch: body.base_branch,
                branch: body.branch,
                operations,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(RebaseBranchResult {
        branch: result.branch,
        commit_sha: result.commit_sha,
    }))
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
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let identity = agent.identity.clone();
    let policy = agent.policy.clone();

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
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((
        StatusCode::CREATED,
        Json(to_json_value(&result.change_request)?),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "Change request closed"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// DELETE /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}
pub async fn close_pull(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);

    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .close_change_request(
            CloseChangeRequestRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    request_body = UpdateChangeRequestBody,
    responses(
        (status = 200, description = "Change request updated"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// PATCH /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}
pub async fn update_pull(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
    Json(body): Json<UpdateChangeRequestBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);

    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .update_change_request(
            UpdateChangeRequestRequest {
                agent: agent.identity.clone(),
                body: body.body,
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                title: body.title,
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/comments",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    request_body = CommentBody,
    responses(
        (status = 201, description = "Comment created"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/comments
pub async fn comment_on_pull(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
    Json(body): Json<CommentBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);

    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .comment_on_change_request(
            CommentOnChangeRequestRequest {
                agent: agent.identity.clone(),
                body: body.body,
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((StatusCode::CREATED, Json(to_json_value(&result)?)))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/comments",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "List of comments and reviews"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/comments
pub async fn get_pull_comments(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_change_request_comments(GetChangeRequestCommentsRequest {
            agent: agent.identity.clone(),
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    request_body = ScheduleAutoMergeBody,
    responses(
        (status = 200, description = "Auto-merge scheduled"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge
pub async fn schedule_auto_merge(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
    Json(body): Json<ScheduleAutoMergeBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);

    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    forge
        .write_service
        .schedule_auto_merge(
            ScheduleAutoMergeRequest {
                agent: agent.identity.clone(),
                delete_branch_after_merge: body.delete_branch_after_merge,
                expected_head_sha: body.expected_head_sha,
                index: path.index,
                merge_style: body.merge_style,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::json!({})))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/reviews",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    request_body = SubmitReviewBody,
    responses(
        (status = 201, description = "Review submitted"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/reviews
pub async fn submit_pull_review(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
    Json(body): Json<SubmitReviewBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);

    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .submit_change_request_review(
            SubmitChangeRequestReviewRequest {
                agent: agent.identity.clone(),
                body: body.body,
                event: body.event,
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((StatusCode::CREATED, Json(to_json_value(&result)?)))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("state" = Option<String>, Query, description = "Optional state filter: open, closed"),
    ),
    responses(
        (status = 200, description = "List of issues"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/issues
pub async fn list_issues(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    Query(query): Query<ListIssuesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .list_issues(domain::ListIssuesRequest {
            agent: agent.identity.clone(),
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            state: query.state,
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
    ),
    responses(
        (status = 200, description = "Issue details"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}
pub async fn get_issue(
    State(state): State<AppState>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_issue(domain::GetIssueRequest {
            agent: agent.identity.clone(),
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/comments",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
    ),
    responses(
        (status = 200, description = "List of comments"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/comments
pub async fn get_issue_comments(
    State(state): State<AppState>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_issue_comments(domain::GetIssueCommentsRequest {
            agent: agent.identity.clone(),
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
    ),
    responses(
        (status = 200, description = "Issue dependencies"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies
pub async fn get_issue_dependencies(
    State(state): State<AppState>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let result = forge
        .read_service
        .get_issue_dependencies(domain::GetIssueDependenciesRequest {
            agent: agent.identity.clone(),
            index: path.index,
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = CreateIssueBody,
    responses(
        (status = 201, description = "Issue created"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/issues
pub async fn create_issue(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<CreateIssueBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .create_issue(
            domain::CreateIssueRequest {
                agent: agent.identity.clone(),
                body: body.body,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                title: body.title,
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((StatusCode::CREATED, Json(to_json_value(&result)?)))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/comments",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
    ),
    request_body = CommentOnIssueBody,
    responses(
        (status = 200, description = "Comment created"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/comments
pub async fn comment_on_issue(
    State(state): State<AppState>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    Json(body): Json<CommentOnIssueBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .comment_on_issue(
            domain::CommentOnIssueRequest {
                agent: agent.identity.clone(),
                body: body.body,
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
    ),
    request_body = UpdateIssueBody,
    responses(
        (status = 200, description = "Issue updated"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// PATCH /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}
pub async fn update_issue(
    State(state): State<AppState>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    Json(body): Json<UpdateIssueBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let repo = repo_ref(&path.forge, &path.owner, &path.repo, forge);

    // Handle close
    if body.state.as_deref() == Some("closed") {
        let result = forge
            .write_service
            .close_issue(
                domain::CloseIssueRequest {
                    agent: agent.identity.clone(),
                    index: path.index,
                    repository: repo,
                },
                authorized,
                &credential,
            )
            .await
            .map_err(map_service_error)?;

        return Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?));
    }

    // Handle assign
    if let Some(assignee) = body.assignees.as_ref().and_then(|a| a.first()) {
        let result = forge
            .write_service
            .assign_issue(
                domain::AssignIssueRequest {
                    agent: agent.identity.clone(),
                    assignee: assignee.clone(),
                    index: path.index,
                    repository: repo,
                },
                authorized,
                &credential,
            )
            .await
            .map_err(map_service_error)?;

        return Ok(Json(to_json_value(&result)?));
    }

    // Handle title/body update
    if body.title.is_some() || body.body.is_some() {
        let result = forge
            .write_service
            .update_issue(
                domain::UpdateIssueRequest {
                    agent: agent.identity.clone(),
                    body: body.body,
                    index: path.index,
                    repository: repo,
                    title: body.title,
                },
                authorized,
                &credential,
            )
            .await
            .map_err(map_service_error)?;

        return Ok(Json(to_json_value(&result)?));
    }

    Err((
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: "update_issue requires state, assignees, or title/body".to_string(),
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
    ),
    request_body = AddIssueDependencyBody,
    responses(
        (status = 200, description = "Dependency added"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies
pub async fn add_issue_dependency(
    State(state): State<AppState>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    Json(body): Json<AddIssueDependencyBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .add_issue_dependency(
            domain::AddIssueDependencyRequest {
                agent: agent.identity.clone(),
                dependency: body.dependency,
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/labels",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
    ),
    request_body = AddIssueLabelBody,
    responses(
        (status = 200, description = "Label added"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// POST /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/labels
pub async fn add_issue_label(
    State(state): State<AppState>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    Json(body): Json<AddIssueLabelBody>,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .add_issue_label(
            domain::AddIssueLabelRequest {
                agent: agent.identity.clone(),
                index: path.index,
                label: body.label,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    delete,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies/{dependency}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
        ("dependency" = u64, Path, description = "Dependency issue index"),
    ),
    responses(
        (status = 200, description = "Dependency removed"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// DELETE /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies/{dependency}
pub async fn remove_issue_dependency(
    State(state): State<AppState>,
    Path(path): Path<IssueDependencyPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .remove_issue_dependency(
            domain::RemoveIssueDependencyRequest {
                agent: agent.identity.clone(),
                dependency: path.dependency,
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    delete,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/labels/{label}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Issue index"),
        ("label" = String, Path, description = "Label name"),
    ),
    responses(
        (status = 200, description = "Label removed"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// DELETE /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/labels/{label}
pub async fn remove_issue_label(
    State(state): State<AppState>,
    Path(path): Path<IssueLabelPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let credential = resolve_credential(agent, &path.forge, forge);
    let authorized = domain::policy::AuthorizedWrite {
        policy: agent.policy.clone(),
    };

    let result = forge
        .write_service
        .remove_issue_label(
            domain::RemoveIssueLabelRequest {
                agent: agent.identity.clone(),
                index: path.index,
                label: path.label,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            authorized,
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
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
            let credential = resolve_credential(agent, alias, instance);
            let username = instance
                .adapter
                .get_authenticated_user(&credential)
                .await
                .ok()
                .map(|u| u.username);
            forges.push(crate::api::AgentForgeInfo {
                alias: alias.clone(),
                forge_type: instance.forge_type.clone(),
                username,
            });
        }
    }
    forges.sort_by(|a, b| a.alias.cmp(&b.alias));

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(crate::api::AgentInfoResult {
        agent_id: agent.identity.agent_id.clone(),
        branch_prefix: agent.policy.branch_prefix.clone(),
        forges,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::todo, clippy::unimplemented)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use domain::{
        ChangeRequest, ChangeRequestCommentDetail, ChangeRequestState, CommitPatchResponse,
        GetChangeRequestCommentsRequest, GetChangeRequestRequest, ListChangeRequestsRequest,
        OpenChangeRequestResponse, ReadRepositoryFileResponse, ServiceError,
    };
    use tower::ServiceExt;

    use crate::auth::AgentRegistry;
    use crate::config::AgentPolicyConfig;

    use super::*;

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
        ) -> Result<domain::Issue, ServiceError> {
            todo!()
        }
        async fn get_issue_comments(
            &self,
            _: domain::GetIssueCommentsRequest,
        ) -> Result<Vec<domain::IssueComment>, ServiceError> {
            todo!()
        }
        async fn get_issue_dependencies(
            &self,
            _: domain::GetIssueDependenciesRequest,
        ) -> Result<domain::IssueDependencies, ServiceError> {
            todo!()
        }
        async fn list_issues(
            &self,
            _: domain::ListIssuesRequest,
        ) -> Result<Vec<domain::Issue>, ServiceError> {
            todo!()
        }

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

        async fn get_change_request_comments(
            &self,
            _request: GetChangeRequestCommentsRequest,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ServiceError> {
            Ok(vec![
                ChangeRequestCommentDetail {
                    author: "reviewer".to_string(),
                    body: "looks good".to_string(),
                    commit_id: None,
                    created_at: "2026-03-18T10:00:00Z".to_string(),
                    id: 1,
                    kind: "comment".to_string(),
                    review_state: None,
                },
                ChangeRequestCommentDetail {
                    author: "reviewer".to_string(),
                    body: "approved".to_string(),
                    commit_id: Some("abc123".to_string()),
                    created_at: "2026-03-18T11:00:00Z".to_string(),
                    id: 2,
                    kind: "review".to_string(),
                    review_state: Some("APPROVED".to_string()),
                },
            ])
        }

        async fn get_change_request_checks(
            &self,
            _request: domain::GetChangeRequestChecksRequest,
        ) -> Result<domain::CombinedCommitStatus, ServiceError> {
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
        ) -> Result<domain::Issue, ServiceError> {
            todo!()
        }
        async fn add_issue_label(
            &self,
            request: domain::AddIssueLabelRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index: request.index,
                labels: vec![request.label],
                state: "open".to_string(),
                title: "Issue".to_string(),
                url: "https://example.com/issues/1".to_string(),
            })
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
            request: CloseChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ServiceError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                index: request.index,
                merge_base_sha: None,
                state: ChangeRequestState::Closed,
                title: "Fix".to_string(),
                url: "https://example.com/pulls/1".to_string(),
            })
        }

        async fn comment_on_change_request(
            &self,
            request: domain::CommentOnChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ServiceError> {
            Ok(domain::ChangeRequestComment {
                body: request.body,
                id: 1,
                index: request.index,
            })
        }

        async fn commit_patch(
            &self,
            request: CommitPatchRequest,
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
            request: domain::CreateIssueRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: request.body,
                index: 1,
                labels: vec![],
                state: "open".to_string(),
                title: request.title,
                url: "https://example.com/issues/1".to_string(),
            })
        }

        async fn open_change_request(
            &self,
            request: OpenChangeRequestRequest,
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
        ) -> Result<domain::Issue, ServiceError> {
            todo!()
        }
        async fn remove_issue_label(
            &self,
            request: domain::RemoveIssueLabelRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index: request.index,
                labels: vec![],
                state: "open".to_string(),
                title: "Issue".to_string(),
                url: "https://example.com/issues/1".to_string(),
            })
        }

        async fn schedule_auto_merge(
            &self,
            _request: domain::ScheduleAutoMergeRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn submit_change_request_review(
            &self,
            request: domain::SubmitChangeRequestReviewRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ServiceError> {
            Ok(domain::ChangeRequestReview {
                body: request.body,
                event: request.event,
                id: 1,
                index: request.index,
            })
        }

        async fn update_change_request(
            &self,
            request: domain::UpdateChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ServiceError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: request.body.unwrap_or_default(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                index: request.index,
                merge_base_sha: None,
                state: ChangeRequestState::Open,
                title: request.title.unwrap_or_else(|| "Fix".to_string()),
                url: "https://example.com/pulls/1".to_string(),
            })
        }

        async fn update_issue(
            &self,
            request: domain::UpdateIssueRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: request.body.unwrap_or_default(),
                index: request.index,
                labels: vec![],
                state: "open".to_string(),
                title: request.title.unwrap_or_else(|| "Issue".to_string()),
                url: "https://example.com/issues/1".to_string(),
            })
        }
    }

    fn test_agent() -> crate::auth::ResolvedAgent {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/repo".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        AgentRegistry::from_configs(&configs)
            .resolve("test-token")
            .expect("test agent should resolve")
            .clone()
    }

    fn test_forge_instance(alias: &str, base_url: &str) -> crate::registry::ForgeInstance {
        crate::registry::ForgeInstance {
            adapter: Arc::new(FakeForgeAdapter),
            alias: alias.to_string(),
            base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            forge_kind: ForgeKind::Forgejo,
            forge_type: "forgejo".to_string(),
            git_auth_user: String::new(),
            read_service: Arc::new(FakeReadService),
            token: None,
            webhook: None,
            webhook_adapter: Arc::new(FakeForgeAdapter),
            write_service: Arc::new(FakeWriteService),
        }
    }

    fn test_auto_merge_service() -> Arc<crate::auto_merge::AutoMergeService> {
        Arc::new(crate::auto_merge::AutoMergeService::new(
            crate::events::EventBus::new(),
            Arc::new(crate::registry::ForgeRegistry::new(
                std::collections::HashMap::new(),
            )),
        ))
    }

    fn test_state() -> AppState {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
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
            test_forge_instance("test-forge", "https://forge.example"),
        );

        AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            auto_merge_service: test_auto_merge_service(),
            event_bus: crate::events::EventBus::new(),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        }
    }

    #[test]
    fn resolve_commit_author_defaults_to_agent_identity() {
        let agent = test_agent();
        let body = CommitPatchBody {
            author_email: None,
            author_name: None,
            base_branch: "main".to_string(),
            commit_message: "fix".to_string(),
            existing_branch: false,
            new_branch: "agent/codex/fix".to_string(),
            patch: "diff --git a/README.md b/README.md\n".to_string(),
        };

        let author = resolve_commit_author(&agent, &body).expect("author should resolve");
        assert_eq!(
            author,
            domain::CommitAuthor {
                email: "codex@forge-mcp".to_string(),
                name: "codex".to_string(),
            }
        );
    }

    #[test]
    fn resolve_commit_author_rejects_partial_author() {
        let agent = test_agent();
        let body = CommitPatchBody {
            author_email: Some("codex@example.com".to_string()),
            author_name: None,
            base_branch: "main".to_string(),
            commit_message: "fix".to_string(),
            existing_branch: false,
            new_branch: "agent/codex/fix".to_string(),
            patch: "diff --git a/README.md b/README.md\n".to_string(),
        };

        let err = resolve_commit_author(&agent, &body).expect_err("partial author should fail");
        assert!(
            matches!(
                err,
                ServiceError::Validation(ref message)
                    if message == "author_name and author_email must be provided together"
            ),
            "unexpected error: {err:#?}",
        );
    }

    #[test]
    fn resolve_commit_author_rejects_blank_values() {
        let agent = test_agent();
        let body = CommitPatchBody {
            author_email: Some("   ".to_string()),
            author_name: Some("Codex".to_string()),
            base_branch: "main".to_string(),
            commit_message: "fix".to_string(),
            existing_branch: false,
            new_branch: "agent/codex/fix".to_string(),
            patch: "diff --git a/README.md b/README.md\n".to_string(),
        };

        let err = resolve_commit_author(&agent, &body).expect_err("blank author should fail");
        assert!(
            matches!(
                err,
                ServiceError::Validation(ref message)
                    if message == "author_name and author_email must be non-empty when provided"
            ),
            "unexpected error: {err:#?}",
        );
    }

    #[tokio::test]
    async fn docs_route_absent_when_disabled() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/docs")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");
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
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert_eq!(json["content"], "file-content");
        assert_eq!(json["path"], "README.md");
    }

    #[tokio::test]
    async fn create_issue_returns_201() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/issues")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"title": "Bug report", "body": "Something is broken"})
                            .to_string(),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert_eq!(json["title"], "Bug report");
        assert_eq!(json["body"], "Something is broken");
        assert_eq!(json["state"], "open");
    }

    #[tokio::test]
    async fn returns_401_without_token() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/contents/README.md")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn returns_403_for_unauthorized_repo() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
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
            test_forge_instance("test-forge", "https://forge.example"),
        );

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            auto_merge_service: test_auto_merge_service(),
            event_bus: crate::events::EventBus::new(),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        };
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/secret-repo/contents/README.md")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

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
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

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
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
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
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
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
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
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
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert_eq!(json["index"], 1);
    }

    #[tokio::test]
    async fn post_patches_rejects_wrong_branch_per_agent_policy() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
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
            test_forge_instance("test-forge", "https://forge.example"),
        );

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            auto_merge_service: test_auto_merge_service(),
            event_bus: crate::events::EventBus::new(),
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
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert!(
            json["error"]
                .as_str()
                .expect("error field should be a string")
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
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");
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
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert_eq!(json["agent_id"], "codex");
        assert_eq!(json["branch_prefix"], "agent/");
        let forges = json["forges"]
            .as_array()
            .expect("forges should be an array");
        assert_eq!(forges.len(), 1);
        assert_eq!(forges[0]["alias"], "test-forge");
        assert_eq!(forges[0]["type"], "forgejo");
        assert_eq!(forges[0]["username"], "test");
    }

    #[tokio::test]
    async fn agent_info_returns_401_without_token() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agent/info")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_info_filters_inaccessible_forges() {
        // Agent only has access to "test-forge/org/allowed-repo", not "other-forge"
        let configs = vec![crate::config::AgentConfig {
            agent_id: "restricted".to_string(),
            forge_identity: std::collections::HashMap::new(),
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
            test_forge_instance("test-forge", "https://forge.example"),
        );
        forges.insert(
            "other-forge".to_string(),
            test_forge_instance("other-forge", "https://other.example"),
        );

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            auto_merge_service: test_auto_merge_service(),
            event_bus: crate::events::EventBus::new(),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        };

        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agent/info")
                    .header("authorization", "Bearer restricted-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        let forges = json["forges"]
            .as_array()
            .expect("forges should be an array");
        // Only test-forge should be visible, not other-forge
        assert_eq!(forges.len(), 1);
        assert_eq!(forges[0]["alias"], "test-forge");
        assert_eq!(forges[0]["username"], "test");
    }

    #[tokio::test]
    async fn agent_info_records_audit() {
        let audit_sink = Arc::new(audit::InMemoryAuditSink::new());
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
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
            auto_merge_service: test_auto_merge_service(),
            event_bus: crate::events::EventBus::new(),
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
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        let records = audit_sink.records().expect("should have audit records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "agent_info");
        assert_eq!(records[0].target, "self");
    }

    #[tokio::test]
    async fn agent_info_omits_branch_prefix_when_none() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "noprefix".to_string(),
            forge_identity: std::collections::HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["*".to_string()],
                branch_prefix: None,
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "noprefix-token".to_string(),
        }];

        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            auto_merge_service: test_auto_merge_service(),
            event_bus: crate::events::EventBus::new(),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(
                std::collections::HashMap::new(),
            )),
        };

        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agent/info")
                    .header("authorization", "Bearer noprefix-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert_eq!(json["agent_id"], "noprefix");
        assert!(json.get("branch_prefix").is_none());
    }

    #[tokio::test]
    async fn get_pull_comments_returns_comments() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/pulls/1/comments")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        let arr = json.as_array().expect("should be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["author"], "reviewer");
        assert_eq!(arr[0]["body"], "looks good");
        assert!(arr[0].get("dismissed").is_none());
        assert!(arr[0]["commit_id"].is_null());
        assert_eq!(arr[0]["kind"], "comment");
        assert!(arr[0]["review_state"].is_null());
        assert_eq!(arr[1]["body"], "approved");
        assert_eq!(arr[1]["commit_id"], "abc123");
        assert!(arr[1].get("dismissed").is_none());
        assert_eq!(arr[1]["kind"], "review");
        assert_eq!(arr[1]["review_state"], "APPROVED");
    }

    #[tokio::test]
    async fn patch_pull_returns_updated_pr() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({
            "title": "Updated title"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/repos/test-forge/org/repo/pulls/1")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert_eq!(json["index"], 1);
        assert_eq!(json["title"], "Updated title");
    }

    #[tokio::test]
    async fn patch_issue_returns_updated_issue() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({
            "title": "Updated issue title"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert_eq!(json["index"], 1);
        assert_eq!(json["title"], "Updated issue title");
    }

    #[tokio::test]
    async fn patch_issue_rejects_empty_body() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({});
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
