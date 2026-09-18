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
    ReadRepositoryFileRequest, RebaseBranchRequest, Repository, RepositoryRef,
    ScheduleAutoMergeRequest, ServiceError, SubmitChangeRequestReviewRequest,
    UpdateChangeRequestRequest,
};

use crate::api::AgentEventsQuery;
use crate::api::{
    AddIssueDependencyBody, AddIssueLabelBody, BranchDetailsResult, BranchItem,
    ChangeRequestCiDetailsResult, CiCheckDetailResult, CiFailureStepResult, CiLogExcerptResult,
    CiProviderResult, CiResolutionResult, CommentBody, CommentOnIssueBody, CommitPatchBody,
    CommitPatchResult, ContentsPath, ContentsQuery, ContentsResult, CreateIssueBody, ErrorBody,
    ForgePath, GetBranchQuery, IssueDependencyPath, IssueLabelPath, IssuePath, ListBranchesQuery,
    ListBranchesResponse as ApiListBranchesResponse, ListIssuesQuery, ListPullsQuery,
    ListRepositoriesQuery, OpenPullBody, PullPath, RebaseBranchBody, RebaseBranchResult,
    RebaseOperationBody, RemoveIssueDependencyQuery, RepoPath, ScheduleAutoMergeBody,
    SubmitReviewBody, UpdateChangeRequestBody, UpdateIssueBody,
};
use crate::auth::{AgentRegistry, extract_bearer_token};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{Instrument, instrument::WithSubscriber};

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
        tracing::warn!(reason = "unknown_forge", "forge resolution failed");
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
        tracing::warn!(reason = "missing_authorization", "authentication failed");
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing or invalid Authorization header".to_string(),
            }),
        )
    })?;

    let agent = registry.resolve(token).ok_or_else(|| {
        tracing::warn!(reason = "invalid_token", "authentication failed");
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid bearer token".to_string(),
            }),
        )
    })?;
    crate::diagnostics::record_agent(&agent.identity);
    Ok(agent)
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
    let error_kind = match &err {
        ServiceError::Audit(_) => "audit",
        ServiceError::GitExec(_) => "git_exec",
        ServiceError::PolicyDenied { .. } => "policy_denied",
        ServiceError::Validation(_) => "validation",
        ServiceError::Upstream(_) => "upstream",
    };
    tracing::warn!(error_kind, "repository operation failed");
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
        tracing::warn!(reason = "repository_denied", "authorization failed");
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
/// Prefers the agent's managed GitHub App installation, then its per-forge
/// identity token, and finally the forge's configured credential.
pub(crate) fn resolve_credential(
    agent: &crate::auth::ResolvedAgent,
    forge_alias: &str,
    forge: &crate::registry::ForgeInstance,
) -> domain::ForgeCredential {
    if let Some(credential) = agent.github_app_credentials.get(forge_alias) {
        tracing::Span::current().record(
            "upstream_username",
            crate::diagnostics::bounded(&credential.username()),
        );
        record_credential_source("agent_github_app");
        return forge.adapter.effective_credential(&credential.credential());
    }
    let token = agent
        .forge_identities
        .get(forge_alias)
        .map(|id| id.token.clone())
        .or_else(|| forge.token.clone());
    let credential = forge
        .adapter
        .effective_credential(&domain::ForgeCredential { token });
    let source = if agent.forge_identities.contains_key(forge_alias) {
        "agent_forge_identity"
    } else if credential.token.is_some() {
        "forge_default"
    } else {
        "none"
    };
    record_credential_source(source);
    credential
}

pub(crate) fn record_credential_source(source: &'static str) {
    tracing::Span::current().record("credential_source", source);
    // Transport usernames (e.g. x-access-token) are not upstream identities.
    tracing::debug!(credential_source = source, "upstream credential selected");
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
            domain::WebhookEvent::BranchPush(e) => e.to_channel_event(),
            domain::WebhookEvent::CiChange(e) => e.to_channel_event(),
            domain::WebhookEvent::PullRequestReviewComment(e) => e.to_channel_event(),
            domain::WebhookEvent::PullRequestReviewThread(e) => e.to_channel_event(),

            domain::WebhookEvent::ChangeRequest(e) => e.to_channel_event(),
            domain::WebhookEvent::Issue(e) => e.to_channel_event(),
            domain::WebhookEvent::IssueComment(e) => e.to_channel_event(),
            domain::WebhookEvent::PullRequestReview(e) => e.to_channel_event(),
        };

        let publish_result = match &event {
            domain::WebhookEvent::BranchPush(e) => state.event_bus.publish(e),
            domain::WebhookEvent::CiChange(e) => state.event_bus.publish(e),
            domain::WebhookEvent::PullRequestReviewComment(e) => state.event_bus.publish(e),
            domain::WebhookEvent::PullRequestReviewThread(e) => state.event_bus.publish(e),

            domain::WebhookEvent::ChangeRequest(e) => state.event_bus.publish(e),
            domain::WebhookEvent::Issue(e) => state.event_bus.publish(e),
            domain::WebhookEvent::IssueComment(e) => state.event_bus.publish(e),
            domain::WebhookEvent::PullRequestReview(e) => state.event_bus.publish(e),
        };
        let status = publish_result
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody { error })))?;

        tracing::info!(
            forge = %crate::diagnostics::bounded(&path.forge),
            event_kind = %channel_event.meta.event_kind,
            action = %channel_event.meta.action,
            owner = %crate::diagnostics::bounded(&channel_event.meta.owner),
            repo = %crate::diagnostics::bounded(&channel_event.meta.repo),
            delivery_id = %crate::diagnostics::bounded(&channel_event.meta.delivery_id),
            status = ?status,
            "webhook accepted",
        );

        if let domain::WebhookEvent::PullRequestReview(review) = event {
            spawn_review_auto_merge(
                review,
                &status,
                webhook.auto_merge,
                &state.auto_merge_service,
            );
        }
    }

    Ok::<_, (StatusCode, Json<ErrorBody>)>(StatusCode::ACCEPTED)
}

/// Return the task so callers can observe completion; HTTP delivery detaches it.
fn spawn_review_auto_merge(
    review: domain::PullRequestReviewEvent,
    status: &crate::events::PublishStatus,
    enabled: bool,
    service: &Arc<crate::auto_merge::AutoMergeService>,
) -> Option<tokio::task::JoinHandle<()>> {
    let skip_reason = if !enabled {
        Some("auto_merge_disabled")
    } else if !matches!(status, crate::events::PublishStatus::Enqueued { .. }) {
        Some("duplicate_delivery")
    } else if review.action != domain::PullRequestReviewEventAction::Submitted {
        Some("review_not_submitted")
    } else if review.review_state != Some(domain::ReviewState::Approved) {
        Some("review_not_approved")
    } else {
        None
    };
    if let Some(reason) = skip_reason {
        tracing::debug!(reason, target = review.index,
            delivery_id = %crate::diagnostics::bounded(&review.delivery_id),
            "auto-merge: skipping review");
        None
    } else {
        let service = Arc::clone(service);
        Some(tokio::spawn(
            async move { service.handle_review(review).await }
                .in_current_span()
                .with_current_subscriber(),
        ))
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
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .read_repository_file(
            ReadRepositoryFileRequest {
                agent: agent.identity.clone(),
                git_ref: query.git_ref.clone(),
                path: path.path.clone(),
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .get_change_request_diff(
            domain::GetChangeRequestDiffRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
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
        (status = 200, description = "Change request details", body = domain::ChangeRequest),
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .get_change_request(
            GetChangeRequestRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .get_change_request_checks(
            GetChangeRequestChecksRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/ci-details",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "Detailed CI/check status for the PR head", body = ChangeRequestCiDetailsResult),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/ci-details
pub async fn get_pull_ci_details(
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

    let result = forge
        .read_service
        .get_change_request_ci_details(
            domain::GetChangeRequestCiDetailsRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    let response = ChangeRequestCiDetailsResult {
        head_sha: result.head_sha,
        state: format!("{:?}", result.state).to_lowercase(),
        details: result
            .details
            .into_iter()
            .map(|d| CiCheckDetailResult {
                context: d.context,
                description: d.description,
                state: format!("{:?}", d.state).to_lowercase(),
                target_url: d.target_url,
                resolution: match d.resolution {
                    domain::CiResolution::Unsupported => CiResolutionResult::Unsupported,
                    domain::CiResolution::Error { message } => {
                        CiResolutionResult::Error { message }
                    }
                    domain::CiResolution::Resolved {
                        provider,
                        pipeline_url,
                        failed_steps,
                    } => CiResolutionResult::Resolved {
                        provider: match provider {
                            domain::CiProvider::GithubActions => CiProviderResult::GithubActions,
                            domain::CiProvider::Woodpecker => CiProviderResult::Woodpecker,
                        },
                        pipeline_url,
                        failed_steps: failed_steps
                            .into_iter()
                            .map(|s| CiFailureStepResult {
                                name: s.name,
                                state: s.state,
                                log_excerpt: s
                                    .log_excerpt
                                    .map(|l| CiLogExcerptResult { lines: l.lines }),
                            })
                            .collect(),
                    },
                },
            })
            .collect(),
    };

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(response))
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
        (status = 200, description = "List of change requests", body = Vec<domain::ChangeRequest>),
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let state_filter = query.state.as_deref().map(|s| match s {
        "closed" => domain::ChangeRequestState::Closed,
        "merged" => domain::ChangeRequestState::Merged,
        _ => domain::ChangeRequestState::Open,
    });

    let result = forge
        .read_service
        .list_change_requests(
            ListChangeRequestsRequest {
                agent: agent.identity.clone(),
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                state: state_filter,
            },
            &credential,
        )
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
            RebaseOperationBody::Reword { commit, message } => {
                domain::RebaseOperation::Reword { commit, message }
            }
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
        old_commit_sha: result.old_commit_sha,
        commit_mapping: result.commit_mapping.map(|mapping| {
            mapping
                .into_iter()
                .map(|pair| crate::api::RebaseCommitMapping {
                    old_commit_sha: pair.old_commit_sha,
                    new_commit_sha: pair.new_commit_sha,
                })
                .collect()
        }),
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .get_change_request_comments(
            GetChangeRequestCommentsRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/discussion-comments",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "General discussion comments only"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/discussion-comments
pub async fn get_pull_discussion_comments(
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

    let result = forge
        .read_service
        .get_change_request_discussion_comments(
            domain::GetChangeRequestDiscussionCommentsRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/reviews",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "Formal reviews only"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/reviews
pub async fn get_pull_reviews(
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

    let result = forge
        .read_service
        .get_change_request_reviews(
            domain::GetChangeRequestReviewsRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
}

#[utoipa::path(
    delete,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("index" = u64, Path, description = "Pull request index"),
    ),
    responses(
        (status = 200, description = "Confirmed cancellation (upstream 204), JSON {}"),
        (status = 400, description = "Unknown forge alias or malformed target", body = ErrorBody),
        (status = 401, description = "Gateway or upstream unauthorized", body = ErrorBody),
        (status = 403, description = "Repository or upstream forbidden", body = ErrorBody),
        (status = 500, description = "Audit failed before write", body = ErrorBody),
        (status = 501, description = "Backend does not support cancellation", body = ErrorBody),
        (status = 502, description = "Cancellation uncertain, including every upstream 404", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// Bodyless PR-scoped cancellation. Only Forgejo 204 confirms success;
/// even an accessible PR's 404 remains uncertain. No head precondition.
pub async fn cancel_auto_merge(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;
    let forge = state.forge_registry.get(&path.forge).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "unknown forge alias".into(),
            }),
        )
    })?;
    let credential = resolve_credential(agent, &path.forge, forge);
    forge
        .write_service
        .cancel_auto_merge(
            domain::CancelAutoMergeRequest {
                agent: agent.identity.clone(),
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                index: path.index,
            },
            domain::policy::AuthorizedWrite {
                policy: agent.policy.clone(),
            },
            &credential,
        )
        .await
        .map_err(map_cancellation_error)?;
    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(serde_json::json!({})))
}

fn map_cancellation_error(error: domain::CancelAutoMergeError) -> (StatusCode, Json<ErrorBody>) {
    use domain::CancelAutoMergeError as Error;
    let status = match error {
        Error::Unauthorized => StatusCode::UNAUTHORIZED,
        Error::Forbidden => StatusCode::FORBIDDEN,
        Error::Unsupported => StatusCode::NOT_IMPLEMENTED,
        Error::Uncertain { .. } => StatusCode::BAD_GATEWAY,
        Error::Audit => StatusCode::INTERNAL_SERVER_ERROR,
    };
    tracing::warn!(operation = "cancel_auto_merge", outcome = "failed", reason = %error);
    (
        status,
        Json(ErrorBody {
            error: error.to_string(),
        }),
    )
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

/// Fetch repositories from the forge adapter, respecting the agent's scoped access.
async fn fetch_repos(
    forge: &crate::registry::ForgeInstance,
    agent: &crate::auth::ResolvedAgent,
    credential: &domain::ForgeCredential,
    search_q: Option<&str>,
    owner: Option<&str>,
) -> Result<Vec<Repository>, (StatusCode, Json<ErrorBody>)> {
    match owner {
        Some(o) => {
            if !agent.policy_config.is_owner_accessible(&forge.alias, o) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorBody {
                        error: format!(
                            "agent '{}' is not authorized to list repositories for owner '{}'",
                            agent.identity.agent_id, o
                        ),
                    }),
                ));
            }
            Ok(forge
                .adapter
                .list_repositories(Some(o), search_q, credential)
                .await
                .map_err(|e| map_service_error(ServiceError::Upstream(e.to_string())))?)
        }
        None => {
            if let Some(owners) = agent.policy_config.listable_owners(&forge.alias) {
                let mut all_repos: Vec<Repository> = Vec::new();
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                for ow in owners {
                    if !agent.policy_config.is_owner_accessible(&forge.alias, &ow) {
                        continue;
                    }
                    let repos = forge
                        .adapter
                        .list_repositories(Some(&ow), search_q, credential)
                        .await
                        .map_err(|e| map_service_error(ServiceError::Upstream(e.to_string())))?;
                    for repo in repos {
                        if seen.insert(repo.full_name.clone()) {
                            all_repos.push(repo);
                        }
                    }
                }
                Ok(all_repos)
            } else {
                // Unscoped access — use existing behavior.
                Ok(forge
                    .adapter
                    .list_repositories(None, search_q, credential)
                    .await
                    .map_err(|e| map_service_error(ServiceError::Upstream(e.to_string())))?)
            }
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = Option<String>, Query, description = "Optional owner/namespace filter"),
        ("q" = Option<String>, Query, description = "Optional search query"),
    ),
    responses(
        (status = 200, description = "List of repositories"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// GET /api/v1/repos/{forge}
pub async fn list_repositories(
    State(state): State<AppState>,
    Path(path): Path<ForgePath>,
    Query(query): Query<ListRepositoriesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_authenticated_agent(&headers, &state.agent_registry)?;

    // Check listing authorization (supports owner-scoped wildcards).
    if !agent.policy_config.can_list_repositories(&path.forge) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: format!(
                    "agent '{}' is not authorized to list repositories on forge '{}'",
                    agent.identity.agent_id, path.forge,
                ),
            }),
        ));
    }

    // Validate owner filter against agent's allowed owners.
    if let Some(owner) = query.owner.as_deref()
        && !agent.policy_config.is_owner_accessible(&path.forge, owner)
    {
        let scope_hint = match agent.policy_config.listable_owners(&path.forge) {
            Some(ref owners) if owners.is_empty() => String::new(),
            Some(ref owners) => format!(
                " Your access is scoped to {} owner(s): {}",
                owners.len(),
                owners
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => String::new(),
        };
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: format!(
                    "agent '{}' is not authorized to list repositories for owner '{}'{}",
                    agent.identity.agent_id, owner, scope_hint,
                ),
            }),
        ));
    }

    let credential = resolve_credential(agent, &path.forge, forge);

    // Audit
    state
        .audit_sink
        .record(audit::AuditRecord {
            action: "list_repositories".to_string(),
            agent: agent.identity.clone(),
            repository: RepositoryRef {
                alias: path.forge.clone(),
                forge: forge.forge_kind.clone(),
                host: forge.base_url.clone(),
                name: String::new(),
                owner: query.owner.clone().unwrap_or_default(),
            },
            target: query.owner.as_deref().unwrap_or("*").to_string(),
        })
        .await
        .map_err(|e| map_service_error(ServiceError::Audit(e.to_string())))?;

    // When no owner filter is provided and the agent has scoped access,
    // collect results from all accessible owners.
    let result = fetch_repos(
        forge,
        agent,
        &credential,
        query.q.as_deref(),
        query.owner.as_deref(),
    )
    .await?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(to_json_value(&result)?))
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
        (status = 200, description = "Exhaustive, deduplicated issue list within the provider pagination safety envelope; exceeding a safety budget returns an error"),
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .list_issues(
            domain::ListIssuesRequest {
                agent: agent.identity.clone(),
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                state: query.state,
            },
            &credential,
        )
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .get_issue(
            domain::GetIssueRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .get_issue_comments(
            domain::GetIssueCommentsRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
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
        (status = 200, description = "Issue dependencies", body = domain::IssueDependencies),
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

    let credential = resolve_credential(agent, &path.forge, forge);

    let result = forge
        .read_service
        .get_issue_dependencies(
            domain::GetIssueDependenciesRequest {
                agent: agent.identity.clone(),
                index: path.index,
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
            },
            &credential,
        )
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
        let message = match &body.message {
            Some(m) if !m.trim().is_empty() => m.clone(),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "message is required when closing an issue".to_string(),
                    }),
                ));
            }
        };
        let result = forge
            .write_service
            .close_issue(
                domain::CloseIssueRequest {
                    agent: agent.identity.clone(),
                    index: path.index,
                    message,
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
        (status = 400, description = "Bad Request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
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
    // Validate dependency_owner/dependency_repo are both provided or both omitted
    match (&body.dependency_owner, &body.dependency_repo) {
        (Some(_), None) | (None, Some(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error:
                        "dependency_owner and dependency_repo must both be provided or both omitted"
                            .to_string(),
                }),
            ));
        }
        _ => {}
    }

    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    // Check authorization for the dependency repository if cross-repo
    let dependency_repository = match (&body.dependency_owner, &body.dependency_repo) {
        (Some(dep_owner), Some(dep_repo)) => {
            if !agent
                .policy_config
                .is_repo_allowed(&path.forge, dep_owner, dep_repo)
            {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorBody {
                        error: format!(
                            "agent '{}' is not authorized for dependency repository '{}/{}'",
                            agent.identity.agent_id, dep_owner, dep_repo
                        ),
                    }),
                ));
            }
            Some(repo_ref(&path.forge, dep_owner, dep_repo, forge))
        }
        _ => None,
    };

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
                dependency_repository,
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
        ("dependency_owner" = Option<String>, Query, description = "Override owner for cross-repo dependency"),
        ("dependency_repo" = Option<String>, Query, description = "Override repository for cross-repo dependency"),
    ),
    responses(
        (status = 200, description = "Dependency removed"),
        (status = 400, description = "Bad Request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
/// DELETE /api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/dependencies/{dependency}
pub async fn remove_issue_dependency(
    State(state): State<AppState>,
    Path(path): Path<IssueDependencyPath>,
    Query(query): Query<RemoveIssueDependencyQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Validate dependency_owner/dependency_repo are both provided or both omitted
    match (&query.dependency_owner, &query.dependency_repo) {
        (Some(_), None) | (None, Some(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error:
                        "dependency_owner and dependency_repo must both be provided or both omitted"
                            .to_string(),
                }),
            ));
        }
        _ => {}
    }

    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let agent = resolve_agent(
        &headers,
        &state.agent_registry,
        &path.forge,
        &path.owner,
        &path.repo,
    )?;

    // Check authorization for the dependency repository if cross-repo
    let dependency_repository = match (&query.dependency_owner, &query.dependency_repo) {
        (Some(dep_owner), Some(dep_repo)) => {
            if !agent
                .policy_config
                .is_repo_allowed(&path.forge, dep_owner, dep_repo)
            {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorBody {
                        error: format!(
                            "agent '{}' is not authorized for dependency repository '{}/{}'",
                            agent.identity.agent_id, dep_owner, dep_repo
                        ),
                    }),
                ));
            }
            Some(repo_ref(&path.forge, dep_owner, dep_repo, forge))
        }
        _ => None,
    };

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
                dependency_repository,
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

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/branches",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("prefix" = Option<String>, Query, description = "Optional branch name prefix filter"),
        ("limit" = Option<u32>, Query, description = "Maximum number of branches to return"),
    ),
    responses(
        (status = 200, description = "List of branches", body = ApiListBranchesResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
pub async fn list_branches(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    Query(query): Query<ListBranchesQuery>,
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

    let result = forge
        .read_service
        .list_branches(
            domain::ListBranchesRequest {
                agent: agent.identity.clone(),
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                prefix: query.prefix,
                limit: query.limit,
            },
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(ApiListBranchesResponse {
        branches: result
            .branches
            .into_iter()
            .map(|b| BranchItem {
                name: b.name,
                commit_sha: b.commit_sha,
            })
            .collect(),
        truncated: result.truncated,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{forge}/{owner}/{repo}/branches/by-name",
    params(
        ("forge" = String, Path, description = "Forge alias"),
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("branch" = String, Query, description = "Branch name to look up"),
    ),
    responses(
        (status = 200, description = "Branch details with existence flag", body = BranchDetailsResult),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
pub async fn get_branch(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    Query(query): Query<GetBranchQuery>,
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

    let result = forge
        .read_service
        .get_branch(
            domain::GetBranchRequest {
                agent: agent.identity.clone(),
                repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
                branch: query.branch,
            },
            &credential,
        )
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(BranchDetailsResult {
        exists: result.exists,
        name: result.name,
        commit_sha: result.commit_sha,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::todo, clippy::unimplemented)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use domain::{
        Branch, BranchDetails, ChangeRequest, ChangeRequestCommentDetail, ChangeRequestState,
        CommitPatchResponse, GetChangeRequestCommentsRequest, GetChangeRequestRequest,
        ListBranchesResponse, ListChangeRequestsRequest, Mergeability, OpenChangeRequestResponse,
        ReadRepositoryFileResponse, ServiceError,
    };
    use tower::ServiceExt;

    use crate::auth::AgentRegistry;
    use crate::config::AgentPolicyConfig;

    use super::*;

    #[tokio::test]
    async fn ci_handler_never_calls_write_service() {
        use domain::{CiChangeEvent, CiEventDetails, CiEventSource, RepositoryRef};
        #[derive(Clone)]
        struct CiAdapter(CiChangeEvent);
        impl forge::ForgeWebhookAdapter for CiAdapter {
            fn verify_and_parse_webhook_event(
                &self,
                _: &[(String, String)],
                _: &[u8],
                _: &str,
                _: domain::ForgeKind,
                _: &str,
                _: &str,
            ) -> Result<Option<domain::WebhookEvent>, forge::ForgeWebhookError> {
                Ok(Some(domain::WebhookEvent::CiChange(self.0.clone())))
            }
        }
        // Authentication and real provider normalization are covered by the
        // integration harness. This isolates the handler's sole side effect.
        for auto_merge in [false, true] {
            for source in [
                CiEventSource::CommitStatus,
                CiEventSource::CheckRun,
                CiEventSource::CheckSuite,
                CiEventSource::Pipeline,
                CiEventSource::Job,
            ] {
                let write = Arc::new(FakeWriteService::new());
                let mut details = CiEventDetails::new(source, "native".into());
                details.status = Some("success".into());
                details.conclusion = Some("success".into());
                let event = CiChangeEvent::new(
                    RepositoryRef {
                        alias: "test-forge".into(),
                        forge: domain::ForgeKind::GitHub,
                        host: "https://forge.example".into(),
                        owner: "org".into(),
                        name: "repo".into(),
                    },
                    "a".repeat(40),
                    "delivery".into(),
                    None,
                    details,
                    "fingerprint".into(),
                )
                .expect("CI event");
                let mut instance =
                    test_forge_instance("test-forge", "https://forge.example", write.clone());
                instance.webhook_adapter = Arc::new(CiAdapter(event));
                instance.webhook = Some(crate::config::ForgeWebhookConfig {
                    auto_merge,
                    secret: "secret".into(),
                });
                let registry = Arc::new(crate::registry::ForgeRegistry::new(
                    std::collections::HashMap::from([("test-forge".into(), instance)]),
                ));
                let bus = crate::events::EventBus::new();
                let state = AppState {
                    agent_registry: AgentRegistry::from_configs(&[]),
                    audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
                    auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
                        bus.clone(),
                        registry.clone(),
                    )),
                    event_bus: bus,
                    forge_registry: registry,
                };
                let response = crate::build_router(state, false)
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/forges/test-forge/webhook")
                            .body(Body::from("{}"))
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                tokio::task::yield_now().await;
                assert_eq!(write.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn inline_handler_never_calls_write_service() {
        use domain::{
            InlineReviewComment, InlineReviewDetails, PullRequestReviewCommentAction,
            PullRequestReviewCommentEvent, PullRequestReviewThreadAction,
            PullRequestReviewThreadEvent, RepositoryRef, WebhookEvent,
        };
        #[derive(Clone)]
        struct CiAdapter(WebhookEvent);
        impl forge::ForgeWebhookAdapter for CiAdapter {
            fn verify_and_parse_webhook_event(
                &self,
                _: &[(String, String)],
                _: &[u8],
                _: &str,
                _: domain::ForgeKind,
                _: &str,
                _: &str,
            ) -> Result<Option<domain::WebhookEvent>, forge::ForgeWebhookError> {
                Ok(Some(self.0.clone()))
            }
        }
        // Authentication and real provider normalization are covered by the
        // integration harness. This isolates the handler's sole side effect.
        for auto_merge in [false, true] {
            for action in ["created", "edited", "deleted", "resolved", "unresolved"] {
                let write = Arc::new(FakeWriteService::new());
                let repository = RepositoryRef {
                    alias: "test-forge".into(),
                    forge: domain::ForgeKind::GitHub,
                    host: "https://forge.example".into(),
                    owner: "org".into(),
                    name: "repo".into(),
                };
                let event = match action {
                    "resolved" | "unresolved" => {
                        WebhookEvent::PullRequestReviewThread(PullRequestReviewThreadEvent::new(
                            repository,
                            42,
                            if action == "resolved" {
                                PullRequestReviewThreadAction::Resolved
                            } else {
                                PullRequestReviewThreadAction::Unresolved
                            },
                            "delivery".into(),
                            None,
                            InlineReviewDetails {
                                thread_id: Some("opaque".into()),
                                ..Default::default()
                            },
                            "fingerprint".into(),
                        ))
                    }
                    _ => {
                        WebhookEvent::PullRequestReviewComment(PullRequestReviewCommentEvent::new(
                            repository,
                            42,
                            match action {
                                "created" => PullRequestReviewCommentAction::Created,
                                "edited" => PullRequestReviewCommentAction::Edited,
                                _ => PullRequestReviewCommentAction::Deleted,
                            },
                            "delivery".into(),
                            None,
                            InlineReviewDetails {
                                comment: Some(InlineReviewComment {
                                    comment_id: Some(7),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            "fingerprint".into(),
                        ))
                    }
                };
                let mut instance =
                    test_forge_instance("test-forge", "https://forge.example", write.clone());
                instance.webhook_adapter = Arc::new(CiAdapter(event));
                instance.webhook = Some(crate::config::ForgeWebhookConfig {
                    auto_merge,
                    secret: "secret".into(),
                });
                let registry = Arc::new(crate::registry::ForgeRegistry::new(
                    std::collections::HashMap::from([("test-forge".into(), instance)]),
                ));
                let bus = crate::events::EventBus::new();
                let state = AppState {
                    agent_registry: AgentRegistry::from_configs(&[]),
                    audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
                    auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
                        bus.clone(),
                        registry.clone(),
                    )),
                    event_bus: bus,
                    forge_registry: registry,
                };
                let response = crate::build_router(state, false)
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/forges/test-forge/webhook")
                            .body(Body::from("{}"))
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                tokio::task::yield_now().await;
                assert_eq!(write.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn branch_state_handler_never_calls_read_or_write_services() {
        use domain::{ChangeRequestEvent, ChangeRequestEventAction, RepositoryRef};
        #[derive(Clone)]
        struct LabelAdapter(domain::WebhookEvent);
        impl forge::ForgeWebhookAdapter for LabelAdapter {
            fn verify_and_parse_webhook_event(
                &self,
                _: &[(String, String)],
                _: &[u8],
                _: &str,
                _: domain::ForgeKind,
                _: &str,
                _: &str,
            ) -> Result<Option<domain::WebhookEvent>, forge::ForgeWebhookError> {
                Ok(Some(self.0.clone()))
            }
        }
        // Authentication and real provider normalization are covered by the
        // integration harness. This isolates the handler's sole side effect.
        for auto_merge in [false, true] {
            for action in [
                ChangeRequestEventAction::Updated,
                ChangeRequestEventAction::Synchronized,
                ChangeRequestEventAction::Closed,
                ChangeRequestEventAction::Merged,
            ] {
                let write = Arc::new(FakeWriteService::new());
                let event = ChangeRequestEvent {
                    change_request_changes: Some(domain::ChangeRequestChanges {
                        base: Some(domain::BaseBranchChange {
                            previous: Some("main".into()),
                            current: "next".into(),
                        }),
                        draft: Some(domain::DraftChange {
                            previous: Some(true),
                            current: false,
                        }),
                    }),
                    provider_action: Some("update".into()),
                    action: action.clone(),
                    labels_changed: true,
                    payload_fingerprint: "internal".into(),
                    delivery_id: "delivery".into(),
                    head_sha: "source".into(),
                    index: 42,
                    repository: RepositoryRef {
                        alias: "test-forge".into(),
                        forge: domain::ForgeKind::GitHub,
                        host: "https://forge.example".into(),
                        owner: "org".into(),
                        name: "repo".into(),
                    },
                    title: "PR".into(),
                    url: "url".into(),
                };
                let mut instance =
                    test_forge_instance("test-forge", "https://forge.example", write.clone());
                let read = Arc::new(FakeReadService::new());
                instance.read_service = read.clone();
                let event = if action == ChangeRequestEventAction::Closed {
                    domain::WebhookEvent::BranchPush(domain::BranchPushEvent {
                        repository: event.repository,
                        delivery_id: event.delivery_id,
                        payload_fingerprint: "internal".into(),
                        details: domain::BranchPushDetails {
                            r#ref: "refs/heads/main".into(),
                            before_sha: "a".repeat(40),
                            after_sha: "b".repeat(40),
                            deleted: None,
                            forced: None,
                            provider_event: "push".into(),
                        },
                    })
                } else {
                    domain::WebhookEvent::ChangeRequest(event)
                };
                instance.webhook_adapter = Arc::new(LabelAdapter(event));
                instance.webhook = Some(crate::config::ForgeWebhookConfig {
                    auto_merge,
                    secret: "secret".into(),
                });
                let registry = Arc::new(crate::registry::ForgeRegistry::new(
                    std::collections::HashMap::from([("test-forge".into(), instance)]),
                ));
                let bus = crate::events::EventBus::new();
                let state = AppState {
                    agent_registry: AgentRegistry::from_configs(&[]),
                    audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
                    auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
                        bus.clone(),
                        registry.clone(),
                    )),
                    event_bus: bus,
                    forge_registry: registry,
                };
                let response = crate::build_router(state, false)
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/forges/test-forge/webhook")
                            .body(Body::from("{}"))
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                tokio::task::yield_now().await;
                assert_eq!(write.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
                assert_eq!(read.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    async fn pr_label_handler_never_calls_write_service() {
        use domain::{ChangeRequestEvent, ChangeRequestEventAction, RepositoryRef};
        #[derive(Clone)]
        struct LabelAdapter(ChangeRequestEvent);
        impl forge::ForgeWebhookAdapter for LabelAdapter {
            fn verify_and_parse_webhook_event(
                &self,
                _: &[(String, String)],
                _: &[u8],
                _: &str,
                _: domain::ForgeKind,
                _: &str,
                _: &str,
            ) -> Result<Option<domain::WebhookEvent>, forge::ForgeWebhookError> {
                Ok(Some(domain::WebhookEvent::ChangeRequest(self.0.clone())))
            }
        }
        // Authentication and real provider normalization are covered by the
        // integration harness. This isolates the handler's sole side effect.
        for auto_merge in [false, true] {
            for action in [
                ChangeRequestEventAction::LabelsChanged,
                ChangeRequestEventAction::Synchronized,
                ChangeRequestEventAction::Closed,
                ChangeRequestEventAction::Merged,
            ] {
                let write = Arc::new(FakeWriteService::new());
                let event = ChangeRequestEvent {
                    change_request_changes: None,
                    provider_action: None,
                    action,
                    labels_changed: true,
                    payload_fingerprint: "internal".into(),
                    delivery_id: "delivery".into(),
                    head_sha: "source".into(),
                    index: 42,
                    repository: RepositoryRef {
                        alias: "test-forge".into(),
                        forge: domain::ForgeKind::GitHub,
                        host: "https://forge.example".into(),
                        owner: "org".into(),
                        name: "repo".into(),
                    },
                    title: "PR".into(),
                    url: "url".into(),
                };
                let mut instance =
                    test_forge_instance("test-forge", "https://forge.example", write.clone());
                instance.webhook_adapter = Arc::new(LabelAdapter(event));
                instance.webhook = Some(crate::config::ForgeWebhookConfig {
                    auto_merge,
                    secret: "secret".into(),
                });
                let registry = Arc::new(crate::registry::ForgeRegistry::new(
                    std::collections::HashMap::from([("test-forge".into(), instance)]),
                ));
                let bus = crate::events::EventBus::new();
                let state = AppState {
                    agent_registry: AgentRegistry::from_configs(&[]),
                    audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
                    auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
                        bus.clone(),
                        registry.clone(),
                    )),
                    event_bus: bus,
                    forge_registry: registry,
                };
                let response = crate::build_router(state, false)
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/forges/test-forge/webhook")
                            .body(Body::from("{}"))
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                tokio::task::yield_now().await;
                assert_eq!(write.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    async fn review_lifecycle_handler_and_service_guard_automation() {
        use crate::events::PublishStatus;
        use domain::{PullRequestReviewEventAction as Action, ReviewState};
        let write_svc = Arc::new(FakeWriteService::new());
        let (state, _events) = webhook_test_state(true, Arc::clone(&write_svc));
        let approved = forge::ForgeWebhookAdapter::verify_and_parse_webhook_event(
            &ApprovedReviewWebhookAdapter,
            &[],
            b"{}",
            "test-forge",
            domain::ForgeKind::Forgejo,
            "https://forge.example",
            "",
        )
        .expect("fixture")
        .and_then(|event| match event {
            domain::WebhookEvent::PullRequestReview(review) => Some(review),
            _ => None,
        })
        .expect("fixture is an approval");
        for action in [Action::Submitted, Action::Edited, Action::Dismissed] {
            for verdict in [
                None,
                Some(ReviewState::Comment),
                Some(ReviewState::RequestChanges),
                Some(ReviewState::Approved),
            ] {
                let mut event = approved.clone();
                event.action = action.clone();
                event.review_state = verdict;
                let accepted = action == Action::Submitted
                    && event.review_state == Some(ReviewState::Approved);
                let before = write_svc.calls.load(std::sync::atomic::Ordering::SeqCst);
                let task = spawn_review_auto_merge(
                    event.clone(),
                    &PublishStatus::Enqueued { delivered: 1 },
                    true,
                    &state.auto_merge_service,
                );
                assert_eq!(task.is_some(), accepted);
                if let Some(task) = task {
                    task.await.expect("schedule task");
                }
                assert_eq!(
                    write_svc.calls.load(std::sync::atomic::Ordering::SeqCst) - before,
                    usize::from(accepted)
                );
                // Independently await the service boundary, including malformed
                // dismissal-with-approval input a caller might construct.
                state.auto_merge_service.handle_review(event).await;
                assert_eq!(
                    write_svc.calls.load(std::sync::atomic::Ordering::SeqCst) - before,
                    2 * usize::from(accepted)
                );
            }
        }
        let before = write_svc.calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            spawn_review_auto_merge(
                approved.clone(),
                &PublishStatus::Duplicate,
                true,
                &state.auto_merge_service
            )
            .is_none()
        );
        assert!(
            spawn_review_auto_merge(
                approved,
                &PublishStatus::Enqueued { delivered: 1 },
                false,
                &state.auto_merge_service
            )
            .is_none()
        );
        assert_eq!(
            write_svc.calls.load(std::sync::atomic::Ordering::SeqCst),
            before
        );
        assert_eq!(
            write_svc.captured_auto_merge.lock().expect("capture").len(),
            2
        );
    }

    struct FakeForgeAdapter;

    struct ApprovedReviewWebhookAdapter;

    impl forge::ForgeWebhookAdapter for ApprovedReviewWebhookAdapter {
        fn verify_and_parse_webhook_event(
            &self,
            _headers: &[(String, String)],
            _body: &[u8],
            forge_alias: &str,
            forge_kind: domain::ForgeKind,
            host: &str,
            _secret: &str,
        ) -> Result<Option<domain::WebhookEvent>, forge::ForgeWebhookError> {
            Ok(Some(domain::WebhookEvent::PullRequestReview(
                domain::PullRequestReviewEvent {
                    action: domain::PullRequestReviewEventAction::Submitted,
                    provider_action: None,
                    reviewed_commit_id: None,
                    payload_fingerprint: String::new(),
                    delivery_id: "approved-review-delivery".to_string(),
                    head_sha: "abc123".to_string(),
                    index: 42,
                    repository: domain::RepositoryRef {
                        alias: forge_alias.to_string(),
                        forge: forge_kind,
                        host: host.to_string(),
                        name: "repo".to_string(),
                        owner: "org".to_string(),
                    },
                    review_body: "approved".to_string(),
                    review_id: 7,
                    review_state: Some(domain::ReviewState::Approved),
                    title: "Fix".to_string(),
                    url: "https://forge.example/org/repo/pulls/42".to_string(),
                },
            )))
        }
    }

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
            Err(forge::ForgeWebhookError::InvalidPayload(
                "unimplemented in test fake".into(),
            ))
        }
    }

    #[async_trait::async_trait]
    impl forge::ForgeAdapter for FakeForgeAdapter {
        async fn get_change_request_ci_details(
            &self,
            _: &domain::RepositoryRef,
            sha: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, forge::ForgeError> {
            Ok(domain::ChangeRequestCiDetails {
                head_sha: sha.to_string(),
                state: domain::CommitStatusState::Failure,
                details: vec![domain::CiCheckDetail {
                    context: "ci/test".into(),
                    description: "failed".into(),
                    state: domain::CommitStatusState::Failure,
                    target_url: "https://ci.example/1".into(),
                    resolution: domain::CiResolution::Resolved {
                        provider: domain::CiProvider::GithubActions,
                        pipeline_url: "https://github.example/actions/runs/1".into(),
                        failed_steps: vec![domain::CiFailureStep {
                            name: "test".into(),
                            state: "failure".into(),
                            log_excerpt: Some(domain::CiLogExcerpt {
                                lines: vec!["error log".into()],
                            }),
                        }],
                    },
                }],
            })
        }
        async fn add_issue_dependency(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn assign_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueComment, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
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
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_issue(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueDependencies, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &domain::RepositoryRef,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::Issue>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::Repository>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
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
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
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
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_change_request_comments(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::ChangeRequestCommentDetail>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_reviews(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::ChangeRequestCommentDetail>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_discussion_comments(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::ChangeRequestCommentDetail>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_combined_commit_status(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &domain::RepositoryRef,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<String>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_change_request_diff(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<String, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_default_merge_style(
            &self,
            _: &domain::RepositoryRef,
            _: &domain::ForgeCredential,
        ) -> Result<Option<String>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_repository_merge_settings(
            &self,
            _: &domain::RepositoryRef,
            _: &domain::ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_change_requests(
            &self,
            _: &domain::RepositoryRef,
            _: Option<&domain::ChangeRequestState>,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::ChangeRequest>, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn read_repository_file(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
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
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn submit_change_request_review(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn update_change_request(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequest, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_issue(
            &self,
            _: &domain::RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_branches(
            &self,
            _: &domain::RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &domain::ForgeCredential,
        ) -> Result<(Vec<domain::Branch>, bool), forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &domain::RepositoryRef,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<(String, Option<String>, bool), forge::ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    struct FakeReadService {
        calls: std::sync::atomic::AtomicUsize,
        issue_dependencies: Arc<Mutex<Option<Result<domain::IssueDependencies, ServiceError>>>>,
        list_branches: Arc<Mutex<Option<ListBranchesResponse>>>,
        get_branch: Arc<Mutex<Option<BranchDetails>>>,
        get_change_request: Arc<Mutex<Option<ChangeRequest>>>,
        list_change_requests: Arc<Mutex<Option<Vec<ChangeRequest>>>>,
    }

    impl FakeReadService {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                issue_dependencies: Arc::new(Mutex::new(None)),
                list_branches: Arc::new(Mutex::new(None)),
                get_branch: Arc::new(Mutex::new(None)),
                get_change_request: Arc::new(Mutex::new(None)),
                list_change_requests: Arc::new(Mutex::new(None)),
            }
        }

        fn with_list_branches(resp: ListBranchesResponse) -> Arc<Self> {
            let svc = Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                issue_dependencies: Arc::new(Mutex::new(None)),
                list_branches: Arc::new(Mutex::new(Some(resp))),
                get_branch: Arc::new(Mutex::new(None)),
                get_change_request: Arc::new(Mutex::new(None)),
                list_change_requests: Arc::new(Mutex::new(None)),
            };
            Arc::new(svc)
        }

        fn with_get_branch(resp: BranchDetails) -> Arc<Self> {
            let svc = Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                issue_dependencies: Arc::new(Mutex::new(None)),
                list_branches: Arc::new(Mutex::new(None)),
                get_branch: Arc::new(Mutex::new(Some(resp))),
                get_change_request: Arc::new(Mutex::new(None)),
                list_change_requests: Arc::new(Mutex::new(None)),
            };
            Arc::new(svc)
        }

        fn with_get_change_request(resp: ChangeRequest) -> Arc<Self> {
            let svc = Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                issue_dependencies: Arc::new(Mutex::new(None)),
                list_branches: Arc::new(Mutex::new(None)),
                get_branch: Arc::new(Mutex::new(None)),
                get_change_request: Arc::new(Mutex::new(Some(resp))),
                list_change_requests: Arc::new(Mutex::new(None)),
            };
            Arc::new(svc)
        }

        fn with_list_change_requests(resp: Vec<ChangeRequest>) -> Arc<Self> {
            let svc = Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                issue_dependencies: Arc::new(Mutex::new(None)),
                list_branches: Arc::new(Mutex::new(None)),
                get_branch: Arc::new(Mutex::new(None)),
                get_change_request: Arc::new(Mutex::new(None)),
                list_change_requests: Arc::new(Mutex::new(Some(resp))),
            };
            Arc::new(svc)
        }

        fn with_issue_dependencies(
            result: Result<domain::IssueDependencies, ServiceError>,
        ) -> Arc<Self> {
            Arc::new(Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                issue_dependencies: Arc::new(Mutex::new(Some(result))),
                list_branches: Arc::new(Mutex::new(None)),
                get_branch: Arc::new(Mutex::new(None)),
                get_change_request: Arc::new(Mutex::new(None)),
                list_change_requests: Arc::new(Mutex::new(None)),
            })
        }
    }

    #[async_trait::async_trait]
    impl domain::RepositoryReadService for FakeReadService {
        async fn get_issue(
            &self,
            _: domain::GetIssueRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            todo!()
        }
        async fn get_issue_comments(
            &self,
            _: domain::GetIssueCommentsRequest,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            todo!()
        }
        async fn get_issue_dependencies(
            &self,
            _: domain::GetIssueDependenciesRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueDependencies, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.issue_dependencies
                .lock()
                .expect("lock issue dependencies")
                .take()
                .expect("issue dependency result configured")
        }
        async fn list_issues(
            &self,
            _: domain::ListIssuesRequest,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            todo!()
        }

        async fn read_repository_file(
            &self,
            request: ReadRepositoryFileRequest,
            _credential: &domain::ForgeCredential,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            _: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

        async fn get_change_request_reviews(
            &self,
            request: domain::GetChangeRequestReviewsRequest,
            credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(request.agent.agent_id, "codex");
            assert_eq!(request.repository.alias, "test-forge");
            assert_eq!(request.repository.owner, "org");
            assert_eq!(request.repository.name, "repo");
            assert_eq!(request.index, 1);
            assert_eq!(credential.token.as_deref(), Some("caller-forge-token"));
            Ok(vec![ChangeRequestCommentDetail {
                author: "reviewer".to_string(),
                body: "approved".to_string(),
                commit_id: Some("abc123".to_string()),
                created_at: "2026-03-18T11:00:00Z".to_string(),
                id: 2,
                kind: "review".to_string(),
                review_state: Some("APPROVED".to_string()),
            }])
        }

        async fn get_change_request_discussion_comments(
            &self,
            request: domain::GetChangeRequestDiscussionCommentsRequest,
            credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(request.agent.agent_id, "codex");
            assert_eq!(request.repository.alias, "test-forge");
            assert_eq!(request.repository.owner, "org");
            assert_eq!(request.repository.name, "repo");
            assert_eq!(request.index, 1);
            assert_eq!(credential.token.as_deref(), Some("caller-forge-token"));
            Ok(vec![ChangeRequestCommentDetail {
                author: "reviewer".to_string(),
                body: "looks good".to_string(),
                commit_id: None,
                created_at: "2026-03-18T10:00:00Z".to_string(),
                id: 1,
                kind: "comment".to_string(),
                review_state: None,
            }])
        }

        async fn get_change_request_checks(
            &self,
            _request: domain::GetChangeRequestChecksRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(ServiceError::Upstream("unimplemented in test fake".into()))
        }

        async fn get_change_request_ci_details(
            &self,
            _req: domain::GetChangeRequestCiDetailsRequest,
            _cred: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, domain::ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(domain::ChangeRequestCiDetails {
                head_sha: "abc123".to_string(),
                state: domain::CommitStatusState::Failure,
                details: vec![domain::CiCheckDetail {
                    context: "ci/test".into(),
                    description: "failed".into(),
                    state: domain::CommitStatusState::Failure,
                    target_url: "https://ci.example/1".into(),
                    resolution: domain::CiResolution::Resolved {
                        provider: domain::CiProvider::GithubActions,
                        pipeline_url: "https://github.example/actions/runs/1".into(),
                        failed_steps: vec![domain::CiFailureStep {
                            name: "test".into(),
                            state: "failure".into(),
                            log_excerpt: Some(domain::CiLogExcerpt {
                                lines: vec!["error log".into()],
                            }),
                        }],
                    },
                }],
            })
        }

        async fn get_change_request_diff(
            &self,
            _request: domain::GetChangeRequestDiffRequest,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestDiff, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(ServiceError::Upstream("unimplemented in test fake".into()))
        }

        async fn list_change_requests(
            &self,
            _request: ListChangeRequestsRequest,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(resp) = self.list_change_requests.lock().expect("lock").take() {
                Ok(resp)
            } else {
                Ok(vec![])
            }
        }

        async fn get_change_request(
            &self,
            request: GetChangeRequestRequest,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(resp) = self.get_change_request.lock().expect("lock").take() {
                Ok(resp)
            } else {
                Ok(ChangeRequest {
                    draft: None,
                    base_branch: "main".to_string(),
                    body: "body".to_string(),
                    changed_files_count: None,
                    commit_count: None,
                    head_branch: "agent/fix".to_string(),
                    head_sha: None,
                    has_conflicts: None,
                    index: request.index,
                    labels: vec![],
                    merge_base_sha: None,
                    mergeability: Mergeability::Unknown,
                    state: ChangeRequestState::Open,
                    title: "Fix".to_string(),
                    url: "https://example.com/pulls/1".to_string(),
                })
            }
        }

        async fn list_branches(
            &self,
            _: domain::ListBranchesRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ListBranchesResponse, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(resp) = self.list_branches.lock().expect("lock").take() {
                Ok(resp)
            } else {
                Err(ServiceError::Upstream("unimplemented in test fake".into()))
            }
        }

        async fn get_branch(
            &self,
            _: domain::GetBranchRequest,
            _: &domain::ForgeCredential,
        ) -> Result<domain::BranchDetails, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(resp) = self.get_branch.lock().expect("lock").take() {
                Ok(resp)
            } else {
                Err(ServiceError::Upstream("unimplemented in test fake".into()))
            }
        }
    }

    type CapturedAutoMerge = Vec<(domain::ScheduleAutoMergeRequest, Option<String>)>;

    #[allow(clippy::struct_field_names)]
    pub(super) struct FakeWriteService {
        pub(super) calls: std::sync::atomic::AtomicUsize,
        captured_close_msg: Arc<Mutex<Option<String>>>,
        captured_rebase: Mutex<Option<domain::RebaseBranchRequest>>,
        captured_add_dep: Arc<Mutex<Option<domain::AddIssueDependencyRequest>>>,
        captured_auto_merge: Arc<Mutex<CapturedAutoMerge>>,
        auto_merge_called: tokio::sync::Notify,
        auto_merge_error: Option<String>,
        captured_remove_dep: Arc<Mutex<Option<domain::RemoveIssueDependencyRequest>>>,
    }

    impl FakeWriteService {
        pub(super) fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                captured_close_msg: Arc::new(Mutex::new(None)),
                captured_rebase: Mutex::new(None),
                captured_add_dep: Arc::new(Mutex::new(None)),
                captured_auto_merge: Arc::new(Mutex::new(Vec::new())),
                auto_merge_called: tokio::sync::Notify::new(),
                auto_merge_error: None,
                captured_remove_dep: Arc::new(Mutex::new(None)),
            }
        }
    }

    #[async_trait::async_trait]
    impl domain::RepositoryWriteService for FakeWriteService {
        async fn cancel_auto_merge(
            &self,
            _request: domain::CancelAutoMergeRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), domain::CancelAutoMergeError> {
            Err(domain::CancelAutoMergeError::Unsupported)
        }

        async fn add_issue_dependency(
            &self,
            request: domain::AddIssueDependencyRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.captured_add_dep.lock().expect("poisoned") = Some(request);
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index: 1,
                labels: vec![],
                state: "open".to_string(),
                title: "Issue".to_string(),
                url: "https://example.com/issues/1".to_string(),
            })
        }
        async fn add_issue_label(
            &self,
            request: domain::AddIssueLabelRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            todo!()
        }
        async fn close_issue(
            &self,
            request: domain::CloseIssueRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.captured_close_msg.lock().expect("poisoned lock") = Some(request.message.clone());
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index: request.index,
                labels: vec![],
                state: "closed".to_string(),
                title: "Issue".to_string(),
                url: "https://example.com/issues/1".to_string(),
            })
        }
        async fn comment_on_issue(
            &self,
            _: domain::CommentOnIssueRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::IssueComment, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            todo!()
        }

        async fn close_change_request(
            &self,
            request: CloseChangeRequestRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ChangeRequest {
                draft: None,
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                has_conflicts: None,
                index: request.index,
                labels: vec![],
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
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
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(OpenChangeRequestResponse {
                change_request: ChangeRequest {
                    draft: None,
                    base_branch: "main".to_string(),
                    body: "body".to_string(),
                    changed_files_count: None,
                    commit_count: None,
                    head_branch: "agent/fix".to_string(),
                    head_sha: None,
                    has_conflicts: None,
                    index: 1,
                    labels: vec![],
                    merge_base_sha: None,
                    mergeability: Mergeability::Unknown,
                    state: ChangeRequestState::Open,
                    title: "Fix".to_string(),
                    url: "https://example.com/pulls/1".to_string(),
                },
                repository: request.repository,
            })
        }

        async fn rebase_branch(
            &self,
            request: domain::RebaseBranchRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::RebaseBranchResponse, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let branch = request.branch.clone();
            *self.captured_rebase.lock().expect("request") = Some(request);
            Ok(domain::RebaseBranchResponse {
                branch,
                commit_sha: "new-head".into(),
                old_commit_sha: Some("old-head".into()),
                commit_mapping: Some(vec![domain::RebaseCommitMapping {
                    old_commit_sha: "old-head".into(),
                    new_commit_sha: "new-head".into(),
                }]),
            })
        }

        async fn remove_issue_dependency(
            &self,
            request: domain::RemoveIssueDependencyRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let idx = request.index;
            *self.captured_remove_dep.lock().expect("poisoned") = Some(request);
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index: idx,
                labels: vec![],
                state: "open".to_string(),
                title: "Issue".to_string(),
                url: "https://example.com/issues/1".to_string(),
            })
        }
        async fn remove_issue_label(
            &self,
            request: domain::RemoveIssueLabelRequest,
            _: domain::policy::AuthorizedWrite,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            request: domain::ScheduleAutoMergeRequest,
            _authorized: domain::policy::AuthorizedWrite,
            credential: &domain::ForgeCredential,
        ) -> Result<(), ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.captured_auto_merge
                .lock()
                .expect("poisoned")
                .push((request, credential.token.clone()));
            self.auto_merge_called.notify_one();
            if let Some(error) = &self.auto_merge_error {
                return Err(ServiceError::Upstream(error.clone()));
            }
            Ok(())
        }

        async fn submit_change_request_review(
            &self,
            request: domain::SubmitChangeRequestReviewRequest,
            _authorized: domain::policy::AuthorizedWrite,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ChangeRequest {
                draft: None,
                base_branch: "main".to_string(),
                body: request.body.unwrap_or_default(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                has_conflicts: None,
                index: request.index,
                labels: vec![],
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
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
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            github_app: std::collections::HashMap::new(),
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

    pub(super) fn test_forge_instance(
        alias: &str,
        base_url: &str,
        write_service: Arc<FakeWriteService>,
    ) -> crate::registry::ForgeInstance {
        crate::registry::ForgeInstance {
            adapter: Arc::new(FakeForgeAdapter),
            alias: alias.to_string(),
            base_url: base_url.to_string(),
            client: crate::http_client::client_builder()
                .build()
                .expect("HTTP client"),
            forge_kind: ForgeKind::Forgejo,
            forge_type: "forgejo".to_string(),
            git_auth_user: String::new(),
            read_service: Arc::new(FakeReadService::new()),
            token: Some("forge-fallback-token".to_string()),
            webhook: None,
            webhook_adapter: Arc::new(FakeForgeAdapter),
            write_service,
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
        test_state_with_write(Arc::new(FakeWriteService::new()))
    }

    fn cancellation_state<S: audit::AuditSink + 'static>(
        url: &str,
        audit: Arc<S>,
        caller: bool,
    ) -> AppState {
        let mut state = test_state();
        let configs = [crate::config::AgentConfig {
            agent_id: "codex".into(),
            session_id: "cancel-session".into(),
            token: "test-token".into(),
            github_app: HashMap::new(),
            forge_identity: if caller {
                HashMap::from([(
                    "test-forge".into(),
                    crate::config::ForgeIdentityConfig {
                        token: "caller-secret-marker".into(),
                    },
                )])
            } else {
                HashMap::new()
            },
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/repo".into(), "unknown/org/repo".into()],
                branch_prefix: Some("agent/".into()),
                protected_paths: vec![],
            },
        }];
        state.agent_registry = AgentRegistry::from_configs(&configs);
        let adapter = Arc::new(
            forge::ForgejoAdapter::new(forge::ForgejoConfig {
                base_url: url.into(),
                token: Some("default-secret-marker".into()),
                woodpecker_url: None,
                woodpecker_token: None,
            })
            .expect("adapter"),
        );
        let mut instance =
            test_forge_instance("test-forge", url, Arc::new(FakeWriteService::new()));
        instance.adapter = adapter.clone();
        instance.token = Some("default-secret-marker".into());
        instance.write_service =
            Arc::new(orchestrator::WriteOrchestrator::new(adapter, audit, None));
        state.forge_registry = Arc::new(crate::registry::ForgeRegistry::new(HashMap::from([(
            "test-forge".into(),
            instance,
        )])));
        state
    }

    fn cancel_request(alias: &str, repo: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("DELETE").uri(format!(
            "/api/v1/repos/{alias}/org/{repo}/pulls/42/automerge"
        ));
        if let Some(bearer) = bearer {
            builder = builder.header("authorization", bearer);
        }
        builder.body(Body::empty()).expect("request")
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn cancellation_router_provider_contract_and_credentials() {
        use tracing::instrument::WithSubscriber;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        // Other cancellation tests can first register shared tracing callsites
        // without a subscriber, caching disabled interest process-wide. Keep
        // the diagnostic assertions isolated while retaining parallel tests.
        const CHILD: &str = "FORGE_MCP_CANCELLATION_DIAGNOSTICS_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--exact",
                        "handlers::tests::cancellation_router_provider_contract_and_credentials",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .status()
                    .expect("isolated cancellation diagnostics test");
            assert!(status.success(), "isolated cancellation diagnostics failed");
            return;
        }
        let capture = crate::diagnostics::tests::Capture::default();
        let dispatch = tracing::Dispatch::new(capture.subscriber());
        for caller in [true, false] {
            for (upstream, expected) in [
                (204, 200),
                (401, 401),
                (403, 403),
                (404, 502),
                (200, 502),
                (202, 502),
                (302, 502),
                (405, 502),
                (409, 502),
                (429, 502),
                (500, 502),
                (501, 502),
            ] {
                let mock = MockServer::start().await;
                let audit = Arc::new(audit::InMemoryAuditSink::new());
                let observed_audit = audit.clone();
                Mock::given(method("DELETE"))
                    .respond_with(move |_: &wiremock::Request| {
                        let records = observed_audit.records().expect("audit");
                        assert_eq!(records.len(), 1, "audit must precede provider write");
                        assert_eq!(records[0].action, "cancel_auto_merge");
                        assert_eq!(records[0].agent.agent_id, "codex");
                        assert_eq!(records[0].agent.session_id, "cancel-session");
                        assert_eq!(records[0].target, "#42");
                        assert_eq!(records[0].repository.owner, "org");
                        assert_eq!(records[0].repository.name, "repo");
                        ResponseTemplate::new(upstream)
                            .set_body_string("provider-secret-marker already absent")
                    })
                    .expect(1)
                    .mount(&mock)
                    .await;
                let app =
                    crate::build_router(cancellation_state(&mock.uri(), audit, caller), false);
                let log_start = capture.logs().len();
                let response = app
                    .oneshot(cancel_request(
                        "test-forge",
                        "repo",
                        Some("Bearer test-token"),
                    ))
                    .with_subscriber(dispatch.clone())
                    .await
                    .expect("response");
                assert_eq!(response.status().as_u16(), expected);
                let body = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .expect("body");
                if expected == 200 {
                    assert_eq!(&body[..], b"{}");
                }
                assert!(!String::from_utf8_lossy(&body).contains("secret-marker"));
                let requests = mock.received_requests().await.expect("requests");
                assert_eq!(requests.len(), 1, "no probes or other mutations");
                assert_eq!(
                    requests[0].url.path(),
                    "/api/v1/repos/org/repo/pulls/42/merge"
                );
                assert!(requests[0].body.is_empty());
                assert!(requests[0].url.query().is_none());
                assert_eq!(
                    requests[0].headers["authorization"],
                    if caller {
                        "Bearer caller-secret-marker"
                    } else {
                        "Bearer default-secret-marker"
                    }
                );
                let all_logs = capture.logs();
                let logs = &all_logs[log_start..];
                for field in [
                    "codex",
                    "cancel-session",
                    "test-forge",
                    "org",
                    "repo",
                    "42",
                    "delete",
                    "upstream_status",
                    "outcome",
                ] {
                    assert!(logs.contains(field), "missing {field}: {logs}");
                }
                assert!(!logs.contains("secret-marker"), "{logs}");
                assert_eq!(logs.contains("confirmed_cancelled"), upstream == 204);
            }
        }
    }

    #[tokio::test]
    async fn cancellation_authorization_precedes_resolution() {
        let mock = wiremock::MockServer::start().await;
        let audit = Arc::new(audit::InMemoryAuditSink::new());
        let app = crate::build_router(cancellation_state(&mock.uri(), audit.clone(), true), false);
        for (alias, repo, token, expected) in [
            ("test-forge", "repo", None, 401),
            ("unknown", "repo", None, 401),
            ("unknown", "repo", Some("Bearer invalid"), 401),
            ("unknown", "denied", Some("Bearer test-token"), 403),
            ("test-forge", "denied", Some("Bearer test-token"), 403),
            ("unknown", "repo", Some("Bearer test-token"), 400),
        ] {
            let response = app
                .clone()
                .oneshot(cancel_request(alias, repo, token))
                .await
                .expect("response");
            assert_eq!(response.status().as_u16(), expected);
        }
        assert!(audit.records().expect("audit").is_empty());
        assert!(mock.received_requests().await.expect("requests").is_empty());
    }

    struct CancellationFailingAudit;
    #[async_trait::async_trait]
    impl audit::AuditSink for CancellationFailingAudit {
        async fn record(&self, _: audit::AuditRecord) -> Result<(), audit::AuditError> {
            Err(audit::AuditError::Unavailable)
        }
    }

    #[tokio::test]
    async fn cancellation_audit_failure_blocks_provider_and_unsupported_is_501() {
        let mock = wiremock::MockServer::start().await;
        let app = crate::build_router(
            cancellation_state(&mock.uri(), Arc::new(CancellationFailingAudit), true),
            false,
        );
        let response = app
            .oneshot(cancel_request(
                "test-forge",
                "repo",
                Some("Bearer test-token"),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(mock.received_requests().await.expect("requests").is_empty());
        let response = crate::build_router(test_state(), false)
            .oneshot(cancel_request(
                "test-forge",
                "repo",
                Some("Bearer test-token"),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn cancellation_repetition_never_caches_success() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let mock = MockServer::start().await;
        let audit = Arc::new(audit::InMemoryAuditSink::new());
        let app = crate::build_router(cancellation_state(&mock.uri(), audit.clone(), true), false);
        for status in [204, 404, 404] {
            mock.reset().await;
            Mock::given(method("DELETE"))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&mock)
                .await;
            let response = app
                .clone()
                .oneshot(cancel_request(
                    "test-forge",
                    "repo",
                    Some("Bearer test-token"),
                ))
                .await
                .expect("response");
            assert_eq!(
                response.status().as_u16(),
                if status == 204 { 200 } else { 502 }
            );
            assert_eq!(mock.received_requests().await.expect("requests").len(), 1);
        }
        assert_eq!(audit.records().expect("audit").len(), 3);
    }

    #[tokio::test]
    async fn cancellation_prior_reads_and_terminal_states_never_prove_absence() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        for (state, merged, head) in [
            ("open", false, Some("changed-head")),
            ("open", false, None),
            ("closed", false, Some("closed-head")),
            ("closed", true, Some("merged-head")),
        ] {
            for status in [204, 404] {
                let mock = MockServer::start().await;
                Mock::given(method("GET"))
                    .and(path("/api/v1/repos/org/repo/pulls/42"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "base":{"ref":"main","sha":"base"}, "head":{"ref":"topic","sha":head},
                        "html_url":"https://example/pull/42", "merged":merged, "number":42,
                        "state":state, "title":"Fixture", "mergeable":false
                    })))
                    .expect(1)
                    .mount(&mock)
                    .await;
                Mock::given(method("DELETE"))
                    .respond_with(
                        ResponseTemplate::new(status)
                            .set_body_string("No scheduled merge; already merged; already absent"),
                    )
                    .expect(1)
                    .mount(&mock)
                    .await;
                let app_state = cancellation_state(
                    &mock.uri(),
                    Arc::new(audit::InMemoryAuditSink::new()),
                    true,
                );
                let instance = app_state
                    .forge_registry
                    .get("test-forge")
                    .expect("instance");
                // Test setup only: cancellation itself must not perform this read.
                let read = instance
                    .adapter
                    .get_change_request(
                        &repo_ref("test-forge", "org", "repo", instance),
                        42,
                        &domain::ForgeCredential {
                            token: Some("caller-secret-marker".into()),
                        },
                    )
                    .await;
                assert_eq!(read.is_ok(), head.is_some());
                let response = crate::build_router(app_state, false)
                    .oneshot(cancel_request(
                        "test-forge",
                        "repo",
                        Some("Bearer test-token"),
                    ))
                    .await
                    .expect("response");
                assert_eq!(
                    response.status().as_u16(),
                    if status == 204 { 200 } else { 502 }
                );
                let requests = mock.received_requests().await.expect("requests");
                assert_eq!(requests.len(), 2, "only setup GET and cancellation DELETE");
                assert_eq!(requests[0].method, "GET");
                assert_eq!(requests[1].method, "DELETE");
            }
        }
    }

    #[tokio::test]
    async fn cancellation_transport_and_malformed_target_never_return_404() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        drop(listener);
        let app = crate::build_router(
            cancellation_state(&url, Arc::new(audit::InMemoryAuditSink::new()), true),
            false,
        );
        let response = app
            .clone()
            .oneshot(cancel_request(
                "test-forge",
                "repo",
                Some("Bearer test-token"),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/repos/test-forge/org/repo/pulls/not-a-number/automerge")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn cancellation_openapi_is_bodyless_and_conservative() {
        use utoipa::OpenApi;
        let schema = serde_json::to_value(crate::ApiDoc::openapi()).expect("schema");
        let path = &schema["paths"]["/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge"];
        assert!(path.get("post").is_some());
        let delete = &path["delete"];
        assert!(delete.get("requestBody").is_none());
        for status in ["200", "400", "401", "403", "500", "501", "502"] {
            assert!(delete["responses"].get(status).is_some());
        }
        assert!(delete["responses"].get("404").is_none());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn explicit_and_review_schedules_share_draft_deferral() {
        use forge::ForgeWebhookAdapter;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        for draft in [Some(true), Some(false), None] {
            let mock = MockServer::start().await;
            let schedules = if draft == Some(true) { 0 } else { 2 };
            Mock::given(method("GET"))
                .and(path("/api/v1/repos/org/repo/pulls/42"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "base":{"ref":"main","sha":"base"}, "head":{"ref":"topic","sha":"abc123"},
                    "html_url":"https://example/pull/42", "merged":false, "number":42,
                    "state":"open", "title":"PR", "draft":draft, "mergeable":true
                })))
                .expect(2)
                .mount(&mock)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/v1/repos/org/repo"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "allow_rebase":true,"default_merge_style":"rebase"
                })))
                .expect(schedules)
                .mount(&mock)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/v1/repos/org/repo/pulls/42/merge"))
                .respond_with(ResponseTemplate::new(200))
                .expect(schedules)
                .mount(&mock)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/v1/repos/org/repo/statuses/abc123"))
                .respond_with(ResponseTemplate::new(201))
                .expect(schedules)
                .mount(&mock)
                .await;
            let adapter = Arc::new(
                forge::ForgejoAdapter::new(forge::ForgejoConfig {
                    base_url: mock.uri(),
                    token: None,
                    woodpecker_url: None,
                    woodpecker_token: None,
                })
                .expect("adapter"),
            );
            let audit = Arc::new(audit::InMemoryAuditSink::new());
            let mut state = test_state();
            let mut instance =
                test_forge_instance("test-forge", &mock.uri(), Arc::new(FakeWriteService::new()));
            instance.write_service = Arc::new(orchestrator::WriteOrchestrator::new(
                adapter,
                Arc::clone(&audit),
                None,
            ));
            let registry = Arc::new(crate::registry::ForgeRegistry::new(HashMap::from([(
                "test-forge".into(),
                instance,
            )])));
            state.forge_registry = Arc::clone(&registry);
            let bus = crate::events::EventBus::new();
            let mut events = bus.subscribe(
                "codex".into(),
                AgentPolicyConfig {
                    allowed_repos: vec!["test-forge/org/repo".into()],
                    branch_prefix: None,
                    protected_paths: vec![],
                },
                "draft-guard".into(),
                None,
            );
            let automatic = crate::auto_merge::AutoMergeService::new(bus, registry);
            let app = crate::build_router(state, false);
            // Authorization still rejects unauthenticated explicit requests before get.
            let denied = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/repos/test-forge/org/repo/pulls/42/automerge")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"expected_head_sha":"abc123"}"#))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/repos/test-forge/org/repo/pulls/42/automerge")
                        .header("authorization", "Bearer test-token")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"expected_head_sha":"abc123"}"#))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                if draft == Some(true) {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::OK
                }
            );
            if draft == Some(true) {
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("body");
                assert!(
                    String::from_utf8_lossy(&bytes).contains(domain::AUTO_MERGE_DRAFT_DEFERRAL)
                );
            }
            let event = ApprovedReviewWebhookAdapter
                .verify_and_parse_webhook_event(
                    &[],
                    b"{}",
                    "test-forge",
                    ForgeKind::Forgejo,
                    &mock.uri(),
                    "",
                )
                .expect("event")
                .expect("review");
            let review = match event {
                domain::WebhookEvent::PullRequestReview(review) => Some(review),
                _ => None,
            }
            .expect("review fixture");
            automatic.handle_review(review).await;
            assert!(matches!(
                events.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
            assert_eq!(audit.records().expect("audit").len() as u64, schedules);
            mock.verify().await;
            let requests = mock.received_requests().await.expect("requests");
            assert_eq!(requests.len() as u64, 2 + schedules * 3);
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn diagnostics_auto_merge_failure_stages() {
        use tracing::instrument::WithSubscriber;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        for schedule_status in [405, 200] {
            let mock = MockServer::start().await;
            Mock::given(method("GET")).and(path("/api/v1/repos/org/repo/pulls/42")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "base":{"ref":"main","sha":"base"}, "head":{"ref":"agent/topic","sha":"head"},
                "html_url":"https://example/pull/42", "merged":false, "number":42, "state":"open", "title":"PR"
            }))).expect(1).mount(&mock).await;
            Mock::given(method("GET"))
                .and(path("/api/v1/repos/org/repo"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"allow_rebase":true,"default_merge_style":"rebase"}),
                ))
                .expect(1)
                .mount(&mock)
                .await;
            Mock::given(method("POST")).and(path("/api/v1/repos/org/repo/pulls/42/merge")).respond_with(ResponseTemplate::new(schedule_status).set_body_json(serde_json::json!({"message":"User not allowed to merge PR", "token":"upstream-secret"}))).expect(1).mount(&mock).await;
            Mock::given(method("POST"))
                .and(path("/api/v1/repos/org/repo/statuses/head"))
                .respond_with(
                    ResponseTemplate::new(500)
                        .set_body_string("Authorization: Bearer publication-secret"),
                )
                .expect(u64::from(schedule_status == 200))
                .mount(&mock)
                .await;
            let adapter = Arc::new(
                forge::ForgejoAdapter::new(forge::ForgejoConfig {
                    base_url: mock.uri(),
                    token: None,
                    woodpecker_url: None,
                    woodpecker_token: None,
                })
                .expect("adapter"),
            );
            let mut state = test_state();
            let mut instance =
                test_forge_instance("test-forge", &mock.uri(), Arc::new(FakeWriteService::new()));
            instance.write_service = Arc::new(orchestrator::WriteOrchestrator::new(
                adapter,
                Arc::new(audit::InMemoryAuditSink::new()),
                None,
            ));
            state.forge_registry =
                Arc::new(crate::registry::ForgeRegistry::new(HashMap::from([(
                    "test-forge".into(),
                    instance,
                )])));
            let capture = crate::diagnostics::tests::Capture::default();
            let response = crate::build_router(state, false)
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/api/v1/repos/test-forge/org/repo/pulls/42/automerge")
                        .header("authorization", "Bearer test-token")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            r#"{"expected_head_sha":"head","merge_style":"rebase"}"#,
                        ))
                        .expect("request"),
                )
                .with_subscriber(capture.subscriber())
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                if schedule_status == 405 {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::OK
                }
            );
            let logs = capture.logs();
            let line = logs
                .lines()
                .find(|line| {
                    line.contains(if schedule_status == 405 {
                        "unexpected upstream status"
                    } else {
                        "evaluation-trigger publication failed"
                    })
                })
                .expect("failure log");
            for expected in [
                "request_id=",
                "test-forge",
                "org",
                "repo",
                "42",
                "codex",
                "default",
                "agent_forge_identity",
                "POST",
            ] {
                assert!(line.contains(expected), "missing {expected}: {line}");
            }
            if schedule_status == 405 {
                assert!(line.contains("405"));
                assert!(line.contains("schedule_auto_merge"));
            } else {
                assert!(line.contains("scheduling_succeeded=true"));
            }
            for secret in [
                "test-token",
                "caller-forge-token",
                "upstream-secret",
                "publication-secret",
                "Authorization",
            ] {
                assert!(!logs.contains(secret), "{logs}");
            }
            mock.verify().await;
        }
    }

    #[test]
    fn diagnostics_credential_selection_preserves_precedence() {
        let capture = crate::diagnostics::tests::Capture::default();
        let subscriber = capture.subscriber();
        let _guard = tracing::subscriber::set_default(subscriber);
        let mut agent = test_agent();
        let mut instance = test_forge_instance(
            "test-forge",
            "https://forge.example",
            Arc::new(FakeWriteService::new()),
        );
        assert_eq!(
            resolve_credential(&agent, "test-forge", &instance)
                .token
                .as_deref(),
            Some("forge-fallback-token")
        );
        agent.forge_identities.insert(
            "test-forge".into(),
            crate::config::ForgeIdentityConfig {
                token: "identity-secret".into(),
            },
        );
        assert_eq!(
            resolve_credential(&agent, "test-forge", &instance)
                .token
                .as_deref(),
            Some("identity-secret")
        );
        agent.forge_identities.clear();
        instance.token = None;
        assert!(
            resolve_credential(&agent, "test-forge", &instance)
                .token
                .is_none()
        );
        let logs = capture.logs();
        for source in ["forge_default", "agent_forge_identity", "none"] {
            assert!(logs.contains(source), "{logs}");
        }
        assert!(!logs.contains("identity-secret"));
        assert!(!logs.contains("forge-fallback-token"));
    }

    #[tokio::test]
    async fn diagnostics_app_selection_uses_known_bot_identity() {
        use tracing::instrument::WithSubscriber;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/app"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"slug":"reviewer"})),
            )
            .expect(1)
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/2/access_tokens"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"token":"installation-secret"})),
            )
            .expect(1)
            .mount(&mock)
            .await;
        let credential = forge::github::GitHubAppCredential::new(
            &mock.uri(),
            forge::github::GitHubAppConfig {
                app_id: 1,
                installation_id: 2,
                private_key_pem: include_str!("test-app-key.pem").into(),
            },
        )
        .await
        .expect("mock app credential");
        let mut agent = test_agent();
        agent
            .github_app_credentials
            .insert("test-forge".into(), credential);
        agent.forge_identities.insert(
            "test-forge".into(),
            crate::config::ForgeIdentityConfig {
                token: "identity-secret".into(),
            },
        );
        let instance =
            test_forge_instance("test-forge", &mock.uri(), Arc::new(FakeWriteService::new()));
        let capture = crate::diagnostics::tests::Capture::default();
        async {
            let span = tracing::info_span!(
                "request",
                agent_id = "codex",
                upstream_username = tracing::field::Empty,
                credential_source = tracing::field::Empty
            );
            span.in_scope(|| {
                assert_eq!(
                    resolve_credential(&agent, "test-forge", &instance)
                        .token
                        .as_deref(),
                    Some("installation-secret")
                );
            });
        }
        .with_subscriber(capture.subscriber())
        .await;
        let logs = capture.logs();
        assert!(logs.contains("agent_github_app"), "{logs}");
        assert!(logs.contains("reviewer[bot]"), "{logs}");
        assert!(logs.contains("codex"));
        for secret in [
            "installation-secret",
            "identity-secret",
            "forge-fallback-token",
        ] {
            assert!(!logs.contains(secret));
        }
        mock.verify().await;
    }

    #[tokio::test]
    async fn diagnostics_authentication_and_denial() {
        use tracing::instrument::WithSubscriber;
        let capture = crate::diagnostics::tests::Capture::default();
        let app = crate::build_router(test_state(), false);
        async {
            for (token, expected) in [
                (None, StatusCode::UNAUTHORIZED),
                (Some("wrong-secret"), StatusCode::UNAUTHORIZED),
                (Some("test-token"), StatusCode::FORBIDDEN),
            ] {
                let mut request = axum::http::Request::builder()
                    .uri("/api/v1/repos/test-forge/denied/repo/pulls/42");
                if let Some(token) = token {
                    request = request.header("authorization", format!("Bearer {token}"));
                }
                let response = app
                    .clone()
                    .oneshot(request.body(axum::body::Body::empty()).expect("request"))
                    .await
                    .expect("response");
                assert_eq!(response.status(), expected);
            }
        }
        .with_subscriber(capture.subscriber())
        .await;
        let logs = capture.logs();
        for reason in [
            "missing_authorization",
            "invalid_token",
            "repository_denied",
        ] {
            assert!(logs.contains(reason), "{logs}");
        }
        assert!(logs.contains("agent_id=\"codex\""));
        assert!(logs.contains("session_id=\"default\""));
        assert!(!logs.contains("wrong-secret"));
        assert!(!logs.contains("test-token"));
    }

    #[tokio::test]
    async fn reword_handler_preserves_request_and_mapping() {
        use http_body_util::BodyExt;
        let write = Arc::new(FakeWriteService::new());
        let app = crate::build_router(test_state_with_write(Arc::clone(&write)), false);
        let message = "  Subject\n\n# café; `cmd` $(cmd)\n\n";
        let body = serde_json::json!({"base_branch":"main", "branch":"agent/reword", "operations":[{"type":"reword", "commit":"full-id", "message":message}]});
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/rebase")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let result: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(result["old_commit_sha"], "old-head");
        assert_eq!(result["commit_mapping"][0]["new_commit_sha"], "new-head");
        let captured = write.captured_rebase.lock().expect("request");
        let request = captured.as_ref().expect("captured");
        assert_eq!(request.branch, "agent/reword");
        assert_eq!(request.base_branch, "main");
        assert_eq!(
            request.operations,
            vec![domain::RebaseOperation::Reword {
                commit: "full-id".into(),
                message: message.into()
            }]
        );
        assert_eq!(request.agent.agent_id, "codex");
        assert_eq!(request.repository.owner, "org");
    }

    #[test]
    fn reword_openapi_and_legacy_response_contract() {
        use utoipa::OpenApi;
        let schema = serde_json::to_value(crate::ApiDoc::openapi()).expect("schema");
        let variants = schema["components"]["schemas"]["RebaseOperationBody"]["oneOf"]
            .as_array()
            .expect("variants");
        let reword = variants
            .iter()
            .find(|variant| variant["properties"]["type"]["enum"][0] == "reword")
            .expect("reword variant");
        let required = reword["required"].as_array().expect("required");
        for field in ["type", "commit", "message"] {
            assert!(required.contains(&serde_json::json!(field)));
        }
        assert!(schema["components"]["schemas"]["RebaseCommitMapping"].is_object());
        assert!(
            schema["components"]["schemas"]["RebaseBranchResult"]["properties"]["commit_mapping"]
                .is_object()
        );
        let response = crate::api::RebaseBranchResult {
            branch: "agent/test".into(),
            commit_sha: "head".into(),
            old_commit_sha: None,
            commit_mapping: None,
        };
        assert_eq!(
            serde_json::to_value(response).expect("response"),
            serde_json::json!({"branch":"agent/test", "commit_sha":"head"})
        );
        for operation in [
            serde_json::json!({"type":"reword", "commit":"id"}),
            serde_json::json!({"type":"reword", "message":"subject"}),
        ] {
            assert!(serde_json::from_value::<crate::api::RebaseOperationBody>(operation).is_err());
        }
    }

    fn test_state_with_write(write_svc: Arc<FakeWriteService>) -> AppState {
        let forge_identity = std::collections::HashMap::from([(
            "test-forge".to_string(),
            crate::config::ForgeIdentityConfig {
                token: "caller-forge-token".to_string(),
            },
        )]);
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity,
            github_app: std::collections::HashMap::new(),
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
            test_forge_instance("test-forge", "https://forge.example", write_svc),
        );

        AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            auto_merge_service: test_auto_merge_service(),
            event_bus: crate::events::EventBus::new(),
            forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
        }
    }

    fn webhook_test_state(
        auto_merge: bool,
        write_svc: Arc<FakeWriteService>,
    ) -> (
        AppState,
        tokio::sync::mpsc::Receiver<crate::events::QueuedEvent>,
    ) {
        let event_bus = crate::events::EventBus::new();
        let receiver = event_bus.subscribe(
            "codex".to_string(),
            AgentPolicyConfig {
                allowed_repos: vec!["test-forge/org/repo".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            "webhook-test".to_string(),
            None,
        );
        let mut forge = test_forge_instance("test-forge", "https://forge.example", write_svc);
        forge.webhook = Some(crate::config::ForgeWebhookConfig {
            auto_merge,
            secret: "distinctive-webhook-secret".to_string(),
        });
        forge.webhook_adapter = Arc::new(ApprovedReviewWebhookAdapter);
        let registry = Arc::new(crate::registry::ForgeRegistry::new(
            std::collections::HashMap::from([("test-forge".to_string(), forge)]),
        ));
        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&[]),
            audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
            auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
                event_bus.clone(),
                Arc::clone(&registry),
            )),
            event_bus,
            forge_registry: registry,
        };
        (state, receiver)
    }

    fn test_state_with_read(
        read_svc: Arc<dyn domain::RepositoryReadService>,
        allowed_repos: Vec<String>,
        write_svc: Arc<FakeWriteService>,
    ) -> AppState {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            github_app: std::collections::HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos,
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let mut fi = test_forge_instance("test-forge", "https://forge.example", write_svc);
        fi.read_service = read_svc;
        let mut forges = std::collections::HashMap::new();
        forges.insert("test-forge".to_string(), fi);

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
            github_app: std::collections::HashMap::new(),
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
            test_forge_instance(
                "test-forge",
                "https://forge.example",
                Arc::new(FakeWriteService::new()),
            ),
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
    async fn get_pull_serializes_mergeability_and_has_conflicts() {
        for draft in [Some(true), Some(false), None] {
            let cr = ChangeRequest {
                draft,
                base_branch: "main".to_string(),
                body: "body".to_string(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: Some("abc123".to_string()),
                has_conflicts: Some(true),
                index: 1,
                labels: vec!["ready-for-code-review".to_string()],
                merge_base_sha: None,
                mergeability: Mergeability::Conflicting,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: "https://example.com/pulls/1".to_string(),
            };

            let state = test_state_with_read(
                FakeReadService::with_get_change_request(cr),
                vec!["test-forge/org/repo".to_string()],
                Arc::new(FakeWriteService::new()),
            );

            let app = crate::build_router(state, false);
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
            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("parse JSON response");
            assert_eq!(json["mergeability"], "conflicting");
            assert_eq!(json["has_conflicts"], true);
            assert_eq!(json["draft"], serde_json::json!(draft));
            assert_eq!(json["labels"], serde_json::json!(["ready-for-code-review"]));
        }
    }

    #[tokio::test]
    async fn list_pulls_serializes_mergeability_and_has_conflicts() {
        for draft in [Some(true), Some(false), None] {
            let crs = vec![ChangeRequest {
                draft,
                base_branch: "main".to_string(),
                body: "body".to_string(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: Some("abc123".to_string()),
                has_conflicts: Some(false),
                index: 1,
                labels: vec![],
                merge_base_sha: None,
                mergeability: Mergeability::Mergeable,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: "https://example.com/pulls/1".to_string(),
            }];

            let state = test_state_with_read(
                FakeReadService::with_list_change_requests(crs),
                vec!["test-forge/org/repo".to_string()],
                Arc::new(FakeWriteService::new()),
            );

            let app = crate::build_router(state, false);
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
            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("parse JSON response");
            assert_eq!(json[0]["mergeability"], "mergeable");
            assert_eq!(json[0]["has_conflicts"], false);
            assert_eq!(json[0]["draft"], serde_json::json!(draft));
            assert!(json[0]["labels"].is_array());
        }
    }

    #[tokio::test]
    async fn post_patches_rejects_wrong_branch_per_agent_policy() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            github_app: std::collections::HashMap::new(),
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
            test_forge_instance(
                "test-forge",
                "https://forge.example",
                Arc::new(FakeWriteService::new()),
            ),
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
            github_app: std::collections::HashMap::new(),
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
            test_forge_instance(
                "test-forge",
                "https://forge.example",
                Arc::new(FakeWriteService::new()),
            ),
        );
        forges.insert(
            "other-forge".to_string(),
            test_forge_instance(
                "other-forge",
                "https://other.example",
                Arc::new(FakeWriteService::new()),
            ),
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
            github_app: std::collections::HashMap::new(),
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
            github_app: std::collections::HashMap::new(),
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
    async fn narrow_pull_reads_preserve_scope_and_access_control() {
        for (endpoint, kind) in [("reviews", "review"), ("discussion-comments", "comment")] {
            for (forge, repo, token, expected) in [
                ("test-forge", "repo", "test-token", StatusCode::OK),
                (
                    "test-forge",
                    "repo",
                    "wrong-token",
                    StatusCode::UNAUTHORIZED,
                ),
                ("test-forge", "denied", "test-token", StatusCode::FORBIDDEN),
                ("unknown", "repo", "test-token", StatusCode::NOT_FOUND),
            ] {
                let response = crate::build_router(test_state(), false)
                    .oneshot(
                        Request::builder()
                            .uri(format!(
                                "/api/v1/repos/{forge}/org/{repo}/pulls/1/{endpoint}"
                            ))
                            .header("authorization", format!("Bearer {token}"))
                            .body(Body::empty())
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                assert_eq!(response.status(), expected);
                if expected == StatusCode::OK {
                    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                        .await
                        .expect("body");
                    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
                    let entries = json.as_array().expect("entries");
                    assert_eq!(entries.len(), 1);
                    assert_eq!(entries[0]["kind"], kind);
                }
            }
        }
    }

    #[test]
    fn openapi_retains_mixed_and_write_routes_with_narrow_reads() {
        use utoipa::OpenApi;
        let api = serde_json::to_value(crate::ApiDoc::openapi()).expect("OpenAPI");
        for (endpoint, methods) in [
            ("reviews", vec!["get", "post"]),
            ("discussion-comments", vec!["get"]),
            ("comments", vec!["get", "post"]),
        ] {
            let path =
                format!("/api/v1/repos/{{forge}}/{{owner}}/{{repo}}/pulls/{{index}}/{endpoint}");
            for method in methods {
                assert!(api["paths"][&path][method].is_object());
            }
        }
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

    #[tokio::test]
    async fn patch_issue_close_without_message_returns_400() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({
            "state": "closed"
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("parse JSON response");
        assert!(
            json["error"]
                .as_str()
                .expect("error field is a string")
                .contains("message is required"),
        );
    }

    #[tokio::test]
    async fn diagnostics_detached_webhook_failure_preserves_correlation() {
        let mut write = FakeWriteService::new();
        write.auto_merge_error = Some("upstream Bearer background-secret".into());
        let write = Arc::new(write);
        let (state, mut events) = webhook_test_state(true, Arc::clone(&write));
        let capture = crate::diagnostics::tests::Capture::default();
        let response = crate::build_router(state, false)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/forges/test-forge/webhook")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .with_subscriber(capture.subscriber())
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        for _ in 0..2 {
            assert!(
                tokio::time::timeout(Duration::from_secs(2), events.recv())
                    .await
                    .expect("event deadline")
                    .is_some()
            );
        }
        let logs = capture.logs();
        let accepted = logs
            .lines()
            .find(|line| line.contains("webhook accepted"))
            .expect("accepted log");
        let failed = logs
            .lines()
            .find(|line| line.contains("failed to schedule"))
            .expect("failure log");
        let correlation = accepted
            .split("request_id=")
            .nth(1)
            .expect("request id")
            .split_whitespace()
            .next()
            .expect("id value");
        assert!(failed.contains(correlation), "{logs}");
        for expected in [
            "system",
            "auto-merge",
            "test-forge",
            "org",
            "repo",
            "42",
            "approved-review-delivery",
            "forge_default",
            "scheduling",
        ] {
            assert!(failed.contains(expected), "{failed}");
        }
        for secret in [
            "background-secret",
            "forge-fallback-token",
            "distinctive-webhook-secret",
        ] {
            assert!(!logs.contains(secret), "{logs}");
        }
        let records = write.captured_auto_merge.lock().expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0.agent.agent_id, "system");
    }

    #[tokio::test]
    async fn diagnostics_auto_merge_skip_reasons() {
        use forge::ForgeWebhookAdapter;
        let service = test_auto_merge_service();
        let event = ApprovedReviewWebhookAdapter
            .verify_and_parse_webhook_event(
                &[],
                b"{}",
                "test-forge",
                ForgeKind::Forgejo,
                "https://forge.example",
                "",
            )
            .expect("event")
            .expect("review");
        let review = match event {
            domain::WebhookEvent::PullRequestReview(review) => Some(review),
            _ => None,
        }
        .expect("review fixture");
        let capture = crate::diagnostics::tests::Capture::default();
        async {
            let enqueued = crate::events::PublishStatus::Enqueued { delivered: 1 };
            assert!(spawn_review_auto_merge(review.clone(), &enqueued, false, &service).is_none());
            assert!(
                spawn_review_auto_merge(
                    review.clone(),
                    &crate::events::PublishStatus::Duplicate,
                    true,
                    &service
                )
                .is_none()
            );
            let mut edited = review.clone();
            edited.action = domain::PullRequestReviewEventAction::Edited;
            assert!(spawn_review_auto_merge(edited, &enqueued, true, &service).is_none());
            let mut comment = review;
            comment.review_state = Some(domain::ReviewState::Comment);
            assert!(spawn_review_auto_merge(comment, &enqueued, true, &service).is_none());
        }
        .with_subscriber(capture.subscriber())
        .await;
        let logs = capture.logs();
        for reason in [
            "auto_merge_disabled",
            "duplicate_delivery",
            "review_not_submitted",
            "review_not_approved",
        ] {
            assert!(logs.contains(reason), "{logs}");
        }
    }

    #[tokio::test]
    async fn webhook_approval_does_not_schedule_when_auto_merge_disabled() {
        let write_svc = Arc::new(FakeWriteService::new());
        let (state, mut events) = webhook_test_state(false, Arc::clone(&write_svc));
        let app = crate::build_router(state, false);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/forges/test-forge/webhook")
                    .body(Body::from("{}"))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let published = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("event should be published");
        assert!(published.is_some());
        assert!(
            write_svc
                .captured_auto_merge
                .lock()
                .expect("poisoned")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn webhook_approval_schedules_when_auto_merge_enabled() {
        let write_svc = Arc::new(FakeWriteService::new());
        let (state, mut events) = webhook_test_state(true, Arc::clone(&write_svc));
        let app = crate::build_router(state, false);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/forges/test-forge/webhook")
                    .body(Body::from("{}"))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(events.recv().await.is_some());
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            write_svc.auto_merge_called.notified(),
        )
        .await
        .expect("schedule completed");
        let records = write_svc.captured_auto_merge.lock().expect("poisoned");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0.merge_style, None);
        assert_eq!(records[0].0.delete_branch_after_merge, None);
        assert_eq!(records[0].1.as_deref(), Some("forge-fallback-token"));
    }

    #[tokio::test]
    async fn schedule_auto_merge_without_style_uses_caller_forge_identity() {
        let write_svc = Arc::new(FakeWriteService::new());
        let app = crate::build_router(test_state_with_write(Arc::clone(&write_svc)), false);
        let body = serde_json::json!({"expected_head_sha": "abc123"});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/pulls/42/automerge")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let records = write_svc.captured_auto_merge.lock().expect("poisoned");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0.merge_style, None);
        assert_eq!(records[0].1.as_deref(), Some("caller-forge-token"));
        assert_ne!(records[0].1.as_deref(), Some("forge-fallback-token"));
    }

    #[tokio::test]
    async fn schedule_auto_merge_preserves_explicit_style() {
        let write_svc = Arc::new(FakeWriteService::new());
        let app = crate::build_router(test_state_with_write(Arc::clone(&write_svc)), false);
        let body = serde_json::json!({
            "expected_head_sha": "abc123",
            "merge_style": "rebase-merge"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/pulls/42/automerge")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let records = write_svc.captured_auto_merge.lock().expect("poisoned");
        assert_eq!(records[0].0.merge_style.as_deref(), Some("rebase-merge"));
    }

    #[tokio::test]
    async fn patch_issue_close_with_message_succeeds() {
        let write_svc = Arc::new(FakeWriteService::new());
        let app = crate::build_router(test_state_with_write(Arc::clone(&write_svc)), false);
        let body = serde_json::json!({
            "state": "closed",
            "message": "fixes done"
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
        let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("parse JSON response");
        assert_eq!(json["state"], "closed");

        assert_eq!(
            write_svc
                .captured_close_msg
                .lock()
                .expect("poisoned lock")
                .as_deref(),
            Some("fixes done"),
            "handler must forward the validated message to CloseIssueRequest"
        );
    }

    #[tokio::test]
    async fn patch_issue_close_with_blank_message_returns_400() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({
            "state": "closed",
            "message": "   "
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("parse JSON response");
        assert!(
            json["error"]
                .as_str()
                .expect("error field is a string")
                .contains("message is required"),
        );
    }

    #[tokio::test]
    async fn get_pull_ci_details_returns_lowercase_state() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/pulls/1/ci-details")
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

        // Mock state in test_state() should be Failure/Error etc.
        // We want to ensure it's lowercase.
        assert_eq!(json["state"], "failure");
        assert_eq!(json["details"][0]["state"], "failure");
        assert_eq!(
            json["details"][0]["resolution"]["provider"],
            "github_actions"
        );
        assert_eq!(
            json["details"][0]["resolution"]["failed_steps"][0]["log_excerpt"]["lines"][0],
            "error log"
        );
    }

    #[tokio::test]
    async fn list_branches_allowed_repo_returns_200() {
        let branches_resp = ListBranchesResponse {
            branches: vec![Branch {
                name: "main".to_string(),
                commit_sha: "abc123".to_string(),
            }],
            truncated: false,
        };
        let read_svc = FakeReadService::with_list_branches(branches_resp);
        let state = test_state_with_read(
            read_svc,
            vec!["test-forge/org/repo".to_string()],
            Arc::new(FakeWriteService::new()),
        );
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/branches")
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
        assert_eq!(json["branches"][0]["name"], "main");
        assert!(json["truncated"].as_bool() == Some(false));
    }

    #[tokio::test]
    async fn list_branches_unauthorized_repo_returns_403() {
        let branches_resp = ListBranchesResponse {
            branches: vec![],
            truncated: false,
        };
        let read_svc = FakeReadService::with_list_branches(branches_resp);
        let state = test_state_with_read(
            read_svc,
            vec!["test-forge/org/other".to_string()],
            Arc::new(FakeWriteService::new()),
        );
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/branches")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_branch_allowed_repo_returns_200() {
        let branch_details = BranchDetails {
            exists: true,
            name: "feature".to_string(),
            commit_sha: Some("def456".to_string()),
        };
        let read_svc = FakeReadService::with_get_branch(branch_details);
        let state = test_state_with_read(
            read_svc,
            vec!["test-forge/org/repo".to_string()],
            Arc::new(FakeWriteService::new()),
        );
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/branches/by-name?branch=feature")
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
        assert_eq!(json["name"], "feature");
        assert_eq!(json["commit_sha"], "def456");
        assert!(json["exists"].as_bool() == Some(true));
    }

    #[tokio::test]
    async fn get_branch_unauthorized_repo_returns_403() {
        let branch_details = BranchDetails {
            exists: true,
            name: "main".to_string(),
            commit_sha: Some("abc123".to_string()),
        };
        let read_svc = FakeReadService::with_get_branch(branch_details);
        let state = test_state_with_read(
            read_svc,
            vec!["test-forge/org/other".to_string()],
            Arc::new(FakeWriteService::new()),
        );
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/branches/by-name?branch=main")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_issue_dependencies_returns_authoritative_metadata_and_arrays() {
        let issue = domain::Issue {
            assignees: vec![],
            body: String::new(),
            index: 2,
            labels: vec![],
            state: "closed".to_string(),
            title: "Dependency".to_string(),
            url: "https://forge.example/org/repo/issues/2".to_string(),
        };
        let read_svc = FakeReadService::with_issue_dependencies(Ok(domain::IssueDependencies {
            blocks: vec![],
            depends_on: vec![issue.clone()],
            depends_on_read_contract: Some(domain::DependsOnReadContract::ExhaustiveV1),
            opaque_depends_on_count: Some(0),
        }));
        let state = test_state_with_read(
            read_svc,
            vec!["test-forge/org/repo".to_string()],
            Arc::new(FakeWriteService::new()),
        );
        let response = crate::build_router(state, false)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies")
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
        assert_eq!(
            json,
            serde_json::json!({
                "blocks": [],
                "depends_on": [issue],
                "depends_on_read_contract": "exhaustive-v1",
                "opaque_depends_on_count": 0
            })
        );
    }

    #[tokio::test]
    async fn get_issue_dependencies_upstream_failure_has_no_authoritative_metadata() {
        let read_svc = FakeReadService::with_issue_dependencies(Err(ServiceError::Upstream(
            "dependency response failed".to_string(),
        )));
        let state = test_state_with_read(
            read_svc,
            vec!["test-forge/org/repo".to_string()],
            Arc::new(FakeWriteService::new()),
        );
        let response = crate::build_router(state, false)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON response");
        assert!(json.get("depends_on_read_contract").is_none());
        assert!(json.get("opaque_depends_on_count").is_none());
    }

    #[tokio::test]
    async fn add_issue_dependency_rejects_owner_only() {
        let state = test_state();
        let app = crate::build_router(state, false);
        let body = serde_json::json!({
            "dependency": 2,
            "dependency_owner": "other-org"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies")
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
                .expect("error field")
                .contains("must both be provided or both omitted")
        );
    }

    #[tokio::test]
    async fn add_issue_dependency_rejects_repo_only() {
        let state = test_state();
        let app = crate::build_router(state, false);
        let body = serde_json::json!({
            "dependency": 2,
            "dependency_repo": "other-repo"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies")
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

    #[tokio::test]
    async fn remove_issue_dependency_rejects_owner_only() {
        let state = test_state();
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies/2?dependency_owner=other-org")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
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
                .expect("error field")
                .contains("must both be provided or both omitted")
        );
    }

    #[tokio::test]
    async fn remove_issue_dependency_rejects_repo_only() {
        let state = test_state();
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies/2?dependency_repo=other-repo")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn add_issue_dependency_forbidden_cross_repo() {
        // Agent is authorized for org/repo but NOT for other-org/other-repo
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            github_app: std::collections::HashMap::new(),
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
            test_forge_instance(
                "test-forge",
                "https://forge.example",
                Arc::new(FakeWriteService::new()),
            ),
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
            "dependency": 5,
            "dependency_owner": "other-org",
            "dependency_repo": "other-repo"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON body"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn remove_issue_dependency_forbidden_cross_repo() {
        // Agent is authorized for org/repo but NOT for other-org/other-repo
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            github_app: std::collections::HashMap::new(),
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
            test_forge_instance(
                "test-forge",
                "https://forge.example",
                Arc::new(FakeWriteService::new()),
            ),
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
                    .method("DELETE")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies/5?dependency_owner=other-org&dependency_repo=other-repo")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn add_issue_dependency_allowed_cross_repo() {
        // Agent is authorized for both repos
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            github_app: std::collections::HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos: vec![
                    "test-forge/org/repo".to_string(),
                    "test-forge/other-org/other-repo".to_string(),
                ],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let write_svc = Arc::new(FakeWriteService::new());
        let mut forges = std::collections::HashMap::new();
        forges.insert(
            "test-forge".to_string(),
            test_forge_instance(
                "test-forge",
                "https://forge.example",
                Arc::clone(&write_svc),
            ),
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
            "dependency": 5,
            "dependency_owner": "other-org",
            "dependency_repo": "other-repo"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies")
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
        // Verify dependency_repository reached the write service
        let captured = write_svc.captured_add_dep.lock().expect("poisoned");
        let req = captured.as_ref().expect("request should be captured");
        let dep_repo = req.dependency_repository.as_ref().expect("dep repo set");
        assert_eq!(dep_repo.owner, "other-org");
        assert_eq!(dep_repo.name, "other-repo");
    }

    #[tokio::test]
    async fn remove_issue_dependency_allowed_cross_repo() {
        // Agent is authorized for both repos
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            forge_identity: std::collections::HashMap::new(),
            github_app: std::collections::HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos: vec![
                    "test-forge/org/repo".to_string(),
                    "test-forge/other-org/other-repo".to_string(),
                ],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];

        let write_svc = Arc::new(FakeWriteService::new());
        let mut forges = std::collections::HashMap::new();
        forges.insert(
            "test-forge".to_string(),
            test_forge_instance(
                "test-forge",
                "https://forge.example",
                Arc::clone(&write_svc),
            ),
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
                    .method("DELETE")
                    .uri("/api/v1/repos/test-forge/org/repo/issues/1/dependencies/5?dependency_owner=other-org&dependency_repo=other-repo")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        // Verify dependency_repository reached the write service
        let captured = write_svc.captured_remove_dep.lock().expect("poisoned");
        let req = captured.as_ref().expect("request should be captured");
        let dep_repo = req.dependency_repository.as_ref().expect("dep repo set");
        assert_eq!(dep_repo.owner, "other-org");
        assert_eq!(dep_repo.name, "other-repo");
    }
}

#[cfg(test)]
#[path = "change_request_terminal_webhooks.rs"]
mod change_request_terminal_webhooks;
