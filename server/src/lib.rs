//! HTTP control plane for forge-mcp.
// The utoipa OpenApi derive macro generates code that triggers this lint.
#![allow(clippy::needless_for_each)]

pub mod api;
pub mod auth;
pub mod auto_merge;
pub mod config;
pub mod events;
pub mod git_proxy;
pub mod handlers;
pub mod registry;

use axum::{Router, routing::delete, routing::get, routing::post};
use handlers::AppState;
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::add_issue_label,
        handlers::agent_events,
        handlers::close_pull,
        handlers::comment_on_issue,
        handlers::comment_on_pull,
        handlers::create_issue,
        handlers::get_contents,
        handlers::get_issue,
        handlers::get_issue_comments,
        handlers::get_pull,
        handlers::get_pull_comments,
        handlers::get_pull_diff,
        handlers::list_issues,
        handlers::list_pulls,
        handlers::post_patches,
        handlers::post_pulls,
        handlers::post_rebase,
        handlers::remove_issue_label,
        handlers::schedule_auto_merge,
        handlers::submit_pull_review,
        handlers::update_issue,
        handlers::update_pull,
    ),
    components(schemas(
        api::AddIssueLabelBody,
        api::CommentBody,
        api::CommentOnIssueBody,
        api::CommitPatchBody,
        api::CommitPatchResult,
        api::ContentsResult,
        api::CreateIssueBody,
        api::ErrorBody,
        api::OpenPullBody,
        api::RebaseBranchBody,
        api::RebaseBranchResult,
        api::RebaseOperationBody,
        api::ScheduleAutoMergeBody,
        api::SubmitReviewBody,
        api::UpdateChangeRequestBody,
        api::UpdateIssueBody,
    )),
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .build(),
            ),
        );
    }
}

fn add_docs_routes(router: Router<AppState>) -> Router<AppState> {
    router.merge(Scalar::with_url("/api/v1/docs", ApiDoc::openapi()))
}

/// Builds the axum router with all API routes.
/// When `enable_docs` is true, serves Scalar UI at `/api/v1/docs`.
pub fn build_router(state: AppState, enable_docs: bool) -> Router {
    let mut router = Router::new()
        .route("/api/v1/agent/info", get(handlers::agent_info))
        .route("/api/v1/agent/events", get(handlers::agent_events))
        .route(
            "/api/v1/forges/{forge}/webhook",
            post(handlers::post_webhook),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/contents/{*path}",
            get(handlers::get_contents),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/patches",
            post(handlers::post_patches),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/issues",
            get(handlers::list_issues).post(handlers::create_issue),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}",
            get(handlers::get_issue).patch(handlers::update_issue),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/comments",
            get(handlers::get_issue_comments).post(handlers::comment_on_issue),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/labels",
            post(handlers::add_issue_label),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}/labels/{label}",
            delete(handlers::remove_issue_label),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls",
            get(handlers::list_pulls).post(handlers::post_pulls),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/rebase",
            post(handlers::post_rebase),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}",
            delete(handlers::close_pull)
                .get(handlers::get_pull)
                .patch(handlers::update_pull),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge",
            post(handlers::schedule_auto_merge),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/checks",
            get(handlers::get_pull_checks),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/comments",
            get(handlers::get_pull_comments).post(handlers::comment_on_pull),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/diff",
            get(handlers::get_pull_diff),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/reviews",
            post(handlers::submit_pull_review),
        )
        .route(
            "/git/{forge}/{owner}/{repo}/git-receive-pack",
            post(git_proxy::receive_pack_rejected),
        )
        .route(
            "/git/{forge}/{owner}/{repo}/git-upload-pack",
            post(git_proxy::upload_pack),
        )
        .route(
            "/git/{forge}/{owner}/{repo}/info/refs",
            get(git_proxy::info_refs),
        );

    if enable_docs {
        router = add_docs_routes(router);
    }

    router.with_state(state)
}
