//! HTTP control plane for forge-mcp.
// The utoipa OpenApi derive macro generates code that triggers this lint.
#![allow(clippy::needless_for_each)]

pub mod api;
pub mod auth;
pub mod config;
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
        handlers::close_pull,
        handlers::comment_on_pull,
        handlers::get_contents,
        handlers::get_pull,
        handlers::get_pull_comments,
        handlers::get_pull_diff,
        handlers::list_pulls,
        handlers::post_patches,
        handlers::post_pulls,
        handlers::post_rebase,
        handlers::schedule_auto_merge,
        handlers::submit_pull_review,
    ),
    components(schemas(
        api::CommentBody,
        api::CommitPatchBody,
        api::CommitPatchResult,
        api::ContentsResult,
        api::ErrorBody,
        api::OpenPullBody,
        api::RebaseBranchBody,
        api::RebaseBranchResult,
        api::RebaseOperationBody,
        api::ScheduleAutoMergeBody,
        api::SubmitReviewBody,
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
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/contents/{*path}",
            get(handlers::get_contents),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/patches",
            post(handlers::post_patches),
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
            delete(handlers::close_pull).get(handlers::get_pull),
        )
        .route(
            "/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge",
            post(handlers::schedule_auto_merge),
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
