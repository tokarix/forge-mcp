//! HTTP control plane for forge-mcp.

pub mod api;
pub mod auth;
pub mod config;
pub mod handlers;

use axum::{Router, routing::get, routing::post};
use handlers::AppState;

/// Builds the axum router with all API routes.
/// When `enable_docs` is true, serves Scalar UI at `/api/v1/docs`.
pub fn build_router(state: AppState, enable_docs: bool) -> Router {
    let mut router = Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/contents/{*path}",
            get(handlers::get_contents),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/patches",
            post(handlers::post_patches),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls",
            get(handlers::list_pulls).post(handlers::post_pulls),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{index}",
            get(handlers::get_pull),
        );

    if enable_docs {
        // Scalar UI added in Task 8
        let _ = &mut router;
    }

    router.with_state(state)
}
