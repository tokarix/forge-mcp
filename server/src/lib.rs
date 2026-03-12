//! HTTP control plane for forge-mcp.
// The utoipa OpenApi derive macro generates code that triggers this lint.
#![allow(clippy::needless_for_each)]

pub mod api;
pub mod auth;
pub mod config;
pub mod handlers;

use axum::{Router, routing::get, routing::post};
use handlers::AppState;
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::get_contents,
        handlers::get_pull,
        handlers::list_pulls,
        handlers::post_patches,
        handlers::post_pulls,
    ),
    components(schemas(
        api::CommitPatchBody,
        api::CommitPatchResult,
        api::ContentsResult,
        api::ErrorBody,
        api::OpenPullBody,
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
        router = add_docs_routes(router);
    }

    router.with_state(state)
}
