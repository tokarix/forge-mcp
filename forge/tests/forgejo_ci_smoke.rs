mod support;

use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::json;
use support::forgejo::{Context, combine_results, unique_name};

#[derive(Debug, Deserialize)]
struct RepositoryResponse {
    name: String,
    private: bool,
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
async fn forgejo_repository_smoke() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let repository = unique_name("forge-mcp-ci-smoke")?;
    let mut repository_needs_cleanup = false;

    let primary = async {
        let created: RepositoryResponse = context
            .request_json(
                Method::POST,
                "/api/v1/user/repos",
                Some(json!({
                    "auto_init": true,
                    "name": repository,
                    "private": true,
                })),
            )
            .await?;
        repository_needs_cleanup = true;
        if created.name != repository || !created.private {
            return Err(format!(
                "created repository did not match request: {created:?}"
            ));
        }

        let path = format!("/api/v1/repos/{}/{repository}", context.username);
        let fetched: RepositoryResponse = context.request_json(Method::GET, &path, None).await?;
        if fetched.name != repository || !fetched.private {
            return Err(format!(
                "fetched repository did not match request: {fetched:?}"
            ));
        }

        context.delete_repository(&repository).await?;
        repository_needs_cleanup = false;
        let (status, _) = context.request(Method::GET, &path, None).await?;
        if status != StatusCode::NOT_FOUND {
            return Err(format!(
                "deleted repository remained readable: status={status}"
            ));
        }
        Ok(())
    }
    .await;

    let mut cleanup = Vec::new();
    if repository_needs_cleanup {
        cleanup.push(context.delete_repository(&repository).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}
