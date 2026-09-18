#[path = "support/cancellation.rs"]
mod cancellation;
mod support;

use domain::{ForgeCredential, ForgeKind, RepositoryRef};
use forge::{ForgeAdapter, ForgejoAdapter, ForgejoConfig};
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

#[derive(Deserialize)]
struct PullResponse {
    number: u64,
}

#[derive(Deserialize)]
struct FeedbackResponse {
    id: u64,
}

async fn create_feedback_fixture(
    context: &Context,
    repository: &str,
) -> Result<(u64, u64, u64), String> {
    let base = format!("/api/v1/repos/{}/{repository}", context.username);
    context
        .request_success(
            Method::POST,
            &format!("{base}/branches"),
            Some(json!({
                "new_branch_name": "feedback", "old_branch_name": "main"
            })),
        )
        .await?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/contents/feedback.txt"),
            Some(json!({
                "branch": "feedback", "content": "ZmVlZGJhY2sK", "message": "Add feedback fixture"
            })),
        )
        .await?;
    let pull: PullResponse = context
        .request_json(
            Method::POST,
            &format!("{base}/pulls"),
            Some(json!({
                "base": "main", "head": "feedback", "title": "Feedback separation"
            })),
        )
        .await?;
    let index = pull.number;
    let discussion: FeedbackResponse = context
        .request_json(
            Method::POST,
            &format!("{base}/issues/{index}/comments"),
            Some(json!({"body": "discussion only"})),
        )
        .await?;
    // COMMENT permits the fixture owner to review its own PR.
    let review: FeedbackResponse = context
        .request_json(
            Method::POST,
            &format!("{base}/pulls/{index}/reviews"),
            Some(json!({"body": "formal review only", "event": "COMMENT"})),
        )
        .await?;
    Ok((index, discussion.id, review.id))
}

async fn verify_feedback_separation(context: &Context, repository: &str) -> Result<(), String> {
    let (index, discussion_id, review_id) = create_feedback_fixture(context, repository).await?;
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: context.base_url.to_string(),
        token: None,
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .map_err(|error| error.to_string())?;
    let repository = RepositoryRef {
        alias: "ci".into(),
        forge: ForgeKind::Forgejo,
        host: context.base_url.to_string(),
        owner: context.username.clone(),
        name: repository.into(),
    };
    let credential = ForgeCredential {
        token: Some(context.token().into()),
    };
    let discussion = adapter
        .get_change_request_discussion_comments(&repository, index, &credential)
        .await
        .map_err(|error| error.to_string())?;
    let reviews = adapter
        .get_change_request_reviews(&repository, index, &credential)
        .await
        .map_err(|error| error.to_string())?;
    let mixed = adapter
        .get_change_request_comments(&repository, index, &credential)
        .await
        .map_err(|error| error.to_string())?;
    if discussion.len() != 1
        || discussion[0].id != discussion_id
        || discussion[0].kind != "comment"
        || discussion[0].body != "discussion only"
        || discussion[0].commit_id.is_some()
        || discussion[0].review_state.is_some()
    {
        return Err("discussion read did not contain exactly the discussion fixture".into());
    }
    if reviews.len() != 1
        || reviews[0].id != review_id
        || reviews[0].kind != "review"
        || reviews[0].body != "formal review only"
        || reviews[0].review_state.as_deref() != Some("COMMENT")
    {
        return Err("review read did not contain exactly the formal review fixture".into());
    }
    if mixed.len() != 2 || !mixed.contains(&discussion[0]) || !mixed.contains(&reviews[0]) {
        return Err("mixed read did not retain both feedback fixtures".into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
async fn forgejo_feedback_separation() -> Result<(), String> {
    let repository = unique_name("forge-mcp-feedback")?;
    let context = Context::connect_from_env().await?;
    let mut repository_needs_cleanup = false;
    let primary =
        async {
            context.request_success(Method::POST, "/api/v1/user/repos", Some(json!({
            "auto_init": true, "default_branch": "main", "name": repository, "private": true
        }))).await?;
            repository_needs_cleanup = true;
            verify_feedback_separation(&context, &repository).await
        }
        .await;
    // Verification uses Result rather than panicking assertions so cleanup also
    // runs when the provider violates the separation contract.
    let mut cleanup = Vec::new();
    if repository_needs_cleanup {
        cleanup.push(context.delete_repository(&repository).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}
