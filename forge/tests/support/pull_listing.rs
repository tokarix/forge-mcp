//! Uses only the existing disposable CI provider and its fixture credentials.
use super::support::forgejo::{Context, combine_results, unique_name};
use domain::{ChangeRequestFilter, ForgeCredential, ForgeKind, RepositoryRef};
use forge::{ForgeAdapter, ForgejoAdapter, ForgejoConfig};
use reqwest::Method;
use serde_json::{Value, json};
use std::time::Duration;

async fn branch(context: &Context, base: &str, name: &str) -> Result<(), String> {
    context
        .request_success(
            Method::POST,
            &format!("{base}/branches"),
            Some(json!({"new_branch_name":name,"old_branch_name":"main"})),
        )
        .await?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/contents/{name}.txt"),
            Some(json!({"branch":name,"content":"Zml4dHVyZQo=","message":"Listing fixture"})),
        )
        .await?;
    Ok(())
}

async fn create(context: &Context, base: &str, head: &str) -> Result<u64, String> {
    let value: Value = context
        .request_json(
            Method::POST,
            &format!("{base}/pulls"),
            Some(json!({"base":"main","head":head,"title":"Listing fixture"})),
        )
        .await?;
    value["number"]
        .as_u64()
        .ok_or_else(|| "missing PR number".into())
}

async fn verify(context: &Context, name: &str) -> Result<(), String> {
    let base = format!("/api/v1/repos/{}/{name}", context.username);
    branch(context, &base, "reused").await?;
    // Closed PRs may reuse a head branch. This creates a real second page
    // without manufacturing 101 independent commits or changing service config.
    for _ in 0..101 {
        let index = create(context, &base, "reused").await?;
        context
            .request_success(
                Method::PATCH,
                &format!("{base}/pulls/{index}"),
                Some(json!({"state":"closed"})),
            )
            .await?;
    }
    let merged = create(context, &base, "reused").await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let value: Value = context
                .request_json(Method::GET, &format!("{base}/pulls/{merged}"), None)
                .await?;
            if value["mergeable"] == true {
                return Ok::<_, String>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "listing fixture mergeability timed out".to_string())??;
    context
        .request_success(
            Method::POST,
            &format!("{base}/pulls/{merged}/merge"),
            Some(json!({"do":"merge","delete_branch_after_merge":false})),
        )
        .await?;
    branch(context, &base, "open").await?;
    let open = create(context, &base, "open").await?;
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: context.base_url.to_string(),
        token: None,
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .map_err(|e| e.to_string())?;
    let repo = RepositoryRef {
        alias: "ci".into(),
        forge: ForgeKind::Forgejo,
        host: context.base_url.to_string(),
        owner: context.username.clone(),
        name: name.into(),
    };
    let credential = ForgeCredential {
        token: Some(context.token().into()),
    };
    for (filter, count) in [
        (ChangeRequestFilter::All, 103),
        (ChangeRequestFilter::Closed, 101),
        (ChangeRequestFilter::Merged, 1),
        (ChangeRequestFilter::Open, 1),
    ] {
        let pulls = adapter
            .list_change_requests(&repo, Some(&filter), &credential)
            .await
            .map_err(|e| e.to_string())?;
        if pulls.len() != count || pulls.iter().any(|pr| !filter.matches(&pr.state)) {
            return Err(format!(
                "{filter:?}: expected {count} matching PRs, got {}",
                pulls.len()
            ));
        }
        if filter == ChangeRequestFilter::All
            && (!pulls.iter().any(|pr| pr.index == 1)
                || !pulls.iter().any(|pr| pr.index == merged)
                || !pulls.iter().any(|pr| pr.index == open))
        {
            return Err("all listing omitted an old, merged, or open PR".into());
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
async fn forgejo_exhaustive_pull_states() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let repository = unique_name("forge-mcp-pull-list")?;
    let mut created = false;
    let primary = async {
        context
            .request_success(
                Method::POST,
                "/api/v1/user/repos",
                Some(json!({
                    "auto_init":true,"default_branch":"main","name":repository,"private":true
                })),
            )
            .await?;
        created = true;
        verify(&context, &repository).await
    }
    .await;
    let mut cleanup = Vec::new();
    if created {
        cleanup.push(context.delete_repository(&repository).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}
