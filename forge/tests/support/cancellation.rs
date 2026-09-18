//! Executed only by the existing provider lane; never starts a provider.
use super::support::forgejo::{Context, combine_results, unique_name};
use domain::{
    CancelAutoMergeError, CancellationUncertainty, ForgeCredential, ForgeKind, RepositoryRef,
};
use forge::{ForgeAdapter, ForgejoAdapter, ForgejoConfig};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

fn ambiguous() -> Result<(), CancelAutoMergeError> {
    Err(CancelAutoMergeError::Uncertain {
        status: Some(404),
        reason: CancellationUncertainty::Ambiguous404,
    })
}

#[allow(clippy::needless_pass_by_value)] // Accept temporary fixture values without borrowed boilerplate.
fn require<T: std::fmt::Debug + PartialEq>(
    actual: T,
    expected: T,
    stage: &str,
) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{stage}: expected {expected:?}, received {actual:?}"
        ))
    }
}

async fn pull(context: &Context, base: &str, index: u64) -> Result<Value, String> {
    context
        .request_json(Method::GET, &format!("{base}/pulls/{index}"), None)
        .await
}

async fn held(context: &Context, base: &str, head: &str) -> Result<(), String> {
    let protection: Value = context
        .request_json(
            Method::GET,
            &format!("{base}/branch_protections/main"),
            None,
        )
        .await?;
    require(
        protection["enable_status_check"].clone(),
        json!(true),
        "status check enabled",
    )?;
    require(
        protection["apply_to_admins"].clone(),
        json!(true),
        "admin hold",
    )?;
    require(
        protection["status_check_contexts"].clone(),
        json!(["cancel-fixture/hold"]),
        "required context",
    )?;
    let status: Value = context
        .request_json(Method::GET, &format!("{base}/commits/{head}/status"), None)
        .await?;
    require(status["state"].clone(), json!("pending"), "held check")
}

async fn make_pull(context: &Context, base: &str, branch: &str) -> Result<u64, String> {
    context
        .request_success(
            Method::POST,
            &format!("{base}/branches"),
            Some(json!({"new_branch_name":branch,"old_branch_name":"main"})),
        )
        .await?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/contents/{branch}.txt"),
            Some(
                json!({"branch":branch,"content":"Y2FuY2VsCg==","message":"Cancellation fixture"}),
            ),
        )
        .await?;
    let pr: Value = context
        .request_json(
            Method::POST,
            &format!("{base}/pulls"),
            Some(json!({"base":"main","head":branch,"title":"Cancellation fixture"})),
        )
        .await?;
    let index = pr["number"].as_u64().ok_or("missing PR index")?;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if pull(context, base, index).await?["mergeable"] == true {
                return Ok(index);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "fixture mergeability timed out".to_string())?
}

async fn user_token(
    context: &Context,
    user: &str,
    password: &str,
    scope: &str,
) -> Result<ForgeCredential, String> {
    let response = context
        .client
        .post(
            context
                .base_url
                .join(&format!("api/v1/users/{user}/tokens"))
                .map_err(|_| "invalid token URL")?,
        )
        .basic_auth(user, Some(password))
        .json(&json!({"name":unique_name("cancel-token")?,"scopes":[scope]}))
        .send()
        .await
        .map_err(|_| "token creation transport failure")?;
    require(response.status(), StatusCode::CREATED, "reader token")?;
    let body: Value = response
        .json()
        .await
        .map_err(|_| "invalid token response")?;
    Ok(ForgeCredential {
        token: Some(body["sha1"].as_str().ok_or("missing reader token")?.into()),
    })
}

#[allow(clippy::too_many_lines)] // Keep the ordered provider truth table and held fixture together.
async fn verify(context: &Context, name: &str, reader: &str, password: &str) -> Result<(), String> {
    let base = format!("/api/v1/repos/{}/{name}", context.username);
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: context.base_url.to_string(),
        token: Some(context.token().into()),
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .map_err(|_| "adapter initialization failed")?;
    let repo = RepositoryRef {
        alias: "ci".into(),
        forge: ForgeKind::Forgejo,
        host: context.base_url.to_string(),
        owner: context.username.clone(),
        name: name.into(),
    };
    let owner = ForgeCredential {
        token: Some(context.token().into()),
    };
    let index = make_pull(context, &base, "pending").await?;
    let original = pull(context, &base, index).await?;
    let head = original["head"]["sha"].as_str().ok_or("missing head")?;
    require(
        adapter.cancel_auto_merge(&repo, index, &owner).await,
        ambiguous(),
        "never scheduled",
    )?;
    require(
        adapter.cancel_auto_merge(&repo, 999_999, &owner).await,
        ambiguous(),
        "missing PR",
    )?;
    require(
        adapter
            .cancel_auto_merge(
                &repo,
                index,
                &ForgeCredential {
                    token: Some("invalid-token".into()),
                },
            )
            .await,
        Err(CancelAutoMergeError::Unauthorized),
        "invalid caller must not fall back",
    )?;

    // A valid user with no access must not be treated as absent or successful.
    let outsider = user_token(context, reader, password, "all").await?;
    require(
        adapter.cancel_auto_merge(&repo, index, &outsider).await,
        ambiguous(),
        "private PR",
    )?;
    context
        .request_success(
            Method::PUT,
            &format!("{base}/collaborators/{reader}"),
            Some(json!({"permission":"read"})),
        )
        .await?;
    let readable = adapter
        .get_change_request(&repo, index, &outsider)
        .await
        .map_err(|_| "read collaborator cannot read fixture")?;
    require(readable.index, index, "readable identity")?;
    require(
        adapter.cancel_auto_merge(&repo, index, &outsider).await,
        ambiguous(),
        "readable absent schedule",
    )?;
    let scoped = user_token(context, reader, password, "read:repository").await?;
    require(
        adapter.cancel_auto_merge(&repo, index, &scoped).await,
        Err(CancelAutoMergeError::Forbidden),
        "insufficient token scope",
    )?;

    context.request_success(Method::POST, &format!("{base}/statuses/{head}"),
        Some(json!({"context":"cancel-fixture/hold","state":"pending","description":"Keep fixture unmergeable"}))).await?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/branch_protections"),
            Some(
                json!({"rule_name":"main","enable_push":true,"enable_status_check":true,
            "status_check_contexts":["cancel-fixture/hold"],"apply_to_admins":true}),
            ),
        )
        .await?;
    held(context, &base, head).await?;
    let (status, _) = context
        .request(
            Method::POST,
            &format!("{base}/pulls/{index}/merge"),
            Some(
                json!({"do":"merge","head_commit_id":head,"merge_when_checks_succeed":true,
            "delete_branch_after_merge":false}),
            ),
        )
        .await?;
    require(status, StatusCode::CREATED, "held schedule accepted")?;
    held(context, &base, head).await?;
    require(
        pull(context, &base, index).await?["state"].clone(),
        json!("open"),
        "still open",
    )?;
    require(
        adapter.cancel_auto_merge(&repo, index, &outsider).await,
        Err(CancelAutoMergeError::Forbidden),
        "readable pending schedule lacks cancellation rights",
    )?;
    require(
        adapter.cancel_auto_merge(&repo, index, &owner).await,
        Ok(()),
        "confirmed cancellation",
    )?;
    require(
        adapter.cancel_auto_merge(&repo, index, &owner).await,
        ambiguous(),
        "repeated cancellation",
    )?;
    require(
        adapter.cancel_auto_merge(&repo, index, &outsider).await,
        ambiguous(),
        "masked absence after readable PR",
    )?;
    let after = pull(context, &base, index).await?;
    for field in ["state", "merged"] {
        require(
            after[field].clone(),
            original[field].clone(),
            "cancellation must preserve PR and heads",
        )?;
    }

    for field in ["head", "base"] {
        require(
            after[field]["sha"].clone(),
            original[field]["sha"].clone(),
            "unchanged commits",
        )?;
    }

    // Terminal states are explicit fixture setup, never adapter side effects.
    context
        .request_success(
            Method::PATCH,
            &format!("{base}/pulls/{index}"),
            Some(json!({"state":"closed"})),
        )
        .await?;
    require(
        adapter.cancel_auto_merge(&repo, index, &owner).await,
        ambiguous(),
        "closed PR",
    )?;
    context
        .request_success(
            Method::DELETE,
            &format!("{base}/branch_protections/main"),
            None,
        )
        .await?;
    let merged_index = make_pull(context, &base, "merged").await?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/pulls/{merged_index}/merge"),
            Some(json!({"do":"merge"})),
        )
        .await?;
    require(
        pull(context, &base, merged_index).await?["merged"].clone(),
        json!(true),
        "merged fixture",
    )?;
    require(
        adapter.cancel_auto_merge(&repo, merged_index, &owner).await,
        ambiguous(),
        "merged PR",
    )?;
    require(
        pull(context, &base, merged_index).await?["merged"].clone(),
        json!(true),
        "merge remains completed",
    )
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
async fn forgejo_confirmed_cancellation() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let name = unique_name("cancel")?;
    let reader = unique_name("reader")?;
    let password = format!("Fixture!{}", unique_name("password")?);
    let mut repo_created = false;
    let mut user_created = false;
    let primary = async {
        context
            .request_success(
                Method::POST,
                "/api/v1/user/repos",
                Some(json!({
                    "auto_init":true,"default_branch":"main","name":name,"private":true,
                })),
            )
            .await?;
        repo_created = true;
        // Avoid helper error diagnostics containing the new user's password.
        let response = context
            .client
            .post(
                context
                    .base_url
                    .join("api/v1/admin/users")
                    .map_err(|_| "user URL")?,
            )
            .bearer_auth(context.token())
            .json(
                &json!({"username":reader,"email":format!("{reader}@example.invalid"),
                "password":password,"must_change_password":false,"send_notify":false}),
            )
            .send()
            .await
            .map_err(|_| "user creation transport failure")?;
        require(response.status(), StatusCode::CREATED, "create reader")?;
        user_created = true;
        verify(&context, &name, &reader, &password).await
    }
    .await;
    let mut cleanup = Vec::new();
    if repo_created {
        cleanup.push(context.delete_repository(&name).await);
    }
    // Deleting the disposable user also revokes both of its fixture tokens.
    if user_created {
        cleanup.push(
            context
                .request_success(
                    Method::DELETE,
                    &format!("/api/v1/admin/users/{reader}"),
                    None,
                )
                .await
                .map(|_| ()),
        );
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}
