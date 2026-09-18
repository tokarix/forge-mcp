// Retained from closed diagnostic PR #236, commit
// 408437b7b5e4363166593b491bd7759a6f1e79b4; extended for issue #237.
mod support;

use std::time::Duration;

use domain::{ForgeCredential, ForgeKind, Mergeability, RepositoryRef};
use forge::{ForgeAdapter, ForgejoAdapter, ForgejoConfig};
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;
use support::forgejo::{Context, combine_results, unique_name};

#[derive(Debug, Deserialize)]
struct Branch {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct Pull {
    number: u64,
    draft: bool,
    mergeable: bool,
    base: Branch,
    head: Branch,
}

// Wait only for the ready baseline/recovery, never for the draft observation:
// waiting away a false conflict would hide precisely the bug being tested.
async fn wait_until_mergeable(context: &Context, path: &str) -> Result<Pull, String> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let pull: Pull = context.request_json(Method::GET, path, None).await?;
            if pull.mergeable && !pull.draft {
                return Ok(pull);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "clean fixture did not become mergeable within 15 seconds".to_string())?
}

async fn verify_draft_is_not_a_conflict(context: &Context, repository: &str) -> Result<(), String> {
    let base = format!("/api/v1/repos/{}/{repository}", context.username);
    context
        .request_success(
            Method::POST,
            &format!("{base}/branches"),
            Some(json!({"new_branch_name": "clean", "old_branch_name": "main"})),
        )
        .await?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/contents/clean.txt"),
            Some(json!({
                "branch": "clean", "content": "Y2xlYW4K", "message": "Add clean fixture"
            })),
        )
        .await?;
    let created: Pull = context
        .request_json(
            Method::POST,
            &format!("{base}/pulls"),
            Some(json!({"base": "main", "head": "clean", "title": "Clean fixture"})),
        )
        .await?;
    let path = format!("{base}/pulls/{}", created.number);
    let clean = wait_until_mergeable(context, &path).await?;
    expect_normalized(
        &observe_normalized(context, repository, created.number).await?,
        false,
        &Mergeability::Mergeable,
        Some(false),
    )?;

    // Forgejo v16 recognizes WIP: via IsWorkInProgress. No commits, base
    // updates, merge attempts or rebases occur between these observations.
    context
        .request_success(
            Method::PATCH,
            &path,
            Some(json!({"title": "WIP: Clean fixture"})),
        )
        .await?;
    let draft: Pull = context.request_json(Method::GET, &path, None).await?;
    if !draft.draft || draft.mergeable {
        return Err(format!(
            "fixture did not enter non-mergeable draft state: {draft:?}"
        ));
    }
    if draft.head.sha != clean.head.sha || draft.base.sha != clean.base.sha {
        return Err("draft transition unexpectedly changed fixture commits".into());
    }

    let normalized = observe_normalized(context, repository, created.number).await?;

    // Complete the round trip even when normalization is wrong. A successful
    // recovery on the identical commits is stronger evidence than false alone.
    context
        .request_success(
            Method::PATCH,
            &path,
            Some(json!({"title": "Clean fixture"})),
        )
        .await?;
    let ready = wait_until_mergeable(context, &path).await?;
    if ready.head.sha != clean.head.sha
        || ready.base.sha != clean.base.sha
        || normalized.head_sha.as_deref() != Some(clean.head.sha.as_str())
    {
        return Err("ready/draft/ready observations refer to different commits".into());
    }
    eprintln!(
        "Forgejo {} PR {}: unchanged base={} head={}; raw mergeable=true/false/true; \
         draft normalization={:?}, has_conflicts={:?}",
        context.version,
        created.number,
        clean.base.sha,
        clean.head.sha,
        normalized.mergeability,
        normalized.has_conflicts
    );
    if normalized.mergeability == Mergeability::Conflicting
        || normalized.has_conflicts == Some(true)
    {
        return Err(
            "false conflict: known-clean draft PR was classified as requiring conflict repair"
                .into(),
        );
    }
    expect_normalized(&normalized, true, &Mergeability::NotMergeable, None)?;
    expect_normalized(
        &observe_normalized(context, repository, created.number).await?,
        false,
        &Mergeability::Mergeable,
        Some(false),
    )?;
    Ok(())
}

async fn observe_normalized(
    context: &Context,
    repository: &str,
    index: u64,
) -> Result<domain::ChangeRequest, String> {
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: context.base_url.to_string(),
        token: None,
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .map_err(|error| error.to_string())?;
    let repo = RepositoryRef {
        alias: "ci".into(),
        forge: ForgeKind::Forgejo,
        host: context.base_url.to_string(),
        owner: context.username.clone(),
        name: repository.into(),
    };
    let credential = ForgeCredential {
        token: Some(context.token().into()),
    };
    let get = adapter
        .get_change_request(&repo, index, &credential)
        .await
        .map_err(|e| e.to_string())?;
    let list = adapter
        .list_change_requests(&repo, None, &credential)
        .await
        .map_err(|e| e.to_string())?;
    let listed = list
        .iter()
        .find(|request| request.index == index)
        .ok_or("fixture missing from list")?;
    if (
        listed.draft,
        &listed.mergeability,
        listed.has_conflicts,
        &listed.head_sha,
    ) != (
        get.draft,
        &get.mergeability,
        get.has_conflicts,
        &get.head_sha,
    ) {
        return Err("list/get draft and conflict contract differs".into());
    }
    Ok(get)
}

fn expect_normalized(
    request: &domain::ChangeRequest,
    draft: bool,
    mergeability: &Mergeability,
    conflicts: Option<bool>,
) -> Result<(), String> {
    if (request.draft, &request.mergeability, request.has_conflicts)
        != (Some(draft), mergeability, conflicts)
    {
        return Err(format!(
            "unexpected normalization: draft={:?}, mergeability={:?}, conflicts={:?}",
            request.draft, request.mergeability, request.has_conflicts
        ));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
async fn clean_draft_pr_must_not_require_conflict_repair() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let repository = unique_name("forge-mcp-mergeability")?;
    let mut repository_needs_cleanup = false;
    let primary =
        async {
            context
            .request_success(Method::POST, "/api/v1/user/repos", Some(json!({
                "auto_init": true, "default_branch": "main", "name": repository, "private": true
            })))
            .await?;
            repository_needs_cleanup = true;
            verify_draft_is_not_a_conflict(&context, &repository).await
        }
        .await;
    // Keep cleanup on the expected regression failure too; do not panic early.
    let mut cleanup = Vec::new();
    if repository_needs_cleanup {
        cleanup.push(context.delete_repository(&repository).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}

#[derive(Deserialize)]
struct FileResponse {
    sha: String,
    content: String,
}

#[derive(Deserialize)]
struct CommitResponse {
    sha: String,
    parents: Vec<Branch>,
}

#[allow(clippy::too_many_lines)] // Keep the ordered ancestry/content control readable together.
async fn verify_content_conflict(context: &Context, repository: &str) -> Result<(), String> {
    use base64::Engine;
    let base = format!("/api/v1/repos/{}/{repository}", context.username);
    let file_path = format!("{base}/contents/conflict.txt");
    context
        .request_success(
            Method::POST,
            &file_path,
            Some(json!({
                "branch": "main", "content": "YW5jZXN0b3IK", "message": "Add common ancestor line"
            })),
        )
        .await?;
    let ancestor: CommitResponse = context
        .request_json(Method::GET, &format!("{base}/git/commits/main"), None)
        .await?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/branches"),
            Some(json!({
                "new_branch_name": "conflict", "old_branch_name": "main"
            })),
        )
        .await?;
    let file: FileResponse = context
        .request_json(Method::GET, &format!("{file_path}?ref=main"), None)
        .await?;
    let ancestor_content = base64::engine::general_purpose::STANDARD
        .decode(file.content.trim())
        .map_err(|e| e.to_string())?;
    if ancestor_content != b"ancestor\n" {
        return Err("incorrect shared ancestor content".into());
    }
    for (branch, encoded_line) in [("main", "YmFzZQo="), ("conflict", "aGVhZAo=")] {
        context.request_success(Method::PUT, &file_path, Some(json!({
            "branch": branch, "sha": file.sha, "content": encoded_line, "message": "Replace same ancestor line"
        }))).await?;
    }
    let mut tips = Vec::new();
    for (branch, expected) in [
        ("main", b"base\n".as_slice()),
        ("conflict", b"head\n".as_slice()),
    ] {
        let tip: CommitResponse = context
            .request_json(Method::GET, &format!("{base}/git/commits/{branch}"), None)
            .await?;
        if tip.parents.len() != 1 || tip.parents[0].sha != ancestor.sha {
            return Err(
                "conflict branches must each directly descend from the same ancestor".into(),
            );
        }
        let file: FileResponse = context
            .request_json(Method::GET, &format!("{file_path}?ref={}", tip.sha), None)
            .await?;
        let decoded_line = base64::engine::general_purpose::STANDARD
            .decode(file.content.trim())
            .map_err(|e| e.to_string())?;
        if decoded_line != expected {
            return Err("conflict tip content differs from controlled replacement".into());
        }
        tips.push(tip.sha);
    }
    if tips[0] == tips[1] {
        return Err("conflicting replacements must have distinct commits".into());
    }
    let ready: Pull = context
        .request_json(
            Method::POST,
            &format!("{base}/pulls"),
            Some(json!({
                "base": "main", "head": "conflict", "title": "Conflicting content fixture"
            })),
        )
        .await?;
    let path = format!("{base}/pulls/{}", ready.number);
    // Content and ancestry establish the conflict. REST false cannot prove that
    // the hidden asynchronous checker has finished; do not wait on that claim.
    for draft in [false, true] {
        if draft {
            context
                .request_success(
                    Method::PATCH,
                    &path,
                    Some(json!({"title": "WIP: Conflicting content fixture"})),
                )
                .await?;
        }
        let observation: Pull = context.request_json(Method::GET, &path, None).await?;
        if observation.draft != draft
            || observation.mergeable
            || observation.base.sha != tips[0]
            || observation.head.sha != tips[1]
        {
            return Err("conflict fixture changed identities or raw draft/mergeability".into());
        }
        expect_normalized(
            &observe_normalized(context, repository, ready.number).await?,
            draft,
            &Mergeability::NotMergeable,
            None,
        )?;
    }
    eprintln!(
        "Forgejo {} controlled conflict PR {}: ancestor={} base={} head={}; ready/draft both not_mergeable/null",
        context.version, ready.number, ancestor.sha, tips[0], tips[1]
    );
    Ok(())
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
async fn genuine_conflict_and_draft_conflict_remain_ambiguous() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let repository = unique_name("forge-mcp-content-conflict")?;
    let mut repository_needs_cleanup = false;
    let primary =
        async {
            context.request_success(Method::POST, "/api/v1/user/repos", Some(json!({
            "auto_init": true, "default_branch": "main", "name": repository, "private": true
        }))).await?;
            repository_needs_cleanup = true;
            verify_content_conflict(&context, &repository).await
        }
        .await;
    let mut cleanup = Vec::new();
    if repository_needs_cleanup {
        cleanup.push(context.delete_repository(&repository).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}
