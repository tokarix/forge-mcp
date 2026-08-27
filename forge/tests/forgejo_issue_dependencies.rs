mod support;

use domain::{ForgeCredential, ForgeKind, IssueDependencies, RepositoryRef};
use forge::{ForgeAdapter, ForgeError, ForgejoAdapter, ForgejoConfig};
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;
use support::forgejo::{Context, bounded_preview, combine_results, unique_name};

#[derive(Debug, Deserialize)]
struct ForgejoIssueResponse {
    number: u64,
}

fn repository_ref(base_url: &str, owner: &str, name: &str) -> RepositoryRef {
    RepositoryRef {
        alias: "forgejo-test".to_string(),
        forge: ForgeKind::Forgejo,
        host: base_url.to_string(),
        name: name.to_string(),
        owner: owner.to_string(),
    }
}

fn contains_issue(dependencies: &IssueDependencies, index: u64) -> bool {
    dependencies
        .depends_on
        .iter()
        .any(|issue| issue.index == index)
}

fn adapter_error(
    context: &Context,
    method: &str,
    path: &str,
    body: &str,
    error: &ForgeError,
) -> String {
    bounded_preview(
        &format!(
            "Forgejo version={}: {method} {path} request_body={body} status=adapter-error response_body={error}",
            context.version,
        ),
        1024,
        &[context.token()],
    )
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
#[allow(clippy::too_many_lines)]
async fn forgejo_issue_dependency_lifecycle() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let source_name = unique_name("forge-mcp-dependency-source")?;
    let dependency_name = unique_name("forge-mcp-dependency-target")?;
    let mut created_repositories = Vec::new();

    let primary: Result<(), String> = async {
        for name in [&source_name, &dependency_name] {
            context
                .request_success(
                    Method::POST,
                    "/api/v1/user/repos",
                    Some(json!({
                        "auto_init": true,
                        "name": name,
                        "private": true,
                    })),
                )
                .await?;
            created_repositories.push(name.clone());
        }

        let source_issue: ForgejoIssueResponse = context
            .request_json(
                Method::POST,
                &format!("/api/v1/repos/{}/{}/issues", context.username, source_name),
                Some(json!({"body": "dependency lifecycle source", "title": "source"})),
            )
            .await?;
        let same_repository_issue: ForgejoIssueResponse = context
            .request_json(
                Method::POST,
                &format!("/api/v1/repos/{}/{}/issues", context.username, source_name),
                Some(json!({
                    "body": "dependency lifecycle same-repo",
                    "title": "same-repo dependency"
                })),
            )
            .await?;
        let cross_repository_issue: ForgejoIssueResponse = context
            .request_json(
                Method::POST,
                &format!(
                    "/api/v1/repos/{}/{}/issues",
                    context.username, dependency_name
                ),
                Some(json!({
                    "body": "dependency lifecycle cross-repo",
                    "title": "cross-repo dependency"
                })),
            )
            .await?;

        let base_url = context.base_url.as_str();
        let source_repository = repository_ref(base_url, &context.username, &source_name);
        let dependency_repository = repository_ref(base_url, &context.username, &dependency_name);
        let credential = ForgeCredential { token: None };
        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: base_url.to_string(),
            token: Some(context.token().to_string()),
            woodpecker_url: None,
            woodpecker_token: None,
        })
        .map_err(|error| {
            format!(
                "Forgejo version={}: could not build adapter: {error}",
                context.version
            )
        })?;

        adapter
            .add_issue_dependency(
                &source_repository,
                source_issue.number,
                &source_repository,
                same_repository_issue.number,
                &credential,
            )
            .await
            .map_err(|error| {
                adapter_error(
                    &context,
                    "POST",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        context.username, source_name, source_issue.number
                    ),
                    &json!({
                        "index": same_repository_issue.number,
                        "owner": context.username,
                        "repo": source_name,
                    })
                    .to_string(),
                    &error,
                )
            })?;
        let dependencies = adapter
            .get_issue_dependencies(&source_repository, source_issue.number, &credential)
            .await
            .map_err(|error| {
                adapter_error(
                    &context,
                    "GET",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        context.username, source_name, source_issue.number
                    ),
                    "<none>",
                    &error,
                )
            })?;
        if !contains_issue(&dependencies, same_repository_issue.number) {
            return Err("same-repository dependency was not returned".to_string());
        }

        adapter
            .remove_issue_dependency(
                &source_repository,
                source_issue.number,
                &source_repository,
                same_repository_issue.number,
                &credential,
            )
            .await
            .map_err(|error| {
                adapter_error(
                    &context,
                    "DELETE",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        context.username, source_name, source_issue.number
                    ),
                    &json!({
                        "index": same_repository_issue.number,
                        "owner": context.username,
                        "repo": source_name,
                    })
                    .to_string(),
                    &error,
                )
            })?;
        let dependencies = adapter
            .get_issue_dependencies(&source_repository, source_issue.number, &credential)
            .await
            .map_err(|error| {
                adapter_error(
                    &context,
                    "GET",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        context.username, source_name, source_issue.number
                    ),
                    "<none>",
                    &error,
                )
            })?;
        if contains_issue(&dependencies, same_repository_issue.number) {
            return Err("same-repository dependency remained after removal".to_string());
        }

        match adapter
            .add_issue_dependency(
                &source_repository,
                source_issue.number,
                &dependency_repository,
                cross_repository_issue.number,
                &credential,
            )
            .await
        {
            Ok(_) => {
                let dependencies = adapter
                    .get_issue_dependencies(&source_repository, source_issue.number, &credential)
                    .await
                    .map_err(|error| {
                        adapter_error(
                            &context,
                            "GET",
                            &format!(
                                "/api/v1/repos/{}/{}/issues/{}/dependencies",
                                context.username, source_name, source_issue.number
                            ),
                            "<none>",
                            &error,
                        )
                    })?;
                if !contains_issue(&dependencies, cross_repository_issue.number) {
                    return Err("cross-repository dependency was not returned".to_string());
                }

                match adapter
                    .remove_issue_dependency(
                        &source_repository,
                        source_issue.number,
                        &dependency_repository,
                        cross_repository_issue.number,
                        &credential,
                    )
                    .await
                {
                    Ok(_) => {
                        let dependencies = adapter
                            .get_issue_dependencies(
                                &source_repository,
                                source_issue.number,
                                &credential,
                            )
                            .await
                            .map_err(|error| {
                                adapter_error(
                                    &context,
                                    "GET",
                                    &format!(
                                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                                        context.username, source_name, source_issue.number
                                    ),
                                    "<none>",
                                    &error,
                                )
                            })?;
                        if contains_issue(&dependencies, cross_repository_issue.number) {
                            return Err(
                                "cross-repository dependency remained after removal".to_string()
                            );
                        }
                    }
                    Err(ForgeError::Unsupported(message)) => {
                        if message.is_empty() {
                            return Err("empty Unsupported diagnostic".to_string());
                        }
                    }
                    Err(error) => {
                        return Err(adapter_error(
                            &context,
                            "DELETE",
                            &format!(
                                "/api/v1/repos/{}/{}/issues/{}/dependencies",
                                context.username, source_name, source_issue.number
                            ),
                            &json!({
                                "index": cross_repository_issue.number,
                                "owner": context.username,
                                "repo": dependency_name,
                            })
                            .to_string(),
                            &error,
                        ));
                    }
                }
            }
            Err(ForgeError::Unsupported(message)) => {
                if message.is_empty() {
                    return Err("empty Unsupported diagnostic".to_string());
                }
            }
            Err(error) => {
                return Err(adapter_error(
                    &context,
                    "POST",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        context.username, source_name, source_issue.number
                    ),
                    &json!({
                        "index": cross_repository_issue.number,
                        "owner": context.username,
                        "repo": dependency_name,
                    })
                    .to_string(),
                    &error,
                ));
            }
        }

        Ok(())
    }
    .await;

    let mut cleanup = Vec::with_capacity(created_repositories.len() + 1);
    for repository in created_repositories {
        cleanup.push(context.delete_repository(&repository).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}
