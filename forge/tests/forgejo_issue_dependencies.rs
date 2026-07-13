use std::time::{SystemTime, UNIX_EPOCH};

use domain::{ForgeCredential, ForgeKind, IssueDependencies, RepositoryRef};
use forge::{ForgeAdapter, ForgeError, ForgejoAdapter, ForgejoConfig};
use reqwest::{Client, Method};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct ForgejoVersionResponse {
    version: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoUserResponse {
    login: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoIssueResponse {
    number: u64,
}

fn body_preview(body: &str) -> String {
    body.chars().take(1024).collect()
}

fn request_context(
    version: &str,
    method: &Method,
    path: &str,
    body: &str,
    status: Option<&str>,
    response_body: &str,
) -> String {
    format!(
        "Forgejo version={version}: {method} {path} request_body={body} status={} response_body={}",
        status.unwrap_or("unknown"),
        body_preview(response_body),
    )
}

async fn request(
    client: &Client,
    base_url: &str,
    token: &str,
    version: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<String, String> {
    let request_body = body
        .as_ref()
        .map_or_else(|| "<none>".to_string(), Value::to_string);
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    let mut builder = client.request(method.clone(), url).bearer_auth(token);
    if let Some(body) = body {
        builder = builder.json(&body);
    }

    let response = builder.send().await.map_err(|error| {
        request_context(
            version,
            &method,
            path,
            &request_body,
            None,
            &format!("transport error: {error}"),
        )
    })?;
    let status = response.status();
    let status_text = status.to_string();
    let response_body = response.text().await.map_err(|error| {
        request_context(
            version,
            &method,
            path,
            &request_body,
            Some(&status_text),
            &format!("response read error: {error}"),
        )
    })?;
    if !status.is_success() {
        return Err(request_context(
            version,
            &method,
            path,
            &request_body,
            Some(&status_text),
            &response_body,
        ));
    }

    Ok(response_body)
}

async fn request_json<T: DeserializeOwned>(
    client: &Client,
    base_url: &str,
    token: &str,
    version: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<T, String> {
    let response_body =
        request(client, base_url, token, version, method.clone(), path, body).await?;
    serde_json::from_str(&response_body).map_err(|error| {
        request_context(
            version,
            &method,
            path,
            "<serialized request body omitted>",
            Some("success"),
            &format!("invalid JSON: {error}; body={response_body}"),
        )
    })
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
    version: &str,
    method: &str,
    path: &str,
    body: &str,
    error: &ForgeError,
) -> String {
    request_context(
        version,
        &Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET),
        path,
        body,
        Some("adapter error"),
        &error.to_string(),
    )
}

#[tokio::test]
#[ignore = "requires a disposable Forgejo instance and token"]
#[allow(clippy::too_many_lines)]
async fn forgejo_issue_dependency_lifecycle() -> Result<(), String> {
    let base_url = std::env::var("FORGEJO_TEST_BASE_URL")
        .map_err(|_| "FORGEJO_TEST_BASE_URL is required".to_string())?;
    let token = std::env::var("FORGEJO_TEST_TOKEN")
        .map_err(|_| "FORGEJO_TEST_TOKEN is required".to_string())?;
    let client = Client::new();

    let version_response: ForgejoVersionResponse = request_json(
        &client,
        &base_url,
        &token,
        "unknown",
        Method::GET,
        "/api/v1/version",
        None,
    )
    .await?;
    let version = version_response.version;
    let user: ForgejoUserResponse = request_json(
        &client,
        &base_url,
        &token,
        &version,
        Method::GET,
        "/api/v1/user",
        None,
    )
    .await?;

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("could not create unique repository suffix: {error}"))?
        .as_nanos();
    let source_name = format!("forge-mcp-dependency-{suffix}-source");
    let dependency_name = format!("forge-mcp-dependency-{suffix}-dependency");
    let mut created_repositories = Vec::new();

    let result: Result<(), String> = async {
        for name in [&source_name, &dependency_name] {
            request(
                &client,
                &base_url,
                &token,
                &version,
                Method::POST,
                "/api/v1/user/repos",
                Some(json!({
                    "auto_init": true,
                    "name": name,
                    "private": true,
                })),
            )
            .await?;
            created_repositories.push((*name).clone());
        }

        let source_issue: ForgejoIssueResponse = request_json(
            &client,
            &base_url,
            &token,
            &version,
            Method::POST,
            &format!("/api/v1/repos/{}/{}/issues", user.login, source_name),
            Some(json!({"body": "dependency lifecycle source", "title": "source"})),
        )
        .await?;
        let same_repository_issue: ForgejoIssueResponse = request_json(
            &client,
            &base_url,
            &token,
            &version,
            Method::POST,
            &format!("/api/v1/repos/{}/{}/issues", user.login, source_name),
            Some(json!({"body": "dependency lifecycle same-repo", "title": "same-repo dependency"})),
        )
        .await?;
        let cross_repository_issue: ForgejoIssueResponse = request_json(
            &client,
            &base_url,
            &token,
            &version,
            Method::POST,
            &format!("/api/v1/repos/{}/{}/issues", user.login, dependency_name),
            Some(json!({"body": "dependency lifecycle cross-repo", "title": "cross-repo dependency"})),
        )
        .await?;

        let source_repository = repository_ref(&base_url, &user.login, &source_name);
        let dependency_repository = repository_ref(&base_url, &user.login, &dependency_name);
        let credential = ForgeCredential { token: None };
        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: base_url.clone(),
            token: Some(token.clone()),
            woodpecker_url: None,
            woodpecker_token: None,
        })
        .map_err(|error| format!("Forgejo version={version}: could not build adapter: {error}"))?;

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
                    &version,
                    "POST",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        user.login, source_name, source_issue.number
                    ),
                    &json!({
                        "index": same_repository_issue.number,
                        "owner": user.login,
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
                    &version,
                    "GET",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        user.login, source_name, source_issue.number
                    ),
                    "<none>",
                    &error,
                )
            })?;
        assert!(
            contains_issue(&dependencies, same_repository_issue.number),
            "same-repository dependency was not returned by get_issue_dependencies"
        );

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
                    &version,
                    "DELETE",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        user.login, source_name, source_issue.number
                    ),
                    &json!({
                        "index": same_repository_issue.number,
                        "owner": user.login,
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
                    &version,
                    "GET",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        user.login, source_name, source_issue.number
                    ),
                    "<none>",
                    &error,
                )
            })?;
        assert!(!contains_issue(&dependencies, same_repository_issue.number));

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
                            &version,
                            "GET",
                            &format!(
                                "/api/v1/repos/{}/{}/issues/{}/dependencies",
                                user.login, source_name, source_issue.number
                            ),
                            "<none>",
                            &error,
                        )
                    })?;
                assert!(contains_issue(&dependencies, cross_repository_issue.number));

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
                                    &version,
                                    "GET",
                                    &format!(
                                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                                        user.login, source_name, source_issue.number
                                    ),
                                    "<none>",
                                    &error,
                                )
                            })?;
                        assert!(!contains_issue(&dependencies, cross_repository_issue.number));
                    }
                    Err(ForgeError::Unsupported(message)) => {
                        assert!(!message.is_empty());
                    }
                    Err(error) => {
                        return Err(adapter_error(
                            &version,
                            "DELETE",
                            &format!(
                                "/api/v1/repos/{}/{}/issues/{}/dependencies",
                                user.login, source_name, source_issue.number
                            ),
                            &json!({
                                "index": cross_repository_issue.number,
                                "owner": user.login,
                                "repo": dependency_name,
                            })
                            .to_string(),
                            &error,
                        ));
                    }
                }
            }
            Err(ForgeError::Unsupported(message)) => {
                assert!(!message.is_empty());
            }
            Err(error) => {
                return Err(adapter_error(
                    &version,
                    "POST",
                    &format!(
                        "/api/v1/repos/{}/{}/issues/{}/dependencies",
                        user.login, source_name, source_issue.number
                    ),
                    &json!({
                        "index": cross_repository_issue.number,
                        "owner": user.login,
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

    for repository in created_repositories {
        let _ = request(
            &client,
            &base_url,
            &token,
            &version,
            Method::DELETE,
            &format!("/api/v1/repos/{}/{}", user.login, repository),
            None,
        )
        .await;
    }

    result
}
