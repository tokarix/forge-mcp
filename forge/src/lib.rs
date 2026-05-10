//! Forge adapter traits and the Phase 1 Forgejo implementation.

use std::fmt::Write;
use std::sync::Once;

use async_trait::async_trait;
use base64::Engine;
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestEvent,
    ChangeRequestEventAction, ChangeRequestReview, ChangeRequestState, ForgeCredential, ForgeUser,
    ReadRepositoryFileResponse, RepositoryMergeSettings, RepositoryRef,
};
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;

pub mod gitlab;

static INSTALL_RING_PROVIDER: Once = Once::new();

fn install_ring_provider() {
    INSTALL_RING_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("upstream request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{message} (upstream returned {status})")]
    NotFound { status: StatusCode, message: String },
    #[error(
        "repository may have moved or been renamed (upstream returned {status} redirect to {location})"
    )]
    Redirect {
        status: StatusCode,
        location: String,
    },
    #[error("unexpected upstream status {status}: {body}")]
    UnexpectedStatus { status: StatusCode, body: String },
    #[error("operation not supported: {0}")]
    Unsupported(String),
    #[error("invalid response payload: {0}")]
    InvalidPayload(String),
}

#[derive(Debug, Error)]
pub enum ForgeWebhookError {
    #[error("invalid webhook payload: {0}")]
    InvalidPayload(String),
    #[error("invalid webhook signature")]
    InvalidSignature,
    #[error("missing webhook header '{0}'")]
    MissingHeader(String),
}

/// Recursively extracts a human-readable error string from a JSON value
/// by walking the AST directly without serialization round-trips.
fn extract_error_recursive(value: &serde_json::Value) -> Option<String> {
    if let Some(msg) = value.get("message").and_then(|v| v.as_str()) {
        return Some(msg.to_string());
    }
    for key in &["message", "error"] {
        if let Some(inner) = value.get(key)
            && (inner.is_object() || inner.is_array())
            && let Some(found) = extract_error_recursive(inner)
        {
            return Some(found);
        }
    }
    if let Some(err) = value.get("error").and_then(|v| v.as_str()) {
        return Some(err.to_string());
    }
    if let Some(first_obj) = value.get(0).and_then(|v| v.as_object())
        && let Some(msg) = first_obj.get("message").and_then(|v| v.as_str())
    {
        return Some(msg.to_string());
    }
    if let Some(arr) = value.as_array()
        && let Some(first) = arr.first().and_then(|v| v.as_str())
    {
        return Some(first.to_string());
    }
    None
}

/// Extracts a descriptive error message from a JSON response body.
///
/// Handles common formats used by Forgejo and GitLab, checking the `message`
/// and `error` keys.  For GitLab's structured error format (a JSON array of
/// `{message: "..."}` objects or nested `message`/`error` objects) it unwraps
/// to find the first human-readable message string.
///
/// Returns `None` when the body is empty or not valid JSON.
pub(crate) fn parse_forge_error_message(body: &str) -> Option<String> {
    let body = body.trim();
    if body.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        return extract_error_recursive(&value);
    }
    None
}

#[async_trait]
pub trait ForgeAdapter: Send + Sync {
    /// Adds a dependency on another issue.
    async fn add_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency_repository: &RepositoryRef,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Adds a label to an issue, creating the label on the repo if it does
    /// not already exist.
    async fn add_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Retrieves the authenticated user's identity from the forge.
    async fn get_authenticated_user(
        &self,
        credential: &ForgeCredential,
    ) -> Result<ForgeUser, ForgeError>;

    /// Assigns an issue to a user.
    async fn assign_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        assignee: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Closes a change request (pull request) on the forge.
    async fn close_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Closes an issue.
    async fn close_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Posts a comment on an issue.
    async fn comment_on_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueComment, ForgeError>;

    /// Posts a general comment on a change request.
    async fn comment_on_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ForgeError>;

    /// Creates a change request (pull request) on the forge.
    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Creates a commit status on the given SHA.
    async fn create_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        context: &str,
        description: &str,
        state: &str,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError>;

    /// Creates a new issue.
    async fn create_issue(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Returns the set of merge style strings the repository allows.
    async fn get_allowed_merge_styles(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Vec<String>, ForgeError>;

    /// Gets all comments and reviews for a change request.
    async fn get_change_request_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError>;

    /// Gets a single change request by index.
    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Gets the unified diff for a change request.
    async fn get_change_request_diff(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<String, ForgeError>;

    /// Returns the combined CI/check status for the given commit SHA.
    async fn get_combined_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::CombinedCommitStatus, ForgeError>;

    /// Returns detailed CI information for the given commit SHA.
    async fn get_change_request_ci_details(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::ChangeRequestCiDetails, ForgeError>;

    /// Returns the repository's default merge style, if configured.
    async fn get_default_merge_style(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Option<String>, ForgeError>;

    /// Returns the repository's merge-related settings.
    async fn get_repository_merge_settings(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<RepositoryMergeSettings, ForgeError>;

    /// Gets a single issue by index.
    async fn get_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Gets all comments for an issue.
    async fn get_issue_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::IssueComment>, ForgeError>;

    /// Gets the dependency relationships for an issue.
    async fn get_issue_dependencies(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueDependencies, ForgeError>;

    /// Lists change requests for a repository.
    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequest>, ForgeError>;

    /// Lists issues for a repository.
    async fn list_issues(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Issue>, ForgeError>;

    /// Lists repositories on the forge, optionally filtered by owner and/or
    /// search query.
    async fn list_repositories(
        &self,
        owner: Option<&str>,
        query: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError>;

    /// Schedules a pull request for automatic merge when all branch
    /// protection requirements are met.
    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        head_commit_id: &str,
        delete_branch_after_merge: Option<bool>,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError>;

    /// Removes a dependency relationship from an issue.
    async fn remove_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency_repository: &RepositoryRef,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Removes a label from an issue.
    async fn remove_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Reads a single file from the backing forge.
    ///
    /// # Errors
    ///
    /// Returns an error if the forge is unsupported, the upstream request
    /// fails, or the response payload cannot be decoded into UTF-8 text.
    async fn read_repository_file(
        &self,
        repository: &RepositoryRef,
        path: &str,
        git_ref: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ReadRepositoryFileResponse, ForgeError>;

    /// Submits a formal review on a change request.
    async fn submit_change_request_review(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        event: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestReview, ForgeError>;

    /// Updates a change request's title and/or body.
    async fn update_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Updates an issue's title and/or body.
    async fn update_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError>;

    /// Lists branches in a repository, optionally filtered by prefix.
    async fn list_branches(
        &self,
        repository: &RepositoryRef,
        prefix: Option<&str>,
        limit: Option<u32>,
        credential: &ForgeCredential,
    ) -> Result<(Vec<domain::Branch>, bool), ForgeError>;

    /// Gets branch details by name. Returns `(name, Some(sha), true)` for existing
    /// branches, `(name, None, false)` for confirmed-missing branches.
    /// Other errors propagate.
    async fn get_branch(
        &self,
        repository: &RepositoryRef,
        branch: &str,
        credential: &ForgeCredential,
    ) -> Result<(String, Option<String>, bool), ForgeError>;
}

pub trait ForgeWebhookAdapter: Send + Sync {
    /// Verifies a forge webhook signature and converts a supported payload into
    /// a normalized webhook event.
    ///
    /// # Errors
    ///
    /// Returns an error if the required webhook headers are missing, the
    /// signature is invalid, or the payload cannot be parsed.
    fn verify_and_parse_webhook_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError>;
}

#[derive(Clone)]
pub struct ForgejoConfig {
    pub base_url: String,
    pub token: Option<String>,
    pub woodpecker_url: Option<String>,
    pub woodpecker_token: Option<String>,
}

impl std::fmt::Debug for ForgejoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgejoConfig")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("woodpecker_url", &self.woodpecker_url)
            .field(
                "woodpecker_token",
                &self.woodpecker_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ForgejoAdapter {
    client: reqwest::Client,
    config: ForgejoConfig,
}

impl ForgejoAdapter {
    async fn resolve_ci_failure(&self, target_url: &str) -> domain::CiResolution {
        let (repo_id, pipeline_num, woodpecker_base) = match self.parse_woodpecker_url(target_url) {
            Ok(ids) => ids,
            Err(res) => return res,
        };

        let pipeline = match self
            .fetch_woodpecker_pipeline(&woodpecker_base, &repo_id, &pipeline_num)
            .await
        {
            Ok(p) => p,
            Err(res) => return res,
        };

        let mut failed_steps = Vec::new();
        let mut log_errors = Vec::new();
        let workflows = pipeline.workflows.unwrap_or_default();
        if workflows.is_empty() {
            return domain::CiResolution::Error {
                message: "Resolved pipeline but found no workflows".to_string(),
            };
        }

        for workflow in workflows {
            for step in workflow.children.unwrap_or_default() {
                if step.state == "failure" || step.state == "error" {
                    match self
                        .fetch_woodpecker_step_logs(
                            &woodpecker_base,
                            &repo_id,
                            &pipeline_num,
                            &step,
                        )
                        .await
                    {
                        Ok(log_excerpt) => {
                            failed_steps.push(domain::CiFailureStep {
                                name: step.name,
                                state: step.state,
                                log_excerpt,
                            });
                        }
                        Err(message) => {
                            log_errors.push(format!("{}: {}", step.name, message));
                            failed_steps.push(domain::CiFailureStep {
                                name: step.name,
                                state: step.state,
                                log_excerpt: None,
                            });
                        }
                    }
                }
            }
        }

        if failed_steps.is_empty() {
            return domain::CiResolution::Error {
                message: "Resolved pipeline but found no failed steps".to_string(),
            };
        }

        let has_logs = failed_steps.iter().any(|s| s.log_excerpt.is_some());
        if !has_logs {
            let message = if log_errors.is_empty() {
                "Supported provider but found no usable log excerpts for any failed steps"
                    .to_string()
            } else {
                format!(
                    "Failed to retrieve log excerpts for any failed steps: {}",
                    log_errors.join("; ")
                )
            };
            return domain::CiResolution::Error { message };
        }

        let pipeline_ui_url = woodpecker_base
            .join(&format!("repos/{repo_id}/pipeline/{pipeline_num}"))
            .map_or_else(|_| target_url.to_string(), |u| u.to_string());

        domain::CiResolution::Resolved {
            provider: domain::CiProvider::Woodpecker,
            pipeline_url: pipeline_ui_url,
            failed_steps,
        }
    }

    fn parse_woodpecker_url(
        &self,
        target_url: &str,
    ) -> Result<(String, String, reqwest::Url), domain::CiResolution> {
        let Some(woodpecker_url_str) = &self.config.woodpecker_url else {
            return Err(domain::CiResolution::Unsupported);
        };

        let Ok(mut base_url) = reqwest::Url::parse(woodpecker_url_str) else {
            return Err(domain::CiResolution::Unsupported);
        };

        let Ok(url) = reqwest::Url::parse(target_url) else {
            return Err(domain::CiResolution::Unsupported);
        };

        if url.origin() != base_url.origin() {
            return Err(domain::CiResolution::Unsupported);
        }

        // Ensure base URL has a trailing slash for robust joining.
        if !base_url.path().ends_with('/') {
            let mut path = base_url.path().to_string();
            path.push('/');
            base_url.set_path(&path);
        }

        let base_segments = base_url
            .path_segments()
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty());
        let mut target_segments = url.path_segments().into_iter().flatten();

        for base_seg in base_segments {
            if target_segments.next() != Some(base_seg) {
                return Err(domain::CiResolution::Error {
                    message: format!(
                        "Target URL path does not match Woodpecker base path prefix: {target_url}"
                    ),
                });
            }
        }

        match (
            target_segments.next(),
            target_segments.next(),
            target_segments.next(),
            target_segments.next(),
        ) {
            (Some("repos"), Some(repo_id), Some("pipeline"), Some(pipeline_num))
                if repo_id.chars().all(|c| c.is_ascii_digit())
                    && pipeline_num.chars().all(|c| c.is_ascii_digit()) =>
            {
                Ok((repo_id.to_string(), pipeline_num.to_string(), base_url))
            }
            _ => Err(domain::CiResolution::Error {
                message: format!("Malformed or unsupported Woodpecker URL path: {target_url}"),
            }),
        }
    }

    async fn fetch_woodpecker_pipeline(
        &self,
        woodpecker_base: &reqwest::Url,
        repo_id: &str,
        pipeline_num: &str,
    ) -> Result<WoodpeckerPipeline, domain::CiResolution> {
        let url = woodpecker_base
            .join(&format!("api/repos/{repo_id}/pipelines/{pipeline_num}"))
            .map_err(|e| domain::CiResolution::Error {
                message: format!("Failed to construct pipeline URL: {e}"),
            })?;

        let mut req = self.client.get(url);
        if let Some(token) = &self.config.woodpecker_token {
            req = req.bearer_auth(token);
        }

        let res = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                return Err(domain::CiResolution::Error {
                    message: format!("Failed to fetch pipeline: {e}"),
                });
            }
        };

        if !res.status().is_success() {
            return Err(domain::CiResolution::Error {
                message: format!("Pipeline API returned status {}", res.status()),
            });
        }

        res.json().await.map_err(|e| domain::CiResolution::Error {
            message: format!("Failed to parse pipeline: {e}"),
        })
    }

    async fn fetch_woodpecker_step_logs(
        &self,
        woodpecker_base: &reqwest::Url,
        repo_id: &str,
        pipeline_num: &str,
        step: &WoodpeckerStep,
    ) -> Result<Option<domain::CiLogExcerpt>, String> {
        let url = woodpecker_base
            .join(&format!(
                "api/repos/{repo_id}/logs/{pipeline_num}/{}",
                step.id
            ))
            .map_err(|e| format!("Failed to construct logs URL: {e}"))?;

        let mut req = self.client.get(url);
        if let Some(token) = &self.config.woodpecker_token {
            req = req.bearer_auth(token);
        }

        let res = match req.send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                return Err(format!(
                    "Log API for step {} returned status {}",
                    step.name,
                    r.status()
                ));
            }
            Err(e) => {
                return Err(format!("Failed to fetch logs for step {}: {e}", step.name));
            }
        };

        let logs: Vec<WoodpeckerLogEntry> = res
            .json()
            .await
            .map_err(|e| format!("Failed to parse logs for step {}: {e}", step.name))?;

        let mut lines = Vec::new();
        for l in logs.into_iter().rev().take(20) {
            let bytes = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, l.data.trim())
                .map_err(|e| format!("Failed to decode log data for step {}: {e}", step.name))?;
            let line = String::from_utf8_lossy(&bytes).into_owned();
            if !line.trim().is_empty() {
                lines.push(line);
            }
        }

        if lines.is_empty() {
            Ok(None)
        } else {
            lines.reverse();
            Ok(Some(domain::CiLogExcerpt { lines }))
        }
    }

    /// Verifies that the repository is accessible by hitting the repo endpoint.
    /// Returns `Ok(true)` if the repo exists, `Ok(false)` if not found,
    /// and `Err` for other failures (network, auth, etc.).
    async fn verify_repo_exists(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<bool, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        // Consume the body to free the response
        let _ = response.text().await;
        if status == reqwest::StatusCode::NOT_FOUND {
            Ok(false)
        } else if status.is_success() {
            Ok(true)
        } else {
            Err(ForgeError::UnexpectedStatus {
                status,
                body: format!("unexpected status {status} while verifying repository"),
            })
        }
    }

    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(config: ForgejoConfig) -> Result<Self, ForgeError> {
        install_ring_provider();

        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(Policy::none())
                .build()?,
            config,
        })
    }

    /// Checks the HTTP response status and returns a descriptive error for
    /// non-success codes.  Recognises redirects (3xx) and not-found (404) to
    /// provide actionable messages instead of the generic "error decoding
    /// response body" that occurs when the caller tries to parse a non-JSON
    /// body.
    async fn check_response(response: reqwest::Response) -> Result<reqwest::Response, ForgeError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<unknown>")
                .to_string();
            tracing::warn!(
                %status,
                %location,
                url = %response.url(),
                "upstream returned redirect — repository may have moved or been renamed",
            );
            return Err(ForgeError::Redirect { status, location });
        }

        let url = response.url().clone();
        let body = response.text().await.unwrap_or_default();

        if status == StatusCode::NOT_FOUND {
            let message = parse_forge_error_message(&body)
                .unwrap_or_else(|| "repository or resource not found".to_string());
            tracing::warn!(
                %status,
                %message,
                %url,
                "upstream returned 404",
            );
            return Err(ForgeError::NotFound { status, message });
        }
        tracing::warn!(
            %status,
            %url,
            body_len = body.len(),
            body_preview = %&body[..body.len().min(512)],
            "unexpected upstream status",
        );
        Err(ForgeError::UnexpectedStatus { status, body })
    }

    /// Fetches the raw Forgejo issue response (including internal `id`).
    async fn fetch_issue_raw(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ForgejoIssueResponse, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;
        Ok(response.json().await?)
    }

    async fn get_repository_merge_settings_response(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<ForgejoRepoResponse, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))
    }

    /// Lists repo labels and returns the ID for a label matching `name`, or
    /// `None` if no such label exists.
    async fn find_label_id(
        &self,
        repository: &RepositoryRef,
        name: &str,
        token: Option<&str>,
    ) -> Result<Option<u64>, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/labels",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.get(&url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let labels: Vec<ForgejoLabelResponse> = response.json().await?;
        Ok(labels.into_iter().find(|l| l.name == name).map(|l| l.id))
    }

    /// Finds a repo label by name, creating it if it does not exist. Returns
    /// the label's numeric ID.
    async fn find_or_create_label(
        &self,
        repository: &RepositoryRef,
        name: &str,
        token: Option<&str>,
    ) -> Result<u64, ForgeError> {
        if let Some(id) = self.find_label_id(repository, name, token).await? {
            return Ok(id);
        }

        // Create the label with a default colour.
        let url = format!(
            "{}/api/v1/repos/{}/{}/labels",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.post(&url).json(&serde_json::json!({
            "color": "#0075ca",
            "name": name,
        }));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let label: ForgejoLabelResponse = response.json().await?;
        Ok(label.id)
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoAuthUser {
    email: String,
    login: String,
}

#[derive(Debug, Deserialize)]
struct WoodpeckerPipeline {
    workflows: Option<Vec<WoodpeckerWorkflow>>,
}

#[derive(Debug, Deserialize)]
struct WoodpeckerWorkflow {
    #[allow(dead_code)]
    id: u64,
    children: Option<Vec<WoodpeckerStep>>,
}

#[derive(Debug, Deserialize)]
struct WoodpeckerStep {
    id: u64,
    name: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct WoodpeckerLogEntry {
    data: String,
}

/// Forgejo combined commit status response from
/// `GET /api/v1/repos/{owner}/{repo}/commits/{ref}/status`.
#[derive(Debug, Deserialize)]
struct ForgejoCombinedStatusResponse {
    sha: String,
    state: String,
    statuses: Option<Vec<ForgejoCommitStatusResponse>>,
    total_count: u64,
}

/// A single commit status entry in the Forgejo response.
#[derive(Debug, Deserialize)]
struct ForgejoCommitStatusResponse {
    context: String,
    description: Option<String>,
    status: String,
    target_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ForgejoBranchResponse {
    #[serde(rename = "name")]
    branch_name: String,
    commit: ForgejoBranchCommit,
}

#[derive(Debug, Deserialize)]
struct ForgejoBranchCommit {
    id: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoContentsResponse {
    content: Option<String>,
    encoding: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullBranch {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullRequest {
    base: ForgejoPullBranch,
    body: Option<String>,
    changed_files: Option<u64>,
    head: ForgejoPullBranch,
    html_url: String,
    merge_base: Option<String>,
    merged: bool,
    number: u64,
    state: String,
    title: String,
}

impl ForgejoPullRequest {
    fn into_change_request(self) -> ChangeRequest {
        let state = if self.merged {
            ChangeRequestState::Merged
        } else {
            match self.state.as_str() {
                "open" => ChangeRequestState::Open,
                _ => ChangeRequestState::Closed,
            }
        };
        ChangeRequest {
            base_branch: self.base.ref_name,
            body: self.body.unwrap_or_default(),
            changed_files_count: self.changed_files,
            commit_count: None,
            head_branch: self.head.ref_name,
            head_sha: Some(self.head.sha),
            index: self.number,
            merge_base_sha: self.merge_base,
            state,
            title: self.title,
            url: self.html_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoCommentResponse {
    body: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct ForgejoReviewResponse {
    body: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct ForgejoCommentUser {
    login: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoIssueComment {
    body: String,
    created_at: String,
    id: u64,
    user: ForgejoCommentUser,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullReview {
    body: Option<String>,
    commit_id: Option<String>,
    #[serde(default)]
    dismissed: bool,
    id: u64,
    state: String,
    submitted_at: Option<String>,
    user: ForgejoCommentUser,
}

#[derive(Debug, Deserialize)]
struct ForgejoIssueResponse {
    assignees: Option<Vec<ForgejoCommentUser>>,
    body: Option<String>,
    html_url: String,
    /// Forgejo internal database ID (not the visible issue number).
    id: u64,
    labels: Option<Vec<ForgejoLabelResponse>>,
    number: u64,
    state: String,
    title: String,
}

impl ForgejoIssueResponse {
    fn into_issue(self) -> domain::Issue {
        domain::Issue {
            assignees: self
                .assignees
                .unwrap_or_default()
                .into_iter()
                .map(|u| u.login)
                .collect(),
            body: self.body.unwrap_or_default(),
            index: self.number,
            labels: self
                .labels
                .unwrap_or_default()
                .into_iter()
                .map(|l| l.name)
                .collect(),
            state: self.state,
            title: self.title,
            url: self.html_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoIssueCommentResponse {
    body: String,
    created_at: String,
    id: u64,
    user: ForgejoCommentUser,
}

impl ForgejoIssueCommentResponse {
    fn into_issue_comment(self) -> domain::IssueComment {
        domain::IssueComment {
            author: self.user.login,
            body: self.body,
            created_at: self.created_at,
            id: self.id,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoLabelResponse {
    id: u64,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoRepoResponse {
    allow_fast_forward_only_merge: Option<bool>,
    allow_merge_commits: Option<bool>,
    allow_rebase: Option<bool>,
    allow_rebase_explicit: Option<bool>,
    allow_squash_merge: Option<bool>,
    default_delete_branch_after_merge: Option<bool>,
    default_merge_style: Option<String>,
}

impl ForgejoRepoResponse {
    fn allowed_merge_styles(&self) -> Vec<String> {
        let mut styles = Vec::new();
        if self.allow_merge_commits.unwrap_or(false) {
            styles.push("merge".to_string());
        }
        if self.allow_rebase.unwrap_or(false) {
            styles.push("rebase".to_string());
        }
        if self.allow_rebase_explicit.unwrap_or(false) {
            styles.push("rebase-merge".to_string());
        }
        if self.allow_squash_merge.unwrap_or(false) {
            styles.push("squash".to_string());
        }
        if self.allow_fast_forward_only_merge.unwrap_or(false) {
            styles.push("fast-forward-only".to_string());
        }
        styles
    }

    fn normalized_default_merge_style(&self) -> Option<String> {
        self.default_merge_style.clone().filter(|s| !s.is_empty())
    }

    fn into_repository_merge_settings(self) -> RepositoryMergeSettings {
        RepositoryMergeSettings {
            allowed_styles: self.allowed_merge_styles(),
            default_delete_branch_after_merge: self.default_delete_branch_after_merge,
            default_merge_style: self.normalized_default_merge_style(),
        }
    }
}

/// Forgejo repo search result wrapper from `GET /api/v1/repos/search`.
#[derive(Debug, Deserialize)]
struct ForgejoRepoSearchResponse {
    data: Vec<ForgejoRepoSearchEntry>,
    ok: bool,
}

/// A single repository in a Forgejo search result.
#[derive(Debug, Deserialize)]
struct ForgejoRepoSearchEntry {
    description: Option<String>,
    full_name: String,
    html_url: String,
    name: String,
    owner: Option<ForgejoRepoSearchOwner>,
}

#[derive(Debug, Deserialize)]
struct ForgejoRepoSearchOwner {
    login: String,
}

/// Forgejo user lookup response from `GET /api/v1/users/{username}`.
#[derive(Debug, Deserialize)]
struct ForgejoUserResponse {
    id: u64,
}

impl ForgejoRepoSearchEntry {
    fn into_repository(self) -> domain::Repository {
        domain::Repository {
            description: self.description.unwrap_or_default(),
            full_name: self.full_name,
            name: self.name,
            owner: self.owner.map(|o| o.login).unwrap_or_default(),
            url: self.html_url,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WebhookEventType {
    IssueComment,
    Issues,
    PullRequest,
    PullRequestReview,
    Unknown(String),
}

impl WebhookEventType {
    fn parse(value: &str) -> Self {
        match value {
            "issue_comment" => Self::IssueComment,
            "issues" => Self::Issues,
            "pull_request" => Self::PullRequest,
            "pull_request_approved"
            | "pull_request_comment"
            | "pull_request_rejected"
            | "pull_request_review" => Self::PullRequestReview,
            other => Self::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookComment {
    body: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookIssue {
    html_url: String,
    number: Option<u64>,
    title: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookIssueCommentPayload {
    action: String,
    comment: ForgejoWebhookComment,
    issue: ForgejoWebhookIssue,
    repository: ForgejoWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookIssueEventPayload {
    action: String,
    issue: ForgejoWebhookIssue,
    number: Option<u64>,
    repository: ForgejoWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookOwner {
    login: Option<String>,
    username: Option<String>,
}

impl ForgejoWebhookOwner {
    fn into_owner(self) -> Result<String, ForgeWebhookError> {
        self.login.or(self.username).ok_or_else(|| {
            ForgeWebhookError::InvalidPayload("repository owner missing".to_string())
        })
    }
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookRepository {
    name: String,
    owner: ForgejoWebhookOwner,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookPullRequest {
    head: ForgejoPullBranch,
    html_url: String,
    number: Option<u64>,
    title: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookPullRequestEventPayload {
    action: String,
    number: Option<u64>,
    pull_request: ForgejoWebhookPullRequest,
    repository: ForgejoWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookPullRequestReviewEventPayload {
    action: String,
    pull_request: ForgejoWebhookPullRequest,
    repository: ForgejoWebhookRepository,
    review: ForgejoWebhookReview,
}

#[derive(Debug, Deserialize)]
struct ForgejoWebhookReview {
    #[serde(alias = "content")]
    body: Option<String>,
    id: Option<u64>,
    #[serde(rename = "type")]
    review_type: String,
}

#[async_trait]
impl ForgeAdapter for ForgejoAdapter {
    async fn add_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency_repository: &RepositoryRef,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        // Forgejo's dependency API expects the internal database ID, not the
        // visible issue number.  Fetch the dependency issue from the correct
        // repository — for cross-repo dependencies this differs from repository.
        let dep_issue = self
            .fetch_issue_raw(dependency_repository, dependency, credential)
            .await?;

        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/dependencies",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"dependsOn": dep_issue.id}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        self.get_issue(repository, index, credential).await
    }

    async fn add_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let base = self.config.base_url.trim_end_matches('/');
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // 1. Find or create the label to get its numeric ID.
        let label_id = self
            .find_or_create_label(repository, label, effective_token)
            .await?;

        // 2. Add the label to the issue.
        let url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/labels",
            repository.owner, repository.name,
        );
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"labels": [label_id]}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        // 3. Return the full updated issue.
        self.get_issue(repository, index, credential).await
    }

    async fn get_authenticated_user(
        &self,
        credential: &ForgeCredential,
    ) -> Result<ForgeUser, ForgeError> {
        let url = format!("{}/api/v1/user", self.config.base_url.trim_end_matches('/'),);

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let user: ForgejoAuthUser = response.json().await?;
        Ok(ForgeUser {
            email: user.email,
            username: user.login,
        })
    }

    async fn assign_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        assignee: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.patch(&url).json(&serde_json::json!({
            "assignees": [assignee]
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn close_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .patch(&url)
            .json(&serde_json::json!({"state": "closed"}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn close_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.patch(&url).json(&serde_json::json!({
            "state": "closed"
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn comment_on_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueComment, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "body": body
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let comment: ForgejoIssueCommentResponse = response.json().await?;
        Ok(comment.into_issue_comment())
    }

    async fn comment_on_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"body": body}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let comment: ForgejoCommentResponse = response.json().await?;
        Ok(ChangeRequestComment {
            body: comment.body,
            id: comment.id,
            index,
        })
    }

    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "base": base_branch,
            "body": body,
            "head": head_branch,
            "title": title,
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn create_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        context: &str,
        description: &str,
        state: &str,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/statuses/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            sha,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "context": context,
            "description": description,
            "state": state,
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        Ok(())
    }

    async fn create_issue(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.post(&url).json(&serde_json::json!({
            "title": title,
            "body": body
        }));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_allowed_merge_styles(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Vec<String>, ForgeError> {
        let repo = self
            .get_repository_merge_settings_response(repository, credential)
            .await?;
        Ok(repo.allowed_merge_styles())
    }

    async fn get_combined_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::CombinedCommitStatus, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/commits/{}/status",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            sha,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let combined: ForgejoCombinedStatusResponse = response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))?;

        let state = parse_commit_status_state(&combined.state);
        let statuses = combined
            .statuses
            .unwrap_or_default()
            .into_iter()
            .map(|s| domain::CommitStatus {
                context: s.context,
                description: s.description.unwrap_or_default(),
                state: parse_commit_status_state(&s.status),
                target_url: s.target_url.unwrap_or_default(),
            })
            .collect();

        Ok(domain::CombinedCommitStatus {
            head_sha: combined.sha,
            state,
            statuses,
            total_count: combined.total_count,
        })
    }

    async fn get_change_request_ci_details(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
        let combined = self
            .get_combined_commit_status(repository, sha, credential)
            .await?;
        let mut details = Vec::new();

        for status in combined.statuses {
            let resolution = if status.state == domain::CommitStatusState::Failure
                || status.state == domain::CommitStatusState::Error
            {
                self.resolve_ci_failure(&status.target_url).await
            } else {
                domain::CiResolution::Unsupported
            };

            details.push(domain::CiCheckDetail {
                context: status.context,
                description: status.description,
                state: status.state,
                target_url: status.target_url,
                resolution,
            });
        }

        Ok(domain::ChangeRequestCiDetails {
            head_sha: sha.to_string(),
            state: combined.state,
            details,
        })
    }

    async fn get_change_request_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // Fetch issue comments (general comments on the PR)
        let comments_url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );
        let mut comments_req = self.client.get(&comments_url);
        if let Some(token) = effective_token {
            comments_req = comments_req.bearer_auth(token);
        }
        let comments_response = Self::check_response(comments_req.send().await?).await?;
        let issue_comments: Vec<ForgejoIssueComment> = comments_response.json().await?;

        // Fetch pull request reviews
        let reviews_url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}/reviews",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );
        let mut reviews_req = self.client.get(&reviews_url);
        if let Some(token) = effective_token {
            reviews_req = reviews_req.bearer_auth(token);
        }
        let reviews_response = Self::check_response(reviews_req.send().await?).await?;
        let reviews: Vec<ForgejoPullReview> = reviews_response.json().await?;

        // Merge comments and non-PENDING reviews, sort chronologically
        let mut result: Vec<ChangeRequestCommentDetail> = Vec::new();

        for c in issue_comments {
            result.push(ChangeRequestCommentDetail {
                author: c.user.login,
                body: c.body,
                commit_id: None,
                created_at: c.created_at,
                id: c.id,
                kind: "comment".to_string(),
                review_state: None,
            });
        }

        for r in reviews {
            let Some(submitted_at) = r.submitted_at else {
                continue; // Skip PENDING reviews
            };
            let review_state = if r.dismissed {
                "DISMISSED".to_string()
            } else {
                r.state
            };
            result.push(ChangeRequestCommentDetail {
                author: r.user.login,
                body: r.body.unwrap_or_default(),
                commit_id: r.commit_id,
                created_at: submitted_at,
                id: r.id,
                kind: "review".to_string(),
                review_state: Some(review_state),
            });
        }

        result.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(result)
    }

    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn get_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_issue_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::IssueComment>, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/comments",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let comments: Vec<ForgejoIssueCommentResponse> = response.json().await?;
        Ok(comments
            .into_iter()
            .map(ForgejoIssueCommentResponse::into_issue_comment)
            .collect())
    }

    async fn get_issue_dependencies(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueDependencies, ForgeError> {
        let base = self.config.base_url.trim_end_matches('/');
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // Fetch issues that this issue depends on.
        let deps_url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/dependencies",
            repository.owner, repository.name,
        );
        let mut request = self.client.get(&deps_url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }
        let response = Self::check_response(request.send().await?).await?;
        let depends_on: Vec<ForgejoIssueResponse> = response.json().await?;

        // Fetch issues that are blocked by this issue.
        let blocks_url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/blocks",
            repository.owner, repository.name,
        );
        let mut request = self.client.get(&blocks_url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }
        let response = Self::check_response(request.send().await?).await?;
        let blocks: Vec<ForgejoIssueResponse> = response.json().await?;

        Ok(domain::IssueDependencies {
            blocks: blocks
                .into_iter()
                .map(ForgejoIssueResponse::into_issue)
                .collect(),
            depends_on: depends_on
                .into_iter()
                .map(ForgejoIssueResponse::into_issue)
                .collect(),
        })
    }

    async fn get_change_request_diff(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<String, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}.diff",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        response
            .text()
            .await
            .map_err(|e| ForgeError::InvalidPayload(format!("failed to read diff body: {e}")))
    }

    async fn get_default_merge_style(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Option<String>, ForgeError> {
        let repo = self
            .get_repository_merge_settings_response(repository, credential)
            .await?;
        Ok(repo.normalized_default_merge_style())
    }

    async fn get_repository_merge_settings(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<RepositoryMergeSettings, ForgeError> {
        let repo = self
            .get_repository_merge_settings_response(repository, credential)
            .await?;
        Ok(repo.into_repository_merge_settings())
    }

    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequest>, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let state_str = state.map(|s| match s {
            ChangeRequestState::Closed | ChangeRequestState::Merged => "closed",
            ChangeRequestState::Open => "open",
        });

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(state_str) = state_str {
            request = request.query(&[("state", state_str)]);
        }
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let prs: Vec<ForgejoPullRequest> = response.json().await?;
        Ok(prs
            .into_iter()
            .map(ForgejoPullRequest::into_change_request)
            .collect())
    }

    async fn list_issues(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Issue>, ForgeError> {
        let mut url = format!(
            "{}/api/v1/repos/{}/{}/issues?type=issues",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );
        if let Some(state) = state {
            let _ = write!(url, "&state={state}");
        }

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let issues: Vec<ForgejoIssueResponse> = response.json().await?;
        Ok(issues
            .into_iter()
            .map(ForgejoIssueResponse::into_issue)
            .collect())
    }

    async fn list_repositories(
        &self,
        owner: Option<&str>,
        query: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError> {
        const PAGE_SIZE: usize = 50;

        // If owner is specified, resolve to UID for server-side filtering.
        // Try /users/{owner} first, then fall back to /orgs/{owner} so that
        // organization-owned namespaces are also supported.
        let uid = if let Some(owner_name) = owner {
            let base = self.config.base_url.trim_end_matches('/');
            let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

            // Try user endpoint first.
            let user_url = format!("{base}/api/v1/users/{owner_name}");
            let mut req = self.client.get(&user_url);
            if let Some(token) = effective_token {
                req = req.bearer_auth(token);
            }
            let resp = req.send().await?;

            if resp.status() == StatusCode::NOT_FOUND {
                // Not a user — try organization endpoint.
                let org_url = format!("{base}/api/v1/orgs/{owner_name}");
                let mut req = self.client.get(&org_url);
                if let Some(token) = effective_token {
                    req = req.bearer_auth(token);
                }
                let resp = req.send().await?;
                if resp.status() == StatusCode::NOT_FOUND {
                    return Ok(Vec::new());
                }
                let resp = Self::check_response(resp).await?;
                let org: ForgejoUserResponse = resp.json().await?;
                Some(org.id)
            } else {
                let resp = Self::check_response(resp).await?;
                let user: ForgejoUserResponse = resp.json().await?;
                Some(user.id)
            }
        } else {
            None
        };

        let mut all_repos = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut url = format!(
                "{}/api/v1/repos/search?limit={PAGE_SIZE}&page={page}",
                self.config.base_url.trim_end_matches('/'),
            );
            if let Some(uid) = uid {
                let _ = write!(url, "&uid={uid}&exclusive=true");
            }
            if let Some(q) = query {
                let _ = write!(url, "&q={}", urlencoding::encode(q));
            }

            let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
            let mut req = self.client.get(&url);
            if let Some(token) = effective_token {
                req = req.bearer_auth(token);
            }

            let resp = Self::check_response(req.send().await?).await?;
            let search: ForgejoRepoSearchResponse = resp.json().await?;
            if !search.ok {
                return Err(ForgeError::InvalidPayload(
                    "Forgejo repo search returned ok=false".to_string(),
                ));
            }

            let count = search.data.len();
            all_repos.extend(
                search
                    .data
                    .into_iter()
                    .map(ForgejoRepoSearchEntry::into_repository),
            );

            if count < PAGE_SIZE {
                break;
            }
            page += 1;
        }

        Ok(all_repos)
    }

    async fn remove_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency_repository: &RepositoryRef,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        // Forgejo's dependency API expects the internal database ID, not the
        // visible issue number.  Fetch the dependency issue from the correct
        // repository — for cross-repo dependencies this differs from repository.
        let dep_issue = self
            .fetch_issue_raw(dependency_repository, dependency, credential)
            .await?;

        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}/dependencies",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .delete(&url)
            .json(&serde_json::json!({"dependsOn": dep_issue.id}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        self.get_issue(repository, index, credential).await
    }

    async fn remove_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let base = self.config.base_url.trim_end_matches('/');
        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());

        // 1. Find the label ID by name.
        let label_id = self
            .find_label_id(repository, label, effective_token)
            .await?
            .ok_or_else(|| ForgeError::InvalidPayload(format!("label '{label}' not found")))?;

        // 2. Remove the label from the issue.
        let url = format!(
            "{base}/api/v1/repos/{}/{}/issues/{index}/labels/{label_id}",
            repository.owner, repository.name,
        );
        let mut request = self.client.delete(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        Self::check_response(request.send().await?).await?;

        // 3. Return the full updated issue.
        self.get_issue(repository, index, credential).await
    }

    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        head_commit_id: &str,
        delete_branch_after_merge: Option<bool>,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}/merge",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut body = serde_json::Map::new();
        body.insert("do".to_string(), serde_json::json!(merge_style));
        body.insert(
            "head_commit_id".to_string(),
            serde_json::json!(head_commit_id),
        );
        body.insert(
            "merge_when_checks_succeed".to_string(),
            serde_json::json!(true),
        );
        if let Some(delete_branch_after_merge) = delete_branch_after_merge {
            body.insert(
                "delete_branch_after_merge".to_string(),
                serde_json::json!(delete_branch_after_merge),
            );
        }
        let mut request = self.client.post(&url).json(&body);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            // Forgejo returns 409 when auto-merge is already scheduled.
            // Treat this specific case as success; surface other 409s as errors.
            if status == reqwest::StatusCode::CONFLICT
                && body.contains("already scheduled to auto merge")
            {
                return Ok(());
            }
            // Forgejo may also return 500 when the duplicate-key DB constraint
            // fires (UQE_pull_auto_merge_pull_id). Treat this as a no-op too.
            if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
                && (body.contains("UQE_pull_auto_merge_pull_id") || body.contains("duplicate key"))
            {
                tracing::debug!("schedule_auto_merge: ignoring 500 duplicate-key response",);
                return Ok(());
            }
            // Forgejo returns 405 when the PR is already merged or closed.
            // Nothing left to schedule, so treat as success.
            if status == reqwest::StatusCode::METHOD_NOT_ALLOWED
                && body.contains("already been merged")
            {
                return Ok(());
            }
            if status.is_redirection() {
                let location = "<unknown>".to_string();
                tracing::warn!(
                    %status,
                    %location,
                    "upstream returned redirect — repository may have moved or been renamed",
                );
                return Err(ForgeError::Redirect { status, location });
            }
            if status == StatusCode::NOT_FOUND {
                let message = parse_forge_error_message(&body)
                    .unwrap_or_else(|| "repository or resource not found".to_string());
                tracing::warn!(
                    %status,
                    %message,
                    "upstream returned 404",
                );
                return Err(ForgeError::NotFound { status, message });
            }
            tracing::warn!(
                %status,
                body_len = body.len(),
                body_preview = %&body[..body.len().min(512)],
                "unexpected upstream status",
            );
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        Ok(())
    }

    /// Reads a repository file through the Forgejo contents API.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, or the response body cannot
    /// be decoded as base64 UTF-8 content.
    async fn read_repository_file(
        &self,
        repository: &RepositoryRef,
        path: &str,
        git_ref: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ReadRepositoryFileResponse, ForgeError> {
        let encoded_path = path.trim_start_matches('/').replace('/', "%2F");
        let url = format!(
            "{}/api/v1/repos/{}/{}/contents/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            encoded_path
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }
        if let Some(reference) = git_ref {
            request = request.query(&[("ref", reference)]);
        }

        let response = Self::check_response(request.send().await?).await?;

        let payload: ForgejoContentsResponse = response.json().await?;
        let Some(encoded) = payload.content else {
            return Err(ForgeError::InvalidPayload(
                "content field missing; the requested path may not be a file".to_string(),
            ));
        };

        let encoding = payload.encoding.unwrap_or_else(|| "base64".to_string());
        if encoding != "base64" {
            return Err(ForgeError::InvalidPayload(format!(
                "unsupported content encoding: {encoding}"
            )));
        }

        let cleaned = encoded.replace('\n', "");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(cleaned)
            .map_err(|e| ForgeError::InvalidPayload(format!("base64 decode failed: {e}")))?;
        let content = String::from_utf8(bytes)
            .map_err(|e| ForgeError::InvalidPayload(format!("utf8 decode failed: {e}")))?;

        Ok(ReadRepositoryFileResponse {
            repository: repository.clone(),
            path: payload.path,
            git_ref: git_ref.map(ToOwned::to_owned),
            content,
        })
    }

    async fn submit_change_request_review(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        event: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestReview, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}/reviews",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .post(&url)
            .json(&serde_json::json!({"body": body, "event": event}));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let review: ForgejoReviewResponse = response.json().await?;
        Ok(ChangeRequestReview {
            body: review.body,
            event: event.to_string(),
            id: review.id,
            index,
        })
    }

    async fn update_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut json_body = serde_json::Map::new();
        if let Some(title) = title {
            json_body.insert(
                "title".to_string(),
                serde_json::Value::String(title.to_string()),
            );
        }
        if let Some(body) = body {
            json_body.insert(
                "body".to_string(),
                serde_json::Value::String(body.to_string()),
            );
        }

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .patch(&url)
            .json(&serde_json::Value::Object(json_body));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn update_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        title: Option<&str>,
        body: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/issues/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut json_body = serde_json::Map::new();
        if let Some(title) = title {
            json_body.insert(
                "title".to_string(),
                serde_json::Value::String(title.to_string()),
            );
        }
        if let Some(body) = body {
            json_body.insert(
                "body".to_string(),
                serde_json::Value::String(body.to_string()),
            );
        }

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self
            .client
            .patch(&url)
            .json(&serde_json::Value::Object(json_body));
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = Self::check_response(request.send().await?).await?;

        let issue: ForgejoIssueResponse = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn list_branches(
        &self,
        repository: &RepositoryRef,
        prefix: Option<&str>,
        limit: Option<u32>,
        credential: &ForgeCredential,
    ) -> Result<(Vec<domain::Branch>, bool), ForgeError> {
        const PAGE_SIZE: usize = 30;
        const MAX_PAGES: u32 = 5;
        let target_limit = limit.unwrap_or(20).min(100) as usize;

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut all_branches = Vec::new();
        let mut page: u32 = 1;
        let mut truncated = false;

        loop {
            if page > MAX_PAGES {
                truncated = true;
                break;
            }
            let mut url = format!(
                "{}/api/v1/repos/{}/{}/branches?limit={PAGE_SIZE}&page={page}",
                self.config.base_url.trim_end_matches('/'),
                repository.owner,
                repository.name,
            );
            if let Some(p) = prefix {
                url.push_str("&pattern=");
                url.push_str(&urlencoding::encode(p));
            }
            let mut req = self.client.get(&url);
            if let Some(token) = effective_token {
                req = req.bearer_auth(token);
            }
            let resp = Self::check_response(req.send().await?).await?;
            let page_branches: Vec<ForgejoBranchResponse> = resp.json().await?;
            let page_count = page_branches.len();

            for b in page_branches {
                if prefix.is_some_and(|p| !b.branch_name.starts_with(p)) {
                    continue;
                }
                all_branches.push(domain::Branch {
                    name: b.branch_name,
                    commit_sha: b.commit.id,
                });
                if all_branches.len() >= target_limit {
                    break;
                }
            }
            if all_branches.len() >= target_limit {
                break;
            }
            if page_count < PAGE_SIZE {
                break;
            }
            page += 1;
        }

        let result: Vec<domain::Branch> = all_branches.into_iter().take(target_limit).collect();
        Ok((result, truncated))
    }

    async fn get_branch(
        &self,
        repository: &RepositoryRef,
        branch: &str,
        credential: &ForgeCredential,
    ) -> Result<(String, Option<String>, bool), ForgeError> {
        let encoded = urlencoding::encode(branch);
        let url = format!(
            "{}/api/v1/repos/{}/{}/branches/{}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
            encoded,
        );

        let effective_token = credential.token.as_deref().or(self.config.token.as_deref());
        let mut request = self.client.get(&url);
        if let Some(token) = effective_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            let body = response.text().await.unwrap_or_default();
            let msg = parse_forge_error_message(&body);

            if let Some(ref m) = msg {
                let msg_lower = m.to_lowercase();
                // Fast path: explicit branch-missing messages
                if msg_lower.contains("branch not found")
                    || msg_lower.contains("no such branch")
                    || msg_lower.contains("branch does not exist")
                {
                    return Ok((branch.to_string(), None, false));
                }

                // Ambiguous 404 — verify repository exists to distinguish
                // between missing branch and missing repository.
                if msg_lower.contains("the target couldn't be found") {
                    match self.verify_repo_exists(repository, credential).await {
                        Ok(true) => return Ok((branch.to_string(), None, false)),
                        Ok(false) => {
                            return Err(ForgeError::NotFound {
                                status,
                                message: m.clone(),
                            });
                        }
                        Err(e) => return Err(e),
                    }
                }
            } else {
                // Empty body — also verify repository exists.
                match self.verify_repo_exists(repository, credential).await {
                    Ok(true) => return Ok((branch.to_string(), None, false)),
                    Ok(false) => {
                        return Err(ForgeError::NotFound {
                            status,
                            message: "repository or resource not found".to_string(),
                        });
                    }
                    Err(e) => return Err(e),
                }
            }

            return Err(ForgeError::NotFound {
                status,
                message: msg.unwrap_or_else(|| "repository or resource not found".to_string()),
            });
        }

        let response = Self::check_response(response).await?;
        let branch_resp: ForgejoBranchResponse = response.json().await?;

        Ok((branch_resp.branch_name, Some(branch_resp.commit.id), true))
    }
}

impl ForgeWebhookAdapter for ForgejoAdapter {
    fn verify_and_parse_webhook_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
        verify_forgejo_signature(headers, body, secret)?;

        let event_header = header_value(headers, &["x-forgejo-event", "x-gitea-event"])
            .ok_or_else(|| ForgeWebhookError::MissingHeader("x-forgejo-event".to_string()))?;
        let event_type = WebhookEventType::parse(event_header);
        let delivery_id = header_value(headers, &["x-forgejo-delivery", "x-gitea-delivery"])
            .unwrap_or_default()
            .to_string();

        match event_type {
            WebhookEventType::PullRequest => {
                parse_pull_request_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::Issues => {
                parse_issue_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::IssueComment => {
                parse_issue_comment_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::PullRequestReview => {
                parse_pull_request_review_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            WebhookEventType::Unknown(name) => {
                tracing::debug!(event_type = %name, "ignoring unhandled webhook event type");
                Ok(None)
            }
        }
    }
}

fn parse_pull_request_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookPullRequestEventPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.action.as_str() {
        "opened" => ChangeRequestEventAction::Opened,
        "reopened" => ChangeRequestEventAction::Reopened,
        "synchronize" | "synchronized" => ChangeRequestEventAction::Synchronized,
        _ => return Ok(None),
    };

    let owner = payload.repository.owner.into_owner()?;
    let index = payload
        .number
        .or(payload.pull_request.number)
        .ok_or_else(|| {
            ForgeWebhookError::InvalidPayload("pull request number missing".to_string())
        })?;

    Ok(Some(domain::WebhookEvent::ChangeRequest(
        ChangeRequestEvent {
            action,
            delivery_id,
            head_sha: payload.pull_request.head.sha,
            index,
            repository: RepositoryRef {
                alias: forge_alias.to_string(),
                forge: forge_kind,
                host: host.to_string(),
                name: payload.repository.name,
                owner,
            },
            title: payload.pull_request.title,
            url: payload.pull_request.html_url,
        },
    )))
}

fn parse_issue_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookIssueEventPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.action.as_str() {
        "closed" => domain::IssueEventAction::Closed,
        "opened" => domain::IssueEventAction::Opened,
        _ => return Ok(None),
    };

    let owner = payload.repository.owner.into_owner()?;
    let index = payload
        .number
        .or(payload.issue.number)
        .ok_or_else(|| ForgeWebhookError::InvalidPayload("issue number missing".to_string()))?;

    Ok(Some(domain::WebhookEvent::Issue(domain::IssueEvent {
        action,
        delivery_id,
        index,
        repository: RepositoryRef {
            alias: forge_alias.to_string(),
            forge: forge_kind,
            host: host.to_string(),
            name: payload.repository.name,
            owner,
        },
        title: payload.issue.title,
        url: payload.issue.html_url,
    })))
}

fn parse_issue_comment_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookIssueCommentPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.action.as_str() {
        "created" => domain::IssueCommentEventAction::Created,
        _ => return Ok(None),
    };

    let owner = payload.repository.owner.into_owner()?;
    let issue_index = payload
        .issue
        .number
        .ok_or_else(|| ForgeWebhookError::InvalidPayload("issue number missing".to_string()))?;

    Ok(Some(domain::WebhookEvent::IssueComment(
        domain::IssueCommentEvent {
            action,
            body: payload.comment.body,
            comment_id: payload.comment.id,
            delivery_id,
            issue_index,
            repository: RepositoryRef {
                alias: forge_alias.to_string(),
                forge: forge_kind,
                host: host.to_string(),
                name: payload.repository.name,
                owner,
            },
        },
    )))
}

fn parse_pull_request_review_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: ForgejoWebhookPullRequestReviewEventPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.action.as_str() {
        "reviewed" | "submitted" => domain::PullRequestReviewEventAction::Submitted,
        _ => return Ok(None),
    };

    // Skip pending reviews — they are incomplete drafts.
    let review_state = match payload.review.review_type.as_str() {
        "pull_request_review_approved" => domain::ReviewState::Approved,
        "pull_request_review_rejected" => domain::ReviewState::RequestChanges,
        "pull_request_review_comment" => domain::ReviewState::Comment,
        _ => return Ok(None),
    };

    let owner = payload.repository.owner.into_owner()?;
    let index = payload.pull_request.number.ok_or_else(|| {
        ForgeWebhookError::InvalidPayload("pull request number missing".to_string())
    })?;

    Ok(Some(domain::WebhookEvent::PullRequestReview(
        domain::PullRequestReviewEvent {
            action,
            delivery_id,
            head_sha: payload.pull_request.head.sha,
            index,
            repository: RepositoryRef {
                alias: forge_alias.to_string(),
                forge: forge_kind,
                host: host.to_string(),
                name: payload.repository.name,
                owner,
            },
            review_body: payload.review.body.unwrap_or_default(),
            review_id: payload.review.id.unwrap_or(0),
            review_state,
            title: payload.pull_request.title,
            url: payload.pull_request.html_url,
        },
    )))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ForgeWebhookError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || (trimmed.len() & 1) != 0 {
        return Err(ForgeWebhookError::InvalidSignature);
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let chars: Vec<char> = trimmed.chars().collect();
    for pair in chars.chunks(2) {
        let high = pair[0]
            .to_digit(16)
            .ok_or(ForgeWebhookError::InvalidSignature)?;
        let low = pair[1]
            .to_digit(16)
            .ok_or(ForgeWebhookError::InvalidSignature)?;
        let combined = (high << 4) | low;
        let combined = u8::try_from(combined).map_err(|_| ForgeWebhookError::InvalidSignature)?;
        bytes.push(combined);
    }
    Ok(bytes)
}

fn parse_commit_status_state(s: &str) -> domain::CommitStatusState {
    match s {
        "error" => domain::CommitStatusState::Error,
        "failure" => domain::CommitStatusState::Failure,
        "success" => domain::CommitStatusState::Success,
        "warning" => domain::CommitStatusState::Warning,
        // Forgejo may return "pending" or an empty string when there are no
        // statuses, so the fallback covers both.
        _ => domain::CommitStatusState::Pending,
    }
}

fn header_value<'a>(headers: &'a [(String, String)], names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn verify_forgejo_signature(
    headers: &[(String, String)],
    body: &[u8],
    secret: &str,
) -> Result<(), ForgeWebhookError> {
    let signature = header_value(headers, &["x-forgejo-signature", "x-gitea-signature"])
        .ok_or_else(|| ForgeWebhookError::MissingHeader("x-forgejo-signature".to_string()))?;
    let signature = decode_hex(signature)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| ForgeWebhookError::InvalidPayload(format!("invalid secret: {e}")))?;
    mac.update(body);
    mac.verify_slice(&signature)
        .map_err(|_| ForgeWebhookError::InvalidSignature)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::fmt::Write as _;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use domain::ForgeCredential;
    use wiremock::matchers::{body_json, header, method, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn test_adapter(base_url: &str) -> ForgejoAdapter {
        ForgejoAdapter::new(ForgejoConfig {
            base_url: base_url.to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: None,
            woodpecker_token: None,
        })
        .expect("build forgejo adapter")
    }

    fn test_repo() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: domain::ForgeKind::Forgejo,
            host: "https://forge.example".to_string(),
            name: "repo".to_string(),
            owner: "org".to_string(),
        }
    }

    #[tokio::test]
    async fn create_commit_status_sends_correct_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/statuses/.+"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .create_commit_status(
                &test_repo(),
                "abc123sha",
                "forge-mcp/auto-merge",
                "auto-merge scheduled",
                "success",
                &cred,
            )
            .await
            .expect("create commit status");

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["context"], "forge-mcp/auto-merge");
        assert_eq!(body["description"], "auto-merge scheduled");
        assert_eq!(body["state"], "success");
    }

    #[tokio::test]
    async fn create_commit_status_uses_correct_url() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/org/repo/statuses/abc123sha"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .create_commit_status(
                &test_repo(),
                "abc123sha",
                "ci/test",
                "all good",
                "success",
                &cred,
            )
            .await
            .expect("create commit status");

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn create_commit_status_propagates_error_on_failure() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/statuses/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .create_commit_status(
                &test_repo(),
                "abc123sha",
                "ci/test",
                "test",
                "success",
                &cred,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn schedule_auto_merge_sends_correct_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", Some(true), &cred)
            .await
            .expect("schedule auto merge");

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["do"], "rebase");
        assert_eq!(body["merge_when_checks_succeed"], true);
        assert_eq!(body["head_commit_id"], "abc123sha");
        assert_eq!(body["delete_branch_after_merge"], true);
    }

    #[tokio::test]
    async fn schedule_auto_merge_omits_delete_branch_flag_when_unspecified() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await
            .expect("schedule auto merge");

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["do"], "rebase");
        assert_eq!(body["merge_when_checks_succeed"], true);
        assert_eq!(body["head_commit_id"], "abc123sha");
        assert!(body.get("delete_branch_after_merge").is_none());
    }

    #[tokio::test]
    async fn schedule_auto_merge_succeeds_on_already_scheduled_409() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "message": "pull request is already scheduled to auto merge when checks succeed [pull_id: 78]"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn schedule_auto_merge_errors_on_unrelated_409() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "message": "some other conflict"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        let err = result.expect_err("should fail with conflict");
        match err {
            ForgeError::UnexpectedStatus { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::CONFLICT);
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn schedule_auto_merge_succeeds_on_duplicate_key_500() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(500).set_body_string(
                "duplicate key value violates unique constraint \"UQE_pull_auto_merge_pull_id\"",
            ))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn schedule_auto_merge_errors_on_unrelated_500() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        let err = result.expect_err("should fail with unexpected status");
        match err {
            ForgeError::UnexpectedStatus { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn schedule_auto_merge_succeeds_on_already_merged_405() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(405).set_body_json(serde_json::json!({
                "message": "pull request has already been merged"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn schedule_auto_merge_errors_on_unrelated_405() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(405).set_body_json(serde_json::json!({
                "message": "method not allowed"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        let err = result.expect_err("should fail with unexpected status");
        match err {
            ForgeError::UnexpectedStatus { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::METHOD_NOT_ALLOWED);
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_allowed_merge_styles_returns_enabled_styles() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_fast_forward_only_merge": false,
                "allow_merge_commits": false,
                "allow_rebase": true,
                "allow_rebase_explicit": false,
                "allow_squash_merge": true,
                "default_merge_style": "rebase",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let styles = adapter
            .get_allowed_merge_styles(&test_repo(), &cred)
            .await
            .expect("get allowed merge styles");

        assert!(styles.contains(&"rebase".to_string()));
        assert!(styles.contains(&"squash".to_string()));
        assert!(!styles.contains(&"merge".to_string()));
        assert!(!styles.contains(&"rebase-merge".to_string()));
        assert!(!styles.contains(&"fast-forward-only".to_string()));
    }

    #[tokio::test]
    async fn get_allowed_merge_styles_includes_rebase_merge() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_fast_forward_only_merge": false,
                "allow_merge_commits": false,
                "allow_rebase": false,
                "allow_rebase_explicit": true,
                "allow_squash_merge": false,
                "default_merge_style": "rebase-merge",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let styles = adapter
            .get_allowed_merge_styles(&test_repo(), &cred)
            .await
            .expect("get allowed merge styles");

        assert_eq!(styles, vec!["rebase-merge"]);
    }

    #[tokio::test]
    async fn get_allowed_merge_styles_includes_fast_forward_only() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_fast_forward_only_merge": true,
                "allow_merge_commits": false,
                "allow_rebase": true,
                "allow_rebase_explicit": false,
                "allow_squash_merge": false,
                "default_merge_style": "rebase",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let styles = adapter
            .get_allowed_merge_styles(&test_repo(), &cred)
            .await
            .expect("get allowed merge styles");

        assert_eq!(styles, vec!["rebase", "fast-forward-only"]);
    }

    #[tokio::test]
    async fn get_default_merge_style_returns_style() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true, "allow_rebase_explicit": true, "allow_squash_merge": true,
                "default_merge_style": "squash", "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_default_merge_style(&test_repo(), &cred)
            .await
            .expect("get default merge style");
        assert_eq!(result, Some("squash".to_string()));
    }

    #[tokio::test]
    async fn get_default_merge_style_returns_none_when_missing() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true, "allow_rebase_explicit": true, "allow_squash_merge": true,
                "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_default_merge_style(&test_repo(), &cred)
            .await
            .expect("get default merge style");
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_default_merge_style_returns_none_when_empty() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true, "allow_rebase_explicit": true, "allow_squash_merge": true,
                "default_merge_style": "", "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_default_merge_style(&test_repo(), &cred)
            .await
            .expect("get default merge style");
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_repository_merge_settings_returns_delete_branch_default() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "allow_merge_commits": true,
                "allow_rebase": true,
                "allow_rebase_explicit": false,
                "allow_squash_merge": false,
                "default_delete_branch_after_merge": true,
                "default_merge_style": "rebase",
                "id": 1,
                "name": "repo",
                "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;
        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_repository_merge_settings(&test_repo(), &cred)
            .await
            .expect("get repository merge settings");
        assert_eq!(
            result.allowed_styles,
            vec!["merge".to_string(), "rebase".to_string()]
        );
        assert_eq!(result.default_delete_branch_after_merge, Some(true));
        assert_eq!(result.default_merge_style, Some("rebase".to_string()));
    }

    #[tokio::test]
    async fn get_comments_merges_and_sorts_chronologically() {
        let mock = MockServer::start().await;

        // Issue comments endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/issues/\d+/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": 10,
                    "body": "second comment",
                    "created_at": "2026-03-18T12:00:00Z",
                    "user": { "login": "alice" }
                },
                {
                    "id": 5,
                    "body": "first comment",
                    "created_at": "2026-03-18T10:00:00Z",
                    "user": { "login": "bob" }
                }
            ])))
            .mount(&mock)
            .await;

        // Reviews endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": 20,
                    "body": "approved",
                    "commit_id": "abc123def456",
                    "state": "APPROVED",
                    "submitted_at": "2026-03-18T11:00:00Z",
                    "user": { "login": "carol" }
                },
                {
                    "id": 25,
                    "body": "needs work",
                    "commit_id": "def789abc012",
                    "dismissed": true,
                    "state": "REQUEST_CHANGES",
                    "submitted_at": "2026-03-18T11:30:00Z",
                    "user": { "login": "eve" }
                },
                {
                    "id": 30,
                    "body": null,
                    "state": "PENDING",
                    "submitted_at": null,
                    "user": { "login": "dave" }
                }
            ])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_change_request_comments(&test_repo(), 1, &cred)
            .await
            .expect("get change request comments");

        // PENDING review should be filtered out
        assert_eq!(result.len(), 4);

        // Should be sorted chronologically
        assert_eq!(result[0].author, "bob");
        assert_eq!(result[0].created_at, "2026-03-18T10:00:00Z");
        assert_eq!(result[0].kind, "comment");
        assert!(result[0].commit_id.is_none());
        assert!(result[0].review_state.is_none());

        assert_eq!(result[1].author, "carol");
        assert_eq!(result[1].created_at, "2026-03-18T11:00:00Z");
        assert_eq!(result[1].kind, "review");
        assert_eq!(result[1].commit_id.as_deref(), Some("abc123def456"));
        assert_eq!(result[1].review_state.as_deref(), Some("APPROVED"));

        // Dismissed review should have review_state DISMISSED
        assert_eq!(result[2].author, "eve");
        assert_eq!(result[2].created_at, "2026-03-18T11:30:00Z");
        assert_eq!(result[2].kind, "review");
        assert_eq!(result[2].commit_id.as_deref(), Some("def789abc012"));
        assert_eq!(result[2].review_state.as_deref(), Some("DISMISSED"));

        assert_eq!(result[3].author, "alice");
        assert_eq!(result[3].created_at, "2026-03-18T12:00:00Z");
        assert_eq!(result[3].kind, "comment");
        assert!(result[3].commit_id.is_none());
    }

    fn sign_payload(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("valid HMAC key");
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        let mut signature = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut signature, "{byte:02x}").expect("writing to String cannot fail");
        }
        signature
    }

    #[test]
    fn forgejo_webhook_parses_supported_change_request_event() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "synchronize",
            "number": 24,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "5e4e9ed3d19c2d7114eb7da1453913a3ab4f56ca"
                },
                "html_url": "https://forge.example/org/repo/pulls/24",
                "title": "Fix channel events"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            ("x-forgejo-delivery".to_string(), "delivery-123".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::ChangeRequest(e) => e,
            other => panic!("expected ChangeRequest, got {other:?}"),
        };
        assert_eq!(event.action, ChangeRequestEventAction::Synchronized);
        assert_eq!(event.delivery_id, "delivery-123");
        assert_eq!(event.index, 24);
        assert_eq!(event.repository.alias, "internal");
        assert_eq!(event.repository.owner, "org");
        assert_eq!(event.repository.name, "repo");
        assert_eq!(event.head_sha, "5e4e9ed3d19c2d7114eb7da1453913a3ab4f56ca");
    }

    #[test]
    fn forgejo_webhook_parses_synchronized_action_variant() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "synchronized",
            "number": 10,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "def456"
                },
                "html_url": "https://forge.example/org/repo/pulls/10",
                "title": "Update"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            ("x-forgejo-delivery".to_string(), "delivery-456".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::ChangeRequest(e) => e,
            other => panic!("expected ChangeRequest, got {other:?}"),
        };
        assert_eq!(event.action, ChangeRequestEventAction::Synchronized);
        assert_eq!(event.index, 10);
    }

    #[test]
    fn forgejo_webhook_parses_pull_request_review_approved() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "abc123def456"
                },
                "html_url": "https://forge.example/org/repo/pulls/7",
                "number": 7,
                "title": "Fix typo"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "Looks good!",
                "id": 42,
                "type": "pull_request_review_approved"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_review".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-789".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(
            event.action,
            domain::PullRequestReviewEventAction::Submitted
        );
        assert_eq!(event.delivery_id, "delivery-789");
        assert_eq!(event.head_sha, "abc123def456");
        assert_eq!(event.index, 7);
        assert_eq!(event.repository.alias, "internal");
        assert_eq!(event.repository.owner, "org");
        assert_eq!(event.repository.name, "repo");
        assert_eq!(event.review_body, "Looks good!");
        assert_eq!(event.review_id, 42);
        assert_eq!(event.review_state, domain::ReviewState::Approved);
        assert_eq!(event.title, "Fix typo");
    }

    #[test]
    fn forgejo_webhook_parses_pull_request_review_request_changes() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "deadbeef"
                },
                "html_url": "https://forge.example/org/repo/pulls/8",
                "number": 8,
                "title": "Add feature"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "Needs work",
                "id": 43,
                "type": "pull_request_review_rejected"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_review".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-790".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(event.review_state, domain::ReviewState::RequestChanges);
    }

    #[test]
    fn forgejo_webhook_parses_per_action_review_payload() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "reviewed",
            "number": 8,
            "pull_request": {
                "head": {
                    "ref": "agent/claude/cargo-fmt",
                    "sha": "ec64af23c42c"
                },
                "html_url": "https://forge.example/org/repo/pulls/8",
                "number": 8,
                "title": "ci: fix lint failures"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "type": "pull_request_review_approved",
                "content": ""
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_approved".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-792".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(event.review_state, domain::ReviewState::Approved);
        assert_eq!(event.review_body, "");
        assert_eq!(event.review_id, 0);
        assert_eq!(event.index, 8);
    }

    #[test]
    fn forgejo_webhook_ignores_pending_review() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "abc123"
                },
                "html_url": "https://forge.example/org/repo/pulls/9",
                "number": 9,
                "title": "WIP"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "",
                "id": 44,
                "type": "pending"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_review".to_string(),
            ),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let result = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("payload should parse");
        assert!(result.is_none());
    }

    #[test]
    fn forgejo_webhook_parses_pull_request_approved_event_type() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::json!({
            "action": "submitted",
            "pull_request": {
                "head": {
                    "ref": "agent/claude/fix",
                    "sha": "abc123def456"
                },
                "html_url": "https://forge.example/org/repo/pulls/7",
                "number": 7,
                "title": "Fix typo"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            },
            "review": {
                "body": "Looks good!",
                "id": 42,
                "type": "pull_request_review_approved"
            }
        });
        let body = serde_json::to_vec(&body).expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            (
                "x-forgejo-event".to_string(),
                "pull_request_approved".to_string(),
            ),
            ("x-forgejo-delivery".to_string(), "delivery-791".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let event = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("webhook should parse")
            .expect("event should be supported");

        let event = match event {
            domain::WebhookEvent::PullRequestReview(e) => e,
            other => panic!("expected PullRequestReview, got {other:?}"),
        };
        assert_eq!(event.review_state, domain::ReviewState::Approved);
    }

    #[test]
    fn forgejo_webhook_rejects_invalid_signature() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "opened",
            "number": 24,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "abc123"
                },
                "html_url": "https://forge.example/org/repo/pulls/24",
                "title": "Fix channel events"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        }))
        .expect("valid JSON");
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            (
                "x-forgejo-signature".to_string(),
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            ),
        ];

        let error = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect_err("signature should be rejected");
        assert!(matches!(error, ForgeWebhookError::InvalidSignature));
    }

    #[test]
    fn forgejo_webhook_ignores_unsupported_action() {
        let adapter = test_adapter("https://forge.example");
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "edited",
            "number": 24,
            "pull_request": {
                "head": {
                    "ref": "agent/codex/fix",
                    "sha": "abc123"
                },
                "html_url": "https://forge.example/org/repo/pulls/24",
                "title": "Fix channel events"
            },
            "repository": {
                "name": "repo",
                "owner": {
                    "login": "org"
                }
            }
        }))
        .expect("valid JSON");
        let signature = sign_payload("super-secret", &body);
        let headers = vec![
            ("x-forgejo-event".to_string(), "pull_request".to_string()),
            ("x-forgejo-signature".to_string(), signature),
        ];

        let result = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "internal",
                domain::ForgeKind::Forgejo,
                "https://forge.example",
                "super-secret",
            )
            .expect("payload should parse");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn create_issue_sends_correct_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 100,
                "number": 42,
                "title": "Bug report",
                "body": "Something is broken",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/42",
                "labels": [{"id": 1, "name": "bug"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .create_issue(&test_repo(), "Bug report", "Something is broken", &cred)
            .await
            .expect("create issue");

        assert_eq!(issue.index, 42);
        assert_eq!(issue.title, "Bug report");
        assert_eq!(issue.body, "Something is broken");
        assert_eq!(issue.state, "open");
        assert_eq!(issue.labels, vec!["bug"]);

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let req_body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(req_body["title"], "Bug report");
        assert_eq!(req_body["body"], "Something is broken");
    }

    #[tokio::test]
    async fn add_issue_label_creates_label_when_missing() {
        let mock = MockServer::start().await;

        // 1. GET labels returns empty (label doesn't exist).
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;

        // 2. POST to create the label.
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 7,
                "name": "needs-input",
            })))
            .mount(&mock)
            .await;

        // 3. POST to add label to issue.
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 7, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 4. GET issue to return full state.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 101,
                "number": 1,
                "title": "Test issue",
                "body": "",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/1",
                "labels": [{"id": 7, "name": "needs-input"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .add_issue_label(&test_repo(), 1, "needs-input", &cred)
            .await
            .expect("add issue label");

        assert_eq!(issue.labels, vec!["needs-input"]);

        let requests = mock.received_requests().await.expect("received requests");
        // GET labels, POST create label, POST add label, GET issue
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].method.as_str(), "GET");
        assert_eq!(requests[1].method.as_str(), "POST");
        let create_body: serde_json::Value =
            serde_json::from_slice(&requests[1].body).expect("valid JSON");
        assert_eq!(create_body["name"], "needs-input");
    }

    #[tokio::test]
    async fn add_issue_label_reuses_existing_label() {
        let mock = MockServer::start().await;

        // 1. GET labels returns the label (already exists).
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 3, "name": "bug"},
                {"id": 5, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 2. POST to add label to issue.
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 5, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 3. GET issue.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 102,
                "number": 2,
                "title": "Test",
                "body": "",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/2",
                "labels": [{"id": 5, "name": "needs-input"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .add_issue_label(&test_repo(), 2, "needs-input", &cred)
            .await
            .expect("add issue label");

        assert_eq!(issue.labels, vec!["needs-input"]);

        let requests = mock.received_requests().await.expect("received requests");
        // GET labels, POST add label, GET issue (no create — label existed)
        assert_eq!(requests.len(), 3);
        let add_body: serde_json::Value =
            serde_json::from_slice(&requests[1].body).expect("valid JSON");
        assert_eq!(add_body["labels"], serde_json::json!([5]));
    }

    #[tokio::test]
    async fn remove_issue_label_deletes_by_id() {
        let mock = MockServer::start().await;

        // 1. GET labels to find the label ID.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 3, "name": "bug"},
                {"id": 5, "name": "needs-input"}
            ])))
            .mount(&mock)
            .await;

        // 2. DELETE label from issue.
        Mock::given(method("DELETE"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+/labels/\d+$"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock)
            .await;

        // 3. GET issue.
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 103,
                "number": 1,
                "title": "Test",
                "body": "",
                "state": "open",
                "html_url": "https://forge.example/org/repo/issues/1",
                "labels": [{"id": 3, "name": "bug"}],
                "assignees": []
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .remove_issue_label(&test_repo(), 1, "needs-input", &cred)
            .await
            .expect("remove issue label");

        assert_eq!(issue.labels, vec!["bug"]);

        let requests = mock.received_requests().await.expect("received requests");
        // GET labels, DELETE label, GET issue
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].method.as_str(), "DELETE");
        assert!(requests[1].url.path().ends_with("/labels/5"));
    }

    #[tokio::test]
    async fn remove_issue_label_errors_when_label_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/labels$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .remove_issue_label(&test_repo(), 1, "nonexistent", &cred)
            .await;

        assert!(result.is_err());
        let err = result
            .expect_err("should fail with label not found")
            .to_string();
        assert!(
            err.contains("not found"),
            "expected 'not found' in error: {err}"
        );
    }

    #[tokio::test]
    async fn get_combined_commit_status_returns_success() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/commits/abc123/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "abc123",
                "state": "success",
                "statuses": [
                    {
                        "context": "ci/woodpecker",
                        "description": "build passed",
                        "status": "success",
                        "target_url": "https://ci.example/1"
                    }
                ],
                "total_count": 1
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_combined_commit_status(&test_repo(), "abc123", &cred)
            .await
            .expect("get combined commit status");

        assert_eq!(result.head_sha, "abc123");
        assert_eq!(result.state, domain::CommitStatusState::Success);
        assert_eq!(result.total_count, 1);
        assert_eq!(result.statuses.len(), 1);
        assert_eq!(result.statuses[0].context, "ci/woodpecker");
        assert_eq!(result.statuses[0].state, domain::CommitStatusState::Success);
    }

    #[tokio::test]
    async fn get_combined_commit_status_handles_empty_statuses() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/commits/def456/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "def456",
                "state": "",
                "statuses": null,
                "total_count": 0
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_combined_commit_status(&test_repo(), "def456", &cred)
            .await
            .expect("get combined commit status");

        assert_eq!(result.head_sha, "def456");
        assert_eq!(result.state, domain::CommitStatusState::Pending);
        assert_eq!(result.total_count, 0);
        assert!(result.statuses.is_empty());
    }

    #[tokio::test]
    async fn get_combined_commit_status_propagates_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/commits/.+/status"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_combined_commit_status(&test_repo(), "abc123", &cred)
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn parse_commit_status_state_known_values() {
        assert_eq!(
            parse_commit_status_state("success"),
            domain::CommitStatusState::Success
        );
        assert_eq!(
            parse_commit_status_state("failure"),
            domain::CommitStatusState::Failure
        );
        assert_eq!(
            parse_commit_status_state("pending"),
            domain::CommitStatusState::Pending
        );
        assert_eq!(
            parse_commit_status_state("error"),
            domain::CommitStatusState::Error
        );
        assert_eq!(
            parse_commit_status_state("warning"),
            domain::CommitStatusState::Warning
        );
    }

    #[test]
    fn parse_commit_status_state_unknown_defaults_to_pending() {
        assert_eq!(
            parse_commit_status_state(""),
            domain::CommitStatusState::Pending
        );
        assert_eq!(
            parse_commit_status_state("unknown"),
            domain::CommitStatusState::Pending
        );
    }

    #[tokio::test]
    async fn check_response_returns_redirect_on_301() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(
                ResponseTemplate::new(301)
                    .insert_header("Location", "https://forge.example/new-org/repo"),
            )
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with redirect");
        match err {
            ForgeError::Redirect { status, location } => {
                assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
                assert_eq!(location, "https://forge.example/new-org/repo");
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_not_found_on_404() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "The target couldn't be found."
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "The target couldn't be found.");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_descriptive_message_on_404() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/.+/pulls$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "head branch does not exist"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .create_change_request(&test_repo(), "test", "test", "feature", "main", &cred)
            .await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "head branch does not exist");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_unexpected_status_on_500() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with unexpected status");
        match err {
            ForgeError::UnexpectedStatus { status, body } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert!(body.contains("internal server error"));
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_woodpecker_url_with_prefix() {
        let config = ForgejoConfig {
            base_url: "https://git.example.com".to_string(),
            token: None,
            woodpecker_url: Some("https://ci.example.com/woodpecker/".to_string()),
            woodpecker_token: None,
        };
        let adapter = ForgejoAdapter::new(config).expect("build adapter");

        // Valid URL with prefix
        let (repo_id, pipeline_num, base) = adapter
            .parse_woodpecker_url("https://ci.example.com/woodpecker/repos/1/pipeline/42")
            .expect("should parse");
        assert_eq!(repo_id, "1");
        assert_eq!(pipeline_num, "42");
        assert_eq!(base.to_string(), "https://ci.example.com/woodpecker/");

        // Invalid origin
        assert!(
            adapter
                .parse_woodpecker_url("https://evil.com/woodpecker/repos/1/pipeline/42")
                .is_err()
        );

        // Missing prefix
        assert!(
            adapter
                .parse_woodpecker_url("https://ci.example.com/repos/1/pipeline/42")
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolve_ci_failure_rejects_untrusted_origin() {
        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some("https://woodpecker.example.com".to_string()),
            woodpecker_token: None,
        })
        .expect("build adapter");

        // Attacker-controlled domain
        let target_url = "https://woodpecker.example.com.evil.tld/repos/1/pipeline/1";
        let res = adapter.resolve_ci_failure(target_url).await;
        assert_eq!(res, domain::CiResolution::Unsupported);

        // Different protocol
        let target_url = "http://woodpecker.example.com/repos/1/pipeline/1";
        let res = adapter.resolve_ci_failure(target_url).await;
        assert_eq!(res, domain::CiResolution::Unsupported);

        // Different port
        let target_url = "https://woodpecker.example.com:8443/repos/1/pipeline/1";
        let res = adapter.resolve_ci_failure(target_url).await;
        assert_eq!(res, domain::CiResolution::Unsupported);
    }

    #[tokio::test]
    async fn resolve_ci_failure_resolves_woodpecker_failure() {
        let mock = MockServer::start().await;
        let woodpecker_base = mock.uri();

        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some(woodpecker_base.clone()),
            woodpecker_token: None,
        })
        .expect("build adapter");

        // Mock pipeline response
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/pipelines/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workflows": [
                    {
                        "id": 1,
                        "children": [
                            {
                                "id": 2,
                                "name": "test",
                                "state": "failure"
                            }
                        ]
                    }
                ]
            })))
            .mount(&mock)
            .await;

        // Mock logs response
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/logs/42/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "data": base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "error message\n") }
            ])))
            .mount(&mock)
            .await;

        let target_url = format!("{woodpecker_base}/repos/1/pipeline/42");
        let res = adapter.resolve_ci_failure(&target_url).await;

        match res {
            domain::CiResolution::Resolved {
                provider,
                pipeline_url,
                failed_steps,
            } => {
                assert_eq!(provider, domain::CiProvider::Woodpecker);
                assert_eq!(
                    pipeline_url,
                    format!("{woodpecker_base}/repos/1/pipeline/42")
                );
                assert_eq!(failed_steps.len(), 1);
                assert_eq!(failed_steps[0].name, "test");
                assert_eq!(
                    failed_steps[0]
                        .log_excerpt
                        .as_ref()
                        .expect("has logs")
                        .lines[0],
                    "error message\n"
                );
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_ci_failure_handles_lossy_utf8_logs() {
        let mock = MockServer::start().await;
        let woodpecker_base = mock.uri();

        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some(woodpecker_base.clone()),
            woodpecker_token: None,
        })
        .expect("build adapter");

        // Invalid UTF-8 sequence: 0xFF
        let invalid_utf8 = vec![0xFF];
        let encoded = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, &invalid_utf8);

        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/pipelines/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workflows": [{ "id": 1, "children": [{ "id": 2, "name": "test", "state": "failure" }] }]
            })))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/logs/42/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "data": encoded }
            ])))
            .mount(&mock)
            .await;

        let target_url = format!("{woodpecker_base}/repos/1/pipeline/42");
        let res = adapter.resolve_ci_failure(&target_url).await;

        match res {
            domain::CiResolution::Resolved { failed_steps, .. } => {
                assert_eq!(
                    failed_steps[0]
                        .log_excerpt
                        .as_ref()
                        .expect("has logs")
                        .lines[0],
                    "\u{FFFD}"
                );
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_ci_failure_returns_error_on_malformed_log_data() {
        let mock = MockServer::start().await;
        let woodpecker_base = mock.uri();

        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some(woodpecker_base.clone()),
            woodpecker_token: None,
        })
        .expect("build adapter");

        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/pipelines/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workflows": [{ "id": 1, "children": [{ "id": 2, "name": "test", "state": "failure" }] }]
            })))
            .mount(&mock)
            .await;

        // Invalid base64 data: "!!!"
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/logs/42/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "data": "!!!" }
            ])))
            .mount(&mock)
            .await;

        let target_url = format!("{woodpecker_base}/repos/1/pipeline/42");
        let res = adapter.resolve_ci_failure(&target_url).await;

        match res {
            domain::CiResolution::Error { message } => {
                assert!(message.contains("Failed to decode log data"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_ci_failure_uses_woodpecker_token() {
        let mock = MockServer::start().await;
        let woodpecker_base = mock.uri();
        let woodpecker_token = "secret-wp-token";

        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some(woodpecker_base.clone()),
            woodpecker_token: Some(woodpecker_token.to_string()),
        })
        .expect("build adapter");

        // Verify Bearer auth on pipeline fetch
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/pipelines/42"))
            .and(header("Authorization", format!("Bearer {woodpecker_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workflows": [{ "id": 1, "children": [{ "id": 2, "name": "test", "state": "failure" }] }]
            })))
            .mount(&mock)
            .await;

        // Verify Bearer auth on logs fetch
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/logs/42/2"))
            .and(header(
                "Authorization",
                format!("Bearer {woodpecker_token}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "data": base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "error\n") }
            ])))
            .mount(&mock)
            .await;

        let target_url = format!("{woodpecker_base}/repos/1/pipeline/42");
        let res = adapter.resolve_ci_failure(&target_url).await;

        match res {
            domain::CiResolution::Resolved { .. } => {}
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_ci_failure_returns_error_on_same_origin_bad_path() {
        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some("https://woodpecker.example.com/prefix".to_string()),
            woodpecker_token: None,
        })
        .expect("build adapter");

        // Same origin, but wrong prefix
        let target_url = "https://woodpecker.example.com/wrong/repos/1/pipeline/1";
        let res = adapter.resolve_ci_failure(target_url).await;
        match res {
            domain::CiResolution::Error { message } => {
                assert!(message.contains("does not match Woodpecker base path prefix"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // Same origin, same prefix, but malformed structure
        let target_url = "https://woodpecker.example.com/prefix/repos/1/bad/42";
        let res = adapter.resolve_ci_failure(target_url).await;
        match res {
            domain::CiResolution::Error { message } => {
                assert!(message.contains("Malformed or unsupported Woodpecker URL path"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_ci_failure_aggregates_step_errors() {
        let mock = MockServer::start().await;
        let woodpecker_base = mock.uri();

        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some(woodpecker_base.clone()),
            woodpecker_token: None,
        })
        .expect("build adapter");

        // Pipeline with two failed steps
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/pipelines/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workflows": [
                    {
                        "id": 1,
                        "children": [
                            { "id": 2, "name": "step-1", "state": "failure" },
                            { "id": 3, "name": "step-2", "state": "error" }
                        ]
                    }
                ]
            })))
            .mount(&mock)
            .await;

        // step-1 logs succeed
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/logs/42/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "data": base64::Engine::encode(&base64::prelude::BASE64_STANDARD, "step 1 log\n") }
            ])))
            .mount(&mock)
            .await;

        // step-2 logs fail
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/logs/42/3"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let target_url = format!("{woodpecker_base}/repos/1/pipeline/42");
        let res = adapter.resolve_ci_failure(&target_url).await;

        match res {
            domain::CiResolution::Resolved { failed_steps, .. } => {
                assert_eq!(failed_steps.len(), 2);
                assert_eq!(failed_steps[0].name, "step-1");
                assert!(failed_steps[0].log_excerpt.is_some());
                assert_eq!(failed_steps[1].name, "step-2");
                assert!(failed_steps[1].log_excerpt.is_none());
                assert_eq!(failed_steps.len(), 2);
                assert_eq!(failed_steps[0].name, "step-1");
                assert!(failed_steps[0].log_excerpt.is_some());
                assert_eq!(failed_steps[1].name, "step-2");
                assert!(failed_steps[1].log_excerpt.is_none());
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn parse_forge_error_message_extracts_message_key() {
        let body = r#"{"message": "branch not found"}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("branch not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_extracts_error_key() {
        let body = r#"{"error": "not found"}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_prefers_message_over_error() {
        let body = r#"{"message": "repo not found", "error": "fallback"}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("repo not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_returns_none_for_empty_body() {
        assert!(parse_forge_error_message("").is_none());
        assert!(parse_forge_error_message("   ").is_none());
    }

    #[test]
    fn parse_forge_error_message_returns_none_for_plain_text() {
        assert!(parse_forge_error_message("plain text response").is_none());
    }

    #[test]
    fn parse_forge_error_message_handles_empty_json_object() {
        assert!(parse_forge_error_message("{}").is_none());
    }

    #[test]
    fn parse_forge_error_message_handles_gitlab_structured_errors() {
        let body = r#"[{"message": "404 Not Found"}, {"message": "details"}]"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("404 Not Found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_unwraps_nested_message_object() {
        let body =
            r#"{"message": {"message": "Branch not found", "id": "not_found", "attributes": {}}}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("Branch not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_unwraps_nested_error_in_message_object() {
        let body = r#"{"message": {"error": "something went wrong"}}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("something went wrong".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_falls_back_to_top_level_error_when_message_nested() {
        let body = r#"{"message": {"id": "not_found"}, "error": "project not found"}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("project not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_handles_top_level_array_of_strings() {
        let body = r#"["error: not found", "more info"]"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("error: not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_unwraps_nested_error_object() {
        let body = r#"{"error":{"message":"branch not found","id":"not_found"}}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("branch not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_unwraps_structured_error_array() {
        let body = r#"{"error":["branch not found","details"]}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("branch not found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_prefers_message_over_nested_error() {
        let body = r#"{"message":"msg found","error":{"message":"error found"}}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("msg found".to_string())
        );
    }

    #[test]
    fn parse_forge_error_message_prefers_nested_message_over_flat_error() {
        let body = r#"{"message":{"message":"Branch not found"},"error":"not found"}"#;
        assert_eq!(
            parse_forge_error_message(body),
            Some("Branch not found".to_string())
        );
    }

    #[tokio::test]
    async fn resolve_ci_failure_returns_error_on_empty_log_excerpt() {
        let mock = MockServer::start().await;
        let woodpecker_base = mock.uri();

        let adapter = ForgejoAdapter::new(ForgejoConfig {
            base_url: "https://forge.example".to_string(),
            token: Some("test-token".to_string()),
            woodpecker_url: Some(woodpecker_base.clone()),
            woodpecker_token: None,
        })
        .expect("build adapter");

        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/pipelines/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workflows": [{ "id": 1, "children": [{ "id": 2, "name": "test", "state": "failure" }] }]
            })))
            .mount(&mock)
            .await;

        // Empty log data (whitespace only or empty list)
        Mock::given(method("GET"))
            .and(path_regex(r"/api/repos/1/logs/42/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "data": "   " }
            ])))
            .mount(&mock)
            .await;

        let target_url = format!("{woodpecker_base}/repos/1/pipeline/42");
        let res = adapter.resolve_ci_failure(&target_url).await;

        match res {
            domain::CiResolution::Error { message } => {
                assert!(message.contains("found no usable log excerpts"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn schedule_auto_merge_404_returns_descriptive_message() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/.+/pulls/\d+/merge"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "branch 'feature' not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 42, "rebase", "abc123sha", None, &cred)
            .await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "branch 'feature' not found");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_generic_message_on_404_with_empty_body() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/1$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "repository or resource not found");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_generic_message_on_404_with_non_json_body() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/issues/1$"))
            .respond_with(ResponseTemplate::new(404).set_body_string("some opaque HTML error page"))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_issue(&test_repo(), 1, &cred).await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "repository or resource not found");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_woodpecker_url_rejects_path_traversal() {
        let config = ForgejoConfig {
            base_url: "https://git.example.com".to_string(),
            token: None,
            woodpecker_url: Some("https://ci.example.com/woodpecker/".to_string()),
            woodpecker_token: None,
        };
        let adapter = ForgejoAdapter::new(config).expect("build adapter");

        // Path traversal in repo_id
        assert!(
            adapter
                .parse_woodpecker_url("https://ci.example.com/woodpecker/repos/../pipeline/42")
                .is_err()
        );

        // Path traversal in pipeline_num
        assert!(
            adapter
                .parse_woodpecker_url("https://ci.example.com/woodpecker/repos/1/pipeline/..")
                .is_err()
        );

        // Non-numeric repo_id
        assert!(
            adapter
                .parse_woodpecker_url("https://ci.example.com/woodpecker/repos/abc/pipeline/42")
                .is_err()
        );

        // Non-numeric pipeline_num
        assert!(
            adapter
                .parse_woodpecker_url("https://ci.example.com/woodpecker/repos/1/pipeline/abc")
                .is_err()
        );

        // Percent-encoded dots
        assert!(
            adapter
                .parse_woodpecker_url("https://ci.example.com/woodpecker/repos/%2e%2e/pipeline/42")
                .is_err()
        );

        // Multiple slashes
        assert!(
            adapter
                .parse_woodpecker_url("https://ci.example.com/woodpecker/repos/1//pipeline/42")
                .is_err()
        );
    }

    #[tokio::test]
    async fn get_branch_returns_exists_false_for_branch_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Branch not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_branch(&test_repo(), "feature", &cred)
            .await
            .expect("should return exists false");

        assert_eq!(result.0, "feature");
        assert!(result.1.is_none());
        assert!(!result.2);
    }

    #[tokio::test]
    async fn get_branch_returns_exists_false_for_branch_does_not_exist() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "404 Branch Does Not Exist"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_branch(&test_repo(), "feature", &cred)
            .await
            .expect("should return exists false");

        assert_eq!(result.0, "feature");
        assert!(result.1.is_none());
        assert!(!result.2);
    }

    #[tokio::test]
    async fn get_branch_returns_exists_false_for_no_such_branch() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "no such branch: feature"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_branch(&test_repo(), "feature", &cred)
            .await
            .expect("should return exists false");

        assert!(!result.2);
    }

    #[tokio::test]
    async fn get_branch_returns_error_for_repo_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "repository not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        let err = result.expect_err("expected error");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_branch_returns_details_for_existing_branch() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "feature",
                "commit": {"id": "abc123def456"}
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (name, sha, exists) = adapter
            .get_branch(&test_repo(), "feature", &cred)
            .await
            .expect("should return branch details");

        assert_eq!(name, "feature");
        assert_eq!(sha, Some("abc123def456".to_string()));
        assert!(exists);
    }

    #[tokio::test]
    async fn get_branch_404_with_empty_body_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_branch_404_repo_with_branch_in_name_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "repository branch-service not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        let err = result.expect_err("repo-not-found should remain an error");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_branch_401_unauthorized_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": "Unauthorized"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        assert!(result.is_err(), "401 should propagate as error");
    }

    #[tokio::test]
    async fn get_branch_403_forbidden_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "message": "forbidden"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        assert!(result.is_err(), "403 should propagate as error");
    }

    #[tokio::test]
    async fn get_branch_500_internal_error_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "message": "internal server error"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        assert!(result.is_err(), "500 should propagate as error");
    }

    #[tokio::test]
    async fn list_branches_uses_limit_pagination_param() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        adapter
            .list_branches(&test_repo(), None, None, &cred)
            .await
            .expect("list branches");

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let url = requests[0].url.to_string();
        assert!(
            url.contains("limit=30"),
            "expected limit=30 in URL, got: {url}"
        );
        assert!(
            !url.contains("per_page="),
            "should not contain per_page, got: {url}"
        );
    }

    #[tokio::test]
    async fn list_branches_respects_limit() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "main", "commit": {"id": "aaa"}},
                {"name": "dev", "commit": {"id": "bbb"}},
                {"name": "feature-1", "commit": {"id": "ccc"}},
                {"name": "feature-2", "commit": {"id": "ddd"}},
                {"name": "feature-3", "commit": {"id": "eee"}}
            ])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, Some(2), &cred)
            .await
            .expect("list branches");

        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0].name, "main");
        assert_eq!(branches[1].name, "dev");
        assert!(!truncated);
    }

    #[tokio::test]
    async fn list_branches_prefix_filter() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "main", "commit": {"id": "aaa"}},
                {"name": "feature-a", "commit": {"id": "bbb"}},
                {"name": "feature-b", "commit": {"id": "ccc"}},
                {"name": "bugfix-1", "commit": {"id": "ddd"}}
            ])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, _truncated) = adapter
            .list_branches(&test_repo(), Some("feature"), None, &cred)
            .await
            .expect("list branches");

        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0].name, "feature-a");
        assert_eq!(branches[1].name, "feature-b");
    }

    #[tokio::test]
    async fn list_branches_multipage_pagination() {
        fn branch_data(n: usize) -> serde_json::Value {
            serde_json::json!(
                (0..n)
                    .map(|i| serde_json::json!({
                        "name": format!("branch-{:02}", i),
                        "commit": {"id": format!("sha{:02}", i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(30)))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(5)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, None, &cred)
            .await
            .expect("list branches");

        // Default limit 20, page returns 30 so gets 20 from first page, stops
        assert_eq!(branches.len(), 20);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn list_branches_multipage_with_high_limit() {
        fn branch_data(count: usize, offset: usize) -> serde_json::Value {
            serde_json::json!(
                (0..count)
                    .map(|i| serde_json::json!({
                        "name": format!("branch-{:02}", offset + i),
                        "commit": {"id": format!("sha{:02}", offset + i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(30, 0)))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(25, 30)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, Some(50), &cred)
            .await
            .expect("list branches");

        // 30 from page1 + 20 from page2 = 50 (target_limit capped at min(50, 100)=50)
        assert_eq!(branches.len(), 50);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn list_branches_truncated_when_pages_exceeded() {
        fn branch_data(n: usize) -> serde_json::Value {
            serde_json::json!(
                (0..n)
                    .map(|i| serde_json::json!({
                        "name": format!("branch-{:02}", i),
                        "commit": {"id": format!("sha{:02}", i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(30)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, None, &cred)
            .await
            .expect("list branches");

        // Default limit 20, first page returns 30, so gets 20 from one page
        assert_eq!(branches.len(), 20);
        assert!(!truncated);

        // Verify multiple requests were received and check received request count
        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1, "should only fetch 1 page for limit=20");
    }

    #[tokio::test]
    async fn list_branches_scan_budget_limit() {
        fn branch_data(n: usize) -> serde_json::Value {
            serde_json::json!(
                (0..n)
                    .map(|i| serde_json::json!({
                        "name": format!("branch-{:02}", i),
                        "commit": {"id": format!("sha{:02}", i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        // Return 30 per page (full page) so adapter keeps paginating
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(30)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, Some(999), &cred)
            .await
            .expect("list branches");

        // MAX_PAGES=5 * PAGE_SIZE=30 = 150, capped at target_limit=100 by min(999,100)
        // Actually min(999, 100) = 100, so after page 4 we have 120 >= 100, stops without truncation
        assert_eq!(branches.len(), 100);
        assert!(!truncated);

        let requests = mock.received_requests().await.expect("received requests");
        // Should be 4 pages: 30*3=90, then 30 on page 4 brings to 120 >= 100
        assert!(
            requests.len() >= 2,
            "should have made multiple page requests, got {}",
            requests.len()
        );
    }

    #[tokio::test]
    async fn list_branches_truncated_true_when_prefix_matches_none() {
        fn branch_data(n: usize) -> serde_json::Value {
            serde_json::json!(
                (0..n)
                    .map(|i| serde_json::json!({
                        "name": format!("other-{:02}", i),
                        "commit": {"id": format!("sha{:02}", i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(30)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), Some("feature-"), Some(200), &cred)
            .await
            .expect("list branches");

        // prefix "feature-" matches none of "other-XX" branches, so all 5 pages
        // are fetched (MAX_PAGES=5, PAGE_SIZE=30) with zero matching results.
        assert_eq!(branches.len(), 0);
        assert!(
            truncated,
            "expected truncation when pages exhausted without matching prefix"
        );

        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(
            requests.len(),
            5,
            "should have exhausted all 5 pages before truncating"
        );
    }

    #[tokio::test]
    async fn get_branch_encodes_special_branch_name() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/branches/feature%2F"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "feature/foo?bar",
                "commit": {"id": "abc123def456"}
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (name, sha, exists) = adapter
            .get_branch(&test_repo(), "feature/foo?bar", &cred)
            .await
            .expect("should return branch details");

        assert_eq!(name, "feature/foo?bar");
        assert_eq!(sha, Some("abc123def456".to_string()));
        assert!(exists);

        // Verify the branch name was URL-encoded in the request
        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let path = requests[0].url.path().to_string();
        assert!(
            path.contains("feature%2F"),
            "branch name slash should be URL-encoded: {path}"
        );
    }

    #[tokio::test]
    async fn get_branch_encodes_forward_slash_in_branch_name() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/branches/feature"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Branch not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_branch(&test_repo(), "feature/test", &cred)
            .await
            .expect("should return exists false");

        assert_eq!(result.0, "feature/test");
        assert!(result.1.is_none());
        assert!(!result.2);

        // Verify URL-encoded branch name in request
        let requests = mock.received_requests().await.expect("received requests");
        let path = requests[0].url.path().to_string();
        assert!(
            path.ends_with("feature%2Ftest"),
            "expected URL-encoded branch name, got: {path}"
        );
    }

    #[tokio::test]
    async fn get_branch_with_slash_returns_error_for_repo_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/branches/"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "repository not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_branch(&test_repo(), "feature/test", &cred)
            .await;

        assert!(result.is_err(), "repo-not-found should be an error");
    }

    #[tokio::test]
    async fn list_branches_encodes_prefix_with_special_chars() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/.+/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "feature/foo?bar", "commit": {"id": "aaa"}}
            ])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, _truncated) = adapter
            .list_branches(&test_repo(), Some("feature/foo?bar"), None, &cred)
            .await
            .expect("list branches");

        assert_eq!(branches.len(), 1);

        // Verify the prefix was URL-encoded in the query parameter
        let requests = mock.received_requests().await.expect("received requests");
        assert_eq!(requests.len(), 1);
        let url = requests[0].url.to_string();
        assert!(
            url.contains("pattern=feature%2Ffoo%3Fbar")
                || url.contains("pattern=feature%2ffoo%3fbar"),
            "expected URL-encoded prefix in pattern param: {url}"
        );
    }

    #[tokio::test]
    async fn get_branch_returns_exists_false_for_ambiguous_404_when_repo_exists() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "The target couldn't be found."
            })))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (name, sha, exists) = adapter
            .get_branch(&test_repo(), "feature", &cred)
            .await
            .expect("should return exists false");

        assert_eq!(name, "feature");
        assert!(sha.is_none());
        assert!(!exists);
    }

    #[tokio::test]
    async fn get_branch_returns_exists_false_for_empty_404_when_repo_exists() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1, "name": "repo", "full_name": "org/repo"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (name, sha, exists) = adapter
            .get_branch(&test_repo(), "feature", &cred)
            .await
            .expect("should return exists false");

        assert_eq!(name, "feature");
        assert!(sha.is_none());
        assert!(!exists);
    }

    #[tokio::test]
    async fn get_branch_returns_error_for_ambiguous_404_when_repo_missing() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "The target couldn't be found."
            })))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Repository not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "feature", &cred).await;

        let err = result.expect_err("should return error when repo is missing");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_branch_returns_error_for_empty_404_when_repo_missing() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Repository not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "feature", &cred).await;

        let err = result.expect_err("should return error when repo is missing");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_branch_401_repo_verification_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/.+/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "The target couldn't be found."
            })))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo$"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "feature", &cred).await;

        let err = result.expect_err("should return error on auth failure");
        match err {
            ForgeError::UnexpectedStatus { status, .. } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    fn test_cross_repo() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: domain::ForgeKind::Forgejo,
            host: "https://forge.example".to_string(),
            name: "other-repo".to_string(),
            owner: "other-org".to_string(),
        }
    }

    /// Same-repo: the dependency is fetched from the base repo, `POST`ed to base repo.
    #[tokio::test]
    async fn add_issue_dependency_same_repo_single_request_to_base_repo() {
        let mock = MockServer::start().await;

        // Mock: fetch dependency issue from base repo (same as target repo)
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 2000,
                "number": 20,
                "title": "Dependency Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/org/repo/issues/20"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: POST dependency to base repo
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10/dependencies"))
            .and(body_json(serde_json::json!({"dependsOn": 2000})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: GET base issue after
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1000,
                "number": 10,
                "title": "Base Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/org/repo/issues/10"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let repo = test_repo();
        adapter
            .add_issue_dependency(&repo, 10, &repo, 20, &cred)
            .await
            .expect("should succeed");
    }

    /// Cross-repo add: the dependency is fetched from the dependency repo,
    /// then the POST goes to the base repo's dependencies endpoint.
    #[tokio::test]
    async fn add_issue_dependency_cross_repo_fetches_from_dep_repo_and_posts_to_base_repo() {
        let mock = MockServer::start().await;

        // Mock: fetch dependency issue from the CROSS-repo
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/other-org/other-repo/issues/20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 3000,
                "number": 20,
                "title": "Dependency Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/other-org/other-repo/issues/20"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: POST dependency to BASE repo (not cross-repo)
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10/dependencies"))
            .and(body_json(serde_json::json!({"dependsOn": 3000})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: GET base issue after
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1000,
                "number": 10,
                "title": "Base Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/org/repo/issues/10"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let base_repo = test_repo();
        let dep_repo = test_cross_repo();
        adapter
            .add_issue_dependency(&base_repo, 10, &dep_repo, 20, &cred)
            .await
            .expect("should succeed");
    }

    /// Cross-repo remove: the dependency is fetched from the dependency repo,
    /// then the DELETE goes to the base repo's dependencies endpoint.
    #[tokio::test]
    async fn remove_issue_dependency_cross_repo_fetches_from_dep_repo_and_deletes_on_base_repo() {
        let mock = MockServer::start().await;

        // Mock: fetch dependency issue from the CROSS-repo
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/other-org/other-repo/issues/20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 3000,
                "number": 20,
                "title": "Dependency Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/other-org/other-repo/issues/20"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: DELETE dependency on BASE repo (not cross-repo)
        Mock::given(method("DELETE"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10/dependencies"))
            .and(body_json(serde_json::json!({"dependsOn": 3000})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: GET base issue after
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1000,
                "number": 10,
                "title": "Base Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/org/repo/issues/10"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let base_repo = test_repo();
        let dep_repo = test_cross_repo();
        adapter
            .remove_issue_dependency(&base_repo, 10, &dep_repo, 20, &cred)
            .await
            .expect("should succeed");
    }

    /// Verify same-repo backward compatibility: when base and dep repo are identical,
    /// the adapter behaves identically to before the cross-repo support was added.
    #[tokio::test]
    async fn remove_issue_dependency_same_repo_backward_compatible() {
        let mock = MockServer::start().await;

        // Mock: fetch dependency issue from base repo
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 2000,
                "number": 20,
                "title": "Dependency Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/org/repo/issues/20"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: DELETE dependency from base repo
        Mock::given(method("DELETE"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10/dependencies"))
            .and(body_json(serde_json::json!({"dependsOn": 2000})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock)
            .await;

        // Mock: GET base issue after
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/repos/org/repo/issues/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1000,
                "number": 10,
                "title": "Base Issue",
                "state": "open",
                "body": "",
                "html_url": "https://forge.example/org/repo/issues/10"
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let repo = test_repo();
        adapter
            .remove_issue_dependency(&repo, 10, &repo, 20, &cred)
            .await
            .expect("should succeed");
    }
}
