//! GitHub REST and GraphQL API adapter.

use async_trait::async_trait;
use base64::Engine;
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestReview,
    ChangeRequestState, ForgeCredential, ForgeUser, Mergeability, ReadRepositoryFileResponse,
    RepositoryMergeSettings, RepositoryRef,
};
use hmac::{Hmac, Mac};
use reqwest::{RequestBuilder, StatusCode, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use crate::github_app::{GitHubAppConfig, GitHubAppCredential};

use crate::{
    ForgeError, ForgeWebhookAdapter, ForgeWebhookError, IssuePaginationLimits,
    issue_list_status_error, next_page_from_link_header, pagination_error,
    read_bounded_issue_response, redirect_error, remaining_deadline, validate_next_page,
};

const API_VERSION: &str = "2022-11-28";
const PAGE_SIZE: u32 = 100;
const MAX_BRANCH_PAGES: u64 = 5;
const MAX_PAGES: u64 = 1_000;
const PAGINATION_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
struct GitHubActionsResolutionLimits {
    deadline: Duration,
    suite_lookups: usize,
    job_lookups: usize,
    api_requests: usize,
    json_page_bytes: usize,
    json_total_bytes: usize,
    workflow_runs: usize,
    workflow_jobs: usize,
    job_steps: usize,
    log_downloads: usize,
    log_bytes: usize,
    log_total_bytes: usize,
    emitted_steps: usize,
    output_bytes: usize,
    excerpt_lines: usize,
    excerpt_line_bytes: usize,
    excerpt_bytes: usize,
}

impl Default for GitHubActionsResolutionLimits {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(30),
            suite_lookups: 16,
            job_lookups: 16,
            api_requests: 64,
            json_page_bytes: 2 * 1024 * 1024,
            json_total_bytes: 8 * 1024 * 1024,
            workflow_runs: 1_000,
            workflow_jobs: 1_000,
            job_steps: 4_096,
            log_downloads: 16,
            log_bytes: 512 * 1024,
            log_total_bytes: 2 * 1024 * 1024,
            emitted_steps: 64,
            output_bytes: 256 * 1024,
            excerpt_lines: 20,
            excerpt_line_bytes: 512,
            excerpt_bytes: 8 * 1024,
        }
    }
}

impl GitHubActionsResolutionLimits {
    fn validate(self) -> Result<Self, ForgeError> {
        let counts = [
            self.suite_lookups,
            self.job_lookups,
            self.api_requests,
            self.json_page_bytes,
            self.json_total_bytes,
            self.workflow_runs,
            self.workflow_jobs,
            self.job_steps,
            self.log_downloads,
            self.log_bytes,
            self.log_total_bytes,
            self.emitted_steps,
            self.output_bytes,
            self.excerpt_lines,
            self.excerpt_line_bytes,
            self.excerpt_bytes,
        ];
        if self.deadline.is_zero() || counts.contains(&0) {
            return Err(ForgeError::InvalidPayload(
                "GitHub Actions resolution limits must be non-zero".to_string(),
            ));
        }
        if self.json_page_bytes > self.json_total_bytes
            || self.log_bytes > self.log_total_bytes
            || self.excerpt_line_bytes > self.excerpt_bytes
        {
            return Err(ForgeError::InvalidPayload(
                "GitHub Actions resolution limits are inconsistent".to_string(),
            ));
        }
        self.excerpt_lines
            .checked_mul(self.excerpt_line_bytes)
            .ok_or_else(|| {
                ForgeError::InvalidPayload("GitHub Actions resolution limits overflow".to_string())
            })?;
        Ok(self)
    }
}

#[derive(Clone, Debug)]
struct ActionsError(String);

type CachedActionsResult<T> = Result<Arc<T>, ActionsError>;

impl ActionsError {
    fn limit(name: &str) -> Self {
        Self(format!("GitHub Actions {name} limit exhausted"))
    }
}

#[derive(Debug)]
struct GitHubActionsResolutionBudget {
    deadline: Instant,
    api_requests: usize,
    json_bytes: usize,
    workflow_runs: usize,
    workflow_jobs: usize,
    job_steps: usize,
    log_downloads: usize,
    log_bytes: usize,
    emitted_steps: usize,
    output_bytes: usize,
}

#[derive(Clone)]
pub struct GitHubConfig {
    /// REST API root (`https://api.github.com` for GitHub.com or
    /// `https://github.example/api/v3` for GitHub Enterprise Server).
    pub api_url: String,
    pub token: Option<String>,
}

impl std::fmt::Debug for GitHubConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubConfig")
            .field("api_url", &self.api_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone)]
pub struct GitHubAdapter {
    auth: GitHubAuth,
    client: reqwest::Client,
    config: GitHubConfig,
    managed_app_credentials: Vec<GitHubAppCredential>,
}

#[derive(Clone)]
enum GitHubAuth {
    App(GitHubAppCredential),
    Token,
}

impl std::fmt::Debug for GitHubAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth_mode = match &self.auth {
            GitHubAuth::App(_) => "github_app",
            GitHubAuth::Token => "token",
        };
        f.debug_struct("GitHubAdapter")
            .field("auth_mode", &auth_mode)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GitHubAdapter {
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(config: GitHubConfig) -> Result<Self, ForgeError> {
        crate::install_ring_provider();
        Ok(Self {
            auth: GitHubAuth::Token,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            config,
            managed_app_credentials: Vec::new(),
        })
    }

    /// Builds an adapter authenticated as a GitHub App installation.
    ///
    /// The initial installation token is fetched before returning. A
    /// background task refreshes it before GitHub's one-hour expiry and exits
    /// automatically when the adapter is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when the private key is invalid, the JWT cannot be
    /// signed, or GitHub rejects the installation-token exchange.
    pub async fn new_app(config: GitHubConfig, app: GitHubAppConfig) -> Result<Self, ForgeError> {
        crate::install_ring_provider();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let managed_credential =
            GitHubAppCredential::new_with_client(client.clone(), config.api_url.clone(), app)
                .await?;
        Ok(Self {
            auth: GitHubAuth::App(managed_credential.clone()),
            client,
            config,
            managed_app_credentials: vec![managed_credential],
        })
    }

    /// Makes additional managed per-agent App identities discoverable by this
    /// adapter. Tokens continue to refresh through the shared credentials.
    pub fn extend_managed_app_credentials(
        &mut self,
        credentials: impl IntoIterator<Item = GitHubAppCredential>,
    ) {
        self.managed_app_credentials.extend(credentials);
    }

    fn api_base(&self) -> &str {
        self.config.api_url.trim_end_matches('/')
    }

    fn graphql_url(&self) -> String {
        let base = self.api_base();
        if let Some(prefix) = base.strip_suffix("/api/v3") {
            format!("{prefix}/api/graphql")
        } else {
            format!("{base}/graphql")
        }
    }

    fn effective_token(&self, credential: &ForgeCredential) -> Option<String> {
        match &self.auth {
            GitHubAuth::App(managed) => credential
                .token
                .clone()
                .or_else(|| managed.credential().token),
            GitHubAuth::Token => credential
                .token
                .clone()
                .or_else(|| self.config.token.clone()),
        }
    }

    pub(crate) fn authenticate(builder: RequestBuilder, token: Option<&str>) -> RequestBuilder {
        let builder = builder
            .header("accept", "application/vnd.github+json")
            .header("user-agent", "forge-mcp")
            .header("x-github-api-version", API_VERSION);
        match token {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    fn request(&self, builder: RequestBuilder, credential: &ForgeCredential) -> RequestBuilder {
        let token = self.effective_token(credential);
        Self::authenticate(builder, token.as_deref())
    }

    fn managed_app_user(&self, credential: &ForgeCredential) -> Option<ForgeUser> {
        let token = self.effective_token(credential)?;
        self.managed_app_credentials
            .iter()
            .find(|managed| managed.matches_token(&token))
            .map(|managed| ForgeUser {
                email: String::new(),
                username: managed.username(),
            })
    }

    fn repo_path(repository: &RepositoryRef) -> String {
        format!(
            "{}/{}",
            urlencoding::encode(&repository.owner),
            urlencoding::encode(&repository.name)
        )
    }

    pub(crate) async fn check_response(
        response: reqwest::Response,
    ) -> Result<reqwest::Response, ForgeError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            return Err(ForgeError::Redirect { status, location });
        }
        let body = response.text().await.unwrap_or_default();
        let message = crate::parse_forge_error_message(&body)
            .unwrap_or_else(|| "repository or resource not found".to_string());
        if status == StatusCode::NOT_FOUND {
            return Err(ForgeError::NotFound { status, message });
        }
        Err(ForgeError::UnexpectedStatus {
            status,
            body: if body.is_empty() { message } else { body },
        })
    }

    async fn get_repository(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<GitHubRepository, ForgeError> {
        let url = format!("{}/repos/{}", self.api_base(), Self::repo_path(repository));
        let response = Self::check_response(
            self.request(self.client.get(url), credential)
                .send()
                .await?,
        )
        .await?;
        response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))
    }

    async fn ensure_label(
        &self,
        repository: &RepositoryRef,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        let repo = Self::repo_path(repository);
        let url = format!(
            "{}/repos/{repo}/labels/{}",
            self.api_base(),
            urlencoding::encode(label)
        );
        let response = self
            .request(self.client.get(url), credential)
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        if response.status() != StatusCode::NOT_FOUND {
            Self::check_response(response).await?;
            return Ok(());
        }
        let create_url = format!("{}/repos/{repo}/labels", self.api_base());
        Self::check_response(
            self.request(
                self.client.post(create_url).json(&serde_json::json!({
                    "name": label,
                    "color": "ededed",
                })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        Ok(())
    }

    async fn get_issue_api(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<GitHubIssue, ForgeError> {
        let url = format!(
            "{}/repos/{}/issues/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(self.client.get(url), credential)
                .send()
                .await?,
        )
        .await?;
        response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))
    }

    async fn list_account_repositories(
        &self,
        owner: &str,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError> {
        let account_url = format!("{}/users/{}", self.api_base(), urlencoding::encode(owner));
        let response = Self::check_response(
            self.request(self.client.get(account_url), credential)
                .send()
                .await?,
        )
        .await?;
        let account: GitHubAccount = response.json().await?;
        let endpoint = if account.account_type == "Organization" {
            format!(
                "{}/orgs/{}/repos",
                self.api_base(),
                urlencoding::encode(owner)
            )
        } else {
            format!(
                "{}/users/{}/repos",
                self.api_base(),
                urlencoding::encode(owner)
            )
        };
        self.list_repository_pages(endpoint, credential).await
    }

    async fn get_paginated<T>(
        &self,
        endpoint: &str,
        query: &[(&str, &str)],
        credential: &ForgeCredential,
    ) -> Result<Vec<T>, ForgeError>
    where
        T: DeserializeOwned,
    {
        let deadline = Instant::now()
            .checked_add(PAGINATION_DEADLINE)
            .ok_or_else(|| pagination_error("deadline overflow"))?;
        let mut values = Vec::new();
        let mut page = 1_u64;
        for _ in 0..MAX_PAGES {
            let response = Self::check_response(
                self.request(
                    self.client
                        .get(endpoint)
                        .query(query)
                        .query(&[
                            ("per_page", PAGE_SIZE.to_string()),
                            ("page", page.to_string()),
                        ])
                        .timeout(remaining_deadline(deadline)?),
                    credential,
                )
                .send()
                .await?,
            )
            .await?;
            let headers = response.headers().clone();
            values.extend(response.json::<Vec<T>>().await?);
            let next = validate_next_page(page, next_page_from_link_header(&headers)?)?;
            let Some(next) = next else {
                return Ok(values);
            };
            page = next;
        }
        Err(pagination_error(format!(
            "GitHub exceeded the page budget of {MAX_PAGES} pages"
        )))
    }

    async fn get_combined_status_pages(
        &self,
        endpoint: &str,
        credential: &ForgeCredential,
    ) -> Result<(String, u64, Vec<GitHubStatus>), ForgeError> {
        let deadline = Instant::now()
            .checked_add(PAGINATION_DEADLINE)
            .ok_or_else(|| pagination_error("deadline overflow"))?;
        let mut head_sha = None;
        let mut total_count = 0_u64;
        let mut statuses = Vec::new();
        let mut page = 1_u64;
        for _ in 0..MAX_PAGES {
            let response = Self::check_response(
                self.request(
                    self.client
                        .get(endpoint)
                        .query(&[
                            ("per_page", PAGE_SIZE.to_string()),
                            ("page", page.to_string()),
                        ])
                        .timeout(remaining_deadline(deadline)?),
                    credential,
                )
                .send()
                .await?,
            )
            .await?;
            let headers = response.headers().clone();
            let combined: GitHubCombinedStatus = response.json().await?;
            if head_sha
                .as_ref()
                .is_some_and(|head_sha| head_sha != &combined.sha)
            {
                return Err(pagination_error(
                    "GitHub changed the commit SHA between status pages",
                ));
            }
            head_sha.get_or_insert(combined.sha);
            total_count = total_count.max(combined.total_count);
            statuses.extend(combined.statuses);
            let next = validate_next_page(page, next_page_from_link_header(&headers)?)?;
            let Some(next) = next else {
                total_count = total_count.max(u64::try_from(statuses.len()).unwrap_or(u64::MAX));
                return Ok((head_sha.unwrap_or_default(), total_count, statuses));
            };
            page = next;
        }
        Err(pagination_error(format!(
            "GitHub exceeded the page budget of {MAX_PAGES} pages"
        )))
    }

    async fn get_check_run_pages(
        &self,
        endpoint: &str,
        credential: &ForgeCredential,
    ) -> Result<Vec<GitHubCheckRun>, ForgeError> {
        let deadline = Instant::now()
            .checked_add(PAGINATION_DEADLINE)
            .ok_or_else(|| pagination_error("deadline overflow"))?;
        let mut check_runs = Vec::new();
        let mut expected_total = None;
        let mut ids = HashSet::new();
        let mut page = 1_u64;
        for _ in 0..MAX_PAGES {
            let response = Self::check_response(
                self.request(
                    self.client
                        .get(endpoint)
                        .query(&[
                            ("per_page", PAGE_SIZE.to_string()),
                            ("page", page.to_string()),
                        ])
                        .timeout(remaining_deadline(deadline)?),
                    credential,
                )
                .send()
                .await?,
            )
            .await?;
            let headers = response.headers().clone();
            let checks: GitHubCheckRuns = response.json().await?;
            if expected_total.is_some_and(|total| total != checks.total_count) {
                return Err(pagination_error(
                    "GitHub changed the check-run total_count between pages",
                ));
            }
            expected_total.get_or_insert(checks.total_count);
            for check in &checks.check_runs {
                if check.id.is_some_and(|id| !ids.insert(id)) {
                    return Err(pagination_error("GitHub returned a duplicate check-run ID"));
                }
            }
            check_runs.extend(checks.check_runs);
            let next = validate_next_page(page, next_page_from_link_header(&headers)?)?;
            let Some(next) = next else {
                if u64::try_from(check_runs.len()).ok() != expected_total {
                    return Err(pagination_error(
                        "GitHub returned an incomplete check-run collection",
                    ));
                }
                return Ok(check_runs);
            };
            page = next;
        }
        Err(pagination_error(format!(
            "GitHub exceeded the page budget of {MAX_PAGES} pages"
        )))
    }

    async fn list_repository_pages(
        &self,
        endpoint: String,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError> {
        Ok(self
            .get_paginated::<GitHubRepositoryListItem>(&endpoint, &[], credential)
            .await?
            .into_iter()
            .map(GitHubRepositoryListItem::into_repository)
            .collect())
    }

    async fn list_installation_repository_pages(
        &self,
        credential: &ForgeCredential,
    ) -> Result<Option<Vec<domain::Repository>>, ForgeError> {
        let endpoint = format!("{}/installation/repositories", self.api_base());
        let deadline = Instant::now()
            .checked_add(PAGINATION_DEADLINE)
            .ok_or_else(|| pagination_error("deadline overflow"))?;
        let mut repositories = Vec::new();
        let mut page = 1_u64;
        for _ in 0..MAX_PAGES {
            let response = self
                .request(
                    self.client
                        .get(&endpoint)
                        .query(&[
                            ("per_page", PAGE_SIZE.to_string()),
                            ("page", page.to_string()),
                        ])
                        .timeout(remaining_deadline(deadline)?),
                    credential,
                )
                .send()
                .await?;
            if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
            ) {
                return Ok(None);
            }
            let response = Self::check_response(response).await?;
            let headers = response.headers().clone();
            let values: GitHubInstallationRepositories = response.json().await?;
            repositories.extend(
                values
                    .repositories
                    .into_iter()
                    .map(GitHubRepositoryListItem::into_repository),
            );
            let next = validate_next_page(page, next_page_from_link_header(&headers)?)?;
            let Some(next) = next else {
                return Ok(Some(repositories));
            };
            page = next;
        }
        Err(pagination_error(format!(
            "GitHub exceeded the page budget of {MAX_PAGES} pages"
        )))
    }

    async fn list_issues_with_limits(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
        limits: IssuePaginationLimits,
    ) -> Result<Vec<domain::Issue>, ForgeError> {
        let limits = limits.validate()?;
        let deadline = Instant::now()
            .checked_add(limits.deadline)
            .ok_or_else(|| pagination_error("deadline overflow"))?;
        let endpoint = format!(
            "{}/repos/{}/issues",
            self.api_base(),
            Self::repo_path(repository)
        );
        let state = state.unwrap_or("all");
        let mut page = 1_u64;
        let mut pages = 0_u64;
        let mut raw_issues = 0_usize;
        let mut used_bytes = 0_usize;
        let mut issues = Vec::new();
        let mut seen = HashSet::new();

        loop {
            if pages >= limits.max_pages {
                return Err(pagination_error(format!(
                    "GitHub exceeded the page budget of {} pages",
                    limits.max_pages
                )));
            }
            let response = self
                .request(
                    self.client
                        .get(&endpoint)
                        .query(&[
                            ("state", state.to_string()),
                            ("per_page", limits.page_size.to_string()),
                            ("page", page.to_string()),
                        ])
                        .timeout(remaining_deadline(deadline)?),
                    credential,
                )
                .send()
                .await?;
            if response.status().is_redirection() {
                return Err(redirect_error(&response));
            }
            let response =
                read_bounded_issue_response(response, limits, used_bytes, deadline).await?;
            used_bytes = used_bytes
                .checked_add(response.body.len())
                .ok_or_else(|| pagination_error("cumulative byte count overflow"))?;
            if !response.status.is_success() {
                return Err(issue_list_status_error(&response));
            }

            let page_issues: Vec<GitHubIssue> =
                serde_json::from_slice(&response.body).map_err(|error| {
                    pagination_error(format!("invalid GitHub issue page JSON: {error}"))
                })?;
            let next_raw_issues = raw_issues
                .checked_add(page_issues.len())
                .ok_or_else(|| pagination_error("raw issue count overflow"))?;
            if next_raw_issues > limits.max_raw_issues {
                return Err(pagination_error(format!(
                    "GitHub exceeded the raw issue budget of {} issues",
                    limits.max_raw_issues
                )));
            }
            raw_issues = next_raw_issues;
            for issue in page_issues {
                if issue.pull_request.is_none() && seen.insert(issue.number) {
                    issues.push(issue.into_issue());
                }
            }

            pages = pages
                .checked_add(1)
                .ok_or_else(|| pagination_error("page count overflow"))?;
            let next = validate_next_page(page, next_page_from_link_header(&response.headers)?)?;
            let Some(next) = next else {
                return Ok(issues);
            };
            page = next;
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    #[serde(default)]
    email: Option<String>,
    login: String,
}

#[derive(Debug, Deserialize)]
struct GitHubAccount {
    #[serde(rename = "type")]
    account_type: String,
}

#[derive(Debug, Deserialize)]
struct GitHubLabel {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRef {
    #[serde(rename = "ref")]
    name: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GitHubPullRequest {
    base: GitHubRef,
    body: Option<String>,
    #[serde(default)]
    changed_files: Option<u64>,
    #[serde(default)]
    commits: Option<u64>,
    head: GitHubRef,
    html_url: String,
    #[serde(default)]
    labels: Vec<GitHubLabel>,
    #[serde(default)]
    mergeable: Option<bool>,
    #[serde(default)]
    mergeable_state: Option<String>,
    #[serde(default)]
    merged_at: Option<String>,
    node_id: String,
    number: u64,
    state: String,
    title: String,
}

impl GitHubPullRequest {
    fn into_change_request(self) -> ChangeRequest {
        let state = if self.merged_at.is_some() {
            ChangeRequestState::Merged
        } else if self.state == "open" {
            ChangeRequestState::Open
        } else {
            ChangeRequestState::Closed
        };
        let mergeability = match (self.mergeable, self.mergeable_state.as_deref()) {
            (Some(true), _) => Mergeability::Mergeable,
            (Some(false), Some("dirty")) => Mergeability::Conflicting,
            (Some(false), _) => Mergeability::NotMergeable,
            _ => Mergeability::Unknown,
        };
        ChangeRequest {
            base_branch: self.base.name,
            body: self.body.unwrap_or_default(),
            changed_files_count: self.changed_files,
            commit_count: self.commits,
            head_branch: self.head.name,
            head_sha: Some(self.head.sha),
            has_conflicts: match mergeability {
                Mergeability::Conflicting => Some(true),
                Mergeability::Mergeable | Mergeability::NotMergeable => Some(false),
                Mergeability::Unknown => None,
            },
            index: self.number,
            labels: self.labels.into_iter().map(|label| label.name).collect(),
            merge_base_sha: None,
            mergeability,
            state,
            title: self.title,
            url: self.html_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitHubIssue {
    #[serde(default)]
    assignees: Vec<GitHubUser>,
    body: Option<String>,
    html_url: String,
    id: u64,
    #[serde(default)]
    labels: Vec<GitHubLabel>,
    number: u64,
    #[serde(default)]
    pull_request: Option<serde_json::Value>,
    state: String,
    title: String,
}

impl GitHubIssue {
    fn into_issue(self) -> domain::Issue {
        domain::Issue {
            assignees: self.assignees.into_iter().map(|user| user.login).collect(),
            body: self.body.unwrap_or_default(),
            index: self.number,
            labels: self.labels.into_iter().map(|label| label.name).collect(),
            state: self.state,
            title: self.title,
            url: self.html_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitHubComment {
    body: String,
    created_at: String,
    id: u64,
    user: GitHubUser,
}

#[derive(Debug, Deserialize)]
struct GitHubReview {
    body: Option<String>,
    commit_id: Option<String>,
    id: u64,
    state: String,
    submitted_at: Option<String>,
    user: GitHubUser,
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    #[serde(default)]
    allow_merge_commit: bool,
    #[serde(default)]
    allow_rebase_merge: bool,
    #[serde(default)]
    allow_squash_merge: bool,
    #[serde(default)]
    delete_branch_on_merge: Option<bool>,
}

impl GitHubRepository {
    fn allowed_merge_styles(&self) -> Vec<String> {
        let mut styles = Vec::new();
        if self.allow_merge_commit {
            styles.push("merge".to_string());
        }
        if self.allow_rebase_merge {
            styles.push("rebase".to_string());
        }
        if self.allow_squash_merge {
            styles.push("squash".to_string());
        }
        styles
    }
}

#[derive(Debug, Deserialize)]
struct GitHubRepositoryListItem {
    description: Option<String>,
    full_name: String,
    html_url: String,
    name: String,
    owner: GitHubUser,
}

#[derive(Debug, Deserialize)]
struct GitHubInstallationRepositories {
    repositories: Vec<GitHubRepositoryListItem>,
}

impl GitHubRepositoryListItem {
    fn into_repository(self) -> domain::Repository {
        domain::Repository {
            description: self.description.unwrap_or_default(),
            full_name: self.full_name,
            name: self.name,
            owner: self.owner.login,
            url: self.html_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitHubFile {
    content: String,
    encoding: String,
    path: String,
}

#[derive(Debug, Deserialize)]
struct GitHubBranch {
    commit: GitHubBranchCommit,
    name: String,
}

#[derive(Debug, Deserialize)]
struct GitHubBranchCommit {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GitHubCombinedStatus {
    sha: String,
    statuses: Vec<GitHubStatus>,
    total_count: u64,
}

#[derive(Debug, Deserialize)]
struct GitHubStatus {
    context: String,
    description: Option<String>,
    state: String,
    target_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubCheckRuns {
    total_count: u64,
    #[serde(default)]
    check_runs: Vec<GitHubCheckRun>,
}

#[derive(Debug, Deserialize)]
struct GitHubCheckRun {
    id: Option<u64>,
    conclusion: Option<String>,
    details_url: Option<String>,
    name: String,
    status: String,
    check_suite: Option<GitHubCheckSuite>,
    app: Option<GitHubCheckApp>,
}

#[derive(Debug, Deserialize)]
struct GitHubCheckSuite {
    id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GitHubCheckApp {
    slug: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowRuns {
    total_count: u64,
    #[serde(default)]
    workflow_runs: Vec<GitHubWorkflowRun>,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowRun {
    id: u64,
    check_suite_id: u64,
    head_sha: String,
    run_attempt: u64,
    html_url: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowJobs {
    total_count: u64,
    #[serde(default)]
    jobs: Vec<GitHubWorkflowJob>,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowJob {
    id: u64,
    run_id: u64,
    head_sha: String,
    name: String,
    conclusion: Option<String>,
    check_run_url: String,
    #[serde(default)]
    steps: Vec<GitHubWorkflowStep>,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowStep {
    name: String,
    conclusion: Option<String>,
}

fn parse_status_state(state: &str) -> domain::CommitStatusState {
    match state {
        "action_required" | "cancelled" | "error" | "stale" | "startup_failure" | "timed_out" => {
            domain::CommitStatusState::Error
        }
        "failure" => domain::CommitStatusState::Failure,
        "success" => domain::CommitStatusState::Success,
        "neutral" | "skipped" => domain::CommitStatusState::Warning,
        _ => domain::CommitStatusState::Pending,
    }
}

fn aggregate_statuses(statuses: &[domain::CommitStatus]) -> domain::CommitStatusState {
    if statuses.is_empty() {
        return domain::CommitStatusState::Pending;
    }
    let mut has_pending = false;
    let mut has_warning = false;
    for status in statuses {
        match status.state {
            domain::CommitStatusState::Error | domain::CommitStatusState::Failure => {
                return domain::CommitStatusState::Failure;
            }
            domain::CommitStatusState::Pending => has_pending = true,
            domain::CommitStatusState::Warning => has_warning = true,
            domain::CommitStatusState::Success => {}
        }
    }
    if has_pending {
        domain::CommitStatusState::Pending
    } else if has_warning {
        domain::CommitStatusState::Warning
    } else {
        domain::CommitStatusState::Success
    }
}

struct GitHubActionsResolver<'a> {
    adapter: &'a GitHubAdapter,
    repository: &'a RepositoryRef,
    head_sha: &'a str,
    credential: &'a ForgeCredential,
    limits: GitHubActionsResolutionLimits,
    budget: GitHubActionsResolutionBudget,
    runs: HashMap<u64, CachedActionsResult<GitHubWorkflowRun>>,
    jobs: HashMap<(u64, u64), CachedActionsResult<Vec<GitHubWorkflowJob>>>,
    logs: HashMap<u64, CachedActionsResult<domain::CiLogExcerpt>>,
}

impl<'a> GitHubActionsResolver<'a> {
    fn new(
        adapter: &'a GitHubAdapter,
        repository: &'a RepositoryRef,
        head_sha: &'a str,
        credential: &'a ForgeCredential,
        limits: GitHubActionsResolutionLimits,
    ) -> Result<Self, ForgeError> {
        let limits = limits.validate()?;
        let deadline = Instant::now()
            .checked_add(limits.deadline)
            .ok_or_else(|| ForgeError::InvalidPayload("deadline overflow".to_string()))?;
        Ok(Self {
            adapter,
            repository,
            head_sha,
            credential,
            limits,
            budget: GitHubActionsResolutionBudget {
                deadline,
                api_requests: 0,
                json_bytes: 0,
                workflow_runs: 0,
                workflow_jobs: 0,
                job_steps: 0,
                log_downloads: 0,
                log_bytes: 0,
                emitted_steps: 0,
                output_bytes: 0,
            },
            runs: HashMap::new(),
            jobs: HashMap::new(),
            logs: HashMap::new(),
        })
    }

    fn remaining(&self) -> Result<Duration, ActionsError> {
        self.budget
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| ActionsError::limit("deadline"))
    }

    fn checked_charge(
        used: &mut usize,
        amount: usize,
        maximum: usize,
        name: &str,
    ) -> Result<(), ActionsError> {
        let next = used
            .checked_add(amount)
            .ok_or_else(|| ActionsError::limit(name))?;
        if next > maximum {
            return Err(ActionsError::limit(name));
        }
        *used = next;
        Ok(())
    }

    async fn send_authenticated(
        &mut self,
        builder: RequestBuilder,
        phase: &str,
    ) -> Result<reqwest::Response, ActionsError> {
        Self::checked_charge(
            &mut self.budget.api_requests,
            1,
            self.limits.api_requests,
            "authenticated request count",
        )?;
        let timeout = self.remaining()?;
        self.adapter
            .request(builder.timeout(timeout), self.credential)
            .send()
            .await
            .map_err(|error| {
                let sanitized = error.without_url();
                let failure = if sanitized.is_timeout() {
                    "timed out"
                } else {
                    "failed"
                };
                ActionsError(format!("GitHub Actions {phase} request {failure}"))
            })
    }

    fn response_status(response: &reqwest::Response, phase: &str) -> Result<(), ActionsError> {
        if response.status() == StatusCode::FORBIDDEN {
            return Err(ActionsError(
                "GitHub Actions access was denied; grant Actions: read and re-approve the installation"
                    .to_string(),
            ));
        }
        if !response.status().is_success() {
            return Err(ActionsError(format!(
                "GitHub Actions {phase} returned status {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn read_json<T: DeserializeOwned>(
        &mut self,
        mut response: reqwest::Response,
        phase: &str,
    ) -> Result<T, ActionsError> {
        Self::response_status(&response, phase)?;
        let remaining_total = self
            .limits
            .json_total_bytes
            .checked_sub(self.budget.json_bytes)
            .ok_or_else(|| ActionsError::limit("JSON byte"))?;
        let page_limit = self.limits.json_page_bytes.min(remaining_total);
        if response.content_length().is_some_and(|length| {
            usize::try_from(length).map_or(true, |length| length > page_limit)
        }) {
            return Err(ActionsError::limit("JSON byte"));
        }
        let mut bytes = Vec::new();
        if let Some(length) = response.content_length() {
            bytes
                .try_reserve_exact(usize::try_from(length).unwrap_or(page_limit))
                .map_err(|_| ActionsError::limit("JSON allocation"))?;
        }
        loop {
            let chunk = tokio::time::timeout(self.remaining()?, response.chunk())
                .await
                .map_err(|_| ActionsError::limit("deadline"))?
                .map_err(|error| {
                    let sanitized = error.without_url();
                    let failure = if sanitized.is_timeout() {
                        "timed out"
                    } else {
                        "failed"
                    };
                    ActionsError(format!("GitHub Actions {phase} response stream {failure}"))
                })?;
            let Some(chunk) = chunk else { break };
            let next_page = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| ActionsError::limit("JSON byte"))?;
            let next_total = self
                .budget
                .json_bytes
                .checked_add(chunk.len())
                .ok_or_else(|| ActionsError::limit("JSON byte"))?;
            if next_page > self.limits.json_page_bytes || next_total > self.limits.json_total_bytes
            {
                return Err(ActionsError::limit("JSON byte"));
            }
            self.budget.json_bytes = next_total;
            bytes
                .try_reserve_exact(chunk.len())
                .map_err(|_| ActionsError::limit("JSON allocation"))?;
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| ActionsError(format!("GitHub Actions {phase} returned malformed JSON")))
    }

    async fn workflow_run(
        &mut self,
        suite_id: u64,
    ) -> Result<Arc<GitHubWorkflowRun>, ActionsError> {
        if let Some(cached) = self.runs.get(&suite_id) {
            return cached.clone();
        }
        if self.runs.len() >= self.limits.suite_lookups {
            return Err(ActionsError::limit("distinct check-suite lookup"));
        }
        let result = self.fetch_workflow_run(suite_id).await;
        self.runs.insert(suite_id, result.clone());
        result
    }

    async fn fetch_workflow_run(
        &mut self,
        suite_id: u64,
    ) -> Result<Arc<GitHubWorkflowRun>, ActionsError> {
        let endpoint = format!(
            "{}/repos/{}/actions/runs",
            self.adapter.api_base(),
            GitHubAdapter::repo_path(self.repository)
        );
        let mut page = 1_u64;
        let mut expected_total = None;
        let mut ids = HashSet::new();
        let mut runs = Vec::new();
        for _ in 0..MAX_PAGES {
            let response = self
                .send_authenticated(
                    self.adapter.client.get(&endpoint).query(&[
                        ("check_suite_id", suite_id.to_string()),
                        ("head_sha", self.head_sha.to_string()),
                        ("per_page", PAGE_SIZE.to_string()),
                        ("page", page.to_string()),
                    ]),
                    &format!("workflow-run lookup for suite {suite_id}"),
                )
                .await?;
            let headers = response.headers().clone();
            let wrapper: GitHubWorkflowRuns = self
                .read_json(
                    response,
                    &format!("workflow-run lookup for suite {suite_id}"),
                )
                .await?;
            if usize::try_from(wrapper.total_count).map_or(true, |total| {
                total > self.limits.workflow_runs.saturating_sub(runs.len())
            }) {
                return Err(ActionsError::limit("workflow-run record"));
            }
            Self::checked_charge(
                &mut self.budget.workflow_runs,
                wrapper.workflow_runs.len(),
                self.limits.workflow_runs,
                "workflow-run record",
            )?;
            if expected_total.is_some_and(|total| total != wrapper.total_count) {
                return Err(ActionsError(
                    "GitHub Actions changed workflow-run total_count between pages".to_string(),
                ));
            }
            expected_total.get_or_insert(wrapper.total_count);
            for run in &wrapper.workflow_runs {
                if !ids.insert(run.id) {
                    return Err(ActionsError(
                        "GitHub Actions returned a duplicate workflow-run ID".to_string(),
                    ));
                }
                if run.check_suite_id != suite_id || run.head_sha != self.head_sha {
                    return Err(ActionsError(format!(
                        "GitHub Actions workflow-run correlation failed for suite {suite_id}"
                    )));
                }
            }
            runs.extend(wrapper.workflow_runs);
            let next = next_page_from_link_header(&headers).map_err(|_| {
                ActionsError(
                    "GitHub Actions returned an invalid workflow-run Link header".to_string(),
                )
            })?;
            let next = validate_next_page(page, next).map_err(|_| {
                ActionsError(
                    "GitHub Actions returned a non-monotonic workflow-run Link header".to_string(),
                )
            })?;
            let Some(next) = next else { break };
            page = next;
        }
        if u64::try_from(runs.len()).ok() != expected_total {
            return Err(ActionsError(
                "GitHub Actions returned an incomplete workflow-run collection".to_string(),
            ));
        }
        runs.into_iter()
            .max_by_key(|run| (run.run_attempt, run.id))
            .map(Arc::new)
            .ok_or_else(|| {
                ActionsError(format!(
                    "GitHub Actions found no workflow run for suite {suite_id} and the requested commit"
                ))
            })
    }

    async fn workflow_jobs(
        &mut self,
        run: &GitHubWorkflowRun,
    ) -> Result<Arc<Vec<GitHubWorkflowJob>>, ActionsError> {
        let key = (run.id, run.run_attempt);
        if let Some(cached) = self.jobs.get(&key) {
            return cached.clone();
        }
        if self.jobs.len() >= self.limits.job_lookups {
            return Err(ActionsError::limit("distinct run-attempt job lookup"));
        }
        let result = self.fetch_workflow_jobs(run).await;
        self.jobs.insert(key, result.clone());
        result
    }

    async fn fetch_workflow_jobs(
        &mut self,
        run: &GitHubWorkflowRun,
    ) -> Result<Arc<Vec<GitHubWorkflowJob>>, ActionsError> {
        let endpoint = format!(
            "{}/repos/{}/actions/runs/{}/attempts/{}/jobs",
            self.adapter.api_base(),
            GitHubAdapter::repo_path(self.repository),
            run.id,
            run.run_attempt
        );
        let mut page = 1_u64;
        let mut expected_total = None;
        let mut ids = HashSet::new();
        let mut jobs = Vec::new();
        for _ in 0..MAX_PAGES {
            let response = self
                .send_authenticated(
                    self.adapter.client.get(&endpoint).query(&[
                        ("per_page", PAGE_SIZE.to_string()),
                        ("page", page.to_string()),
                    ]),
                    &format!("job lookup for run {} attempt {}", run.id, run.run_attempt),
                )
                .await?;
            let headers = response.headers().clone();
            let wrapper: GitHubWorkflowJobs = self
                .read_json(
                    response,
                    &format!("job lookup for run {} attempt {}", run.id, run.run_attempt),
                )
                .await?;
            if usize::try_from(wrapper.total_count).map_or(true, |total| {
                total > self.limits.workflow_jobs.saturating_sub(jobs.len())
            }) {
                return Err(ActionsError::limit("workflow-job record"));
            }
            Self::checked_charge(
                &mut self.budget.workflow_jobs,
                wrapper.jobs.len(),
                self.limits.workflow_jobs,
                "workflow-job record",
            )?;
            let step_count = wrapper
                .jobs
                .iter()
                .try_fold(0_usize, |total, job| total.checked_add(job.steps.len()))
                .ok_or_else(|| ActionsError::limit("job-step record"))?;
            Self::checked_charge(
                &mut self.budget.job_steps,
                step_count,
                self.limits.job_steps,
                "job-step record",
            )?;
            if expected_total.is_some_and(|total| total != wrapper.total_count) {
                return Err(ActionsError(
                    "GitHub Actions changed workflow-job total_count between pages".to_string(),
                ));
            }
            expected_total.get_or_insert(wrapper.total_count);
            for job in &wrapper.jobs {
                if !ids.insert(job.id) {
                    return Err(ActionsError(
                        "GitHub Actions returned a duplicate workflow-job ID".to_string(),
                    ));
                }
                if job.run_id != run.id || job.head_sha != self.head_sha {
                    return Err(ActionsError(format!(
                        "GitHub Actions job correlation failed for run {} attempt {}",
                        run.id, run.run_attempt
                    )));
                }
            }
            jobs.extend(wrapper.jobs);
            let next = next_page_from_link_header(&headers).map_err(|_| {
                ActionsError(
                    "GitHub Actions returned an invalid workflow-job Link header".to_string(),
                )
            })?;
            let next = validate_next_page(page, next).map_err(|_| {
                ActionsError(
                    "GitHub Actions returned a non-monotonic workflow-job Link header".to_string(),
                )
            })?;
            let Some(next) = next else { break };
            page = next;
        }
        if u64::try_from(jobs.len()).ok() != expected_total {
            return Err(ActionsError(
                "GitHub Actions returned an incomplete workflow-job collection".to_string(),
            ));
        }
        Ok(Arc::new(jobs))
    }

    fn check_run_id_from_job_url(&self, value: &str) -> Result<u64, ActionsError> {
        let url = Url::parse(value).map_err(|_| {
            ActionsError("GitHub Actions job contains a malformed check_run_url".to_string())
        })?;
        let api = Url::parse(self.adapter.api_base())
            .map_err(|_| ActionsError("configured GitHub API origin is invalid".to_string()))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.username() != ""
            || url.password().is_some()
            || !same_url_origin(&url, &api)
        {
            return Err(ActionsError(
                "GitHub Actions job check_run_url is outside the configured API origin".to_string(),
            ));
        }
        let expected_prefix = format!(
            "{}/repos/{}/check-runs/",
            api.path().trim_end_matches('/'),
            GitHubAdapter::repo_path(self.repository)
        );
        let id = url.path().strip_prefix(&expected_prefix).ok_or_else(|| {
            ActionsError("GitHub Actions job contains an unexpected check_run_url path".to_string())
        })?;
        if id.is_empty() || id.contains('/') || url.query().is_some() || url.fragment().is_some() {
            return Err(ActionsError(
                "GitHub Actions job contains an unexpected check_run_url path".to_string(),
            ));
        }
        id.parse().map_err(|_| {
            ActionsError("GitHub Actions job contains a non-numeric check-run ID".to_string())
        })
    }

    async fn job_log(&mut self, job_id: u64) -> Result<Arc<domain::CiLogExcerpt>, ActionsError> {
        if let Some(cached) = self.logs.get(&job_id) {
            return cached.clone();
        }
        if self.budget.log_downloads >= self.limits.log_downloads {
            return Err(ActionsError::limit("signed log download count"));
        }
        if self.budget.log_bytes >= self.limits.log_total_bytes {
            return Err(ActionsError::limit("signed log byte"));
        }
        let result = self.fetch_job_log(job_id).await;
        self.logs.insert(job_id, result.clone());
        result
    }

    #[allow(clippy::too_many_lines)]
    async fn fetch_job_log(
        &mut self,
        job_id: u64,
    ) -> Result<Arc<domain::CiLogExcerpt>, ActionsError> {
        let endpoint = format!(
            "{}/repos/{}/actions/jobs/{job_id}/logs",
            self.adapter.api_base(),
            GitHubAdapter::repo_path(self.repository)
        );
        let response = self
            .send_authenticated(
                self.adapter.client.get(endpoint),
                &format!("job-log lookup for job {job_id}"),
            )
            .await?;
        if response.status() == StatusCode::FORBIDDEN {
            return Err(ActionsError(
                "GitHub Actions access was denied; grant Actions: read and re-approve the installation"
                    .to_string(),
            ));
        }
        if response.status() != StatusCode::FOUND {
            return Err(ActionsError(format!(
                "GitHub Actions job-log lookup for job {job_id} returned status {}",
                response.status()
            )));
        }
        let mut locations = response.headers().get_all(reqwest::header::LOCATION).iter();
        let location = locations.next().ok_or_else(|| {
            ActionsError(format!(
                "GitHub Actions job-log lookup for job {job_id} omitted Location"
            ))
        })?;
        if locations.next().is_some() {
            return Err(ActionsError(format!(
                "GitHub Actions job-log lookup for job {job_id} returned multiple Location headers"
            )));
        }
        let destination = location
            .to_str()
            .ok()
            .and_then(|value| Url::parse(value).ok())
            .ok_or_else(|| {
                ActionsError(format!(
                    "GitHub Actions job-log lookup for job {job_id} returned an invalid destination"
                ))
            })?;
        let api = Url::parse(self.adapter.api_base())
            .map_err(|_| ActionsError("configured GitHub API origin is invalid".to_string()))?;
        let destination = validate_signed_log_destination(&api, destination, job_id)?;
        Self::checked_charge(
            &mut self.budget.log_downloads,
            1,
            self.limits.log_downloads,
            "signed log download count",
        )?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                ActionsError(format!(
                    "GitHub Actions could not prepare job-log download for job {job_id}"
                ))
            })?;
        let mut request = client
            .get(destination)
            .timeout(self.remaining()?)
            .build()
            .map_err(|error| {
                let sanitized = error.without_url();
                let failure = if sanitized.is_builder() {
                    "was invalid"
                } else {
                    "could not be prepared"
                };
                ActionsError(format!(
                    "GitHub Actions signed job-log request for job {job_id} {failure}"
                ))
            })?;
        request.headers_mut().remove(reqwest::header::ACCEPT);
        request.headers_mut().remove(reqwest::header::AUTHORIZATION);
        request.headers_mut().remove(reqwest::header::USER_AGENT);
        request.headers_mut().remove("x-github-api-version");
        let mut response = client.execute(request).await.map_err(|error| {
            let sanitized = error.without_url();
            let failure = if sanitized.is_timeout() {
                "timed out"
            } else {
                "failed"
            };
            ActionsError(format!(
                "GitHub Actions signed job-log request {failure} for job {job_id}"
            ))
        })?;
        if response.status().is_redirection() {
            return Err(ActionsError(format!(
                "GitHub Actions signed job-log response redirected for job {job_id} with status {}",
                response.status()
            )));
        }
        if !response.status().is_success() {
            return Err(ActionsError(format!(
                "GitHub Actions signed job-log response failed for job {job_id} with status {}",
                response.status()
            )));
        }
        let remaining_total = self
            .limits
            .log_total_bytes
            .checked_sub(self.budget.log_bytes)
            .ok_or_else(|| ActionsError::limit("signed log byte"))?;
        let body_limit = self.limits.log_bytes.min(remaining_total);
        if response.content_length().is_some_and(|length| {
            usize::try_from(length).map_or(true, |length| length > body_limit)
        }) {
            return Err(ActionsError::limit("signed log byte"));
        }
        let mut bytes = Vec::new();
        if let Some(length) = response.content_length() {
            bytes
                .try_reserve_exact(usize::try_from(length).unwrap_or(body_limit))
                .map_err(|_| ActionsError::limit("signed log allocation"))?;
        }
        loop {
            let chunk = tokio::time::timeout(self.remaining()?, response.chunk())
                .await
                .map_err(|_| ActionsError::limit("deadline"))?
                .map_err(|error| {
                    let sanitized = error.without_url();
                    let failure = if sanitized.is_timeout() {
                        "timed out"
                    } else {
                        "failed"
                    };
                    ActionsError(format!(
                        "GitHub Actions signed job-log stream {failure} for job {job_id}"
                    ))
                })?;
            let Some(chunk) = chunk else { break };
            let next_body = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| ActionsError::limit("signed log byte"))?;
            let next_total = self
                .budget
                .log_bytes
                .checked_add(chunk.len())
                .ok_or_else(|| ActionsError::limit("signed log byte"))?;
            if next_body > self.limits.log_bytes || next_total > self.limits.log_total_bytes {
                return Err(ActionsError::limit("signed log byte"));
            }
            self.budget.log_bytes = next_total;
            bytes
                .try_reserve_exact(chunk.len())
                .map_err(|_| ActionsError::limit("signed log allocation"))?;
            bytes.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(bytes).map_err(|_| {
            ActionsError(format!(
                "GitHub Actions job log for job {job_id} is not valid UTF-8"
            ))
        })?;
        let mut selected = Vec::new();
        for line in text.lines().rev().filter(|line| !line.trim().is_empty()) {
            if selected.len() == self.limits.excerpt_lines {
                break;
            }
            let line = utf8_prefix(line, self.limits.excerpt_line_bytes);
            let used = selected
                .iter()
                .try_fold(0_usize, |total, line: &String| {
                    total.checked_add(line.len())
                })
                .ok_or_else(|| ActionsError::limit("excerpt byte"))?;
            if used
                .checked_add(line.len())
                .is_none_or(|total| total > self.limits.excerpt_bytes)
            {
                break;
            }
            selected
                .try_reserve_exact(1)
                .map_err(|_| ActionsError::limit("excerpt allocation"))?;
            selected.push(line.to_string());
        }
        selected.reverse();
        if selected.is_empty() {
            return Err(ActionsError(format!(
                "GitHub Actions job log for job {job_id} contained no usable lines"
            )));
        }
        Ok(Arc::new(domain::CiLogExcerpt { lines: selected }))
    }

    #[allow(clippy::too_many_lines)]
    async fn resolve(
        &mut self,
        check: &GitHubCheckRun,
    ) -> Result<domain::CiResolution, ActionsError> {
        self.remaining()?;
        let check_id = check.id.ok_or_else(|| {
            ActionsError("GitHub Actions check run is missing its ID".to_string())
        })?;
        let suite_id = check
            .check_suite
            .as_ref()
            .and_then(|suite| suite.id)
            .ok_or_else(|| {
                ActionsError("GitHub Actions check run is missing its check-suite ID".to_string())
            })?;
        let run = self.workflow_run(suite_id).await?;
        let jobs = self.workflow_jobs(&run).await?;
        let mut matches = Vec::new();
        for job in jobs.iter() {
            if self.check_run_id_from_job_url(&job.check_run_url)? == check_id {
                matches.push(job);
            }
        }
        if matches.len() != 1 {
            return Err(ActionsError(format!(
                "GitHub Actions expected exactly one job for check run {check_id}, found {}",
                matches.len()
            )));
        }
        let job = matches[0];
        let job_state = job.conclusion.as_deref().unwrap_or("error");
        if !is_failure_state(&parse_status_state(job_state)) {
            return Err(ActionsError(format!(
                "GitHub Actions job {} is not failed or errored",
                job.id
            )));
        }
        let is_failed_step = |step: &&GitHubWorkflowStep| {
            is_failure_state(&parse_status_state(
                step.conclusion.as_deref().unwrap_or("pending"),
            ))
        };
        let failed_step_count = job.steps.iter().filter(is_failed_step).count();
        let emitted = failed_step_count.max(1);
        let mut added_bytes = run.html_url.len();
        if failed_step_count == 0 {
            added_bytes = added_bytes
                .checked_add(job.name.len())
                .and_then(|value| value.checked_add(job_state.len()))
                .ok_or_else(|| ActionsError::limit("resolved output byte"))?;
        } else {
            for step in job.steps.iter().filter(is_failed_step) {
                added_bytes = added_bytes
                    .checked_add(job.name.len())
                    .and_then(|value| value.checked_add(3))
                    .and_then(|value| value.checked_add(step.name.len()))
                    .and_then(|value| {
                        value.checked_add(step.conclusion.as_deref().unwrap_or("error").len())
                    })
                    .ok_or_else(|| ActionsError::limit("resolved output byte"))?;
            }
        }
        let preflight_steps = self
            .budget
            .emitted_steps
            .checked_add(emitted)
            .ok_or_else(|| ActionsError::limit("emitted failure-step"))?;
        let preflight_bytes = self
            .budget
            .output_bytes
            .checked_add(added_bytes)
            .ok_or_else(|| ActionsError::limit("resolved output byte"))?;
        if preflight_steps > self.limits.emitted_steps {
            return Err(ActionsError::limit("emitted failure-step"));
        }
        if preflight_bytes > self.limits.output_bytes {
            return Err(ActionsError::limit("resolved output byte"));
        }
        let excerpt = self.job_log(job.id).await?;
        // The excerpt size is known only after its bounded download. Repeat the
        // aggregate output preflight before allocating or cloning public output.
        added_bytes = excerpt
            .lines
            .iter()
            .try_fold(added_bytes, |total, line| total.checked_add(line.len()))
            .ok_or_else(|| ActionsError::limit("resolved output byte"))?;
        let next_steps = self
            .budget
            .emitted_steps
            .checked_add(emitted)
            .ok_or_else(|| ActionsError::limit("emitted failure-step"))?;
        let next_bytes = self
            .budget
            .output_bytes
            .checked_add(added_bytes)
            .ok_or_else(|| ActionsError::limit("resolved output byte"))?;
        if next_steps > self.limits.emitted_steps {
            return Err(ActionsError::limit("emitted failure-step"));
        }
        if next_bytes > self.limits.output_bytes {
            return Err(ActionsError::limit("resolved output byte"));
        }
        self.remaining()?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(emitted)
            .map_err(|_| ActionsError::limit("resolved output allocation"))?;
        let excerpt = copy_actions_excerpt(&excerpt)?;
        if failed_step_count == 0 {
            output.push(domain::CiFailureStep {
                name: copy_actions_output(&job.name)?,
                state: copy_actions_output(job_state)?,
                log_excerpt: Some(excerpt),
            });
        } else {
            let mut excerpt = Some(excerpt);
            for (index, step) in job.steps.iter().filter(is_failed_step).enumerate() {
                output.push(domain::CiFailureStep {
                    name: actions_step_name(&job.name, &step.name)?,
                    state: copy_actions_output(step.conclusion.as_deref().unwrap_or("error"))?,
                    log_excerpt: if index == 0 { excerpt.take() } else { None },
                });
            }
        }
        self.remaining()?;
        let pipeline_url = copy_actions_output(&run.html_url)?;
        self.budget.emitted_steps = next_steps;
        self.budget.output_bytes = next_bytes;
        Ok(domain::CiResolution::Resolved {
            provider: domain::CiProvider::GithubActions,
            pipeline_url,
            failed_steps: output,
        })
    }
}

fn is_failure_state(state: &domain::CommitStatusState) -> bool {
    matches!(
        state,
        domain::CommitStatusState::Failure | domain::CommitStatusState::Error
    )
}

fn same_url_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn validate_signed_log_destination(
    api: &Url,
    destination: Url,
    job_id: u64,
) -> Result<Url, ActionsError> {
    if !matches!(destination.scheme(), "http" | "https")
        || destination.host_str().is_none_or(str::is_empty)
        || !destination.username().is_empty()
        || destination.password().is_some()
        || (api.scheme() == "https" && destination.scheme() != "https")
    {
        return Err(ActionsError(format!(
            "GitHub Actions job-log destination for job {job_id} failed security validation"
        )));
    }
    Ok(destination)
}

fn utf8_prefix(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn copy_actions_output(value: &str) -> Result<String, ActionsError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| ActionsError::limit("resolved output allocation"))?;
    output.push_str(value);
    Ok(output)
}

fn actions_step_name(job: &str, step: &str) -> Result<String, ActionsError> {
    let length = job
        .len()
        .checked_add(3)
        .and_then(|length| length.checked_add(step.len()))
        .ok_or_else(|| ActionsError::limit("resolved output byte"))?;
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| ActionsError::limit("resolved output allocation"))?;
    output.push_str(job);
    output.push_str(" / ");
    output.push_str(step);
    Ok(output)
}

fn copy_actions_excerpt(
    excerpt: &domain::CiLogExcerpt,
) -> Result<domain::CiLogExcerpt, ActionsError> {
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(excerpt.lines.len())
        .map_err(|_| ActionsError::limit("resolved output allocation"))?;
    for line in &excerpt.lines {
        lines.push(copy_actions_output(line)?);
    }
    Ok(domain::CiLogExcerpt { lines })
}

async fn build_change_request_ci_details(
    adapter: &GitHubAdapter,
    repository: &RepositoryRef,
    sha: &str,
    credential: &ForgeCredential,
    legacy_statuses: Vec<domain::CommitStatus>,
    checks: Vec<GitHubCheckRun>,
    limits: GitHubActionsResolutionLimits,
) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
    let check_statuses: Vec<_> = checks
        .iter()
        .map(|check| {
            let state = if check.status == "completed" {
                parse_status_state(check.conclusion.as_deref().unwrap_or("error"))
            } else {
                domain::CommitStatusState::Pending
            };
            domain::CommitStatus {
                context: check.name.clone(),
                description: check
                    .conclusion
                    .clone()
                    .unwrap_or_else(|| check.status.clone()),
                state,
                target_url: check.details_url.clone().unwrap_or_default(),
            }
        })
        .collect();
    let mut statuses = legacy_statuses.clone();
    statuses.extend(check_statuses.iter().cloned());
    let state = aggregate_statuses(&statuses);
    let mut details: Vec<_> = legacy_statuses
        .into_iter()
        .map(|status| domain::CiCheckDetail {
            context: status.context,
            description: status.description,
            state: status.state,
            target_url: status.target_url,
            resolution: domain::CiResolution::Unsupported,
        })
        .collect();
    let mut resolver = GitHubActionsResolver::new(adapter, repository, sha, credential, limits)?;
    details.try_reserve_exact(checks.len()).map_err(|_| {
        ForgeError::InvalidPayload("unable to allocate CI check details".to_string())
    })?;
    for (check, status) in checks.iter().zip(check_statuses) {
        let eligible = check.status == "completed"
            && is_failure_state(&status.state)
            && check.app.as_ref().and_then(|app| app.slug.as_deref()) == Some("github-actions");
        let resolution = if eligible {
            match resolver.resolve(check).await {
                Ok(resolution) => resolution,
                Err(error) => domain::CiResolution::Error { message: error.0 },
            }
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
        state,
        details,
    })
}

#[async_trait]
impl crate::ForgeAdapter for GitHubAdapter {
    fn effective_credential(&self, credential: &ForgeCredential) -> ForgeCredential {
        ForgeCredential {
            token: self.effective_token(credential),
        }
    }

    async fn add_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency_repository: &RepositoryRef,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let dependency_issue = self
            .get_issue_api(dependency_repository, dependency, credential)
            .await?;
        let url = format!(
            "{}/repos/{}/issues/{index}/dependencies/blocked_by",
            self.api_base(),
            Self::repo_path(repository)
        );
        Self::check_response(
            self.request(
                self.client.post(url).json(&serde_json::json!({
                    "issue_id": dependency_issue.id,
                })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        self.get_issue(repository, index, credential).await
    }

    async fn add_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        self.ensure_label(repository, label, credential).await?;
        let url = format!(
            "{}/repos/{}/issues/{index}/labels",
            self.api_base(),
            Self::repo_path(repository)
        );
        Self::check_response(
            self.request(
                self.client
                    .post(url)
                    .json(&serde_json::json!({ "labels": [label] })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        self.get_issue(repository, index, credential).await
    }

    async fn get_authenticated_user(
        &self,
        credential: &ForgeCredential,
    ) -> Result<ForgeUser, ForgeError> {
        if let Some(user) = self.managed_app_user(credential) {
            return Ok(user);
        }
        let url = format!("{}/user", self.api_base());
        let response = Self::check_response(
            self.request(self.client.get(url), credential)
                .send()
                .await?,
        )
        .await?;
        let user: GitHubUser = response.json().await?;
        Ok(ForgeUser {
            email: user.email.unwrap_or_default(),
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
            "{}/repos/{}/issues/{index}/assignees",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(
                self.client
                    .post(url)
                    .json(&serde_json::json!({ "assignees": [assignee] })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let issue: GitHubIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn close_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/repos/{}/pulls/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(
                self.client
                    .patch(url)
                    .json(&serde_json::json!({ "state": "closed" })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let pull: GitHubPullRequest = response.json().await?;
        Ok(pull.into_change_request())
    }

    async fn close_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/repos/{}/issues/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(
                self.client
                    .patch(url)
                    .json(&serde_json::json!({ "state": "closed" })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let issue: GitHubIssue = response.json().await?;
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
            "{}/repos/{}/issues/{index}/comments",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(
                self.client
                    .post(url)
                    .json(&serde_json::json!({ "body": body })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let comment: GitHubComment = response.json().await?;
        Ok(domain::IssueComment {
            author: comment.user.login,
            body: comment.body,
            created_at: comment.created_at,
            id: comment.id,
        })
    }

    async fn comment_on_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ForgeError> {
        let comment = self
            .comment_on_issue(repository, index, body, credential)
            .await?;
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
            "{}/repos/{}/pulls",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(
                self.client.post(url).json(&serde_json::json!({
                    "base": base_branch,
                    "body": body,
                    "head": head_branch,
                    "title": title,
                })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let pull: GitHubPullRequest = response.json().await?;
        Ok(pull.into_change_request())
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
            "{}/repos/{}/statuses/{}",
            self.api_base(),
            Self::repo_path(repository),
            urlencoding::encode(sha)
        );
        let state = match state {
            "warning" => "success",
            other => other,
        };
        Self::check_response(
            self.request(
                self.client.post(url).json(&serde_json::json!({
                    "context": context,
                    "description": description,
                    "state": state,
                })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
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
            "{}/repos/{}/issues",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(
                self.client.post(url).json(&serde_json::json!({
                    "body": body,
                    "title": title,
                })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let issue: GitHubIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_allowed_merge_styles(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Vec<String>, ForgeError> {
        Ok(self
            .get_repository(repository, credential)
            .await?
            .allowed_merge_styles())
    }

    async fn get_change_request_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
        let mut details = self
            .get_change_request_discussion_comments(repository, index, credential)
            .await?;
        details.extend(
            self.get_change_request_reviews(repository, index, credential)
                .await?,
        );
        details.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(details)
    }

    async fn get_change_request_discussion_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
        let repo = Self::repo_path(repository);
        let url = format!("{}/repos/{repo}/issues/{index}/comments", self.api_base());
        let comments = self
            .get_paginated::<GitHubComment>(&url, &[], credential)
            .await?;
        let mut details: Vec<ChangeRequestCommentDetail> = comments
            .into_iter()
            .map(|comment| ChangeRequestCommentDetail {
                author: comment.user.login,
                body: comment.body,
                commit_id: None,
                created_at: comment.created_at,
                id: comment.id,
                kind: "comment".to_string(),
                review_state: None,
            })
            .collect();
        details.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(details)
    }

    async fn get_change_request_reviews(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
        let repo = Self::repo_path(repository);
        let url = format!("{}/repos/{repo}/pulls/{index}/reviews", self.api_base());
        let reviews = self
            .get_paginated::<GitHubReview>(&url, &[], credential)
            .await?;
        let mut details: Vec<ChangeRequestCommentDetail> = reviews
            .into_iter()
            .filter_map(|review| {
                review
                    .submitted_at
                    .map(|created_at| ChangeRequestCommentDetail {
                        author: review.user.login,
                        body: review.body.unwrap_or_default(),
                        commit_id: review.commit_id,
                        created_at,
                        id: review.id,
                        kind: "review".to_string(),
                        review_state: Some(review.state),
                    })
            })
            .collect();
        details.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(details)
    }

    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/repos/{}/pulls/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(self.client.get(url), credential)
                .send()
                .await?,
        )
        .await?;
        let pull: GitHubPullRequest = response.json().await?;
        Ok(pull.into_change_request())
    }

    async fn get_change_request_diff(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<String, ForgeError> {
        let url = format!(
            "{}/repos/{}/pulls/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let request = self
            .request(self.client.get(url), credential)
            .header("accept", "application/vnd.github.diff");
        Self::check_response(request.send().await?)
            .await?
            .text()
            .await
            .map_err(ForgeError::Http)
    }

    async fn get_combined_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::CombinedCommitStatus, ForgeError> {
        let url = format!(
            "{}/repos/{}/commits/{}/status",
            self.api_base(),
            Self::repo_path(repository),
            urlencoding::encode(sha)
        );
        let (head_sha, total_count, statuses) =
            self.get_combined_status_pages(&url, credential).await?;
        let statuses: Vec<domain::CommitStatus> = statuses
            .into_iter()
            .map(|status| domain::CommitStatus {
                context: status.context,
                description: status.description.unwrap_or_default(),
                state: parse_status_state(&status.state),
                target_url: status.target_url.unwrap_or_default(),
            })
            .collect();
        let state = aggregate_statuses(&statuses);
        Ok(domain::CombinedCommitStatus {
            head_sha,
            state,
            statuses,
            total_count,
        })
    }

    async fn get_change_request_ci_details(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
        let legacy_statuses = self
            .get_combined_commit_status(repository, sha, credential)
            .await?
            .statuses;
        let url = format!(
            "{}/repos/{}/commits/{}/check-runs",
            self.api_base(),
            Self::repo_path(repository),
            urlencoding::encode(sha)
        );
        let checks = self.get_check_run_pages(&url, credential).await?;
        build_change_request_ci_details(
            self,
            repository,
            sha,
            credential,
            legacy_statuses,
            checks,
            GitHubActionsResolutionLimits::default(),
        )
        .await
    }

    async fn get_default_merge_style(
        &self,
        _repository: &RepositoryRef,
        _credential: &ForgeCredential,
    ) -> Result<Option<String>, ForgeError> {
        // GitHub exposes allowed methods but has no repository-level default.
        Ok(None)
    }

    async fn get_repository_merge_settings(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<RepositoryMergeSettings, ForgeError> {
        let repository = self.get_repository(repository, credential).await?;
        Ok(RepositoryMergeSettings {
            allowed_styles: repository.allowed_merge_styles(),
            default_delete_branch_after_merge: repository.delete_branch_on_merge,
            default_merge_style: None,
        })
    }

    async fn get_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        Ok(self
            .get_issue_api(repository, index, credential)
            .await?
            .into_issue())
    }

    async fn get_issue_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::IssueComment>, ForgeError> {
        let url = format!(
            "{}/repos/{}/issues/{index}/comments",
            self.api_base(),
            Self::repo_path(repository)
        );
        let comments = self
            .get_paginated::<GitHubComment>(&url, &[], credential)
            .await?;
        Ok(comments
            .into_iter()
            .map(|comment| domain::IssueComment {
                author: comment.user.login,
                body: comment.body,
                created_at: comment.created_at,
                id: comment.id,
            })
            .collect())
    }

    async fn get_issue_dependencies(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::IssueDependencies, ForgeError> {
        let base = format!(
            "{}/repos/{}/issues/{index}/dependencies",
            self.api_base(),
            Self::repo_path(repository)
        );
        let depends_on = self
            .get_paginated::<GitHubIssue>(&format!("{base}/blocked_by"), &[], credential)
            .await?;
        let blocks = self
            .get_paginated::<GitHubIssue>(&format!("{base}/blocking"), &[], credential)
            .await?;
        Ok(domain::IssueDependencies {
            blocks: blocks.into_iter().map(GitHubIssue::into_issue).collect(),
            depends_on: depends_on
                .into_iter()
                .map(GitHubIssue::into_issue)
                .collect(),
            depends_on_read_contract: None,
            opaque_depends_on_count: None,
        })
    }

    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequest>, ForgeError> {
        let requested_state = state.cloned();
        let api_state = match state {
            Some(ChangeRequestState::Open) => "open",
            Some(ChangeRequestState::Closed | ChangeRequestState::Merged) => "closed",
            None => "all",
        };
        let url = format!(
            "{}/repos/{}/pulls",
            self.api_base(),
            Self::repo_path(repository)
        );
        let pulls = self
            .get_paginated::<GitHubPullRequest>(&url, &[("state", api_state)], credential)
            .await?;
        let mut result: Vec<ChangeRequest> = pulls
            .into_iter()
            .map(GitHubPullRequest::into_change_request)
            .collect();
        if let Some(requested_state) = requested_state {
            result.retain(|pull| pull.state == requested_state);
        }
        Ok(result)
    }

    async fn list_issues(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Issue>, ForgeError> {
        self.list_issues_with_limits(
            repository,
            state,
            credential,
            IssuePaginationLimits::default(),
        )
        .await
    }

    async fn list_repositories(
        &self,
        owner: Option<&str>,
        query: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError> {
        let mut repositories = if let Some(owner) = owner {
            self.list_account_repositories(owner, credential).await?
        } else if let Some(repositories) =
            self.list_installation_repository_pages(credential).await?
        {
            repositories
        } else {
            let endpoint = format!("{}/user/repos", self.api_base());
            self.list_repository_pages(endpoint, credential).await?
        };
        if let Some(query) = query {
            let query = query.to_ascii_lowercase();
            repositories.retain(|repo| {
                repo.name.to_ascii_lowercase().contains(&query)
                    || repo.full_name.to_ascii_lowercase().contains(&query)
                    || repo.description.to_ascii_lowercase().contains(&query)
            });
        }
        Ok(repositories)
    }

    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        head_commit_id: &str,
        _delete_branch_after_merge: Option<bool>,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        let pull_url = format!(
            "{}/repos/{}/pulls/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(self.client.get(pull_url), credential)
                .send()
                .await?,
        )
        .await?;
        let pull: GitHubPullRequest = response.json().await?;
        let merge_method = match merge_style {
            "merge" => "MERGE",
            "rebase" | "rebase_merge" => "REBASE",
            "squash" => "SQUASH",
            other => {
                return Err(ForgeError::Unsupported(format!(
                    "GitHub does not support auto-merge style '{other}'"
                )));
            }
        };
        let query = r"
mutation EnableAutoMerge($input: EnablePullRequestAutoMergeInput!) {
  enablePullRequestAutoMerge(input: $input) {
    pullRequest { id }
  }
}";
        let response = Self::check_response(
            self.request(
                self.client
                    .post(self.graphql_url())
                    .json(&serde_json::json!({
                        "query": query,
                        "variables": {
                            "input": {
                                "expectedHeadOid": head_commit_id,
                                "mergeMethod": merge_method,
                                "pullRequestId": pull.node_id,
                            }
                        }
                    })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let payload: GitHubGraphQlResponse = response.json().await?;
        if let Some(errors) = payload.errors
            && !errors.is_empty()
        {
            return Err(ForgeError::UnexpectedStatus {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                body: errors
                    .into_iter()
                    .map(|error| error.message)
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }
        Ok(())
    }

    async fn remove_issue_dependency(
        &self,
        repository: &RepositoryRef,
        index: u64,
        dependency_repository: &RepositoryRef,
        dependency: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let dependency_issue = self
            .get_issue_api(dependency_repository, dependency, credential)
            .await?;
        let url = format!(
            "{}/repos/{}/issues/{index}/dependencies/blocked_by/{}",
            self.api_base(),
            Self::repo_path(repository),
            dependency_issue.id
        );
        Self::check_response(
            self.request(self.client.delete(url), credential)
                .send()
                .await?,
        )
        .await?;
        self.get_issue(repository, index, credential).await
    }

    async fn remove_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/repos/{}/issues/{index}/labels/{}",
            self.api_base(),
            Self::repo_path(repository),
            urlencoding::encode(label)
        );
        Self::check_response(
            self.request(self.client.delete(url), credential)
                .send()
                .await?,
        )
        .await?;
        self.get_issue(repository, index, credential).await
    }

    async fn read_repository_file(
        &self,
        repository: &RepositoryRef,
        path: &str,
        git_ref: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ReadRepositoryFileResponse, ForgeError> {
        let encoded_path = path
            .split('/')
            .map(|segment| urlencoding::encode(segment).into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let url = format!(
            "{}/repos/{}/contents/{encoded_path}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let mut request = self.request(self.client.get(url), credential);
        if let Some(git_ref) = git_ref {
            request = request.query(&[("ref", git_ref)]);
        }
        let response = Self::check_response(request.send().await?).await?;
        let file: GitHubFile = response.json().await?;
        if file.encoding != "base64" {
            return Err(ForgeError::InvalidPayload(format!(
                "unsupported GitHub content encoding '{}'",
                file.encoding
            )));
        }
        let compact: String = file
            .content
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|e| ForgeError::InvalidPayload(format!("invalid base64 content: {e}")))?;
        let content = String::from_utf8(decoded)
            .map_err(|e| ForgeError::InvalidPayload(format!("file is not valid UTF-8: {e}")))?;
        Ok(ReadRepositoryFileResponse {
            repository: repository.clone(),
            path: file.path,
            git_ref: git_ref.map(ToString::to_string),
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
        let event = match event {
            "APPROVED" | "APPROVE" => "APPROVE",
            "REQUEST_CHANGES" => "REQUEST_CHANGES",
            "COMMENT" => "COMMENT",
            other => {
                return Err(ForgeError::Unsupported(format!(
                    "GitHub review event '{other}' is not supported"
                )));
            }
        };
        let url = format!(
            "{}/repos/{}/pulls/{index}/reviews",
            self.api_base(),
            Self::repo_path(repository)
        );
        let response = Self::check_response(
            self.request(
                self.client.post(url).json(&serde_json::json!({
                    "body": body,
                    "event": event,
                })),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let review: GitHubReview = response.json().await?;
        Ok(ChangeRequestReview {
            body: review.body.unwrap_or_default(),
            event: review.state,
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
            "{}/repos/{}/pulls/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let mut payload = serde_json::Map::new();
        if let Some(title) = title {
            payload.insert("title".to_string(), title.into());
        }
        if let Some(body) = body {
            payload.insert("body".to_string(), body.into());
        }
        let response = Self::check_response(
            self.request(
                self.client
                    .patch(url)
                    .json(&serde_json::Value::Object(payload)),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let pull: GitHubPullRequest = response.json().await?;
        Ok(pull.into_change_request())
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
            "{}/repos/{}/issues/{index}",
            self.api_base(),
            Self::repo_path(repository)
        );
        let mut payload = serde_json::Map::new();
        if let Some(title) = title {
            payload.insert("title".to_string(), title.into());
        }
        if let Some(body) = body {
            payload.insert("body".to_string(), body.into());
        }
        let response = Self::check_response(
            self.request(
                self.client
                    .patch(url)
                    .json(&serde_json::Value::Object(payload)),
                credential,
            )
            .send()
            .await?,
        )
        .await?;
        let issue: GitHubIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn list_branches(
        &self,
        repository: &RepositoryRef,
        prefix: Option<&str>,
        limit: Option<u32>,
        credential: &ForgeCredential,
    ) -> Result<(Vec<domain::Branch>, bool), ForgeError> {
        let target_limit = limit.unwrap_or(20).min(100) as usize;
        let mut branches = Vec::new();
        let mut truncated = false;
        for page in 1..=MAX_BRANCH_PAGES {
            let url = format!(
                "{}/repos/{}/branches",
                self.api_base(),
                Self::repo_path(repository)
            );
            let response = Self::check_response(
                self.request(
                    self.client.get(url).query(&[
                        ("per_page", PAGE_SIZE.to_string()),
                        ("page", page.to_string()),
                    ]),
                    credential,
                )
                .send()
                .await?,
            )
            .await?;
            let page_branches: Vec<GitHubBranch> = response.json().await?;
            let count = page_branches.len();
            for branch in page_branches {
                if prefix.is_some_and(|prefix| !branch.name.starts_with(prefix)) {
                    continue;
                }
                branches.push(domain::Branch {
                    commit_sha: branch.commit.sha,
                    name: branch.name,
                });
                if branches.len() >= target_limit {
                    break;
                }
            }
            if branches.len() >= target_limit || count < PAGE_SIZE as usize {
                break;
            }
            if page == MAX_BRANCH_PAGES {
                truncated = true;
            }
        }
        Ok((branches, truncated))
    }

    async fn get_branch(
        &self,
        repository: &RepositoryRef,
        branch: &str,
        credential: &ForgeCredential,
    ) -> Result<(String, Option<String>, bool), ForgeError> {
        let url = format!(
            "{}/repos/{}/branches/{}",
            self.api_base(),
            Self::repo_path(repository),
            urlencoding::encode(branch)
        );
        let response = self
            .request(self.client.get(url), credential)
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            // GitHub uses the same 404 payload for a missing repository and a
            // missing branch. Verify the repository before classifying it.
            self.get_repository(repository, credential).await?;
            return Ok((branch.to_string(), None, false));
        }
        let response = Self::check_response(response).await?;
        let branch: GitHubBranch = response.json().await?;
        Ok((branch.name, Some(branch.commit.sha), true))
    }
}

#[derive(Debug, Deserialize)]
struct GitHubGraphQlResponse {
    #[serde(default)]
    errors: Option<Vec<GitHubGraphQlError>>,
}

#[derive(Debug, Deserialize)]
struct GitHubGraphQlError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookRepository {
    name: String,
    owner: GitHubUser,
}

#[derive(Debug, Deserialize)]
struct GitHubLifecyclePullRequest {
    #[serde(rename = "number")]
    _number: u64,
    head: Option<LifecycleHead>,
    merged: Option<bool>,
    html_url: String,
    title: String,
}

#[derive(Debug, Deserialize)]
struct LifecycleHead {
    #[serde(rename = "ref")]
    ref_name: Option<String>,
    sha: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookPullRequestPayload {
    action: String,
    number: u64,
    pull_request: GitHubLifecyclePullRequest,
    repository: GitHubWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookPullRequest {
    // Retain review payload head validation, even though commit_id is used.
    #[serde(rename = "head")]
    _head: GitHubRef,
    html_url: String,
    number: u64,
    title: String,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookIssuePayload {
    action: String,
    issue: GitHubWebhookIssue,
    repository: GitHubWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookIssue {
    html_url: String,
    number: u64,
    title: String,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookIssueCommentPayload {
    action: String,
    comment: GitHubWebhookComment,
    issue: GitHubWebhookIssue,
    repository: GitHubWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookComment {
    body: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookReviewPayload {
    action: String,
    pull_request: GitHubWebhookPullRequest,
    repository: GitHubWebhookRepository,
    review: GitHubWebhookReview,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookReview {
    body: Option<String>,
    commit_id: String,
    id: u64,
    state: String,
}

impl ForgeWebhookAdapter for GitHubAdapter {
    fn verify_and_parse_webhook_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
        verify_github_signature(headers, body, secret)?;
        let event = header_value(headers, "x-github-event")
            .ok_or_else(|| ForgeWebhookError::MissingHeader("x-github-event".to_string()))?;
        let delivery_id = header_value(headers, "x-github-delivery")
            .unwrap_or_default()
            .to_string();
        match event {
            "pull_request" => {
                parse_pull_request_webhook(body, delivery_id, forge_alias, forge_kind, host)
            }
            "issues" => parse_issue_webhook(body, delivery_id, forge_alias, forge_kind, host),
            "issue_comment" => {
                parse_issue_comment_webhook(body, delivery_id, forge_alias, forge_kind, host)
            }
            "pull_request_review" => {
                parse_review_webhook(body, delivery_id, forge_alias, forge_kind, host)
            }
            other => {
                tracing::debug!(event_type = %other, "ignoring unhandled GitHub webhook event");
                Ok(None)
            }
        }
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ForgeWebhookError> {
    let input = input.trim();
    if input.is_empty() || !input.len().is_multiple_of(2) {
        return Err(ForgeWebhookError::InvalidSignature);
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| ForgeWebhookError::InvalidSignature)?;
            u8::from_str_radix(text, 16).map_err(|_| ForgeWebhookError::InvalidSignature)
        })
        .collect()
}

fn verify_github_signature(
    headers: &[(String, String)],
    body: &[u8],
    secret: &str,
) -> Result<(), ForgeWebhookError> {
    let signature = header_value(headers, "x-hub-signature-256")
        .ok_or_else(|| ForgeWebhookError::MissingHeader("x-hub-signature-256".to_string()))?;
    let signature = signature
        .strip_prefix("sha256=")
        .ok_or(ForgeWebhookError::InvalidSignature)?;
    let signature = decode_hex(signature)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| ForgeWebhookError::InvalidPayload(format!("invalid secret: {e}")))?;
    mac.update(body);
    mac.verify_slice(&signature)
        .map_err(|_| ForgeWebhookError::InvalidSignature)
}

fn webhook_repository(
    repository: GitHubWebhookRepository,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> RepositoryRef {
    RepositoryRef {
        alias: forge_alias.to_string(),
        forge: forge_kind,
        host: host.to_string(),
        name: repository.name,
        owner: repository.owner.login,
    }
}

fn parse_pull_request_webhook(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: GitHubWebhookPullRequestPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;
    let action = match payload.action.as_str() {
        "opened" => domain::ChangeRequestEventAction::Opened,
        "reopened" => domain::ChangeRequestEventAction::Reopened,
        "synchronize" => domain::ChangeRequestEventAction::Synchronized,
        "closed" => match payload.pull_request.merged {
            Some(true) => domain::ChangeRequestEventAction::Merged,
            Some(false) => domain::ChangeRequestEventAction::Closed,
            None => {
                return Err(ForgeWebhookError::InvalidPayload(
                    "closed pull request missing merged boolean".to_string(),
                ));
            }
        },
        _ => return Ok(None),
    };
    if action.is_terminal() {
        crate::validate_terminal_identity(
            payload.number,
            &payload.repository.owner.login,
            &payload.repository.name,
        )?;
    }
    let head_sha = match payload.pull_request.head {
        Some(head) if action.is_terminal() => head.sha.unwrap_or_default(),
        Some(LifecycleHead {
            ref_name: Some(_),
            sha: Some(sha),
        }) => sha,
        None if action.is_terminal() => String::new(),
        _ => {
            return Err(ForgeWebhookError::InvalidPayload(
                "pull request head metadata missing".to_string(),
            ));
        }
    };

    Ok(Some(domain::WebhookEvent::ChangeRequest(
        domain::ChangeRequestEvent {
            action,
            delivery_id,
            head_sha,
            index: payload.number,
            repository: webhook_repository(payload.repository, forge_alias, forge_kind, host),
            title: payload.pull_request.title,
            url: payload.pull_request.html_url,
        },
    )))
}

fn parse_issue_webhook(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: GitHubWebhookIssuePayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;
    let action = match payload.action.as_str() {
        "opened" => domain::IssueEventAction::Opened,
        "closed" => domain::IssueEventAction::Closed,
        _ => return Ok(None),
    };
    Ok(Some(domain::WebhookEvent::Issue(domain::IssueEvent {
        action,
        delivery_id,
        index: payload.issue.number,
        repository: webhook_repository(payload.repository, forge_alias, forge_kind, host),
        title: payload.issue.title,
        url: payload.issue.html_url,
    })))
}

fn parse_issue_comment_webhook(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: GitHubWebhookIssueCommentPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;
    if payload.action != "created" {
        return Ok(None);
    }
    Ok(Some(domain::WebhookEvent::IssueComment(
        domain::IssueCommentEvent {
            action: domain::IssueCommentEventAction::Created,
            body: payload.comment.body,
            comment_id: payload.comment.id,
            delivery_id,
            issue_index: payload.issue.number,
            repository: webhook_repository(payload.repository, forge_alias, forge_kind, host),
        },
    )))
}

fn parse_review_webhook(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: GitHubWebhookReviewPayload = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;
    if payload.action != "submitted" {
        return Ok(None);
    }
    let state = match payload.review.state.as_str() {
        "approved" => domain::ReviewState::Approved,
        "changes_requested" => domain::ReviewState::RequestChanges,
        "commented" => domain::ReviewState::Comment,
        _ => return Ok(None),
    };
    Ok(Some(domain::WebhookEvent::PullRequestReview(
        domain::PullRequestReviewEvent {
            action: domain::PullRequestReviewEventAction::Submitted,
            delivery_id,
            head_sha: payload.review.commit_id,
            index: payload.pull_request.number,
            repository: webhook_repository(payload.repository, forge_alias, forge_kind, host),
            review_body: payload.review.body.unwrap_or_default(),
            review_id: payload.review.id,
            review_state: state,
            title: payload.pull_request.title,
            url: payload.pull_request.html_url,
        },
    )))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {

    #[test]
    fn github_lifecycle_optional_head_does_not_relax_review_payloads() {
        for head in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"sha": "source"}),
        ] {
            let pr = serde_json::json!({
                "number": 42, "merged": true, "head": head,
                "html_url": "https://forge.example/pr/42", "title": "Change"
            });
            let payload = serde_json::json!({
                "action": "closed", "number": 42, "pull_request": pr,
                "repository": {"owner": {"login": "org"}, "name": "repo"}
            });
            assert!(
                serde_json::from_value::<super::GitHubWebhookPullRequestPayload>(payload).is_ok()
            );
            assert!(serde_json::from_value::<super::GitHubWebhookPullRequest>(pr).is_err());
        }
        let pr = serde_json::json!({
            "number": 42, "head": {"ref": "feature", "sha": "source"},
            "html_url": "https://forge.example/pr/42", "title": "Change"
        });
        assert!(serde_json::from_value::<super::GitHubWebhookPullRequest>(pr).is_ok());
    }
    use std::fmt::Write as _;
    use std::io::{self, Read as _, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex, RwLock};
    use std::thread::JoinHandle;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tracing::instrument::WithSubscriber as _;
    use wiremock::matchers::{body_json, header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::ForgeAdapter;

    const TEST_RSA_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCtaES59VI/NIBJ
E4W55WWW6ljKx+nzK4R0SsyoDVb4xSBYCVRdb24H5P76cNCOHho5yOjE7NbpfX4W
K7xIptZAhBA7G6/WMDv6WI5oHQl/lzYnzthFcLWMQH2Xc6+ovXfsj8e+bk7kUbp/
SYNBalRs8TVjmkFdDdBZ0uDExTRHXpRlcobX/pSi/61lrogJuEmjehdsLlLHWuW4
I6HFLfCTfKjZp6s82kpeBoP1wkXemH4Hkmv3jnvr287xRkWnyE4c1/UyMomOrhIm
rxTBs1xLj+dDxS9cp4ZVkdXk0Z9iMypPmvvVR7L+i+JzBT5uIjt/9wOsn+NmlOTc
kcgTevqBAgMBAAECggEAIeps1romlfocxS4uT4eQcQ3ww+iJ12fBhkVC9fN1+T4E
73MTrxqmOKEPRche4gz9MCQdcran6g8DZC61qrgG26N40Ta/E3Nnp7U+VRqoyu22
R97q6dn7iCzs43xa9PPpyrjsZlCI2ZsqkM69/0Nes9gRiyOWeS7Ee20FTTcM3JBO
Z2K7QM4ChFos8NxYIShXq4RPhtPn3x9PYmtJMns83YrYas6OW/Gkc/HLu/U3rXGO
od8CLOlSLF3MHcyekFZUs8haF8Y+Dhbf1LUDKeRXOdxUzJo3wP68mYJQ/Xo2thNo
f3o8pmLM6oJRLPrVLAslNM38MTneled8a2kIs9bUYQKBgQDjrmW7w0gPVllF2KmW
1MbcqdLAXOfVoQMqCjXC2yJ3Sq6YVEuOCqf2raq0UXLDE4IO0lJjsanhzqy5be52
G1CpzxfWdEad6/Lzbqkd+XMEGCD3jhpdERQ1GvMaJXGMHshu5myTNkiC79bPomRR
9u1UNje8dnBirgjYoRZPHyigfQKBgQDC+bvGQcjJ4DBOAYy7QK1YSYB0MihbdON8
iJu2xnxyrZbIeB51GjryZNwd+gLTd3XmDWSzJ4F6zeVgxnlQ/M+8tQYvHcex3smz
el+FSKQFogvxP7FdeakstyWIqdyJVN63rauXEDVnyvpXpvePDzn9xwb1GlfuAwA8
5+5Ez2xFVQKBgCOGqNUdaXcLMC7X2c5xMP5peTsOxBXvY8EBitX2v3ABtTCLpqZp
P0AcZRBxzQhnWNnbM4PeyvUy/HyKjLTdGj8E02FhD0vA703QrI7Cx5GR+kLmZ3Ky
IYcPx3MC+K62duvnBHYL+FCF/+yyGBk6AFotg5DiojKjmTnEGOkLoZk5AoGBAL0P
plonngjLQGvTquBEZhJvK4UAwgt0+8XdPYjtTO1yj/ySJY6Nwc0bqinTLXxaoVNT
d2sVisNG9f5yVl8G1nV436c+bE545wMHTaqTdqETshrcFSO7/iSi711mwLfWOSTI
3dNc3zxnIXtvJyxsqmH/5So0wkDEXi2xBGVq8OUFAoGBAJBUMIkQ+BWgLnz1wi7T
8AU9nYc5Qh62LM31CkR9d/qVQdy5OuKf0dK5tfj97kpUI8yh+Kenhjczy0ivYAn1
0cKHzy9kpOHnej/nm1PvD6Ps9euQTKPh8/Z+etMpok7xbDvSrZUMOJCEY5g9suAz
rRwzv5g6zr/Xm2UKcduXYVQs
-----END PRIVATE KEY-----";

    fn adapter(base_url: &str) -> GitHubAdapter {
        GitHubAdapter::new(GitHubConfig {
            api_url: base_url.to_string(),
            token: Some("app-token".to_string()),
        })
        .expect("adapter")
    }

    fn credential() -> ForgeCredential {
        ForgeCredential {
            token: Some("user-token".to_string()),
        }
    }

    fn repository() -> RepositoryRef {
        RepositoryRef {
            alias: "github".to_string(),
            forge: domain::ForgeKind::GitHub,
            host: "https://github.com".to_string(),
            name: "repo".to_string(),
            owner: "org".to_string(),
        }
    }

    struct TraceWriter(Arc<Mutex<Vec<u8>>>);

    impl IoWrite for TraceWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("trace buffer lock poisoned"))?
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn one_shot_http_response(response: Vec<u8>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind one-shot HTTP fixture");
        let address = listener.local_addr().expect("one-shot fixture address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept one-shot HTTP request");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).expect("read one-shot request");
            stream
                .write_all(&response)
                .expect("write one-shot HTTP response");
        });
        (format!("http://{address}"), handle)
    }

    fn actions_check(id: u64, suite_id: u64, name: &str) -> GitHubCheckRun {
        GitHubCheckRun {
            id: Some(id),
            conclusion: Some("failure".to_string()),
            details_url: Some(format!("https://github.example/checks/{id}")),
            name: name.to_string(),
            status: "completed".to_string(),
            check_suite: Some(GitHubCheckSuite { id: Some(suite_id) }),
            app: Some(GitHubCheckApp {
                slug: Some("github-actions".to_string()),
            }),
        }
    }

    async fn mount_actions_resolution(
        server: &MockServer,
        suite_id: u64,
        run_id: u64,
        check_id: u64,
        job_id: u64,
        steps: Vec<serde_json::Value>,
        log: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", suite_id.to_string()))
            .and(query_param("head_sha", "head-sha"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "workflow_runs": [{
                    "id": run_id,
                    "check_suite_id": suite_id,
                    "head_sha": "head-sha",
                    "run_attempt": 1,
                    "html_url": format!("https://github.example/actions/runs/{run_id}")
                }]
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/org/repo/actions/runs/{run_id}/attempts/1/jobs"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "jobs": [{
                    "id": job_id,
                    "run_id": run_id,
                    "head_sha": "head-sha",
                    "name": format!("job-{job_id}"),
                    "conclusion": "failure",
                    "check_run_url": format!(
                        "{}/repos/org/repo/check-runs/{check_id}",
                        server.uri()
                    ),
                    "steps": steps
                }]
            })))
            .mount(server)
            .await;
        let signed_path = format!("/signed-log-{job_id}");
        Mock::given(method("GET"))
            .and(path(format!("/repos/org/repo/actions/jobs/{job_id}/logs")))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "Location",
                format!("{}{signed_path}?secret=hidden-{job_id}", server.uri()),
            ))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(signed_path))
            .respond_with(ResponseTemplate::new(200).set_body_string(log))
            .mount(server)
            .await;
    }

    fn issue_json(number: u64, id: u64) -> serde_json::Value {
        serde_json::json!({
            "assignees": [{"login": "octocat"}],
            "body": "body",
            "html_url": format!("https://github.com/org/repo/issues/{number}"),
            "id": id,
            "labels": [{"name": "bug"}],
            "number": number,
            "state": "open",
            "title": "Issue"
        })
    }

    #[test]
    fn actions_limits_reject_zero_inconsistent_and_overflowing_values() {
        let defaults = GitHubActionsResolutionLimits::default();
        assert!(defaults.validate().is_ok());
        assert!(
            GitHubActionsResolutionLimits {
                api_requests: 0,
                ..defaults
            }
            .validate()
            .is_err()
        );
        assert!(
            GitHubActionsResolutionLimits {
                json_page_bytes: defaults.json_total_bytes + 1,
                ..defaults
            }
            .validate()
            .is_err()
        );
        assert!(
            GitHubActionsResolutionLimits {
                excerpt_lines: usize::MAX,
                excerpt_line_bytes: 2,
                excerpt_bytes: usize::MAX,
                ..defaults
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn actions_excerpt_clips_on_utf8_boundary() {
        assert_eq!(utf8_prefix("abéz", 3), "ab");
        assert_eq!(utf8_prefix("abéz", 4), "abé");
    }

    #[test]
    fn actions_signed_log_destination_enforces_scheme_and_credentials() {
        let https_api = Url::parse("https://api.github.example/api/v3").expect("API URL");
        let explicitly_insecure_api =
            Url::parse("http://api.github.example/api/v3").expect("API URL");
        assert!(
            validate_signed_log_destination(
                &https_api,
                Url::parse("https://storage.example/log?secret=value").expect("destination"),
                7,
            )
            .is_ok()
        );
        assert!(
            validate_signed_log_destination(
                &explicitly_insecure_api,
                Url::parse("http://storage.example/log?secret=value").expect("destination"),
                7,
            )
            .is_ok()
        );
        for invalid in [
            "http://storage.example/log",
            "https://user:password@storage.example/log",
            "ftp://storage.example/log",
        ] {
            let error = validate_signed_log_destination(
                &https_api,
                Url::parse(invalid).expect("parseable invalid destination"),
                7,
            )
            .expect_err("destination must be rejected");
            assert!(!error.0.contains(invalid));
        }
    }

    #[test]
    fn actions_check_run_url_supports_enterprise_api_prefix() {
        let adapter = adapter("https://ghe.example/api/v3");
        let repository = repository();
        let credential = credential();
        let resolver = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");

        assert_eq!(
            resolver
                .check_run_id_from_job_url(
                    "https://ghe.example/api/v3/repos/org/repo/check-runs/42",
                )
                .expect("enterprise check-run URL"),
            42
        );
        assert!(
            resolver
                .check_run_id_from_job_url("https://ghe.example/repos/org/repo/check-runs/42")
                .is_err()
        );
    }

    fn pull_json(number: u64) -> serde_json::Value {
        serde_json::json!({
            "base": {"ref": "main", "sha": "base-sha"},
            "body": "body",
            "changed_files": 2,
            "commits": 3,
            "head": {"ref": "agent/fix", "sha": "head-sha"},
            "html_url": format!("https://github.com/org/repo/pull/{number}"),
            "labels": [{"name": "ready"}],
            "mergeable": true,
            "mergeable_state": "clean",
            "merged_at": null,
            "node_id": "PR_node",
            "number": number,
            "state": "open",
            "title": "Fix"
        })
    }

    #[tokio::test]
    async fn authenticated_user_prefers_request_credential_and_sets_github_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("authorization", "Bearer user-token"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "email": "octocat@example.com",
                "login": "octocat"
            })))
            .mount(&server)
            .await;

        let user = adapter(&server.uri())
            .get_authenticated_user(&credential())
            .await
            .expect("user");
        assert_eq!(user.username, "octocat");
        assert_eq!(user.email, "octocat@example.com");
    }

    #[tokio::test]
    async fn github_app_exchanges_jwt_and_accepts_per_agent_app_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/app"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "slug": "stintel-codex"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/456/access_tokens"))
            .and(header_exists("authorization"))
            .and(header("accept", "application/vnd.github+json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "expires_at": "2099-01-01T00:00:00Z",
                "token": "installation-token"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = GitHubAdapter::new_app(
            GitHubConfig {
                api_url: server.uri(),
                token: None,
            },
            GitHubAppConfig {
                app_id: 123,
                installation_id: 456,
                private_key_pem: TEST_RSA_PRIVATE_KEY.to_string(),
            },
        )
        .await
        .expect("GitHub App adapter");
        let fallback = adapter.effective_credential(&ForgeCredential { token: None });
        assert_eq!(fallback.token.as_deref(), Some("installation-token"));
        let app_user = adapter
            .get_authenticated_user(&fallback)
            .await
            .expect("managed App identity");
        assert_eq!(app_user.username, "stintel-codex[bot]");
        let per_agent = adapter.effective_credential(&credential());
        assert_eq!(per_agent.token.as_deref(), Some("user-token"));
        let debug = format!("{adapter:?}");
        assert!(!debug.contains("installation-token"));
        assert!(!debug.contains("user-token"));
        assert!(debug.contains("github_app"));
    }

    #[tokio::test]
    async fn managed_per_agent_app_token_resolves_its_own_bot_identity() {
        let server = MockServer::start().await;
        let reviewer = GitHubAppCredential {
            app_slug: Arc::from("stintel-qwen"),
            token: Arc::new(RwLock::new("reviewer-installation-token".to_string())),
        };
        let mut adapter = adapter(&server.uri());
        adapter.extend_managed_app_credentials([reviewer.clone()]);

        let user = adapter
            .get_authenticated_user(&reviewer.credential())
            .await
            .expect("per-agent App identity");
        assert_eq!(user.username, "stintel-qwen[bot]");
        assert!(user.email.is_empty());
    }

    #[tokio::test]
    async fn per_agent_app_token_submits_approval_instead_of_system_app() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/app"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "slug": "system"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/456/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "expires_at": "2099-01-01T00:00:00Z",
                "token": "system-installation-token"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/org/repo/pulls/7/reviews"))
            .and(header(
                "authorization",
                "Bearer reviewer-installation-token",
            ))
            .and(body_json(serde_json::json!({
                "body": "Looks good",
                "event": "APPROVE"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "body": "Looks good",
                "id": 99,
                "state": "APPROVED",
                "user": {"login": "stintel-qwen[bot]"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = GitHubAdapter::new_app(
            GitHubConfig {
                api_url: server.uri(),
                token: None,
            },
            GitHubAppConfig {
                app_id: 123,
                installation_id: 456,
                private_key_pem: TEST_RSA_PRIVATE_KEY.to_string(),
            },
        )
        .await
        .expect("GitHub App adapter");
        let review = adapter
            .submit_change_request_review(
                &repository(),
                7,
                "Looks good",
                "APPROVED",
                &ForgeCredential {
                    token: Some("reviewer-installation-token".to_string()),
                },
            )
            .await
            .expect("approval review");
        assert_eq!(review.id, 99);
        assert_eq!(review.event, "APPROVED");
    }

    #[tokio::test]
    async fn creates_and_maps_pull_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/org/repo/pulls"))
            .and(body_json(serde_json::json!({
                "base": "main",
                "body": "Details",
                "head": "agent/fix",
                "title": "Fix"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(pull_json(7)))
            .mount(&server)
            .await;

        let pull = adapter(&server.uri())
            .create_change_request(
                &repository(),
                "Fix",
                "Details",
                "agent/fix",
                "main",
                &credential(),
            )
            .await
            .expect("pull");
        assert_eq!(pull.index, 7);
        assert_eq!(pull.head_sha.as_deref(), Some("head-sha"));
        assert_eq!(pull.labels, vec!["ready"]);
        assert_eq!(pull.mergeability, Mergeability::Mergeable);
    }

    #[tokio::test]
    async fn issue_listing_excludes_pull_requests() {
        let server = MockServer::start().await;
        let mut pull_issue = issue_json(2, 102);
        pull_issue["pull_request"] = serde_json::json!({"url": "api/pulls/2"});
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([issue_json(1, 101), pull_issue])),
            )
            .mount(&server)
            .await;

        let issues = adapter(&server.uri())
            .list_issues(&repository(), Some("all"), &credential())
            .await
            .expect("issues");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].index, 1);
    }

    #[tokio::test]
    async fn issue_listing_follows_links_and_deduplicates_first_occurrence() {
        let server = MockServer::start().await;
        let mut pull_issue = issue_json(2, 102);
        pull_issue["pull_request"] = serde_json::json!({"url": "api/pulls/2"});
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues"))
            .and(query_param("state", "all"))
            .and(query_param("per_page", "2"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "Link",
                        format!(
                            "<{}/repos/org/repo/issues?page=2>; rel=\"next\"",
                            server.uri()
                        ),
                    )
                    .set_body_json(serde_json::json!([issue_json(1, 101), pull_issue])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues"))
            .and(query_param("state", "all"))
            .and(query_param("per_page", "2"))
            .and(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([issue_json(3, 103), issue_json(1, 101)])),
            )
            .mount(&server)
            .await;

        let issues = adapter(&server.uri())
            .list_issues_with_limits(
                &repository(),
                Some("all"),
                &credential(),
                IssuePaginationLimits {
                    page_size: 2,
                    max_pages: 2,
                    max_raw_issues: 4,
                    max_page_bytes: 4096,
                    max_total_bytes: 8192,
                    deadline: Duration::from_secs(1),
                },
            )
            .await
            .expect("paginated issues");
        assert_eq!(
            issues.iter().map(|issue| issue.index).collect::<Vec<_>>(),
            [1, 3]
        );
    }

    #[tokio::test]
    async fn issue_listing_without_state_includes_open_and_closed_issues() {
        let server = MockServer::start().await;
        let mut closed_issue = issue_json(2, 102);
        closed_issue["state"] = serde_json::json!("closed");
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues"))
            .and(query_param("state", "all"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "Link",
                        format!(
                            "<{}/repos/org/repo/issues?page=2>; rel=\"next\"",
                            server.uri()
                        ),
                    )
                    .set_body_json(serde_json::json!([issue_json(1, 101)])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues"))
            .and(query_param("state", "all"))
            .and(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([closed_issue.clone()])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues"))
            .and(query_param("state", "open"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([issue_json(1, 101)])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues"))
            .and(query_param("state", "closed"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([closed_issue])),
            )
            .mount(&server)
            .await;

        let adapter = adapter(&server.uri());
        let all = adapter
            .list_issues(&repository(), None, &credential())
            .await
            .expect("all issues");
        let open = adapter
            .list_issues(&repository(), Some("open"), &credential())
            .await
            .expect("open issues");
        let closed = adapter
            .list_issues(&repository(), Some("closed"), &credential())
            .await
            .expect("closed issues");

        assert_eq!(
            all.iter()
                .map(|issue| (issue.index, issue.state.as_str()))
                .collect::<Vec<_>>(),
            [(1, "open"), (2, "closed")]
        );
        assert_eq!(
            open.iter().map(|issue| issue.index).collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(
            closed.iter().map(|issue| issue.index).collect::<Vec<_>>(),
            [2]
        );
    }

    #[tokio::test]
    async fn change_request_comments_include_later_review_pages() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues/7/comments"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/pulls/7/reviews"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "Link",
                        format!(
                            "<{}/repos/org/repo/pulls/7/reviews?page=2>; rel=\"next\"",
                            server.uri()
                        ),
                    )
                    .set_body_json(serde_json::json!([{
                        "body": "first",
                        "commit_id": "old-head",
                        "id": 1,
                        "state": "COMMENTED",
                        "submitted_at": "2026-08-05T08:00:00Z",
                        "user": {"login": "reviewer"}
                    }])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/pulls/7/reviews"))
            .and(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "body": "blocking",
                    "commit_id": "head-sha",
                    "id": 2,
                    "state": "CHANGES_REQUESTED",
                    "submitted_at": "2026-08-05T09:00:00Z",
                    "user": {"login": "reviewer"}
                }])),
            )
            .mount(&server)
            .await;

        let details = adapter(&server.uri())
            .get_change_request_comments(&repository(), 7, &credential())
            .await
            .expect("change request comments");
        assert_eq!(details.len(), 2);
        assert_eq!(details[1].id, 2);
        assert_eq!(details[1].commit_id.as_deref(), Some("head-sha"));
        assert_eq!(
            details[1].review_state.as_deref(),
            Some("CHANGES_REQUESTED")
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn ci_details_aggregate_all_status_and_check_run_pages() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/status"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "Link",
                        format!(
                            "<{}/repos/org/repo/commits/head-sha/status?page=2>; rel=\"next\"",
                            server.uri()
                        ),
                    )
                    .set_body_json(serde_json::json!({
                        "sha": "head-sha",
                        "state": "success",
                        "statuses": [{
                            "context": "status-first",
                            "description": "ok",
                            "state": "success",
                            "target_url": "https://ci/first"
                        }],
                        "total_count": 2
                    })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/status"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "head-sha",
                "state": "failure",
                "statuses": [{
                    "context": "status-late",
                    "description": "failed",
                    "state": "failure",
                    "target_url": "https://ci/late"
                }],
                "total_count": 2
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/check-runs"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "Link",
                        format!(
                            "<{}/repos/org/repo/commits/head-sha/check-runs?page=2>; rel=\"next\"",
                            server.uri()
                        ),
                    )
                    .set_body_json(serde_json::json!({
                        "check_runs": [{
                            "conclusion": "success",
                            "details_url": "https://checks/first",
                            "name": "check-first",
                            "status": "completed"
                        }],
                        "total_count": 2
                    })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/check-runs"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "check_runs": [{
                    "conclusion": "timed_out",
                    "details_url": "https://checks/late",
                    "name": "check-late",
                    "status": "completed"
                }],
                "total_count": 2
            })))
            .mount(&server)
            .await;

        let details = adapter(&server.uri())
            .get_change_request_ci_details(&repository(), "head-sha", &credential())
            .await
            .expect("CI details");
        assert_eq!(details.state, domain::CommitStatusState::Failure);
        assert_eq!(details.details.len(), 4);
        assert_eq!(
            details
                .details
                .iter()
                .map(|detail| detail.context.as_str())
                .collect::<Vec<_>>(),
            ["status-first", "status-late", "check-first", "check-late"]
        );
        assert_eq!(
            details
                .details
                .iter()
                .map(|detail| &detail.state)
                .collect::<Vec<_>>(),
            [
                &domain::CommitStatusState::Success,
                &domain::CommitStatusState::Failure,
                &domain::CommitStatusState::Success,
                &domain::CommitStatusState::Error,
            ]
        );
        assert!(
            details
                .details
                .iter()
                .all(|detail| matches!(detail.resolution, domain::CiResolution::Unsupported))
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn ci_details_resolves_github_actions_failure_with_job_log() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "head-sha",
                "statuses": [],
                "total_count": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/check-runs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "check_runs": [{
                    "id": 42,
                    "app": {"slug": "github-actions"},
                    "check_suite": {"id": 9},
                    "conclusion": "failure",
                    "details_url": "https://github.example/checks/42",
                    "name": "build",
                    "status": "completed"
                }],
                "total_count": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", "9"))
            .and(query_param("head_sha", "head-sha"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 2,
                "workflow_runs": [
                    {
                        "id": 99,
                        "check_suite_id": 9,
                        "head_sha": "head-sha",
                        "run_attempt": 1,
                        "html_url": "https://github.example/actions/runs/100"
                    },
                    {
                        "id": 100,
                        "check_suite_id": 9,
                        "head_sha": "head-sha",
                        "run_attempt": 2,
                        "html_url": "https://github.example/actions/runs/100/attempts/2"
                    }
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs/100/attempts/2/jobs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "jobs": [{
                    "id": 77,
                    "run_id": 100,
                    "head_sha": "head-sha",
                    "name": "linux",
                    "conclusion": "failure",
                    "check_run_url": format!("{}/repos/org/repo/check-runs/42", server.uri()),
                    "steps": [
                        {"name": "compile", "conclusion": "success"},
                        {"name": "test", "conclusion": "failure"},
                        {"name": "lint", "conclusion": "timed_out"}
                    ]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/jobs/77/logs"))
            .and(header("authorization", "Bearer user-token"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "Location",
                format!("{}/signed-log?secret=hidden", server.uri()),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/signed-log"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("\ncompile ok\nassertion failed\n"),
            )
            .mount(&server)
            .await;

        let details = adapter(&server.uri())
            .get_change_request_ci_details(&repository(), "head-sha", &credential())
            .await
            .expect("CI details");
        assert_eq!(details.state, domain::CommitStatusState::Failure);
        let domain::CiResolution::Resolved {
            provider,
            pipeline_url,
            failed_steps,
        } = &details.details[0].resolution
        else {
            panic!("expected resolved GitHub Actions check")
        };
        assert_eq!(*provider, domain::CiProvider::GithubActions);
        assert_eq!(
            pipeline_url,
            "https://github.example/actions/runs/100/attempts/2"
        );
        assert_eq!(failed_steps.len(), 2);
        assert_eq!(failed_steps[0].name, "linux / test");
        assert_eq!(
            failed_steps[0]
                .log_excerpt
                .as_ref()
                .expect("first excerpt")
                .lines,
            ["compile ok", "assertion failed"]
        );
        assert!(failed_steps[1].log_excerpt.is_none());

        let requests = server.received_requests().await.expect("request log");
        let signed = requests
            .iter()
            .find(|request| request.url.path() == "/signed-log")
            .expect("signed request");
        assert!(!signed.headers.contains_key("authorization"));
        // reqwest supplies its generic default, never the GitHub API media type.
        assert_eq!(
            signed
                .headers
                .get("accept")
                .and_then(|value| value.to_str().ok()),
            Some("*/*")
        );
        assert!(!signed.headers.contains_key("x-github-api-version"));
    }

    #[tokio::test]
    async fn actions_many_failed_steps_are_atomic_and_preserve_other_details() {
        let server = MockServer::start().await;
        mount_actions_resolution(
            &server,
            11,
            101,
            1,
            1001,
            vec![
                serde_json::json!({"name": "first", "conclusion": "failure"}),
                serde_json::json!({"name": "second", "conclusion": "timed_out"}),
            ],
            "first excerpt\n",
        )
        .await;
        mount_actions_resolution(
            &server,
            22,
            202,
            2,
            2002,
            vec![
                serde_json::json!({"name": "one", "conclusion": "failure"}),
                serde_json::json!({"name": "two", "conclusion": "failure"}),
                serde_json::json!({"name": "three", "conclusion": "failure"}),
            ],
            "must not be downloaded\n",
        )
        .await;
        let mut external = actions_check(3, 33, "external");
        external.app = Some(GitHubCheckApp {
            slug: Some("external-ci".to_string()),
        });
        let details = build_change_request_ci_details(
            &adapter(&server.uri()),
            &repository(),
            "head-sha",
            &credential(),
            vec![domain::CommitStatus {
                context: "legacy".to_string(),
                description: "ok".to_string(),
                state: domain::CommitStatusState::Success,
                target_url: "https://legacy.example".to_string(),
            }],
            vec![
                actions_check(1, 11, "within-budget"),
                actions_check(2, 22, "oversized"),
                external,
            ],
            GitHubActionsResolutionLimits {
                emitted_steps: 4,
                ..GitHubActionsResolutionLimits::default()
            },
        )
        .await
        .expect("bounded CI details");

        assert_eq!(details.state, domain::CommitStatusState::Failure);
        assert_eq!(
            details
                .details
                .iter()
                .map(|detail| detail.context.as_str())
                .collect::<Vec<_>>(),
            ["legacy", "within-budget", "oversized", "external"]
        );
        let domain::CiResolution::Resolved { failed_steps, .. } = &details.details[1].resolution
        else {
            panic!("the earlier check should remain resolved")
        };
        assert_eq!(failed_steps.len(), 2);
        assert_eq!(
            failed_steps
                .iter()
                .filter(|step| step.log_excerpt.is_some())
                .count(),
            1
        );
        let domain::CiResolution::Error { message } = &details.details[2].resolution else {
            panic!("the oversized check must fail atomically")
        };
        assert!(message.contains("emitted failure-step limit"));
        assert!(matches!(
            details.details[3].resolution,
            domain::CiResolution::Unsupported
        ));
        let requests = server.received_requests().await.expect("request log");
        assert!(
            requests
                .iter()
                .any(|request| request.url.path().ends_with("/jobs/1001/logs"))
        );
        assert!(
            requests
                .iter()
                .all(|request| !request.url.path().ends_with("/jobs/2002/logs"))
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn actions_aggregate_limits_are_shared_across_suites_runs_and_jobs() {
        let server = MockServer::start().await;
        for (suite, run, check, job) in [(11, 101, 1, 1001), (22, 202, 2, 2002)] {
            mount_actions_resolution(
                &server,
                suite,
                run,
                check,
                job,
                vec![serde_json::json!({
                    "name": "failed",
                    "conclusion": "failure"
                })],
                "bounded excerpt\n",
            )
            .await;
        }
        let adapter = adapter(&server.uri());
        let repository = repository();
        let credential = credential();
        let first = actions_check(1, 11, "first");
        let second = actions_check(2, 22, "second");

        let mut requests = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        requests.resolve(&first).await.expect("first resolution");
        requests.limits.api_requests = requests.budget.api_requests;
        assert!(
            requests
                .resolve(&second)
                .await
                .expect_err("shared request budget")
                .0
                .contains("authenticated request count limit")
        );

        let mut json = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        json.resolve(&first).await.expect("first resolution");
        json.limits.json_total_bytes = json.budget.json_bytes;
        assert!(
            json.resolve(&second)
                .await
                .expect_err("shared JSON budget")
                .0
                .contains("JSON byte limit")
        );

        let mut records = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        records.resolve(&first).await.expect("first resolution");
        records.limits.workflow_runs = records.budget.workflow_runs;
        assert!(
            records
                .resolve(&second)
                .await
                .expect_err("shared record budget")
                .0
                .contains("workflow-run record limit")
        );

        let mut steps = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        steps.resolve(&first).await.expect("first resolution");
        steps.limits.job_steps = steps.budget.job_steps;
        assert!(
            steps
                .resolve(&second)
                .await
                .expect_err("shared raw-step budget")
                .0
                .contains("job-step record limit")
        );

        let mut downloads = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        downloads.resolve(&first).await.expect("first resolution");
        downloads.limits.log_downloads = downloads.budget.log_downloads;
        assert!(
            downloads
                .resolve(&second)
                .await
                .expect_err("shared download budget")
                .0
                .contains("signed log download count limit")
        );

        let mut output = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        output.resolve(&first).await.expect("first resolution");
        output.limits.output_bytes = output.budget.output_bytes;
        assert!(
            output
                .resolve(&second)
                .await
                .expect_err("shared output budget")
                .0
                .contains("resolved output byte limit")
        );
    }

    #[tokio::test]
    async fn ci_details_gates_actions_enrichment_and_reports_missing_ids() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "head-sha",
                "statuses": [],
                "total_count": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/commits/head-sha/check-runs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 4,
                "check_runs": [
                    {"id": 1, "app": {"slug": "github-actions"}, "check_suite": {"id": 1}, "conclusion": "success", "name": "success", "status": "completed"},
                    {"id": 2, "app": {"slug": "github-actions"}, "check_suite": {"id": 1}, "conclusion": null, "name": "pending", "status": "in_progress"},
                    {"id": 3, "app": {"slug": "external-ci"}, "check_suite": {"id": 1}, "conclusion": "failure", "name": "external", "status": "completed"},
                    {"app": {"slug": "github-actions"}, "check_suite": {}, "conclusion": "startup_failure", "name": "missing", "status": "completed"}
                ]
            })))
            .mount(&server)
            .await;

        let details = adapter(&server.uri())
            .get_change_request_ci_details(&repository(), "head-sha", &credential())
            .await
            .expect("CI details");
        assert!(matches!(
            details.details[0].resolution,
            domain::CiResolution::Unsupported
        ));
        assert!(matches!(
            details.details[1].resolution,
            domain::CiResolution::Unsupported
        ));
        assert!(matches!(
            details.details[2].resolution,
            domain::CiResolution::Unsupported
        ));
        let domain::CiResolution::Error { message } = &details.details[3].resolution else {
            panic!("identified Actions check with missing IDs must be an error")
        };
        assert!(message.contains("missing its ID"));
    }

    #[tokio::test]
    async fn actions_log_errors_do_not_expose_signed_secrets() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/jobs/77/logs"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "Location",
                format!("{}/signed-log?first-secret=alpha", server.uri()),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/signed-log"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header(
                        "Location",
                        format!("{}/other?second-secret=bravo", server.uri()),
                    )
                    .set_body_string("destination-body-secret-charlie"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/jobs/78/logs"))
            .respond_with(ResponseTemplate::new(403).set_body_string("upstream-body-secret-delta"))
            .mount(&server)
            .await;

        let trace = Arc::new(Mutex::new(Vec::new()));
        let trace_writer = Arc::clone(&trace);
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || TraceWriter(Arc::clone(&trace_writer)))
            .finish();
        let serialized = async {
            let adapter = adapter(&server.uri());
            let repository = repository();
            let credential = credential();
            let mut resolver = GitHubActionsResolver::new(
                &adapter,
                &repository,
                "head-sha",
                &credential,
                GitHubActionsResolutionLimits::default(),
            )
            .expect("resolver");
            let redirect_error = resolver.job_log(77).await.expect_err("second redirect");
            let permission_error = resolver.job_log(78).await.expect_err("permission error");
            serde_json::to_string(&domain::CiResolution::Error {
                message: format!("{}; {}", redirect_error.0, permission_error.0),
            })
            .expect("serialize error resolution")
        }
        .with_subscriber(subscriber)
        .await;
        let captured = String::from_utf8(trace.lock().expect("trace buffer").clone())
            .expect("UTF-8 tracing output");
        for secret in ["alpha", "bravo", "charlie", "delta", "signed-log"] {
            assert!(!serialized.contains(secret));
            assert!(!captured.contains(secret));
        }
        assert!(serialized.contains("Actions: read"));
        assert!(serialized.contains("re-approve"));
    }

    #[tokio::test]
    async fn actions_json_reader_bounds_and_sanitizes_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", "1"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("permission-body-secret-alpha"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", "3"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(65)))
            .mount(&server)
            .await;

        let adapter = adapter(&server.uri());
        let repository = repository();
        let credential = credential();
        let mut resolver = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits {
                json_page_bytes: 64,
                json_total_bytes: 128,
                ..GitHubActionsResolutionLimits::default()
            },
        )
        .expect("resolver");
        let permission = resolver.workflow_run(1).await.expect_err("permission");
        assert!(permission.0.contains("Actions: read"));
        assert!(!permission.0.contains("permission-body-secret-alpha"));
        let malformed = resolver.workflow_run(2).await.expect_err("malformed JSON");
        assert!(malformed.0.contains("malformed JSON"));
        let overflow = resolver.workflow_run(3).await.expect_err("bounded JSON");
        assert!(overflow.0.contains("JSON byte limit"));
    }

    #[tokio::test]
    async fn actions_rejected_chunks_do_not_consume_shared_byte_budgets() {
        let oversized = "x".repeat(65);
        let json_response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{oversized}\r\n0\r\n\r\n",
            oversized.len()
        )
        .into_bytes();
        let (json_url, json_fixture) = one_shot_http_response(json_response);
        let json_adapter = adapter(&json_url);
        let repository = repository();
        let credential = credential();
        let mut resolver = GitHubActionsResolver::new(
            &json_adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits {
                json_page_bytes: 64,
                json_total_bytes: 64,
                ..GitHubActionsResolutionLimits::default()
            },
        )
        .expect("JSON resolver");
        let response = json_adapter
            .client
            .get(&json_url)
            .send()
            .await
            .expect("chunked JSON response");
        let error = resolver
            .read_json::<serde_json::Value>(response, "test lookup")
            .await
            .expect_err("oversized chunk");
        assert!(error.0.contains("JSON byte limit"));
        assert_eq!(resolver.budget.json_bytes, 0);
        json_fixture.join().expect("JSON fixture");

        let log_response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{oversized}\r\n0\r\n\r\n",
            oversized.len()
        )
        .into_bytes();
        let (log_url, log_fixture) = one_shot_http_response(log_response);
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/jobs/7/logs"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{log_url}?secret=hidden")),
            )
            .mount(&api)
            .await;
        let log_adapter = adapter(&api.uri());
        let mut resolver = GitHubActionsResolver::new(
            &log_adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits {
                log_bytes: 64,
                log_total_bytes: 64,
                ..GitHubActionsResolutionLimits::default()
            },
        )
        .expect("log resolver");
        let error = resolver.job_log(7).await.expect_err("oversized log chunk");
        assert!(error.0.contains("signed log byte limit"));
        assert!(!error.0.contains("hidden"));
        assert_eq!(resolver.budget.log_bytes, 0);
        log_fixture.join().expect("log fixture");
    }

    #[tokio::test]
    async fn actions_truncated_log_stream_sanitizes_transport_error() {
        let (log_url, fixture) = one_shot_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\ndestination-body-secret"
                .to_vec(),
        );
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/jobs/7/logs"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{log_url}?location-query-secret")),
            )
            .mount(&api)
            .await;

        let adapter = adapter(&api.uri());
        let repository = repository();
        let credential = credential();
        let mut resolver = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        let error = resolver.job_log(7).await.expect_err("truncated log stream");
        assert!(error.0.contains("signed job-log stream"));
        assert!(!error.0.contains("location-query-secret"));
        assert!(!error.0.contains("destination-body-secret"));
        fixture.join().expect("truncated fixture");
    }

    #[tokio::test]
    async fn actions_job_lookup_paginates_and_sanitizes_permission_errors() {
        let server = MockServer::start().await;
        let endpoint = "/repos/org/repo/actions/runs/100/attempts/2/jobs";
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Link", format!("<{}{endpoint}?page=2>; rel=\"next\"", server.uri()))
                    .set_body_json(serde_json::json!({
                        "total_count": 2,
                        "jobs": [{
                            "id": 1,
                            "run_id": 100,
                            "head_sha": "head-sha",
                            "name": "first",
                            "conclusion": "success",
                            "check_run_url": format!("{}/repos/org/repo/check-runs/1", server.uri()),
                            "steps": []
                        }]
                    })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 2,
                "jobs": [{
                    "id": 2,
                    "run_id": 100,
                    "head_sha": "head-sha",
                    "name": "second",
                    "conclusion": "failure",
                    "check_run_url": format!("{}/repos/org/repo/check-runs/2", server.uri()),
                    "steps": []
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs/200/attempts/1/jobs"))
            .respond_with(ResponseTemplate::new(403).set_body_string("jobs-body-secret"))
            .mount(&server)
            .await;

        let adapter = adapter(&server.uri());
        let repository = repository();
        let credential = credential();
        let mut resolver = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        let jobs = resolver
            .workflow_jobs(&GitHubWorkflowRun {
                id: 100,
                check_suite_id: 9,
                head_sha: "head-sha".to_string(),
                run_attempt: 2,
                html_url: "https://github.example/actions/runs/100".to_string(),
            })
            .await
            .expect("paginated jobs");
        assert_eq!(jobs.iter().map(|job| job.id).collect::<Vec<_>>(), [1, 2]);

        let error = resolver
            .workflow_jobs(&GitHubWorkflowRun {
                id: 200,
                check_suite_id: 10,
                head_sha: "head-sha".to_string(),
                run_attempt: 1,
                html_url: "https://github.example/actions/runs/200".to_string(),
            })
            .await
            .expect_err("jobs permission error");
        assert!(error.0.contains("Actions: read"));
        assert!(error.0.contains("re-approve"));
        assert!(!error.0.contains("jobs-body-secret"));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn actions_run_lookup_rejects_incomplete_duplicate_and_mismatched_records() {
        let server = MockServer::start().await;
        let run = |id: u64, suite: u64, sha: &str| {
            serde_json::json!({
                "id": id,
                "check_suite_id": suite,
                "head_sha": sha,
                "run_attempt": 1,
                "html_url": format!("https://github.example/actions/runs/{id}")
            })
        };
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 2,
                "workflow_runs": [run(1, 1, "head-sha")]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 2,
                "workflow_runs": [run(2, 2, "head-sha"), run(2, 2, "head-sha")]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/actions/runs"))
            .and(query_param("check_suite_id", "3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "workflow_runs": [run(3, 999, "other-sha")]
            })))
            .mount(&server)
            .await;

        let adapter = adapter(&server.uri());
        let repository = repository();
        let credential = credential();
        let mut resolver = GitHubActionsResolver::new(
            &adapter,
            &repository,
            "head-sha",
            &credential,
            GitHubActionsResolutionLimits::default(),
        )
        .expect("resolver");
        assert!(
            resolver
                .workflow_run(1)
                .await
                .expect_err("incomplete")
                .0
                .contains("incomplete")
        );
        assert!(
            resolver
                .workflow_run(2)
                .await
                .expect_err("duplicate")
                .0
                .contains("duplicate")
        );
        assert!(
            resolver
                .workflow_run(3)
                .await
                .expect_err("mismatch")
                .0
                .contains("correlation")
        );
    }

    #[tokio::test]
    async fn dependency_uses_github_database_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/other/dep/issues/9"))
            .respond_with(ResponseTemplate::new(200).set_body_json(issue_json(9, 9009)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/org/repo/issues/3/dependencies/blocked_by"))
            .and(body_json(serde_json::json!({"issue_id": 9009})))
            .respond_with(ResponseTemplate::new(201).set_body_json(issue_json(9, 9009)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues/3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(issue_json(3, 3003)))
            .mount(&server)
            .await;
        let dependency_repo = RepositoryRef {
            owner: "other".to_string(),
            name: "dep".to_string(),
            ..repository()
        };

        let issue = adapter(&server.uri())
            .add_issue_dependency(&repository(), 3, &dependency_repo, 9, &credential())
            .await
            .expect("dependency");
        assert_eq!(issue.index, 3);
    }

    #[tokio::test]
    async fn issue_dependencies_remain_unmarked_for_github() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues/3/dependencies/blocked_by"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([issue_json(9, 9009)])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/issues/3/dependencies/blocking"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;

        let dependencies = adapter(&server.uri())
            .get_issue_dependencies(&repository(), 3, &credential())
            .await
            .expect("dependency read");

        assert_eq!(dependencies.depends_on[0].index, 9);
        assert_eq!(dependencies.depends_on_read_contract, None);
        assert_eq!(dependencies.opaque_depends_on_count, None);
        let json = serde_json::to_value(dependencies).expect("serialize dependencies");
        assert!(json.get("depends_on_read_contract").is_none());
        assert!(json.get("opaque_depends_on_count").is_none());
    }

    #[tokio::test]
    async fn auto_merge_uses_graphql_node_id_and_expected_head() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/pulls/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(pull_json(7)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_json(serde_json::json!({
                "query": "\nmutation EnableAutoMerge($input: EnablePullRequestAutoMergeInput!) {\n  enablePullRequestAutoMerge(input: $input) {\n    pullRequest { id }\n  }\n}",
                "variables": {"input": {
                    "expectedHeadOid": "head-sha",
                    "mergeMethod": "SQUASH",
                    "pullRequestId": "PR_node"
                }}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"enablePullRequestAutoMerge": {"pullRequest": {"id": "PR_node"}}}
            })))
            .mount(&server)
            .await;

        adapter(&server.uri())
            .schedule_auto_merge(&repository(), 7, "squash", "head-sha", None, &credential())
            .await
            .expect("auto merge");
    }

    #[test]
    fn verifies_and_parses_github_pull_request_webhook() {
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "synchronize",
            "number": 7,
            "pull_request": {
                "head": {"ref": "agent/fix", "sha": "new-head"},
                "html_url": "https://github.com/org/repo/pull/7",
                "number": 7,
                "title": "Fix"
            },
            "repository": {"name": "repo", "owner": {"login": "org"}}
        }))
        .expect("json");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").expect("hmac");
        mac.update(&body);
        let signature = mac.finalize().into_bytes();
        let signature = signature.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").expect("write to string");
            output
        });
        let headers = vec![
            ("x-github-event".to_string(), "pull_request".to_string()),
            ("x-github-delivery".to_string(), "delivery-1".to_string()),
            (
                "x-hub-signature-256".to_string(),
                format!("sha256={signature}"),
            ),
        ];

        let event = adapter("https://api.github.com")
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "github",
                domain::ForgeKind::GitHub,
                "https://github.com",
                "secret",
            )
            .expect("webhook")
            .expect("event");
        let domain::WebhookEvent::ChangeRequest(event) = event else {
            panic!("expected change request event");
        };
        assert_eq!(event.index, 7);
        assert_eq!(event.head_sha, "new-head");
        assert_eq!(event.action, domain::ChangeRequestEventAction::Synchronized);
    }
}
