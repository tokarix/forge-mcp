//! GitHub REST and GraphQL API adapter.

use async_trait::async_trait;
use base64::Engine;
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestReview,
    ChangeRequestState, ForgeCredential, ForgeUser, Mergeability, ReadRepositoryFileResponse,
    RepositoryMergeSettings, RepositoryRef,
};
use hmac::{Hmac, Mac};
use reqwest::{RequestBuilder, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::collections::HashSet;
use std::time::{Duration, Instant};

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
    client: reqwest::Client,
    config: GitHubConfig,
}

impl std::fmt::Debug for GitHubAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubAdapter")
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
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            config,
        })
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
        credential
            .token
            .clone()
            .or_else(|| self.config.token.clone())
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
            check_runs.extend(checks.check_runs);
            let next = validate_next_page(page, next_page_from_link_header(&headers)?)?;
            let Some(next) = next else {
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
    #[serde(default)]
    check_runs: Vec<GitHubCheckRun>,
}

#[derive(Debug, Deserialize)]
struct GitHubCheckRun {
    conclusion: Option<String>,
    details_url: Option<String>,
    name: String,
    status: String,
}

fn parse_status_state(state: &str) -> domain::CommitStatusState {
    match state {
        "action_required" | "cancelled" | "error" | "stale" | "timed_out" => {
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

#[async_trait]
impl crate::ForgeAdapter for GitHubAdapter {
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
        let repo = Self::repo_path(repository);
        let comments_url = format!("{}/repos/{repo}/issues/{index}/comments", self.api_base());
        let reviews_url = format!("{}/repos/{repo}/pulls/{index}/reviews", self.api_base());
        let comments = self
            .get_paginated::<GitHubComment>(&comments_url, &[], credential)
            .await?;
        let reviews = self
            .get_paginated::<GitHubReview>(&reviews_url, &[], credential)
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
            .chain(reviews.into_iter().filter_map(|review| {
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
            }))
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
        let mut statuses = self
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
        statuses.extend(checks.into_iter().map(|check| {
            let state = if check.status == "completed" {
                parse_status_state(check.conclusion.as_deref().unwrap_or("error"))
            } else {
                domain::CommitStatusState::Pending
            };
            domain::CommitStatus {
                context: check.name,
                description: check.conclusion.unwrap_or(check.status),
                state,
                target_url: check.details_url.unwrap_or_default(),
            }
        }));
        let state = aggregate_statuses(&statuses);
        let details = statuses
            .into_iter()
            .map(|status| domain::CiCheckDetail {
                context: status.context,
                description: status.description,
                state: status.state,
                target_url: status.target_url,
                resolution: domain::CiResolution::Unsupported,
            })
            .collect();
        Ok(domain::ChangeRequestCiDetails {
            head_sha: sha.to_string(),
            state,
            details,
        })
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
struct GitHubWebhookPullRequestPayload {
    action: String,
    number: u64,
    pull_request: GitHubWebhookPullRequest,
    repository: GitHubWebhookRepository,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookPullRequest {
    head: GitHubRef,
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
        _ => return Ok(None),
    };
    Ok(Some(domain::WebhookEvent::ChangeRequest(
        domain::ChangeRequestEvent {
            action,
            delivery_id,
            head_sha: payload.pull_request.head.sha,
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
    use std::fmt::Write as _;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::ForgeAdapter;

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
        assert!(
            details
                .details
                .iter()
                .any(|detail| detail.context == "status-late")
        );
        assert!(
            details
                .details
                .iter()
                .any(|detail| detail.context == "check-late")
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
