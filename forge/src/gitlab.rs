//! GitLab REST API v4 adapter.

use std::fmt::Write;

use async_trait::async_trait;
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestEvent,
    ChangeRequestEventAction, ChangeRequestReview, ChangeRequestState, ForgeCredential, ForgeUser,
    ReadRepositoryFileResponse, RepositoryMergeSettings, RepositoryRef,
};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::{ForgeError, ForgeWebhookAdapter, ForgeWebhookError};

#[derive(Clone)]
pub struct GitLabConfig {
    pub base_url: String,
    pub token: Option<String>,
}

impl std::fmt::Debug for GitLabConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitLabConfig")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct GitLabAdapter {
    client: reqwest::Client,
    config: GitLabConfig,
}

impl GitLabAdapter {
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(config: GitLabConfig) -> Result<Self, crate::ForgeError> {
        crate::install_ring_provider();

        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            config,
        })
    }

    /// Returns the API v4 base URL with trailing slash stripped.
    fn api_base(&self) -> String {
        format!("{}/api/v4", self.config.base_url.trim_end_matches('/'))
    }

    /// URL-encodes the full project path (`owner/repo` or
    /// `group/subgroup/repo`) for use in GitLab API URLs.
    fn project_path(repository: &RepositoryRef) -> String {
        let full_path = format!("{}/{}", repository.owner, repository.name);
        urlencoding::encode(&full_path).into_owned()
    }

    /// Adds authentication header to a request.  Uses `PRIVATE-TOKEN` for
    /// personal/project access tokens.
    fn authenticate(
        request: reqwest::RequestBuilder,
        token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        match token {
            Some(token) => request.header("PRIVATE-TOKEN", token),
            None => request,
        }
    }

    /// Returns the effective token: per-call credential first, then adapter
    /// default.
    fn effective_token<'a>(&'a self, credential: &'a ForgeCredential) -> Option<&'a str> {
        credential.token.as_deref().or(self.config.token.as_deref())
    }

    /// Checks the HTTP response status and returns a descriptive error for
    /// non-success codes.
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
                "upstream returned redirect",
            );
            return Err(ForgeError::Redirect { status, location });
        }

        let url = response.url().clone();
        let body = response.text().await.unwrap_or_default();

        if status == StatusCode::NOT_FOUND {
            let message = crate::parse_forge_error_message(&body)
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

    /// Lists project labels and returns the ID for a label matching `name`.
    async fn find_label_id(
        &self,
        repository: &RepositoryRef,
        name: &str,
        token: Option<&str>,
    ) -> Result<Option<u64>, ForgeError> {
        let url = format!(
            "{}/projects/{}/labels",
            self.api_base(),
            Self::project_path(repository),
        );
        let request = Self::authenticate(self.client.get(&url).query(&[("search", name)]), token);
        let response = Self::check_response(request.send().await?).await?;
        let labels: Vec<GitLabLabelResponse> = response.json().await?;
        Ok(labels.into_iter().find(|l| l.name == name).map(|l| l.id))
    }

    /// Finds a project label by name, creating it if it does not exist.
    async fn find_or_create_label(
        &self,
        repository: &RepositoryRef,
        name: &str,
        token: Option<&str>,
    ) -> Result<u64, ForgeError> {
        if let Some(id) = self.find_label_id(repository, name, token).await? {
            return Ok(id);
        }
        let url = format!(
            "{}/projects/{}/labels",
            self.api_base(),
            Self::project_path(repository),
        );
        let request = Self::authenticate(
            self.client.post(&url).json(&serde_json::json!({
                "color": "#0075ca",
                "name": name,
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let label: GitLabLabelResponse = response.json().await?;
        Ok(label.id)
    }

    /// Lists projects belonging to a GitLab group, with pagination.
    async fn list_gitlab_group_projects(
        &self,
        group_id: u64,
        query: Option<&str>,
        token: Option<&str>,
    ) -> Result<Vec<domain::Repository>, crate::ForgeError> {
        const PAGE_SIZE: usize = 100;
        let mut all_repos = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut url = format!(
                "{}/groups/{group_id}/projects?include_subgroups=true&with_shared=false&per_page={PAGE_SIZE}&page={page}",
                self.api_base(),
            );
            if let Some(q) = query {
                let _ = write!(url, "&search={}", urlencoding::encode(q));
            }
            let request = Self::authenticate(self.client.get(&url), token);
            let response = Self::check_response(request.send().await?).await?;
            let projects: Vec<GitLabProjectListEntry> = response.json().await?;
            let count = projects.len();
            all_repos.extend(
                projects
                    .into_iter()
                    .map(GitLabProjectListEntry::into_repository),
            );
            if count < PAGE_SIZE {
                break;
            }
            page += 1;
        }
        Ok(all_repos)
    }

    /// Lists projects belonging to a GitLab user, with pagination.
    async fn list_gitlab_user_projects(
        &self,
        encoded_user: &str,
        query: Option<&str>,
        token: Option<&str>,
    ) -> Result<Vec<domain::Repository>, crate::ForgeError> {
        const PAGE_SIZE: usize = 100;
        let mut all_repos = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut url = format!(
                "{}/users/{encoded_user}/projects?per_page={PAGE_SIZE}&page={page}",
                self.api_base(),
            );
            if let Some(q) = query {
                let _ = write!(url, "&search={}", urlencoding::encode(q));
            }
            let request = Self::authenticate(self.client.get(&url), token);
            let response = Self::check_response(request.send().await?).await?;
            let projects: Vec<GitLabProjectListEntry> = response.json().await?;
            let count = projects.len();
            all_repos.extend(
                projects
                    .into_iter()
                    .map(GitLabProjectListEntry::into_repository),
            );
            if count < PAGE_SIZE {
                break;
            }
            page += 1;
        }
        Ok(all_repos)
    }
}

// ---------------------------------------------------------------------------
// GitLab API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitLabUser {
    email: Option<String>,
    username: String,
}

#[derive(Debug, Deserialize)]
struct GitLabLabelResponse {
    id: u64,
    name: String,
}

#[derive(Debug, Deserialize)]
struct GitLabMergeRequest {
    #[serde(default)]
    changes_count: Option<String>,
    description: Option<String>,
    diff_refs: Option<GitLabDiffRefs>,
    iid: u64,
    sha: Option<String>,
    source_branch: String,
    state: String,
    target_branch: String,
    title: String,
    web_url: String,
}

#[derive(Debug, Deserialize)]
struct GitLabDiffRefs {
    base_sha: Option<String>,
    head_sha: Option<String>,
}

impl GitLabMergeRequest {
    fn into_change_request(self) -> ChangeRequest {
        let state = match self.state.as_str() {
            "opened" => ChangeRequestState::Open,
            "merged" => ChangeRequestState::Merged,
            _ => ChangeRequestState::Closed,
        };
        let head_sha = self
            .diff_refs
            .as_ref()
            .and_then(|d| d.head_sha.clone())
            .or(self.sha);
        let merge_base_sha = self.diff_refs.as_ref().and_then(|d| d.base_sha.clone());
        let changed_files_count = self
            .changes_count
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok());
        ChangeRequest {
            base_branch: self.target_branch,
            body: self.description.unwrap_or_default(),
            changed_files_count,
            commit_count: None,
            head_branch: self.source_branch,
            head_sha,
            index: self.iid,
            merge_base_sha,
            state,
            title: self.title,
            url: self.web_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitLabNote {
    author: GitLabNoteAuthor,
    body: String,
    created_at: String,
    id: u64,
    #[serde(default)]
    system: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabNoteAuthor {
    username: String,
}

#[derive(Debug, Deserialize)]
struct GitLabIssue {
    assignees: Option<Vec<GitLabNoteAuthor>>,
    description: Option<String>,
    iid: u64,
    labels: Option<Vec<String>>,
    state: String,
    title: String,
    web_url: String,
}

impl GitLabIssue {
    fn into_issue(self) -> domain::Issue {
        domain::Issue {
            assignees: self
                .assignees
                .unwrap_or_default()
                .into_iter()
                .map(|u| u.username)
                .collect(),
            body: self.description.unwrap_or_default(),
            index: self.iid,
            labels: self.labels.unwrap_or_default(),
            state: self.state,
            title: self.title,
            url: self.web_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitLabProjectResponse {
    merge_method: Option<String>,
    #[serde(default)]
    squash_option: Option<String>,
    remove_source_branch_after_merge: Option<bool>,
}

impl GitLabProjectResponse {
    fn allowed_merge_styles(&self) -> Vec<String> {
        // GitLab's merge_method can be: "merge", "rebase_merge", or "ff".
        // Squash is controlled separately via squash_option.
        let mut styles = Vec::new();
        match self.merge_method.as_deref() {
            Some("merge") => {
                styles.push("merge".to_string());
                styles.push("rebase_merge".to_string());
            }
            Some("rebase_merge") => {
                styles.push("rebase_merge".to_string());
            }
            Some("ff") => {
                styles.push("ff".to_string());
            }
            _ => {
                styles.push("merge".to_string());
            }
        }
        // Squash is available unless squash_option is "never".
        match self.squash_option.as_deref() {
            Some("never") => {}
            _ => styles.push("squash".to_string()),
        }
        styles
    }

    fn default_merge_style(&self) -> Option<String> {
        self.merge_method.clone()
    }

    fn into_repository_merge_settings(self) -> RepositoryMergeSettings {
        RepositoryMergeSettings {
            allowed_styles: self.allowed_merge_styles(),
            default_delete_branch_after_merge: self.remove_source_branch_after_merge,
            default_merge_style: self.default_merge_style(),
        }
    }
}

/// A project entry from GitLab's project listing endpoints.
#[derive(Debug, Deserialize)]
struct GitLabProjectListEntry {
    description: Option<String>,
    name: String,
    namespace: Option<GitLabNamespace>,
    path_with_namespace: String,
    web_url: String,
}

#[derive(Debug, Deserialize)]
struct GitLabNamespace {
    full_path: String,
}

/// GitLab group lookup response.
#[derive(Debug, Deserialize)]
struct GitLabGroupResponse {
    id: u64,
}

impl GitLabProjectListEntry {
    fn into_repository(self) -> domain::Repository {
        domain::Repository {
            description: self.description.unwrap_or_default(),
            full_name: self.path_with_namespace.clone(),
            name: self.name,
            owner: self.namespace.map(|n| n.full_path).unwrap_or_default(),
            url: self.web_url,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitLabFileResponse {
    content: String,
    encoding: String,
    file_path: String,
}

#[derive(Debug, Deserialize)]
struct GitLabBranchResponse {
    name: String,
    commit: GitLabBranchCommit,
}

#[derive(Debug, Deserialize)]
struct GitLabBranchCommit {
    id: String,
}

/// GitLab combined commit status response.
#[derive(Debug, Deserialize)]
struct GitLabCommitStatusResponse {
    description: Option<String>,
    name: String,
    status: String,
    target_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitLabApprovalResponse {
    approved_by: Option<Vec<GitLabApprover>>,
}

#[derive(Debug, Deserialize)]
struct GitLabApprover {
    user: GitLabNoteAuthor,
}

// ---------------------------------------------------------------------------
// ForgeAdapter implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl crate::ForgeAdapter for GitLabAdapter {
    async fn add_issue_dependency(
        &self,
        _repository: &RepositoryRef,
        _index: u64,
        _dependency: u64,
        _credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        Err(ForgeError::Unsupported(
            "issue dependencies are not supported on GitLab".to_string(),
        ))
    }

    async fn add_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let token = self.effective_token(credential);

        // Ensure the label exists on the project.
        self.find_or_create_label(repository, label, token).await?;

        // GitLab updates issue labels by sending the full label list.
        // First, get the current issue to read existing labels.
        let issue = self.get_issue(repository, index, credential).await?;
        let mut labels = issue.labels.clone();
        if !labels.contains(&label.to_string()) {
            labels.push(label.to_string());
        }

        let url = format!(
            "{}/projects/{}/issues/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let request = Self::authenticate(
            self.client.put(&url).json(&serde_json::json!({
                "labels": labels.join(","),
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let issue: GitLabIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_authenticated_user(
        &self,
        credential: &ForgeCredential,
    ) -> Result<ForgeUser, ForgeError> {
        let url = format!("{}/user", self.api_base());
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        let user: GitLabUser = response.json().await?;
        Ok(ForgeUser {
            email: user.email.unwrap_or_default(),
            username: user.username,
        })
    }

    async fn assign_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        assignee: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let token = self.effective_token(credential);

        // GitLab requires user IDs for assignment. Look up the user first.
        let user_url = format!("{}/users?username={}", self.api_base(), assignee);
        let user_request = Self::authenticate(self.client.get(&user_url), token);
        let user_response = Self::check_response(user_request.send().await?).await?;
        let users: Vec<GitLabUserIdResponse> = user_response.json().await?;
        let user_id = users
            .first()
            .map(|u| u.id)
            .ok_or_else(|| ForgeError::InvalidPayload(format!("user '{assignee}' not found")))?;

        let url = format!(
            "{}/projects/{}/issues/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let request = Self::authenticate(
            self.client.put(&url).json(&serde_json::json!({
                "assignee_ids": [user_id],
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let issue: GitLabIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn close_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ForgeError> {
        let url = format!(
            "{}/projects/{}/merge_requests/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client.put(&url).json(&serde_json::json!({
                "state_event": "close",
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let mr: GitLabMergeRequest = response.json().await?;
        Ok(mr.into_change_request())
    }

    async fn close_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/projects/{}/issues/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client.put(&url).json(&serde_json::json!({
                "state_event": "close",
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let issue: GitLabIssue = response.json().await?;
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
            "{}/projects/{}/issues/{}/notes",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client.post(&url).json(&serde_json::json!({
                "body": body,
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let note: GitLabNote = response.json().await?;
        Ok(domain::IssueComment {
            author: note.author.username,
            body: note.body,
            created_at: note.created_at,
            id: note.id,
        })
    }

    async fn comment_on_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
        body: &str,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ForgeError> {
        let url = format!(
            "{}/projects/{}/merge_requests/{}/notes",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client.post(&url).json(&serde_json::json!({
                "body": body,
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let note: GitLabNote = response.json().await?;
        Ok(ChangeRequestComment {
            body: note.body,
            id: note.id,
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
            "{}/projects/{}/merge_requests",
            self.api_base(),
            Self::project_path(repository),
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client.post(&url).json(&serde_json::json!({
                "description": body,
                "source_branch": head_branch,
                "target_branch": base_branch,
                "title": title,
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let mr: GitLabMergeRequest = response.json().await?;
        Ok(mr.into_change_request())
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
            "{}/projects/{}/statuses/{}",
            self.api_base(),
            Self::project_path(repository),
            sha,
        );
        // Map generic state names to GitLab's expected values.
        let gl_state = match state {
            "error" | "failure" | "warning" => "failed",
            other => other,
        };
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client.post(&url).json(&serde_json::json!({
                "context": context,
                "description": description,
                "name": context,
                "state": gl_state,
            })),
            token,
        );
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
            "{}/projects/{}/issues",
            self.api_base(),
            Self::project_path(repository),
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client.post(&url).json(&serde_json::json!({
                "description": body,
                "title": title,
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let issue: GitLabIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_allowed_merge_styles(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Vec<String>, ForgeError> {
        let project = self.get_project(repository, credential).await?;
        Ok(project.allowed_merge_styles())
    }

    async fn get_change_request_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
        let token = self.effective_token(credential);

        // Fetch merge request notes (comments).
        let notes_url = format!(
            "{}/projects/{}/merge_requests/{}/notes?sort=asc&order_by=created_at",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let notes_request = Self::authenticate(self.client.get(&notes_url), token);
        let notes_response = Self::check_response(notes_request.send().await?).await?;
        let notes: Vec<GitLabNote> = notes_response.json().await?;

        // Fetch approvals to map as reviews.
        let approvals_url = format!(
            "{}/projects/{}/merge_requests/{}/approvals",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let approvals_request = Self::authenticate(self.client.get(&approvals_url), token);
        let approvals_response = Self::check_response(approvals_request.send().await?).await?;
        let approvals: GitLabApprovalResponse = approvals_response.json().await?;

        let mut result: Vec<ChangeRequestCommentDetail> = Vec::new();

        // Add non-system notes as comments.
        for note in notes {
            if note.system {
                continue;
            }
            result.push(ChangeRequestCommentDetail {
                author: note.author.username,
                body: note.body,
                commit_id: None,
                created_at: note.created_at,
                id: note.id,
                kind: "comment".to_string(),
                review_state: None,
            });
        }

        // Add approvals as review entries.
        for approver in approvals.approved_by.unwrap_or_default() {
            result.push(ChangeRequestCommentDetail {
                author: approver.user.username,
                body: String::new(),
                commit_id: None,
                created_at: String::new(),
                id: 0,
                kind: "review".to_string(),
                review_state: Some("APPROVED".to_string()),
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
            "{}/projects/{}/merge_requests/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        let mr: GitLabMergeRequest = response.json().await?;
        Ok(mr.into_change_request())
    }

    async fn get_change_request_diff(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<String, ForgeError> {
        // GitLab provides a .diff endpoint for merge requests since v13.
        let url = format!(
            "{}/projects/{}/merge_requests/{}.diff",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        response
            .text()
            .await
            .map_err(|e| ForgeError::InvalidPayload(format!("failed to read diff body: {e}")))
    }

    async fn get_combined_commit_status(
        &self,
        repository: &RepositoryRef,
        sha: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::CombinedCommitStatus, ForgeError> {
        let url = format!(
            "{}/projects/{}/repository/commits/{}/statuses",
            self.api_base(),
            Self::project_path(repository),
            sha,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        let statuses: Vec<GitLabCommitStatusResponse> = response.json().await?;

        let domain_statuses: Vec<domain::CommitStatus> = statuses
            .iter()
            .map(|s| domain::CommitStatus {
                context: s.name.clone(),
                description: s.description.clone().unwrap_or_default(),
                state: parse_gitlab_status_state(&s.status),
                target_url: s.target_url.clone().unwrap_or_default(),
            })
            .collect();

        let total_count = domain_statuses.len() as u64;
        let aggregate_state = aggregate_status_states(&domain_statuses);

        Ok(domain::CombinedCommitStatus {
            head_sha: sha.to_string(),
            state: aggregate_state,
            statuses: domain_statuses,
            total_count,
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
        let details = combined
            .statuses
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
            state: combined.state,
            details,
        })
    }

    async fn get_default_merge_style(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<Option<String>, ForgeError> {
        let project = self.get_project(repository, credential).await?;
        Ok(project.default_merge_style())
    }

    async fn get_repository_merge_settings(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<RepositoryMergeSettings, ForgeError> {
        let project = self.get_project(repository, credential).await?;
        Ok(project.into_repository_merge_settings())
    }

    async fn get_issue(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let url = format!(
            "{}/projects/{}/issues/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        let issue: GitLabIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn get_issue_comments(
        &self,
        repository: &RepositoryRef,
        index: u64,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::IssueComment>, ForgeError> {
        let url = format!(
            "{}/projects/{}/issues/{}/notes?sort=asc&order_by=created_at",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        let notes: Vec<GitLabNote> = response.json().await?;
        Ok(notes
            .into_iter()
            .filter(|n| !n.system)
            .map(|n| domain::IssueComment {
                author: n.author.username,
                body: n.body,
                created_at: n.created_at,
                id: n.id,
            })
            .collect())
    }

    async fn get_issue_dependencies(
        &self,
        _repository: &RepositoryRef,
        _index: u64,
        _credential: &ForgeCredential,
    ) -> Result<domain::IssueDependencies, ForgeError> {
        Err(ForgeError::Unsupported(
            "issue dependencies are not supported on GitLab".to_string(),
        ))
    }

    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequest>, ForgeError> {
        let url = format!(
            "{}/projects/{}/merge_requests",
            self.api_base(),
            Self::project_path(repository),
        );
        let state_str = state.map(|s| match s {
            ChangeRequestState::Closed => "closed",
            ChangeRequestState::Merged => "merged",
            ChangeRequestState::Open => "opened",
        });
        let token = self.effective_token(credential);
        let mut request = Self::authenticate(self.client.get(&url), token);
        if let Some(state_str) = state_str {
            request = request.query(&[("state", state_str)]);
        }
        let response = Self::check_response(request.send().await?).await?;
        let mrs: Vec<GitLabMergeRequest> = response.json().await?;
        Ok(mrs
            .into_iter()
            .map(GitLabMergeRequest::into_change_request)
            .collect())
    }

    async fn list_issues(
        &self,
        repository: &RepositoryRef,
        state: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Issue>, ForgeError> {
        let mut url = format!(
            "{}/projects/{}/issues",
            self.api_base(),
            Self::project_path(repository),
        );
        if let Some(state) = state {
            // GitLab uses "opened" instead of "open".
            let gl_state = if state == "open" { "opened" } else { state };
            let _ = write!(url, "?state={gl_state}");
        }
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        let issues: Vec<GitLabIssue> = response.json().await?;
        Ok(issues.into_iter().map(GitLabIssue::into_issue).collect())
    }

    async fn list_repositories(
        &self,
        owner: Option<&str>,
        query: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<Vec<domain::Repository>, ForgeError> {
        const PAGE_SIZE: usize = 100;
        let token = self.effective_token(credential);

        if let Some(owner_name) = owner {
            // Try group first, fall back to user only on 404.
            let encoded = urlencoding::encode(owner_name);
            let group_url = format!("{}/groups/{encoded}", self.api_base());
            let group_req = Self::authenticate(self.client.get(&group_url), token);
            let group_resp = group_req.send().await?;

            let status = group_resp.status();
            if status.is_success() {
                let group: GitLabGroupResponse = group_resp.json().await?;
                return self
                    .list_gitlab_group_projects(group.id, query, token)
                    .await;
            } else if status == StatusCode::NOT_FOUND {
                // Not a group — try user projects.
                let encoded_user = urlencoding::encode(owner_name);
                return self
                    .list_gitlab_user_projects(&encoded_user, query, token)
                    .await;
            }
            // Surface permission errors and server failures instead of
            // silently falling back to the user endpoint.
            Self::check_response(group_resp).await?;
            return Err(ForgeError::InvalidPayload(format!(
                "unexpected success response for group '{owner_name}'"
            )));
        }

        // No owner filter — list all accessible projects.
        let mut all_repos = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut url = format!(
                "{}/projects?membership=true&per_page={PAGE_SIZE}&page={page}",
                self.api_base(),
            );
            if let Some(q) = query {
                let _ = write!(url, "&search={}", urlencoding::encode(q));
            }
            let request = Self::authenticate(self.client.get(&url), token);
            let response = Self::check_response(request.send().await?).await?;
            let projects: Vec<GitLabProjectListEntry> = response.json().await?;
            let count = projects.len();
            all_repos.extend(
                projects
                    .into_iter()
                    .map(GitLabProjectListEntry::into_repository),
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
        _repository: &RepositoryRef,
        _index: u64,
        _dependency: u64,
        _credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        Err(ForgeError::Unsupported(
            "issue dependencies are not supported on GitLab".to_string(),
        ))
    }

    async fn remove_issue_label(
        &self,
        repository: &RepositoryRef,
        index: u64,
        label: &str,
        credential: &ForgeCredential,
    ) -> Result<domain::Issue, ForgeError> {
        let token = self.effective_token(credential);

        // Get current issue labels and remove the target.
        let issue = self.get_issue(repository, index, credential).await?;
        let labels: Vec<&str> = issue
            .labels
            .iter()
            .map(String::as_str)
            .filter(|l| *l != label)
            .collect();

        let url = format!(
            "{}/projects/{}/issues/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let request = Self::authenticate(
            self.client.put(&url).json(&serde_json::json!({
                "labels": labels.join(","),
            })),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let issue: GitLabIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn schedule_auto_merge(
        &self,
        repository: &RepositoryRef,
        index: u64,
        merge_style: &str,
        _head_commit_id: &str,
        delete_branch_after_merge: Option<bool>,
        credential: &ForgeCredential,
    ) -> Result<(), ForgeError> {
        // GitLab uses "merge when pipeline succeeds" via the merge API with
        // merge_when_pipeline_succeeds=true.
        let url = format!(
            "{}/projects/{}/merge_requests/{}/merge",
            self.api_base(),
            Self::project_path(repository),
            index,
        );
        let token = self.effective_token(credential);
        let mut body = serde_json::Map::new();
        body.insert(
            "merge_when_pipeline_succeeds".to_string(),
            serde_json::json!(true),
        );
        // Map merge styles to GitLab's expected format.
        if merge_style == "squash" {
            body.insert("squash".to_string(), serde_json::json!(true));
        }
        if let Some(delete) = delete_branch_after_merge {
            body.insert(
                "should_remove_source_branch".to_string(),
                serde_json::json!(delete),
            );
        }
        let request = Self::authenticate(self.client.put(&url).json(&body), token);
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            // GitLab returns 405 Method Not Allowed when MR is already set
            // to auto-merge or is not mergeable.
            if status == StatusCode::METHOD_NOT_ALLOWED
                && body.contains("already scheduled to be merged")
            {
                return Ok(());
            }
            if status == StatusCode::NOT_FOUND {
                let message = crate::parse_forge_error_message(&body)
                    .unwrap_or_else(|| "repository or resource not found".to_string());
                return Err(ForgeError::NotFound { status, message });
            }
            return Err(ForgeError::UnexpectedStatus { status, body });
        }
        Ok(())
    }

    async fn read_repository_file(
        &self,
        repository: &RepositoryRef,
        path: &str,
        git_ref: Option<&str>,
        credential: &ForgeCredential,
    ) -> Result<ReadRepositoryFileResponse, ForgeError> {
        let encoded_path = urlencoding::encode(path.trim_start_matches('/'));
        let url = format!(
            "{}/projects/{}/repository/files/{}",
            self.api_base(),
            Self::project_path(repository),
            encoded_path,
        );
        let token = self.effective_token(credential);
        let mut request = Self::authenticate(self.client.get(&url), token);
        if let Some(reference) = git_ref {
            request = request.query(&[("ref", reference)]);
        } else {
            // GitLab requires a ref parameter for the files API.
            request = request.query(&[("ref", "HEAD")]);
        }
        let response = Self::check_response(request.send().await?).await?;
        let payload: GitLabFileResponse = response.json().await?;

        if payload.encoding != "base64" {
            return Err(ForgeError::InvalidPayload(format!(
                "unsupported content encoding: {}",
                payload.encoding,
            )));
        }

        let cleaned = payload.content.replace('\n', "");
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, cleaned)
            .map_err(|e| ForgeError::InvalidPayload(format!("base64 decode failed: {e}")))?;
        let content = String::from_utf8(bytes)
            .map_err(|e| ForgeError::InvalidPayload(format!("utf8 decode failed: {e}")))?;

        Ok(ReadRepositoryFileResponse {
            repository: repository.clone(),
            path: payload.file_path,
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
        let token = self.effective_token(credential);

        // Map review events to GitLab actions:
        // - APPROVED  -> POST /approve
        // - REQUEST_CHANGES -> POST note (GitLab has no native "request changes")
        // - COMMENT -> POST note
        if event.eq_ignore_ascii_case("APPROVED") {
            let url = format!(
                "{}/projects/{}/merge_requests/{}/approve",
                self.api_base(),
                Self::project_path(repository),
                index,
            );
            let request = Self::authenticate(self.client.post(&url), token);
            let response = Self::check_response(request.send().await?).await?;
            let approval: serde_json::Value = response.json().await?;
            let id = approval
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);

            // Post the review body as a comment if non-empty.
            if !body.is_empty() {
                let _ = self
                    .comment_on_change_request(repository, index, body, credential)
                    .await;
            }

            Ok(ChangeRequestReview {
                body: body.to_string(),
                event: "APPROVED".to_string(),
                id,
                index,
            })
        } else {
            // REQUEST_CHANGES and COMMENT: post as a note.
            let comment = self
                .comment_on_change_request(repository, index, body, credential)
                .await?;
            Ok(ChangeRequestReview {
                body: comment.body,
                event: event.to_string(),
                id: comment.id,
                index,
            })
        }
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
            "{}/projects/{}/merge_requests/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
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
                "description".to_string(),
                serde_json::Value::String(body.to_string()),
            );
        }
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client
                .put(&url)
                .json(&serde_json::Value::Object(json_body)),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let mr: GitLabMergeRequest = response.json().await?;
        Ok(mr.into_change_request())
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
            "{}/projects/{}/issues/{}",
            self.api_base(),
            Self::project_path(repository),
            index,
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
                "description".to_string(),
                serde_json::Value::String(body.to_string()),
            );
        }
        let token = self.effective_token(credential);
        let request = Self::authenticate(
            self.client
                .put(&url)
                .json(&serde_json::Value::Object(json_body)),
            token,
        );
        let response = Self::check_response(request.send().await?).await?;
        let issue: GitLabIssue = response.json().await?;
        Ok(issue.into_issue())
    }

    async fn list_branches(
        &self,
        repository: &RepositoryRef,
        prefix: Option<&str>,
        limit: Option<u32>,
        credential: &ForgeCredential,
    ) -> Result<(Vec<domain::Branch>, bool), ForgeError> {
        const PAGE_SIZE: u32 = 100;
        const MAX_PAGES: u32 = 5;
        let token = self.effective_token(credential);
        let target_limit = limit.unwrap_or(20).min(100) as usize;
        let mut all_branches = Vec::new();
        let mut page: u32 = 1;
        let mut truncated = false;

        loop {
            if page > MAX_PAGES {
                truncated = true;
                break;
            }
            let mut url = format!(
                "{}/projects/{}/repository/branches?page={page}&per_page={PAGE_SIZE}",
                self.api_base(),
                Self::project_path(repository),
            );
            if let Some(p) = prefix {
                url.push_str("&search=");
                url.push_str(&urlencoding::encode(p));
            }
            let request = Self::authenticate(self.client.get(&url), token);
            let response = Self::check_response(request.send().await?).await?;
            let page_branches: Vec<GitLabBranchResponse> = response.json().await?;
            let page_count = page_branches.len();

            for b in page_branches {
                if prefix.is_some_and(|p| !b.name.starts_with(p)) {
                    continue;
                }
                all_branches.push(domain::Branch {
                    name: b.name,
                    commit_sha: b.commit.id,
                });
                if all_branches.len() >= target_limit {
                    break;
                }
            }
            if all_branches.len() >= target_limit {
                break;
            }
            if page_count < PAGE_SIZE as usize {
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
            "{}/projects/{}/repository/branches/{}",
            self.api_base(),
            Self::project_path(repository),
            encoded,
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = request.send().await?;
        let status = response.status();

        if status == StatusCode::NOT_FOUND {
            let body = response.text().await.unwrap_or_default();
            let msg = crate::parse_forge_error_message(&body);

            if let Some(ref m) = msg {
                let msg_lower = m.to_lowercase();
                // Fast path: explicit branch-missing messages
                if msg_lower.contains("branch not found")
                    || msg_lower.contains("no such branch")
                    || msg_lower.contains("branch does not exist")
                {
                    return Ok((branch.to_string(), None, false));
                }

                // Ambiguous 404 — verify project exists to distinguish
                // between missing branch and missing project.
                if msg_lower.contains("the target couldn't be found") {
                    match self.get_project(repository, credential).await {
                        Ok(_) => return Ok((branch.to_string(), None, false)),
                        Err(e) => return Err(e),
                    }
                }
            } else {
                // Empty body — also verify project exists.
                match self.get_project(repository, credential).await {
                    Ok(_) => return Ok((branch.to_string(), None, false)),
                    Err(e) => return Err(e),
                }
            }

            return Err(ForgeError::NotFound {
                status,
                message: msg.unwrap_or_else(|| "repository or resource not found".to_string()),
            });
        }
        let response = Self::check_response(response).await?;
        let branch_resp: GitLabBranchResponse = response.json().await?;

        Ok((branch_resp.name, Some(branch_resp.commit.id), true))
    }
}

// ---------------------------------------------------------------------------
// Helper: project info
// ---------------------------------------------------------------------------

impl GitLabAdapter {
    async fn get_project(
        &self,
        repository: &RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<GitLabProjectResponse, ForgeError> {
        let url = format!(
            "{}/projects/{}",
            self.api_base(),
            Self::project_path(repository),
        );
        let token = self.effective_token(credential);
        let request = Self::authenticate(self.client.get(&url), token);
        let response = Self::check_response(request.send().await?).await?;
        response
            .json()
            .await
            .map_err(|e| ForgeError::InvalidPayload(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// GitLab user ID lookup helper
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitLabUserIdResponse {
    id: u64,
}

// ---------------------------------------------------------------------------
// Webhook adapter
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum GitLabWebhookEventType {
    IssueHook,
    MergeRequestHook,
    NoteHook,
    Unknown(String),
}

impl GitLabWebhookEventType {
    fn parse(value: &str) -> Self {
        match value {
            "Issue Hook" => Self::IssueHook,
            "Merge Request Hook" => Self::MergeRequestHook,
            "Note Hook" => Self::NoteHook,
            _ => Self::Unknown(value.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookProject {
    name: String,
    namespace: String,
    path_with_namespace: String,
}

impl GitLabWebhookProject {
    /// Extracts the owner (namespace) and repo name from the full path.
    fn owner_and_name(&self) -> (String, String) {
        match self.path_with_namespace.rsplit_once('/') {
            Some((namespace, name)) => (namespace.to_string(), name.to_string()),
            None => (self.namespace.clone(), self.name.clone()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookMergeRequestEvent {
    object_attributes: GitLabWebhookMergeRequestAttrs,
    project: GitLabWebhookProject,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookMergeRequestAttrs {
    action: Option<String>,
    iid: u64,
    last_commit: Option<GitLabWebhookCommit>,
    title: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookCommit {
    id: String,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookIssueEvent {
    object_attributes: GitLabWebhookIssueAttrs,
    project: GitLabWebhookProject,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookIssueAttrs {
    action: Option<String>,
    iid: u64,
    title: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookNoteEvent {
    issue: Option<GitLabWebhookNoteIssue>,
    merge_request: Option<GitLabWebhookNoteMergeRequest>,
    object_attributes: GitLabWebhookNoteAttrs,
    project: GitLabWebhookProject,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookNoteAttrs {
    id: u64,
    note: String,
    noteable_type: String,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookNoteIssue {
    iid: u64,
}

#[derive(Debug, Deserialize)]
struct GitLabWebhookNoteMergeRequest {
    iid: u64,
    last_commit: Option<GitLabWebhookCommit>,
    title: String,
    url: String,
}

impl ForgeWebhookAdapter for GitLabAdapter {
    fn verify_and_parse_webhook_event(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        forge_alias: &str,
        forge_kind: domain::ForgeKind,
        host: &str,
        secret: &str,
    ) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
        // GitLab uses a simple secret token comparison, not HMAC.
        verify_gitlab_token(headers, secret)?;

        let event_header = header_value(headers, &["x-gitlab-event"])
            .ok_or_else(|| ForgeWebhookError::MissingHeader("X-Gitlab-Event".to_string()))?;
        let event_type = GitLabWebhookEventType::parse(event_header);

        let delivery_id = header_value(headers, &["x-gitlab-event-uuid"])
            .unwrap_or_default()
            .to_string();

        match event_type {
            GitLabWebhookEventType::MergeRequestHook => {
                parse_gitlab_merge_request_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            GitLabWebhookEventType::IssueHook => {
                parse_gitlab_issue_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            GitLabWebhookEventType::NoteHook => {
                parse_gitlab_note_event(body, delivery_id, forge_alias, forge_kind, host)
            }
            GitLabWebhookEventType::Unknown(name) => {
                tracing::debug!(event_type = %name, "ignoring unhandled GitLab webhook event type");
                Ok(None)
            }
        }
    }
}

fn parse_gitlab_merge_request_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: GitLabWebhookMergeRequestEvent = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.object_attributes.action.as_deref() {
        Some("open") => ChangeRequestEventAction::Opened,
        Some("reopen") => ChangeRequestEventAction::Reopened,
        Some("update") => ChangeRequestEventAction::Synchronized,
        _ => return Ok(None),
    };

    let (owner, name) = payload.project.owner_and_name();
    let head_sha = payload
        .object_attributes
        .last_commit
        .map(|c| c.id)
        .unwrap_or_default();

    Ok(Some(domain::WebhookEvent::ChangeRequest(
        ChangeRequestEvent {
            action,
            delivery_id,
            head_sha,
            index: payload.object_attributes.iid,
            repository: RepositoryRef {
                alias: forge_alias.to_string(),
                forge: forge_kind,
                host: host.to_string(),
                name,
                owner,
            },
            title: payload.object_attributes.title,
            url: payload.object_attributes.url,
        },
    )))
}

fn parse_gitlab_issue_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: GitLabWebhookIssueEvent = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let action = match payload.object_attributes.action.as_deref() {
        Some("open") => domain::IssueEventAction::Opened,
        Some("close") => domain::IssueEventAction::Closed,
        _ => return Ok(None),
    };

    let (owner, name) = payload.project.owner_and_name();

    Ok(Some(domain::WebhookEvent::Issue(domain::IssueEvent {
        action,
        delivery_id,
        index: payload.object_attributes.iid,
        repository: RepositoryRef {
            alias: forge_alias.to_string(),
            forge: forge_kind,
            host: host.to_string(),
            name,
            owner,
        },
        title: payload.object_attributes.title,
        url: payload.object_attributes.url,
    })))
}

fn parse_gitlab_note_event(
    body: &[u8],
    delivery_id: String,
    forge_alias: &str,
    forge_kind: domain::ForgeKind,
    host: &str,
) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
    let payload: GitLabWebhookNoteEvent = serde_json::from_slice(body)
        .map_err(|e| ForgeWebhookError::InvalidPayload(e.to_string()))?;

    let (owner, name) = payload.project.owner_and_name();

    match payload.object_attributes.noteable_type.as_str() {
        "Issue" => {
            let issue = payload.issue.ok_or_else(|| {
                ForgeWebhookError::InvalidPayload("issue field missing in note event".to_string())
            })?;
            Ok(Some(domain::WebhookEvent::IssueComment(
                domain::IssueCommentEvent {
                    action: domain::IssueCommentEventAction::Created,
                    body: payload.object_attributes.note,
                    comment_id: payload.object_attributes.id,
                    delivery_id,
                    issue_index: issue.iid,
                    repository: RepositoryRef {
                        alias: forge_alias.to_string(),
                        forge: forge_kind,
                        host: host.to_string(),
                        name,
                        owner,
                    },
                },
            )))
        }
        "MergeRequest" => {
            let mr = payload.merge_request.ok_or_else(|| {
                ForgeWebhookError::InvalidPayload(
                    "merge_request field missing in note event".to_string(),
                )
            })?;
            let head_sha = mr.last_commit.map(|c| c.id).unwrap_or_default();
            // Treat MR notes as review comments.
            Ok(Some(domain::WebhookEvent::PullRequestReview(
                domain::PullRequestReviewEvent {
                    action: domain::PullRequestReviewEventAction::Submitted,
                    delivery_id,
                    head_sha,
                    index: mr.iid,
                    repository: RepositoryRef {
                        alias: forge_alias.to_string(),
                        forge: forge_kind,
                        host: host.to_string(),
                        name,
                        owner,
                    },
                    review_body: payload.object_attributes.note,
                    review_id: payload.object_attributes.id,
                    review_state: domain::ReviewState::Comment,
                    title: mr.title,
                    url: mr.url,
                },
            )))
        }
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn header_value<'a>(headers: &'a [(String, String)], names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn verify_gitlab_token(
    headers: &[(String, String)],
    secret: &str,
) -> Result<(), ForgeWebhookError> {
    let token = header_value(headers, &["x-gitlab-token"])
        .ok_or_else(|| ForgeWebhookError::MissingHeader("X-Gitlab-Token".to_string()))?;
    if token != secret {
        return Err(ForgeWebhookError::InvalidSignature);
    }
    Ok(())
}

fn parse_gitlab_status_state(s: &str) -> domain::CommitStatusState {
    match s {
        "failed" => domain::CommitStatusState::Failure,
        "success" => domain::CommitStatusState::Success,
        "canceled" | "skipped" => domain::CommitStatusState::Error,
        _ => domain::CommitStatusState::Pending,
    }
}

/// Aggregate individual status states into one combined state.
fn aggregate_status_states(statuses: &[domain::CommitStatus]) -> domain::CommitStatusState {
    if statuses.is_empty() {
        return domain::CommitStatusState::Pending;
    }
    let mut has_pending = false;
    for s in statuses {
        match s.state {
            domain::CommitStatusState::Failure | domain::CommitStatusState::Error => {
                return domain::CommitStatusState::Failure;
            }
            domain::CommitStatusState::Pending => has_pending = true,
            _ => {}
        }
    }
    if has_pending {
        domain::CommitStatusState::Pending
    } else {
        domain::CommitStatusState::Success
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use crate::ForgeAdapter;
    use domain::ForgeCredential;
    use wiremock::matchers::{header, method, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_adapter(base_url: &str) -> GitLabAdapter {
        GitLabAdapter::new(GitLabConfig {
            base_url: base_url.to_string(),
            token: Some("test-token".to_string()),
        })
        .expect("build gitlab adapter")
    }

    fn test_repo() -> RepositoryRef {
        RepositoryRef {
            alias: "gl".to_string(),
            forge: domain::ForgeKind::GitLab,
            host: "https://gitlab.example".to_string(),
            name: "repo".to_string(),
            owner: "group/subgroup".to_string(),
        }
    }

    #[test]
    fn project_path_encodes_nested_namespace() {
        let repo = test_repo();
        let path = GitLabAdapter::project_path(&repo);
        assert_eq!(path, "group%2Fsubgroup%2Frepo");
    }

    #[test]
    fn project_path_encodes_simple_namespace() {
        let repo = RepositoryRef {
            alias: "gl".to_string(),
            forge: domain::ForgeKind::GitLab,
            host: "https://gitlab.example".to_string(),
            name: "repo".to_string(),
            owner: "org".to_string(),
        };
        let path = GitLabAdapter::project_path(&repo);
        assert_eq!(path, "org%2Frepo");
    }

    #[test]
    fn merge_request_state_mapping() {
        let mr = GitLabMergeRequest {
            changes_count: None,
            description: Some("body".to_string()),
            diff_refs: None,
            iid: 1,
            sha: Some("abc123".to_string()),
            source_branch: "feature".to_string(),
            state: "opened".to_string(),
            target_branch: "main".to_string(),
            title: "Test MR".to_string(),
            web_url: "https://gitlab.example/mr/1".to_string(),
        };
        let cr = mr.into_change_request();
        assert_eq!(cr.state, ChangeRequestState::Open);
        assert_eq!(cr.head_sha.as_deref(), Some("abc123"));
    }

    #[test]
    fn merge_request_merged_state() {
        let mr = GitLabMergeRequest {
            changes_count: Some("3".to_string()),
            description: None,
            diff_refs: None,
            iid: 2,
            sha: None,
            source_branch: "feature".to_string(),
            state: "merged".to_string(),
            target_branch: "main".to_string(),
            title: "Merged MR".to_string(),
            web_url: "https://gitlab.example/mr/2".to_string(),
        };
        let cr = mr.into_change_request();
        assert_eq!(cr.state, ChangeRequestState::Merged);
        assert_eq!(cr.changed_files_count, Some(3));
    }

    #[test]
    fn issue_conversion() {
        let issue = GitLabIssue {
            assignees: Some(vec![GitLabNoteAuthor {
                username: "alice".to_string(),
            }]),
            description: Some("Issue body".to_string()),
            iid: 42,
            labels: Some(vec!["bug".to_string(), "urgent".to_string()]),
            state: "opened".to_string(),
            title: "Test issue".to_string(),
            web_url: "https://gitlab.example/issues/42".to_string(),
        };
        let i = issue.into_issue();
        assert_eq!(i.index, 42);
        assert_eq!(i.assignees, vec!["alice"]);
        assert_eq!(i.labels, vec!["bug", "urgent"]);
    }

    #[test]
    fn webhook_token_verification_succeeds() {
        let headers = vec![("x-gitlab-token".to_string(), "my-secret".to_string())];
        assert!(verify_gitlab_token(&headers, "my-secret").is_ok());
    }

    #[test]
    fn webhook_token_verification_fails() {
        let headers = vec![("x-gitlab-token".to_string(), "wrong".to_string())];
        assert!(verify_gitlab_token(&headers, "my-secret").is_err());
    }

    #[test]
    fn webhook_token_missing() {
        let headers: Vec<(String, String)> = vec![];
        let err =
            verify_gitlab_token(&headers, "secret").expect_err("should fail with missing header");
        matches!(err, ForgeWebhookError::MissingHeader(_));
    }

    #[test]
    fn webhook_merge_request_event() {
        let payload = serde_json::json!({
            "object_attributes": {
                "action": "open",
                "iid": 5,
                "last_commit": {"id": "abc123"},
                "source_branch": "feature",
                "target_branch": "main",
                "title": "New feature",
                "url": "https://gitlab.example/mr/5"
            },
            "project": {
                "name": "repo",
                "namespace": "group",
                "path_with_namespace": "group/subgroup/repo"
            }
        });
        let body = serde_json::to_vec(&payload).expect("serialize json");
        let result = parse_gitlab_merge_request_event(
            &body,
            "delivery-1".to_string(),
            "gl",
            domain::ForgeKind::GitLab,
            "https://gitlab.example",
        )
        .expect("parse merge request event");
        let event = result.expect("should produce an event");
        match event {
            domain::WebhookEvent::ChangeRequest(cr) => {
                assert_eq!(cr.index, 5);
                assert_eq!(cr.head_sha, "abc123");
                assert_eq!(cr.repository.owner, "group/subgroup");
                assert_eq!(cr.repository.name, "repo");
            }
            _ => panic!("expected ChangeRequest event"),
        }
    }

    #[test]
    fn webhook_issue_event() {
        let payload = serde_json::json!({
            "object_attributes": {
                "action": "open",
                "iid": 10,
                "title": "Bug report",
                "url": "https://gitlab.example/issues/10"
            },
            "project": {
                "name": "repo",
                "namespace": "org",
                "path_with_namespace": "org/repo"
            }
        });
        let body = serde_json::to_vec(&payload).expect("serialize json");
        let result = parse_gitlab_issue_event(
            &body,
            "delivery-2".to_string(),
            "gl",
            domain::ForgeKind::GitLab,
            "https://gitlab.example",
        )
        .expect("parse issue event");
        let event = result.expect("should produce an event");
        match event {
            domain::WebhookEvent::Issue(ie) => {
                assert_eq!(ie.index, 10);
                assert_eq!(ie.repository.owner, "org");
                assert_eq!(ie.repository.name, "repo");
            }
            _ => panic!("expected Issue event"),
        }
    }

    #[test]
    fn webhook_note_on_issue_event() {
        let payload = serde_json::json!({
            "object_attributes": {
                "id": 100,
                "note": "A comment",
                "noteable_type": "Issue"
            },
            "issue": {"iid": 7},
            "project": {
                "name": "repo",
                "namespace": "org",
                "path_with_namespace": "org/repo"
            }
        });
        let body = serde_json::to_vec(&payload).expect("serialize json");
        let result = parse_gitlab_note_event(
            &body,
            "delivery-3".to_string(),
            "gl",
            domain::ForgeKind::GitLab,
            "https://gitlab.example",
        )
        .expect("parse note event");
        let event = result.expect("should produce an event");
        match event {
            domain::WebhookEvent::IssueComment(ic) => {
                assert_eq!(ic.issue_index, 7);
                assert_eq!(ic.comment_id, 100);
                assert_eq!(ic.body, "A comment");
            }
            _ => panic!("expected IssueComment event"),
        }
    }

    #[test]
    fn webhook_note_on_merge_request_event() {
        let payload = serde_json::json!({
            "object_attributes": {
                "id": 200,
                "note": "Review comment",
                "noteable_type": "MergeRequest"
            },
            "merge_request": {
                "iid": 3,
                "last_commit": {"id": "def456"},
                "title": "Feature MR",
                "url": "https://gitlab.example/mr/3"
            },
            "project": {
                "name": "repo",
                "namespace": "org",
                "path_with_namespace": "org/repo"
            }
        });
        let body = serde_json::to_vec(&payload).expect("serialize json");
        let result = parse_gitlab_note_event(
            &body,
            "delivery-4".to_string(),
            "gl",
            domain::ForgeKind::GitLab,
            "https://gitlab.example",
        )
        .expect("parse note event");
        let event = result.expect("should produce an event");
        match event {
            domain::WebhookEvent::PullRequestReview(pr) => {
                assert_eq!(pr.index, 3);
                assert_eq!(pr.review_body, "Review comment");
                assert_eq!(pr.head_sha, "def456");
            }
            _ => panic!("expected PullRequestReview event"),
        }
    }

    #[test]
    fn project_merge_styles_merge_method() {
        let project = GitLabProjectResponse {
            merge_method: Some("merge".to_string()),
            squash_option: Some("default_off".to_string()),
            remove_source_branch_after_merge: Some(true),
        };
        let styles = project.allowed_merge_styles();
        assert!(styles.contains(&"merge".to_string()));
        assert!(styles.contains(&"rebase_merge".to_string()));
        assert!(styles.contains(&"squash".to_string()));
    }

    #[test]
    fn project_merge_styles_ff_no_squash() {
        let project = GitLabProjectResponse {
            merge_method: Some("ff".to_string()),
            squash_option: Some("never".to_string()),
            remove_source_branch_after_merge: None,
        };
        let styles = project.allowed_merge_styles();
        assert_eq!(styles, vec!["ff"]);
    }

    #[test]
    fn aggregate_status_all_success() {
        let statuses = vec![
            domain::CommitStatus {
                context: "ci".to_string(),
                description: String::new(),
                state: domain::CommitStatusState::Success,
                target_url: String::new(),
            },
            domain::CommitStatus {
                context: "lint".to_string(),
                description: String::new(),
                state: domain::CommitStatusState::Success,
                target_url: String::new(),
            },
        ];
        assert_eq!(
            aggregate_status_states(&statuses),
            domain::CommitStatusState::Success
        );
    }

    #[test]
    fn aggregate_status_with_failure() {
        let statuses = vec![
            domain::CommitStatus {
                context: "ci".to_string(),
                description: String::new(),
                state: domain::CommitStatusState::Success,
                target_url: String::new(),
            },
            domain::CommitStatus {
                context: "lint".to_string(),
                description: String::new(),
                state: domain::CommitStatusState::Failure,
                target_url: String::new(),
            },
        ];
        assert_eq!(
            aggregate_status_states(&statuses),
            domain::CommitStatusState::Failure
        );
    }

    #[test]
    fn aggregate_status_empty() {
        let statuses: Vec<domain::CommitStatus> = vec![];
        assert_eq!(
            aggregate_status_states(&statuses),
            domain::CommitStatusState::Pending
        );
    }

    #[test]
    fn gitlab_status_state_mapping() {
        assert_eq!(
            parse_gitlab_status_state("success"),
            domain::CommitStatusState::Success
        );
        assert_eq!(
            parse_gitlab_status_state("failed"),
            domain::CommitStatusState::Failure
        );
        assert_eq!(
            parse_gitlab_status_state("pending"),
            domain::CommitStatusState::Pending
        );
        assert_eq!(
            parse_gitlab_status_state("running"),
            domain::CommitStatusState::Pending
        );
        assert_eq!(
            parse_gitlab_status_state("canceled"),
            domain::CommitStatusState::Error
        );
    }

    #[tokio::test]
    async fn get_issue_sends_correct_request() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v4/projects/.+/issues/\d+"))
            .and(header("PRIVATE-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "assignees": [],
                "description": "Issue description",
                "iid": 1,
                "labels": ["bug"],
                "state": "opened",
                "title": "Test issue",
                "web_url": "https://gitlab.example/issues/1"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let issue = adapter
            .get_issue(&test_repo(), 1, &cred)
            .await
            .expect("get issue");
        assert_eq!(issue.index, 1);
        assert_eq!(issue.title, "Test issue");
        assert_eq!(issue.labels, vec!["bug"]);
    }

    #[tokio::test]
    async fn create_commit_status_sends_correct_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/api/v4/projects/.+/statuses/.+"))
            .and(header("PRIVATE-TOKEN", "test-token"))
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
    }

    #[tokio::test]
    async fn get_merge_request_returns_change_request() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v4/projects/.+/merge_requests/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "description": "MR body",
                "diff_refs": {
                    "base_sha": "base000",
                    "head_sha": "head111",
                    "start_sha": "start222"
                },
                "iid": 5,
                "source_branch": "feature",
                "state": "opened",
                "target_branch": "main",
                "title": "Feature MR",
                "web_url": "https://gitlab.example/mr/5"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let cr = adapter
            .get_change_request(&test_repo(), 5, &cred)
            .await
            .expect("get change request");
        assert_eq!(cr.index, 5);
        assert_eq!(cr.state, ChangeRequestState::Open);
        assert_eq!(cr.head_sha.as_deref(), Some("head111"));
        assert_eq!(cr.merge_base_sha.as_deref(), Some("base000"));
    }

    #[tokio::test]
    async fn webhook_full_flow() {
        let adapter = GitLabAdapter::new(GitLabConfig {
            base_url: "https://gitlab.example".to_string(),
            token: None,
        })
        .expect("build gitlab adapter");

        let payload = serde_json::json!({
            "object_attributes": {
                "action": "open",
                "iid": 1,
                "last_commit": {"id": "sha123"},
                "source_branch": "feature",
                "target_branch": "main",
                "title": "MR Title",
                "url": "https://gitlab.example/mr/1"
            },
            "project": {
                "name": "repo",
                "namespace": "group",
                "path_with_namespace": "group/repo"
            }
        });

        let headers = vec![
            (
                "x-gitlab-event".to_string(),
                "Merge Request Hook".to_string(),
            ),
            ("x-gitlab-token".to_string(), "test-secret".to_string()),
            ("x-gitlab-event-uuid".to_string(), "uuid-123".to_string()),
        ];

        let result = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &serde_json::to_vec(&payload).expect("serialize json"),
                "gl",
                domain::ForgeKind::GitLab,
                "https://gitlab.example",
                "test-secret",
            )
            .expect("parse webhook event");

        let event = result.expect("should produce an event");
        match event {
            domain::WebhookEvent::ChangeRequest(cr) => {
                assert_eq!(cr.index, 1);
                assert_eq!(cr.head_sha, "sha123");
                assert_eq!(cr.delivery_id, "uuid-123");
            }
            _ => panic!("expected ChangeRequest event"),
        }
    }

    #[tokio::test]
    async fn schedule_auto_merge_404_returns_descriptive_message() {
        let mock = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path_regex(r"/projects/.+/merge_requests/\d+/merge"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "404 Branch Does Not Exist"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .schedule_auto_merge(&test_repo(), 1, "merge", "abc", None, &cred)
            .await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "404 Branch Does Not Exist");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_descriptive_message_on_404() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/projects/.+/merge_requests$"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_string("{\"message\":\"404 Project Not Found\"}"),
            )
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .create_change_request(&test_repo(), "test", "body", "feature", "main", &cred)
            .await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "404 Project Not Found");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_unwraps_nested_gitlab_message_object_on_404() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/projects/.+/merge_requests$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": {
                    "message": "Branch not found",
                    "id": "not_found"
                }
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .create_change_request(&test_repo(), "test", "body", "feature", "main", &cred)
            .await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "Branch not found");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_unwraps_nested_gitlab_error_object_on_404() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/projects/.+/merge_requests$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "message": "branch not found",
                    "id": "not_found"
                }
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .create_change_request(&test_repo(), "test", "body", "feature", "main", &cred)
            .await;

        let err = result.expect_err("should fail with not found");
        match err {
            ForgeError::NotFound { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(message, "branch not found");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_response_returns_generic_message_on_404_with_empty_body() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/projects/.+/merge_requests$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .create_change_request(&test_repo(), "test", "body", "feature", "main", &cred)
            .await;

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
    async fn gitlab_get_branch_exists_false_for_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!([
                {"message": "404 Branch not found"}
            ])))
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
    async fn gitlab_get_branch_exists_false_for_does_not_exist() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!([
                {"message": "404 Branch Does Not Exist"}
            ])))
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
    async fn gitlab_get_branch_error_for_repo_not_found() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": {"note": "Project Not Found"}
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        let err = result.expect_err("expected error");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gitlab_get_branch_404_repo_with_branch_in_name_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "404 repository branch-service not found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        let err = result.expect_err("repo-not-found should remain an error");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gitlab_get_branch_details_for_existing() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
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
    async fn gitlab_get_branch_401_unauthorized_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": "401 Unauthorized"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        assert!(result.is_err(), "401 should propagate as error");
    }

    #[tokio::test]
    async fn gitlab_get_branch_403_forbidden_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "message": "403 Forbidden"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        assert!(result.is_err(), "403 should propagate as error");
    }

    #[tokio::test]
    async fn gitlab_get_branch_500_internal_error_is_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "message": "500 Internal Server Error"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "main", &cred).await;

        assert!(result.is_err(), "500 should propagate as error");
    }

    #[tokio::test]
    async fn gitlab_list_branches_multipage_with_high_limit() {
        fn branch_data(count: usize, offset: usize) -> serde_json::Value {
            serde_json::json!(
                (0..count)
                    .map(|i| serde_json::json!({
                        "name": format!("branch-{:03}", offset + i),
                        "commit": {"id": format!("sha{:03}", offset + i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(100, 0)))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(25, 100)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, Some(120), &cred)
            .await
            .expect("list branches");

        assert_eq!(branches.len(), 100);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn gitlab_list_branches_respects_limit() {
        fn branch_data(n: usize) -> serde_json::Value {
            serde_json::json!(
                (0..n)
                    .map(|i| serde_json::json!({
                        "name": format!("branch-{:03}", i),
                        "commit": {"id": format!("sha{:03}", i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(100)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, Some(5), &cred)
            .await
            .expect("list branches");

        assert_eq!(branches.len(), 5);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn gitlab_list_branches_prefix_filter() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                [
                    {"name": "main", "commit": {"id": "aaa"}},
                    {"name": "feature-a", "commit": {"id": "bbb"}},
                    {"name": "feature-b", "commit": {"id": "ccc"}},
                    {"name": "bugfix-1", "commit": {"id": "ddd"}}
                ]
            )))
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
    async fn gitlab_list_branches_truncated_when_pages_exceeded() {
        fn branch_data(n: usize) -> serde_json::Value {
            serde_json::json!(
                (0..n)
                    .map(|i| serde_json::json!({
                        "name": format!("branch-{:03}", i),
                        "commit": {"id": format!("sha{:03}", i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(100)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), None, None, &cred)
            .await
            .expect("list branches");

        assert_eq!(branches.len(), 20);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn gitlab_list_branches_truncated_true_when_prefix_matches_none() {
        fn branch_data(n: usize) -> serde_json::Value {
            serde_json::json!(
                (0..n)
                    .map(|i| serde_json::json!({
                        "name": format!("other-{:03}", i),
                        "commit": {"id": format!("sha{:03}", i)}
                    }))
                    .collect::<Vec<_>>()
            )
        }

        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(branch_data(100)))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let (branches, truncated) = adapter
            .list_branches(&test_repo(), Some("feature-"), Some(200), &cred)
            .await
            .expect("list branches");

        // prefix "feature-" matches none of "other-XXX" branches, so all 5 pages
        // are fetched (MAX_PAGES=5, PAGE_SIZE=100) with zero matching results.
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
    async fn gitlab_get_branch_encodes_special_branch_name() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/feature%2F"))
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
    }

    #[tokio::test]
    async fn gitlab_get_branch_encodes_forward_slash() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/feature%2F"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!([
                {"message": "404 Branch not found"}
            ])))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter
            .get_branch(&test_repo(), "feature/test", &cred)
            .await
            .expect("should return exists false");

        assert_eq!(result.0, "feature/test");
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
    async fn gitlab_list_branches_encodes_prefix_with_special_chars() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches"))
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
            url.contains("search=feature%2Ffoo%3Fbar")
                || url.contains("search=feature%2ffoo%3fbar"),
            "expected URL-encoded prefix in search param: {url}"
        );
    }

    #[tokio::test]
    async fn gitlab_get_branch_exists_false_for_ambiguous_404_when_project_exists() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "The target couldn't be found."
            })))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v4/projects/group%2Fsubgroup%2Frepo$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1, "name": "repo", "path_with_namespace": "group/subgroup/repo"
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
    async fn gitlab_get_branch_exists_false_for_empty_404_when_project_exists() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v4/projects/group%2Fsubgroup%2Frepo$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1, "name": "repo", "path_with_namespace": "group/subgroup/repo"
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
        assert!(!result.2);
    }

    #[tokio::test]
    async fn gitlab_get_branch_error_for_ambiguous_404_when_project_missing() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "The target couldn't be found."
            })))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v4/projects/group%2Fsubgroup%2Frepo$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "404 Project Not Found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "feature", &cred).await;

        let err = result.expect_err("should return error when project is missing");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gitlab_get_branch_error_for_empty_404_when_project_missing() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v4/projects/group%2Fsubgroup%2Frepo$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "404 Project Not Found"
            })))
            .mount(&mock)
            .await;

        let adapter = test_adapter(&mock.uri());
        let cred = ForgeCredential { token: None };
        let result = adapter.get_branch(&test_repo(), "feature", &cred).await;

        let err = result.expect_err("should return error when project is missing");
        match err {
            ForgeError::NotFound { status, .. } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gitlab_get_branch_exists_false_for_no_such_branch() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/projects/.+/repository/branches/.+"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "No such branch"
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
}
