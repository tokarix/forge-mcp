//! Workflow orchestration for forge-mcp.

use std::sync::Arc;

use async_trait::async_trait;
use audit::{AuditRecord, AuditSink};
use domain::{
    AddIssueDependencyRequest, AddIssueLabelRequest, AssignIssueRequest, BranchDetails,
    ChangeRequest, ChangeRequestCiDetails, ChangeRequestComment, ChangeRequestCommentDetail,
    ChangeRequestDiff, ChangeRequestReview, CloseChangeRequestRequest, CloseIssueRequest,
    CombinedCommitStatus, CommentOnChangeRequestRequest, CommentOnIssueRequest, CreateIssueRequest,
    ForgeCredential, GetBranchRequest, GetChangeRequestChecksRequest,
    GetChangeRequestCiDetailsRequest, GetChangeRequestCommentsRequest, GetChangeRequestDiffRequest,
    GetChangeRequestRequest, GetIssueCommentsRequest, GetIssueDependenciesRequest, GetIssueRequest,
    Issue, IssueComment, IssueDependencies, ListBranchesRequest, ListBranchesResponse,
    ListChangeRequestsRequest, ListIssuesRequest, ReadRepositoryFileRequest,
    ReadRepositoryFileResponse, RebaseBranchRequest, RebaseBranchResponse,
    RemoveIssueDependencyRequest, RemoveIssueLabelRequest, RepositoryReadService,
    ScheduleAutoMergeRequest, ServiceError, SubmitChangeRequestReviewRequest,
    UpdateChangeRequestRequest, UpdateIssueRequest, validate_repository_path,
};
use forge::ForgeAdapter;

/// Resolves the committer identity for git operations.
///
/// Tries the forge user API first; falls back to `agent_id` / `agent_id@forge-mcp`
/// if the token lacks `read:user` scope or the response has empty fields.
fn resolve_committer_identity(
    forge_user: Result<domain::ForgeUser, impl std::fmt::Display>,
    agent_id: &str,
) -> (String, String) {
    match forge_user {
        Ok(user) if !user.username.is_empty() && !user.email.is_empty() => {
            (user.username, user.email)
        }
        _ => (agent_id.to_string(), format!("{agent_id}@forge-mcp")),
    }
}

fn sanitize_commit_message(message: &str) -> String {
    let mut lines: Vec<&str> = message
        .lines()
        .filter(|line| {
            !line
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("co-committed-by:")
        })
        .collect();

    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }

    lines.join("\n")
}

pub struct ReadOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    adapter: Arc<A>,
    audit_sink: Arc<S>,
}

impl<A, S> ReadOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    #[must_use]
    pub fn new(adapter: Arc<A>, audit_sink: Arc<S>) -> Self {
        Self {
            adapter,
            audit_sink,
        }
    }
}

#[async_trait]
impl<A, S> RepositoryReadService for ReadOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    async fn get_change_request_checks(
        &self,
        request: GetChangeRequestChecksRequest,
        credential: &ForgeCredential,
    ) -> Result<CombinedCommitStatus, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent.clone(),
                action: "get_change_request_checks".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        let cr = self
            .adapter
            .get_change_request(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        let head_sha = cr
            .head_sha
            .ok_or_else(|| ServiceError::Upstream("change request has no head SHA".to_string()))?;

        self.adapter
            .get_combined_commit_status(&request.repository, &head_sha, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn get_change_request_ci_details(
        &self,
        request: GetChangeRequestCiDetailsRequest,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestCiDetails, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "get_change_request_ci_details".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        let cr = self
            .adapter
            .get_change_request(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        let head_sha = cr
            .head_sha
            .ok_or_else(|| ServiceError::Upstream("change request has no head SHA".to_string()))?;

        self.adapter
            .get_change_request_ci_details(&request.repository, &head_sha, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn get_change_request_comments(
        &self,
        request: GetChangeRequestCommentsRequest,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequestCommentDetail>, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "get_change_request_comments".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .get_change_request_comments(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn get_change_request_diff(
        &self,
        request: GetChangeRequestDiffRequest,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestDiff, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "get_change_request_diff".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        let patch = self
            .adapter
            .get_change_request_diff(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        Ok(ChangeRequestDiff {
            index: request.index,
            patch,
        })
    }

    async fn get_change_request(
        &self,
        request: GetChangeRequestRequest,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "get_change_request".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .get_change_request(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn list_change_requests(
        &self,
        request: ListChangeRequestsRequest,
        credential: &ForgeCredential,
    ) -> Result<Vec<ChangeRequest>, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "list_change_requests".to_string(),
                repository: request.repository.clone(),
                target: request
                    .state
                    .as_ref()
                    .map_or("all".to_string(), |s| format!("{s:?}")),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .list_change_requests(&request.repository, request.state.as_ref(), credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn read_repository_file(
        &self,
        request: ReadRepositoryFileRequest,
        credential: &ForgeCredential,
    ) -> Result<ReadRepositoryFileResponse, ServiceError> {
        validate_repository_path(&request.path).map_err(ServiceError::Validation)?;

        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "read_repository_file".to_string(),
                repository: request.repository.clone(),
                target: request.path.clone(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .read_repository_file(
                &request.repository,
                &request.path,
                request.git_ref.as_deref(),
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn get_issue(
        &self,
        request: GetIssueRequest,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "get_issue".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .get_issue(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn get_issue_comments(
        &self,
        request: GetIssueCommentsRequest,
        credential: &ForgeCredential,
    ) -> Result<Vec<IssueComment>, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "get_issue_comments".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .get_issue_comments(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn get_issue_dependencies(
        &self,
        request: GetIssueDependenciesRequest,
        credential: &ForgeCredential,
    ) -> Result<IssueDependencies, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "get_issue_dependencies".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .get_issue_dependencies(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn list_issues(
        &self,
        request: ListIssuesRequest,
        credential: &ForgeCredential,
    ) -> Result<Vec<Issue>, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "list_issues".to_string(),
                repository: request.repository.clone(),
                target: String::new(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .list_issues(&request.repository, request.state.as_deref(), credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn list_branches(
        &self,
        request: ListBranchesRequest,
        credential: &ForgeCredential,
    ) -> Result<ListBranchesResponse, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent.clone(),
                action: "list_branches".to_string(),
                repository: request.repository.clone(),
                target: request.prefix.clone().unwrap_or_else(|| "*".to_string()),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        let (branches, truncated) = self
            .adapter
            .list_branches(
                &request.repository,
                request.prefix.as_deref(),
                request.limit,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        Ok(ListBranchesResponse {
            branches,
            truncated,
        })
    }

    async fn get_branch(
        &self,
        request: GetBranchRequest,
        credential: &ForgeCredential,
    ) -> Result<BranchDetails, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent.clone(),
                action: "get_branch".to_string(),
                repository: request.repository.clone(),
                target: request.branch.clone(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        let (name, commit_sha, exists) = self
            .adapter
            .get_branch(&request.repository, &request.branch, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        Ok(BranchDetails {
            name,
            commit_sha,
            exists,
        })
    }
}

/// Validates rebase operations against the list of commits in the branch.
///
/// Checks that:
/// - All referenced SHAs exist in the commit list
/// - No commit is used as both a fixup source and target
/// - No commit fixups into itself
/// - Each commit appears as a fixup source at most once
/// - Fixup targets appear before sources in commit order
fn validate_rebase_operations(
    operations: &[domain::RebaseOperation],
    commits: &[String],
) -> Result<(), ServiceError> {
    use std::collections::{HashMap, HashSet};

    let commit_set: HashSet<&str> = commits.iter().map(String::as_str).collect();
    let commit_index: HashMap<&str, usize> = commits
        .iter()
        .enumerate()
        .map(|(i, c)| (c.as_str(), i))
        .collect();

    let mut drop_commits: HashSet<String> = HashSet::new();
    let mut fixup_sources: HashSet<String> = HashSet::new();
    let mut fixup_targets: HashSet<String> = HashSet::new();

    for op in operations {
        match op {
            domain::RebaseOperation::Drop { commit } => {
                if !commit_set.contains(commit.as_str()) {
                    return Err(ServiceError::Validation(format!(
                        "drop commit '{commit}' not found in branch commits"
                    )));
                }
                if !drop_commits.insert(commit.clone()) {
                    return Err(ServiceError::Validation(format!(
                        "commit '{commit}' is dropped more than once"
                    )));
                }
            }
            domain::RebaseOperation::Fixup { commit, into } => {
                // Check SHAs exist
                if !commit_set.contains(commit.as_str()) {
                    return Err(ServiceError::Validation(format!(
                        "fixup commit '{commit}' not found in branch commits"
                    )));
                }
                if !commit_set.contains(into.as_str()) {
                    return Err(ServiceError::Validation(format!(
                        "fixup target '{into}' not found in branch commits"
                    )));
                }

                // No self-fixup
                if commit == into {
                    return Err(ServiceError::Validation(format!(
                        "commit '{commit}' cannot fixup into itself"
                    )));
                }

                // Target must come before source in commit order
                let target_idx = commit_index[into.as_str()];
                let source_idx = commit_index[commit.as_str()];
                if target_idx >= source_idx {
                    return Err(ServiceError::Validation(format!(
                        "fixup target '{into}' must come before source '{commit}' in commit order"
                    )));
                }

                // Each commit used as fixup source at most once
                if !fixup_sources.insert(commit.clone()) {
                    return Err(ServiceError::Validation(format!(
                        "commit '{commit}' is used as fixup source more than once"
                    )));
                }

                fixup_targets.insert(into.clone());
            }
            domain::RebaseOperation::RebaseOnto => {
                return Err(ServiceError::Validation(
                    "rebase_onto cannot appear in commit-level operations".to_string(),
                ));
            }
        }
    }

    // A commit cannot be both a fixup source and target
    let conflicts: Vec<_> = fixup_sources.intersection(&fixup_targets).collect();
    if !conflicts.is_empty() {
        return Err(ServiceError::Validation(format!(
            "commit(s) used as both fixup source and target: {}",
            conflicts
                .iter()
                .map(|c| &c[..std::cmp::min(7, c.len())])
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // A commit cannot be both dropped and used in a fixup
    let drop_fixup_conflicts: Vec<_> = drop_commits
        .intersection(&fixup_sources)
        .chain(drop_commits.intersection(&fixup_targets))
        .collect();
    if !drop_fixup_conflicts.is_empty() {
        return Err(ServiceError::Validation(format!(
            "commit(s) used in both drop and fixup operations: {}",
            drop_fixup_conflicts
                .iter()
                .map(|c| &c[..std::cmp::min(7, c.len())])
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Ok(())
}

pub struct WriteOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    adapter: Arc<A>,
    audit_sink: Arc<S>,
}

impl<A, S> WriteOrchestrator<A, S>
where
    A: ForgeAdapter + 'static,
    S: AuditSink + 'static,
{
    #[must_use]
    pub fn new(adapter: Arc<A>, audit_sink: Arc<S>) -> Self {
        Self {
            adapter,
            audit_sink,
        }
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl<A, S> domain::RepositoryWriteService for WriteOrchestrator<A, S>
where
    A: ForgeAdapter + 'static,
    S: AuditSink + 'static,
{
    async fn add_issue_dependency(
        &self,
        request: AddIssueDependencyRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        let dep_repo = request
            .dependency_repository
            .as_ref()
            .unwrap_or(&request.repository);
        let audit_target = if dep_repo == &request.repository {
            format!("#{} depends on #{}", request.index, request.dependency)
        } else {
            format!(
                "#{} depends on {}/{}#{}",
                request.index, dep_repo.owner, dep_repo.name, request.dependency
            )
        };
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "add_issue_dependency".to_string(),
                repository: request.repository.clone(),
                target: audit_target,
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .add_issue_dependency(
                &request.repository,
                request.index,
                dep_repo,
                request.dependency,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn add_issue_label(
        &self,
        request: AddIssueLabelRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "add_issue_label".to_string(),
                repository: request.repository.clone(),
                target: format!("#{} +label:{}", request.index, request.label),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .add_issue_label(
                &request.repository,
                request.index,
                &request.label,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn assign_issue(
        &self,
        request: AssignIssueRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "assign_issue".to_string(),
                repository: request.repository.clone(),
                target: format!("#{} -> {}", request.index, request.assignee),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .assign_issue(
                &request.repository,
                request.index,
                &request.assignee,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn close_change_request(
        &self,
        request: CloseChangeRequestRequest,
        authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ServiceError> {
        // 1. Enforce branch-scope: require branch_prefix
        let prefix = authorized
            .policy
            .branch_prefix
            .as_deref()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| ServiceError::PolicyDenied {
                reasons: "close_change_request requires a configured branch_prefix".to_string(),
            })?;

        // 2. Fetch the PR to inspect its head branch
        let pr = self
            .adapter
            .get_change_request(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        // 3. Verify head branch matches agent's prefix
        if !pr.head_branch.starts_with(prefix) {
            return Err(ServiceError::PolicyDenied {
                reasons: format!(
                    "agent may only close PRs whose head branch starts with '{prefix}', \
                     but PR #{} has head branch '{}'",
                    request.index, pr.head_branch
                ),
            });
        }

        // 4. Audit
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "close_change_request".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 5. Close
        self.adapter
            .close_change_request(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn comment_on_change_request(
        &self,
        request: CommentOnChangeRequestRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestComment, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "comment_on_change_request".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .comment_on_change_request(
                &request.repository,
                request.index,
                &request.body,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn close_issue(
        &self,
        request: CloseIssueRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        let agent = request.agent.clone();
        let repository = request.repository.clone();
        let index = request.index;
        let message = request.message.clone();

        // 1. Audit the comment action
        self.audit_sink
            .record(AuditRecord {
                agent: agent.clone(),
                action: "comment_on_issue".to_string(),
                repository: repository.clone(),
                target: index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 2. Post comment upstream
        self.adapter
            .comment_on_issue(&repository, index, &message, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        // 3. Audit the close action
        self.audit_sink
            .record(AuditRecord {
                agent,
                action: "close_issue".to_string(),
                repository: repository.clone(),
                target: index.to_string(),
            })
            .await
            .map_err(|e| {
                ServiceError::Audit(format!(
                    "audit failed (closing comment may already have been posted): {e}"
                ))
            })?;

        // 4. Close issue upstream
        self.adapter
            .close_issue(&repository, index, credential)
            .await
            .map_err(|e| {
                ServiceError::Upstream(format!(
                    "close failed (closing comment may already have been posted): {e}"
                ))
            })
    }

    async fn comment_on_issue(
        &self,
        request: CommentOnIssueRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<IssueComment, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "comment_on_issue".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .comment_on_issue(
                &request.repository,
                request.index,
                &request.body,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn commit_patch(
        &self,
        request: domain::CommitPatchRequest,
        authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<domain::CommitPatchResponse, ServiceError> {
        // 1. Validate the diff
        let diff_result = domain::diff::validate_diff(&request.patch)
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        let touched_paths: Vec<String> = diff_result
            .files
            .iter()
            .flat_map(|f| {
                let mut paths = vec![f.path.clone()];
                if let Some(ref source) = f.source_path {
                    paths.push(source.clone());
                }
                paths
            })
            .collect();

        // 2. Evaluate policy
        let policy_context = domain::policy::PolicyContext {
            action: "commit_patch".to_string(),
            agent: request.agent.clone(),
            repository: request.repository.clone(),
            target_branch: request.new_branch.clone(),
            touched_paths,
        };
        let decision = domain::policy::evaluate(&authorized.policy, &policy_context)
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !decision.is_allowed() {
            return Err(ServiceError::PolicyDenied {
                reasons: decision.reasons.join("; "),
            });
        }

        // 2b. Safety: existing_branch requires a configured branch_prefix
        if request.existing_branch && authorized.policy.branch_prefix.is_none() {
            return Err(ServiceError::PolicyDenied {
                reasons: "existing_branch requires a configured branch_prefix to prevent \
                          writes to unscoped branches"
                    .to_string(),
            });
        }

        // 3. Audit intent
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent.clone(),
                action: "commit_patch".to_string(),
                repository: request.repository.clone(),
                target: request.new_branch.clone(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 4. Execute git operations (behind spawn_blocking)
        let clone_url = format!(
            "{}/{}/{}.git",
            request.repository.host.trim_end_matches('/'),
            request.repository.owner,
            request.repository.name,
        );
        let clone_branch = if request.existing_branch {
            request.new_branch.clone()
        } else {
            request.base_branch.clone()
        };
        let existing = request.existing_branch;
        let patch = request.patch.clone();
        let new_branch = request.new_branch.clone();
        let commit_author = request.commit_author.clone();
        let commit_message = sanitize_commit_message(&request.commit_message);
        let token = credential.token.clone();

        let git_result = tokio::task::spawn_blocking(move || {
            let workspace = git_exec::GitWorkspace::clone_repo(
                &clone_url,
                &clone_branch,
                token.as_deref(),
                true,
            )?;
            if !existing {
                workspace.create_branch(&new_branch)?;
            }
            workspace.apply_patch(&patch)?;
            let result =
                workspace.commit(&commit_message, &commit_author.name, &commit_author.email)?;
            workspace.push_branch(&new_branch)?;
            Ok::<_, git_exec::GitExecError>(result)
        })
        .await
        .map_err(|e| ServiceError::GitExec(e.to_string()))?
        .map_err(|e| ServiceError::GitExec(e.to_string()))?;

        Ok(domain::CommitPatchResponse {
            branch: request.new_branch,
            commit_sha: git_result.commit_sha,
            repository: request.repository,
        })
    }

    async fn create_issue(
        &self,
        request: CreateIssueRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "create_issue".to_string(),
                repository: request.repository.clone(),
                target: request.title.clone(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .create_issue(
                &request.repository,
                &request.title,
                &request.body,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn open_change_request(
        &self,
        request: domain::OpenChangeRequestRequest,
        authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<domain::OpenChangeRequestResponse, ServiceError> {
        // 1. Evaluate policy — enforce branch constraints
        let policy_context = domain::policy::PolicyContext {
            action: "open_change_request".to_string(),
            agent: request.agent.clone(),
            repository: request.repository.clone(),
            target_branch: request.head_branch.clone(),
            touched_paths: Vec::new(),
        };
        let decision = domain::policy::evaluate(&authorized.policy, &policy_context)
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !decision.is_allowed() {
            return Err(ServiceError::PolicyDenied {
                reasons: decision.reasons.join("; "),
            });
        }

        // 2. Audit intent
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent.clone(),
                action: "open_change_request".to_string(),
                repository: request.repository.clone(),
                target: request.head_branch.clone(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 3. Create on forge
        let change_request = self
            .adapter
            .create_change_request(
                &request.repository,
                &request.title,
                &request.body,
                &request.head_branch,
                &request.base_branch,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        Ok(domain::OpenChangeRequestResponse {
            change_request,
            repository: request.repository,
        })
    }

    async fn rebase_branch(
        &self,
        request: RebaseBranchRequest,
        authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<RebaseBranchResponse, ServiceError> {
        // 1. Validate branch prefix
        let prefix = authorized
            .policy
            .branch_prefix
            .as_deref()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| ServiceError::PolicyDenied {
                reasons: "rebase_branch requires a configured branch_prefix".to_string(),
            })?;

        if !request.branch.starts_with(prefix) {
            return Err(ServiceError::PolicyDenied {
                reasons: format!(
                    "branch '{}' does not start with required prefix '{prefix}'",
                    request.branch
                ),
            });
        }

        // 2. Reject empty operations
        if request.operations.is_empty() {
            return Err(ServiceError::Validation(
                "operations must not be empty".to_string(),
            ));
        }

        // 2a. Validate rebase_onto exclusivity
        let is_rebase_onto = request
            .operations
            .iter()
            .any(|op| matches!(op, domain::RebaseOperation::RebaseOnto));
        if is_rebase_onto && request.operations.len() > 1 {
            return Err(ServiceError::Validation(
                "rebase_onto cannot be combined with other operations".to_string(),
            ));
        }

        // 3. Fetch committer identity from forge (best-effort)
        let forge_user_result = self.adapter.get_authenticated_user(credential).await;
        let (committer_name, committer_email) =
            resolve_committer_identity(forge_user_result, &request.agent.agent_id);

        // 4. Clone full depth, check out the branch
        let clone_url = format!(
            "{}/{}/{}.git",
            request.repository.host.trim_end_matches('/'),
            request.repository.owner,
            request.repository.name,
        );
        let branch = request.branch.clone();
        let base_branch = request.base_branch.clone();
        let operations = request.operations.clone();
        let agent_identity = request.agent.clone();
        let repository = request.repository.clone();
        let token = credential.token.clone();

        let git_result = tokio::task::spawn_blocking(move || {
            let workspace =
                git_exec::GitWorkspace::clone_repo(&clone_url, &branch, token.as_deref(), false)
                    .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            // 4. Compute merge base
            let mb = workspace
                .merge_base(&format!("origin/{base_branch}"), "HEAD")
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            // 5. Check for merge commits
            if workspace
                .has_merge_commits(&mb)
                .map_err(|e| ServiceError::GitExec(e.to_string()))?
            {
                return Err(ServiceError::Validation(
                    "branch contains merge commits; rebase is not safe".to_string(),
                ));
            }

            // 6. Capture old HEAD SHA
            let old_head = workspace
                .rev_parse("HEAD")
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            if is_rebase_onto {
                // 7a. Rebase all commits onto the latest base branch
                workspace
                    .rebase_onto(
                        &format!("origin/{base_branch}"),
                        &committer_name,
                        &committer_email,
                    )
                    .map_err(|e| ServiceError::GitExec(e.to_string()))?;
            } else {
                // 7b. List commits in range and validate operations
                let commits = workspace
                    .list_commits_in_range(&mb)
                    .map_err(|e| ServiceError::GitExec(e.to_string()))?;

                validate_rebase_operations(&operations, &commits)?;

                let old_tree = workspace
                    .rev_parse("HEAD^{tree}")
                    .map_err(|e| ServiceError::GitExec(e.to_string()))?;

                // Convert domain operations to git-exec operations
                let git_ops: Vec<git_exec::RebaseOperation> = operations
                    .iter()
                    .map(|op| match op {
                        domain::RebaseOperation::Drop { commit } => {
                            git_exec::RebaseOperation::Drop {
                                commit: commit.clone(),
                            }
                        }
                        domain::RebaseOperation::Fixup { commit, into } => {
                            git_exec::RebaseOperation::Fixup {
                                commit: commit.clone(),
                                into: into.clone(),
                            }
                        }
                        domain::RebaseOperation::RebaseOnto => {
                            unreachable!("rebase_onto excluded by prior validation")
                        }
                    })
                    .collect();

                // Run interactive rebase
                workspace
                    .rebase_interactive(&mb, &git_ops, &committer_name, &committer_email)
                    .map_err(|e| ServiceError::GitExec(e.to_string()))?;

                // Verify tree integrity (skip when drops are present — drops
                // intentionally remove content, so the tree is expected to change)
                let has_drops = operations
                    .iter()
                    .any(|op| matches!(op, domain::RebaseOperation::Drop { .. }));
                let new_tree = workspace
                    .rev_parse("HEAD^{tree}")
                    .map_err(|e| ServiceError::GitExec(e.to_string()))?;
                if !has_drops && old_tree != new_tree {
                    return Err(ServiceError::Validation(format!(
                        "rebase changed the tree: old={old_tree}, new={new_tree}; \
                         this indicates a conflict or data loss"
                    )));
                }
            }

            // 8. Capture new HEAD SHA
            let new_head = workspace
                .rev_parse("HEAD")
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            Ok((
                workspace,
                old_head,
                new_head,
                branch,
                agent_identity,
                repository,
            ))
        })
        .await
        .map_err(|e| ServiceError::GitExec(e.to_string()))?;

        let (workspace, old_head, new_head, branch, agent_identity, repository) = git_result?;

        // 9. Audit BEFORE push — failure blocks the write
        let audit_target = if is_rebase_onto {
            format!(
                "{}..{} rebase-onto:{} {branch}",
                &old_head[..8.min(old_head.len())],
                &new_head[..8.min(new_head.len())],
                request.base_branch,
            )
        } else {
            let op_count = request.operations.len();
            format!(
                "{}..{} fixup:{op_count} {branch}",
                &old_head[..8.min(old_head.len())],
                &new_head[..8.min(new_head.len())],
            )
        };
        self.audit_sink
            .record(AuditRecord {
                agent: agent_identity,
                action: "rebase_branch".to_string(),
                repository: repository.clone(),
                target: audit_target,
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 10. Force push with lease (after audit succeeds)
        tokio::task::spawn_blocking(move || {
            workspace
                .force_push_with_lease(&branch, &old_head)
                .map_err(|e| ServiceError::GitExec(e.to_string()))
        })
        .await
        .map_err(|e| ServiceError::GitExec(e.to_string()))??;

        Ok(RebaseBranchResponse {
            branch: request.branch,
            commit_sha: new_head,
        })
    }

    async fn remove_issue_dependency(
        &self,
        request: RemoveIssueDependencyRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        let dep_repo = request
            .dependency_repository
            .as_ref()
            .unwrap_or(&request.repository);
        let audit_target = if dep_repo == &request.repository {
            format!(
                "#{} no longer depends on #{}",
                request.index, request.dependency
            )
        } else {
            format!(
                "#{} no longer depends on {}/{}#{}",
                request.index, dep_repo.owner, dep_repo.name, request.dependency
            )
        };
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "remove_issue_dependency".to_string(),
                repository: request.repository.clone(),
                target: audit_target,
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .remove_issue_dependency(
                &request.repository,
                request.index,
                dep_repo,
                request.dependency,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn remove_issue_label(
        &self,
        request: RemoveIssueLabelRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "remove_issue_label".to_string(),
                repository: request.repository.clone(),
                target: format!("#{} -label:{}", request.index, request.label),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .remove_issue_label(
                &request.repository,
                request.index,
                &request.label,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn schedule_auto_merge(
        &self,
        request: ScheduleAutoMergeRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<(), ServiceError> {
        // 1. Validate merge_style
        match request.merge_style.as_str() {
            "fast-forward-only" | "merge" | "rebase" | "rebase-merge" | "squash" => {}
            other => {
                return Err(ServiceError::Validation(format!(
                    "invalid merge style '{other}': must be rebase, rebase-merge, merge, squash, or fast-forward-only"
                )));
            }
        }

        // 2. Fetch PR to verify head SHA
        let pr = self
            .adapter
            .get_change_request(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        // 3. Check head SHA is available
        let current_sha = pr.head_sha.ok_or_else(|| {
            ServiceError::Validation(
                "pull request head SHA unavailable; cannot schedule auto-merge".to_string(),
            )
        })?;

        // 4. Check expected head SHA matches
        if current_sha != request.expected_head_sha {
            return Err(ServiceError::Validation(format!(
                "expected head SHA '{}' does not match current '{current_sha}'",
                request.expected_head_sha
            )));
        }

        // 5. Load merge settings for validation and default behavior.
        let merge_settings = self
            .adapter
            .get_repository_merge_settings(&request.repository, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        if !merge_settings
            .allowed_styles
            .iter()
            .any(|s| s == &request.merge_style)
        {
            return Err(ServiceError::Validation(format!(
                "merge style '{}' is not allowed by this repository (allowed: {})",
                request.merge_style,
                merge_settings.allowed_styles.join(", "),
            )));
        }

        let delete_branch_after_merge = request
            .delete_branch_after_merge
            .or(merge_settings.default_delete_branch_after_merge);

        // 6. Audit before action
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "schedule_auto_merge".to_string(),
                repository: request.repository.clone(),
                target: format!(
                    "schedule_auto_merge {} head:{} #{}",
                    request.merge_style, current_sha, request.index
                ),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 7. Call adapter
        self.adapter
            .schedule_auto_merge(
                &request.repository,
                request.index,
                &request.merge_style,
                &current_sha,
                delete_branch_after_merge,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        // 8. Post a synthetic commit status to kick auto-merge evaluation.
        //
        // Forgejo only evaluates auto-merge on commit-status, review, or push
        // events. If all conditions were already met before scheduling, no
        // event fires and the PR sits forever. A synthetic success status
        // triggers the evaluation path.  Best-effort: ignore failures since
        // the auto-merge is already scheduled.
        let _ = self
            .adapter
            .create_commit_status(
                &request.repository,
                &current_sha,
                "forge-mcp/auto-merge",
                "auto-merge scheduled",
                "success",
                credential,
            )
            .await;

        Ok(())
    }

    async fn submit_change_request_review(
        &self,
        request: SubmitChangeRequestReviewRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequestReview, ServiceError> {
        // Validate event
        match request.event.as_str() {
            "APPROVED" | "COMMENT" | "REQUEST_CHANGES" => {}
            other => {
                return Err(ServiceError::Validation(format!(
                    "invalid review event '{other}': must be APPROVED, COMMENT, or REQUEST_CHANGES"
                )));
            }
        }

        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "submit_change_request_review".to_string(),
                repository: request.repository.clone(),
                target: request.index.to_string(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .submit_change_request_review(
                &request.repository,
                request.index,
                &request.body,
                &request.event,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn update_change_request(
        &self,
        request: UpdateChangeRequestRequest,
        authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ServiceError> {
        // Validate at least one field is provided
        if request.title.is_none() && request.body.is_none() {
            return Err(ServiceError::Validation(
                "at least one of title or body must be provided".to_string(),
            ));
        }

        // Enforce branch-scope: require branch_prefix
        let prefix = authorized
            .policy
            .branch_prefix
            .as_deref()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| ServiceError::PolicyDenied {
                reasons: "update_change_request requires a configured branch_prefix".to_string(),
            })?;

        // Fetch the PR to inspect its head branch
        let pr = self
            .adapter
            .get_change_request(&request.repository, request.index, credential)
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        // Verify head branch matches agent's prefix
        if !pr.head_branch.starts_with(prefix) {
            return Err(ServiceError::PolicyDenied {
                reasons: format!(
                    "agent may only update PRs whose head branch starts with '{prefix}', \
                     but PR #{} has head branch '{}'",
                    request.index, pr.head_branch
                ),
            });
        }

        // Audit before action
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "update_change_request".to_string(),
                repository: request.repository.clone(),
                target: format!("#{}", request.index),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // Delegate to adapter
        self.adapter
            .update_change_request(
                &request.repository,
                request.index,
                request.title.as_deref(),
                request.body.as_deref(),
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn update_issue(
        &self,
        request: UpdateIssueRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<Issue, ServiceError> {
        if request.title.is_none() && request.body.is_none() {
            return Err(ServiceError::Validation(
                "at least one of title or body must be provided".to_string(),
            ));
        }

        self.audit_sink
            .record(AuditRecord {
                agent: request.agent,
                action: "update_issue".to_string(),
                repository: request.repository.clone(),
                target: format!("#{}", request.index),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        self.adapter
            .update_issue(
                &request.repository,
                request.index,
                request.title.as_deref(),
                request.body.as_deref(),
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
mod tests {
    use std::sync::{Arc, Mutex};

    use audit::{AuditError, AuditRecord, AuditSink, InMemoryAuditSink};
    use domain::{
        AgentIdentity, Branch, ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail,
        ChangeRequestState, CloseChangeRequestRequest, CloseIssueRequest,
        CommentOnChangeRequestRequest, CommitPatchRequest, ForgeCredential, ForgeKind,
        IssueComment, Mergeability, OpenChangeRequestRequest, ReadRepositoryFileRequest,
        RepositoryReadService, RepositoryRef, RepositoryWriteService, ServiceError,
        SubmitChangeRequestReviewRequest, UpdateChangeRequestRequest,
    };
    use forge::{ForgeAdapter, ForgeError};

    use super::{
        ReadOrchestrator, WriteOrchestrator, resolve_committer_identity, sanitize_commit_message,
        validate_rebase_operations,
    };

    fn test_request(path: &str) -> ReadRepositoryFileRequest {
        ReadRepositoryFileRequest {
            agent: AgentIdentity {
                agent_id: "codex".to_string(),
                session_id: "test".to_string(),
            },
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            path: path.to_string(),
            git_ref: Some("main".to_string()),
        }
    }

    struct FakeForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for FakeForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_ci_details(
            &self,
            _repo: &domain::RepositoryRef,
            _head_sha: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_authenticated_user(
            &self,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }

        async fn close_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn comment_on_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn create_change_request(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _head_branch: &str,
            _base_branch: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_default_merge_style(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_repository_merge_settings(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
            _credential: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn read_repository_file(
            &self,
            repository: &RepositoryRef,
            path: &str,
            git_ref: Option<&str>,
            _credential: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Ok(domain::ReadRepositoryFileResponse {
                repository: repository.clone(),
                path: path.to_string(),
                git_ref: git_ref.map(ToOwned::to_owned),
                content: "hello".to_string(),
            })
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _delete_branch_after_merge: Option<bool>,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _event: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _title: Option<&str>,
            _body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_issue(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _title: Option<&str>,
            _body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    struct FailingForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for FailingForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_ci_details(
            &self,
            _repo: &domain::RepositoryRef,
            _head_sha: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_authenticated_user(
            &self,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }

        async fn close_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn comment_on_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn create_change_request(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _head_branch: &str,
            _base_branch: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_default_merge_style(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_repository_merge_settings(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
            _credential: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
            _credential: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(ForgeError::InvalidPayload("test error".to_string()))
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _delete_branch_after_merge: Option<bool>,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _event: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _title: Option<&str>,
            _body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_issue(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _title: Option<&str>,
            _body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    struct FailingAuditSink;

    #[async_trait::async_trait]
    impl AuditSink for FailingAuditSink {
        async fn record(&self, _record: AuditRecord) -> Result<(), AuditError> {
            Err(AuditError::Unavailable)
        }
    }

    #[tokio::test]
    async fn reads_a_repository_file_and_records_audit() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let response = orchestrator
            .read_repository_file(test_request("README.md"), &ForgeCredential { token: None })
            .await
            .expect("read should succeed");

        assert_eq!(response.content, "hello");
        assert_eq!(audit.records().expect("audit records").len(), 1);
    }

    #[tokio::test]
    async fn rejects_empty_path() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .read_repository_file(test_request(""), &ForgeCredential { token: None })
            .await
            .expect_err("empty path should fail");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .read_repository_file(
                test_request("../../../etc/passwd"),
                &ForgeCredential { token: None },
            )
            .await
            .expect_err("traversal should fail");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn returns_upstream_error_on_forge_failure() {
        let adapter = Arc::new(FailingForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .read_repository_file(test_request("README.md"), &ForgeCredential { token: None })
            .await
            .expect_err("forge failure should propagate");

        assert!(matches!(err, ServiceError::Upstream(_)));
        // Audit was recorded before the forge call
        assert_eq!(audit.records().expect("audit records").len(), 1);
    }

    #[tokio::test]
    async fn returns_audit_error_on_sink_failure() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(FailingAuditSink);
        let orchestrator = ReadOrchestrator::new(adapter, audit);

        let err = orchestrator
            .read_repository_file(test_request("README.md"), &ForgeCredential { token: None })
            .await
            .expect_err("audit failure should propagate");

        assert!(matches!(err, ServiceError::Audit(_)));
    }

    // --- get_change_request_checks tests ---

    /// A minimal `ForgeAdapter` that returns a PR with a `head_sha` and a combined
    /// commit status, used to test the `ReadOrchestrator::get_change_request_checks`
    /// method.
    struct ChecksTestForgeAdapter {
        combined_status: domain::CombinedCommitStatus,
        ci_details: domain::ChangeRequestCiDetails,
        head_sha: Option<String>,
    }

    impl ChecksTestForgeAdapter {
        fn success() -> Self {
            let head_sha = "abc123".to_string();
            Self {
                combined_status: domain::CombinedCommitStatus {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Success,
                    statuses: vec![domain::CommitStatus {
                        context: "ci/test".to_string(),
                        description: "passed".to_string(),
                        state: domain::CommitStatusState::Success,
                        target_url: "https://ci.example/1".to_string(),
                    }],
                    total_count: 1,
                },
                ci_details: domain::ChangeRequestCiDetails {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Success,
                    details: vec![domain::CiCheckDetail {
                        context: "ci/test".to_string(),
                        description: "passed".to_string(),
                        state: domain::CommitStatusState::Success,
                        target_url: "https://ci.example/1".to_string(),
                        resolution: domain::CiResolution::Unsupported,
                    }],
                },
                head_sha: Some(head_sha),
            }
        }

        fn failure() -> Self {
            let head_sha = "abc123".to_string();
            Self {
                combined_status: domain::CombinedCommitStatus {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Failure,
                    statuses: vec![domain::CommitStatus {
                        context: "ci/test".to_string(),
                        description: "failed".to_string(),
                        state: domain::CommitStatusState::Failure,
                        target_url: "https://ci.example/1".to_string(),
                    }],
                    total_count: 1,
                },
                ci_details: domain::ChangeRequestCiDetails {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Failure,
                    details: vec![domain::CiCheckDetail {
                        context: "ci/test".to_string(),
                        description: "failed".to_string(),
                        state: domain::CommitStatusState::Failure,
                        target_url: "https://ci.example/1".to_string(),
                        resolution: domain::CiResolution::Unsupported,
                    }],
                },
                head_sha: Some(head_sha),
            }
        }

        fn error() -> Self {
            let head_sha = "abc123".to_string();
            Self {
                combined_status: domain::CombinedCommitStatus {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Error,
                    statuses: vec![domain::CommitStatus {
                        context: "ci/test".to_string(),
                        description: "error".to_string(),
                        state: domain::CommitStatusState::Error,
                        target_url: "https://ci.example/1".to_string(),
                    }],
                    total_count: 1,
                },
                ci_details: domain::ChangeRequestCiDetails {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Error,
                    details: vec![domain::CiCheckDetail {
                        context: "ci/test".to_string(),
                        description: "error".to_string(),
                        state: domain::CommitStatusState::Error,
                        target_url: "https://ci.example/1".to_string(),
                        resolution: domain::CiResolution::Unsupported,
                    }],
                },
                head_sha: Some(head_sha),
            }
        }

        fn pending() -> Self {
            let head_sha = "abc123".to_string();
            Self {
                combined_status: domain::CombinedCommitStatus {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Pending,
                    statuses: vec![domain::CommitStatus {
                        context: "ci/test".to_string(),
                        description: "running".to_string(),
                        state: domain::CommitStatusState::Pending,
                        target_url: "https://ci.example/1".to_string(),
                    }],
                    total_count: 1,
                },
                ci_details: domain::ChangeRequestCiDetails {
                    head_sha: head_sha.clone(),
                    state: domain::CommitStatusState::Pending,
                    details: vec![domain::CiCheckDetail {
                        context: "ci/test".to_string(),
                        description: "running".to_string(),
                        state: domain::CommitStatusState::Pending,
                        target_url: "https://ci.example/1".to_string(),
                        resolution: domain::CiResolution::Unsupported,
                    }],
                },
                head_sha: Some(head_sha),
            }
        }
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for ChecksTestForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_change_request(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Ok(self.combined_status.clone())
        }

        async fn get_change_request_ci_details(
            &self,
            _repo: &domain::RepositoryRef,
            _head_sha: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Ok(self.ci_details.clone())
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_authenticated_user(
            &self,
            _: &ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "feature".to_string(),
                head_sha: self.head_sha.clone(),
                has_conflicts: None,
                index: 1,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Open,
                title: "test".to_string(),
                url: "https://example.com/pulls/1".to_string(),
            })
        }
        async fn get_change_request_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_default_merge_style(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_repository_merge_settings(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_change_requests(
            &self,
            _: &RepositoryRef,
            _: Option<&ChangeRequestState>,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn read_repository_file(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn schedule_auto_merge(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: Option<bool>,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn submit_change_request_review(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn update_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn update_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    fn checks_test_agent() -> AgentIdentity {
        AgentIdentity {
            agent_id: "codex".to_string(),
            session_id: "test".to_string(),
        }
    }

    fn checks_test_repo() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: ForgeKind::Forgejo,
            host: "https://forge.example".to_string(),
            name: "repo".to_string(),
            owner: "org".to_string(),
        }
    }

    #[tokio::test]
    async fn get_change_request_ci_details_returns_details_and_audits() {
        let adapter = Arc::new(ChecksTestForgeAdapter::success());
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .get_change_request_ci_details(
                domain::GetChangeRequestCiDetailsRequest {
                    agent: checks_test_agent(),
                    index: 1,
                    repository: checks_test_repo(),
                },
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.head_sha, "abc123");
        assert_eq!(result.details.len(), 1);
        assert_eq!(result.details[0].context, "ci/test");
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "get_change_request_ci_details"
        );
    }

    #[tokio::test]
    async fn get_change_request_ci_details_failure() {
        let adapter = Arc::new(ChecksTestForgeAdapter::failure());
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .get_change_request_ci_details(
                domain::GetChangeRequestCiDetailsRequest {
                    agent: checks_test_agent(),
                    index: 1,
                    repository: checks_test_repo(),
                },
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.state, domain::CommitStatusState::Failure);
        assert_eq!(result.details[0].state, domain::CommitStatusState::Failure);
    }

    #[tokio::test]
    async fn get_change_request_ci_details_error() {
        let adapter = Arc::new(ChecksTestForgeAdapter::error());
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .get_change_request_ci_details(
                domain::GetChangeRequestCiDetailsRequest {
                    agent: checks_test_agent(),
                    index: 1,
                    repository: checks_test_repo(),
                },
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.state, domain::CommitStatusState::Error);
        assert_eq!(result.details[0].state, domain::CommitStatusState::Error);
    }

    #[tokio::test]
    async fn get_change_request_ci_details_pending() {
        let adapter = Arc::new(ChecksTestForgeAdapter::pending());
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .get_change_request_ci_details(
                domain::GetChangeRequestCiDetailsRequest {
                    agent: checks_test_agent(),
                    index: 1,
                    repository: checks_test_repo(),
                },
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.state, domain::CommitStatusState::Pending);
        assert_eq!(result.details[0].state, domain::CommitStatusState::Pending);
    }

    #[tokio::test]
    async fn get_change_request_checks_returns_status_and_audits() {
        let adapter = Arc::new(ChecksTestForgeAdapter::success());
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .get_change_request_checks(
                domain::GetChangeRequestChecksRequest {
                    agent: checks_test_agent(),
                    index: 1,
                    repository: checks_test_repo(),
                },
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.head_sha, "abc123");
        assert_eq!(result.state, domain::CommitStatusState::Success);
        assert_eq!(result.total_count, 1);
        assert_eq!(result.statuses.len(), 1);
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "get_change_request_checks"
        );
    }

    #[tokio::test]
    async fn get_change_request_checks_errors_when_no_head_sha() {
        let adapter = Arc::new(ChecksTestForgeAdapter {
            combined_status: domain::CombinedCommitStatus {
                head_sha: String::new(),
                state: domain::CommitStatusState::Pending,
                statuses: vec![],
                total_count: 0,
            },
            ci_details: domain::ChangeRequestCiDetails {
                head_sha: String::new(),
                state: domain::CommitStatusState::Pending,
                details: vec![],
            },
            head_sha: None,
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .get_change_request_checks(
                domain::GetChangeRequestChecksRequest {
                    agent: checks_test_agent(),
                    index: 1,
                    repository: checks_test_repo(),
                },
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("should fail without head_sha");

        assert!(matches!(err, ServiceError::Upstream(_)));
    }

    // --- WriteOrchestrator tests ---

    struct WriteTestForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for WriteTestForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            repository: &RepositoryRef,
            index: u64,
            label: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index,
                labels: vec![label.to_string()],
                state: "open".to_string(),
                title: "Test".to_string(),
                url: format!(
                    "https://forge.example/{}/{}/issues/{index}",
                    repository.owner, repository.name
                ),
            })
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_issue(
            &self,
            repository: &RepositoryRef,
            title: &str,
            body: &str,
            _credential: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: body.to_string(),
                index: 1,
                labels: vec![],
                state: "open".to_string(),
                title: title.to_string(),
                url: format!(
                    "https://forge.example/{}/{}/issues/1",
                    repository.owner, repository.name
                ),
            })
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_ci_details(
            &self,
            _repo: &domain::RepositoryRef,
            _head_sha: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            repository: &RepositoryRef,
            index: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index,
                labels: vec![],
                state: "open".to_string(),
                title: "Test".to_string(),
                url: format!(
                    "https://forge.example/{}/{}/issues/{index}",
                    repository.owner, repository.name
                ),
            })
        }
        async fn get_authenticated_user(
            &self,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }

        async fn close_change_request(
            &self,
            repository: &RepositoryRef,
            index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                has_conflicts: None,
                index,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Closed,
                title: "Fix".to_string(),
                url: format!(
                    "https://forge.example/{}/{}/pulls/{index}",
                    repository.owner, repository.name
                ),
            })
        }

        async fn comment_on_change_request(
            &self,
            _repository: &RepositoryRef,
            index: u64,
            body: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            Ok(domain::ChangeRequestComment {
                body: body.to_string(),
                id: 1,
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
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: base_branch.to_string(),
                body: body.to_string(),
                changed_files_count: None,
                commit_count: None,
                head_branch: head_branch.to_string(),
                head_sha: None,
                has_conflicts: None,
                index: 1,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Open,
                title: title.to_string(),
                url: format!(
                    "https://forge.example/{}/{}/pulls/1",
                    repository.owner, repository.name
                ),
            })
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                has_conflicts: None,
                index,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: format!("https://forge.example/org/repo/pulls/{index}"),
            })
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_default_merge_style(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_repository_merge_settings(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
            _credential: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
            _credential: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _delete_branch_after_merge: Option<bool>,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            index: u64,
            body: &str,
            event: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Ok(domain::ChangeRequestReview {
                body: body.to_string(),
                event: event.to_string(),
                id: 1,
                index,
            })
        }

        async fn update_change_request(
            &self,
            repository: &RepositoryRef,
            index: u64,
            title: Option<&str>,
            body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: body.unwrap_or_default().to_string(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: None,
                has_conflicts: None,
                index,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Open,
                title: title.unwrap_or("Fix").to_string(),
                url: format!(
                    "https://forge.example/{}/{}/pulls/{index}",
                    repository.owner, repository.name
                ),
            })
        }

        async fn update_issue(
            &self,
            repository: &RepositoryRef,
            index: u64,
            title: Option<&str>,
            body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Ok(domain::Issue {
                assignees: vec![],
                body: body.unwrap_or_default().to_string(),
                index,
                labels: vec![],
                state: "open".to_string(),
                title: title.unwrap_or("Issue").to_string(),
                url: format!(
                    "https://forge.example/{}/{}/issues/{index}",
                    repository.owner, repository.name
                ),
            })
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    fn write_test_request() -> CommitPatchRequest {
        CommitPatchRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            commit_author: domain::CommitAuthor {
                email: "test@example.com".to_string(),
                name: "Test User".to_string(),
            },
            commit_message: "test commit".to_string(),
            existing_branch: false,
            new_branch: "agent/test-fix".to_string(),
            patch: "\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # Hello
+World
"
            .to_string(),
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
        }
    }

    fn default_authorized() -> domain::policy::AuthorizedWrite {
        domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig::default(),
        }
    }

    #[test]
    fn sanitize_commit_message_removes_co_committed_by_trailers() {
        let message = "feat: improve gateway\n\nBody text.\n\nCo-authored-by: Claude Opus 4.6 <noreply@anthropic.com>\nCo-committed-by: agent-claude <noreply+claude@adlevio.net>\n";
        let sanitized = sanitize_commit_message(message);
        assert!(sanitized.contains("Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>"));
        assert!(!sanitized.contains("Co-committed-by:"));
    }

    #[test]
    fn sanitize_commit_message_handles_uppercase_trailers_and_blank_lines() {
        let message = "feat: improve gateway\n\nCO-COMMITTED-BY: agent-claude <noreply+claude@adlevio.net>\n\n\n";
        let sanitized = sanitize_commit_message(message);
        assert_eq!(sanitized, "feat: improve gateway");
    }

    #[test]
    fn sanitize_commit_message_can_strip_trailers_only() {
        let message = "Co-committed-by: agent-claude <noreply+claude@adlevio.net>\n\n";
        let sanitized = sanitize_commit_message(message);
        assert!(sanitized.is_empty());
    }

    #[tokio::test]
    async fn commit_patch_rejects_invalid_diff() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let mut request = write_test_request();
        request.patch = "\
diff --git a/image.png b/image.png
Binary files /dev/null and b/image.png differ
"
        .to_string();

        let err = orchestrator
            .commit_patch(
                request,
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("binary diff should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn commit_patch_rejects_wrong_branch_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let mut request = write_test_request();
        request.new_branch = "main".to_string();

        let err = orchestrator
            .commit_patch(
                request,
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("wrong branch prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn commit_patch_rejects_protected_paths() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let mut request = write_test_request();
        request.patch = "\
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1 +1,2 @@
 name: CI
+# hacked
"
        .to_string();

        let err = orchestrator
            .commit_patch(
                request,
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("protected path should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn open_change_request_rejects_wrong_branch_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let request = OpenChangeRequestRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            body: "Fix things".to_string(),
            head_branch: "unauthorized-branch".to_string(),
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            title: "Fix".to_string(),
        };

        let err = orchestrator
            .open_change_request(
                request,
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("wrong branch prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn commit_patch_rejects_existing_branch_without_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let mut request = write_test_request();
        request.existing_branch = true;

        // Use a policy with no branch prefix
        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig {
                branch_prefix: None,
                protected_paths: vec![],
            },
        };

        let err = orchestrator
            .commit_patch(
                request,
                authorized,
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("should reject existing_branch without prefix");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
    }

    #[tokio::test]
    async fn open_change_request_records_audit_and_creates() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let request = OpenChangeRequestRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            body: "Fix things".to_string(),
            head_branch: "agent/fix".to_string(),
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            title: "Fix".to_string(),
        };

        let response = orchestrator
            .open_change_request(
                request,
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(response.change_request.index, 1);
        assert_eq!(audit.records().expect("audit records").len(), 1);
    }

    // --- create_issue tests ---

    #[tokio::test]
    async fn create_issue_records_audit_and_creates() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .create_issue(
                domain::CreateIssueRequest {
                    agent: AgentIdentity {
                        agent_id: "test-agent".to_string(),
                        session_id: "test-session".to_string(),
                    },
                    body: "Something is broken".to_string(),
                    repository: RepositoryRef {
                        alias: "test".to_string(),
                        forge: ForgeKind::Forgejo,
                        host: "https://forge.example".to_string(),
                        name: "repo".to_string(),
                        owner: "org".to_string(),
                    },
                    title: "Bug report".to_string(),
                },
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.title, "Bug report");
        assert_eq!(result.body, "Something is broken");
        assert_eq!(result.state, "open");
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "create_issue"
        );
        assert_eq!(
            audit.records().expect("audit records")[0].target,
            "Bug report"
        );
    }

    // --- add_issue_label / remove_issue_label tests ---

    #[tokio::test]
    async fn add_issue_label_records_audit_and_adds() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .add_issue_label(
                domain::AddIssueLabelRequest {
                    agent: AgentIdentity {
                        agent_id: "test-agent".to_string(),
                        session_id: "test-session".to_string(),
                    },
                    index: 5,
                    label: "needs-input".to_string(),
                    repository: RepositoryRef {
                        alias: "test".to_string(),
                        forge: ForgeKind::Forgejo,
                        host: "https://forge.example".to_string(),
                        name: "repo".to_string(),
                        owner: "org".to_string(),
                    },
                },
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.labels, vec!["needs-input"]);
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "add_issue_label"
        );
        assert_eq!(
            audit.records().expect("audit records")[0].target,
            "#5 +label:needs-input"
        );
    }

    #[tokio::test]
    async fn remove_issue_label_records_audit_and_removes() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .remove_issue_label(
                domain::RemoveIssueLabelRequest {
                    agent: AgentIdentity {
                        agent_id: "test-agent".to_string(),
                        session_id: "test-session".to_string(),
                    },
                    index: 5,
                    label: "needs-input".to_string(),
                    repository: RepositoryRef {
                        alias: "test".to_string(),
                        forge: ForgeKind::Forgejo,
                        host: "https://forge.example".to_string(),
                        name: "repo".to_string(),
                        owner: "org".to_string(),
                    },
                },
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert!(result.labels.is_empty());
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "remove_issue_label"
        );
        assert_eq!(
            audit.records().expect("audit records")[0].target,
            "#5 -label:needs-input"
        );
    }

    // --- close_change_request tests ---

    /// Fake adapter where `get_change_request` returns a PR with a
    /// configurable head branch, so we can test prefix enforcement.
    struct CloseTestForgeAdapter {
        head_branch: String,
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for CloseTestForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_ci_details(
            &self,
            _repo: &domain::RepositoryRef,
            _head_sha: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_authenticated_user(
            &self,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }

        async fn close_change_request(
            &self,
            repository: &RepositoryRef,
            index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: self.head_branch.clone(),
                head_sha: None,
                has_conflicts: None,
                index,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Closed,
                title: "Fix".to_string(),
                url: format!(
                    "https://forge.example/{}/{}/pulls/{index}",
                    repository.owner, repository.name
                ),
            })
        }

        async fn comment_on_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn create_change_request(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _head_branch: &str,
            _base_branch: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: self.head_branch.clone(),
                head_sha: None,
                has_conflicts: None,
                index,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: format!("https://forge.example/org/repo/pulls/{index}"),
            })
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_default_merge_style(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_repository_merge_settings(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
            _credential: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
            _credential: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _delete_branch_after_merge: Option<bool>,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _event: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _title: Option<&str>,
            _body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_issue(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _title: Option<&str>,
            _body: Option<&str>,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    fn close_test_request(index: u64) -> CloseChangeRequestRequest {
        CloseChangeRequestRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            index,
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn close_change_request_records_audit_and_closes() {
        let adapter = Arc::new(CloseTestForgeAdapter {
            head_branch: "agent/fix".to_string(),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .close_change_request(
                close_test_request(42),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.state, ChangeRequestState::Closed);
        assert_eq!(result.index, 42);
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "close_change_request"
        );
    }

    #[tokio::test]
    async fn close_change_request_rejects_without_prefix() {
        let adapter = Arc::new(CloseTestForgeAdapter {
            head_branch: "agent/fix".to_string(),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig {
                branch_prefix: None,
                ..domain::policy::PolicyConfig::default()
            },
        };

        let err = orchestrator
            .close_change_request(
                close_test_request(1),
                authorized,
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("missing prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn close_change_request_rejects_wrong_prefix() {
        let adapter = Arc::new(CloseTestForgeAdapter {
            head_branch: "other-agent/fix".to_string(),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .close_change_request(
                close_test_request(1),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("wrong prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    // --- comment_on_change_request tests ---

    fn comment_test_request(index: u64) -> CommentOnChangeRequestRequest {
        CommentOnChangeRequestRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            body: "Looks good".to_string(),
            index,
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn comment_on_change_request_records_audit_and_comments() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .comment_on_change_request(
                comment_test_request(42),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.index, 42);
        assert_eq!(result.body, "Looks good");
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "comment_on_change_request"
        );
    }

    // --- submit_change_request_review tests ---

    fn review_test_request(index: u64, event: &str) -> SubmitChangeRequestReviewRequest {
        SubmitChangeRequestReviewRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            body: "LGTM".to_string(),
            event: event.to_string(),
            index,
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn submit_review_records_audit_and_submits() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .submit_change_request_review(
                review_test_request(42, "APPROVED"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.index, 42);
        assert_eq!(result.event, "APPROVED");
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "submit_change_request_review"
        );
    }

    #[tokio::test]
    async fn submit_review_rejects_invalid_event() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .submit_change_request_review(
                review_test_request(1, "INVALID"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("invalid event should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    // --- credential override tests ---

    /// Sentinel to distinguish "not called" from "called with None token".
    enum CapturedCredential {
        NotCalled,
        Called(Option<String>),
    }

    struct CredentialCapturingAdapter {
        captured: std::sync::Mutex<CapturedCredential>,
    }

    impl CredentialCapturingAdapter {
        fn new() -> Self {
            Self {
                captured: std::sync::Mutex::new(CapturedCredential::NotCalled),
            }
        }

        fn captured_token(&self) -> Option<String> {
            match &*self
                .captured
                .lock()
                .expect("captured credential lock poisoned")
            {
                CapturedCredential::NotCalled => panic!("adapter was not called"),
                CapturedCredential::Called(t) => t.clone(),
            }
        }
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for CredentialCapturingAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_ci_details(
            &self,
            _repo: &domain::RepositoryRef,
            _head_sha: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_authenticated_user(
            &self,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }

        async fn close_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn comment_on_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            *self
                .captured
                .lock()
                .expect("captured credential lock poisoned") =
                CapturedCredential::Called(credential.token.clone());
            Ok(domain::ChangeRequestComment {
                body: "test".to_string(),
                id: 1,
                index: 1,
            })
        }

        async fn create_change_request(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_default_merge_style(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_repository_merge_settings(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_change_requests(
            &self,
            _: &RepositoryRef,
            _: Option<&ChangeRequestState>,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn read_repository_file(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn schedule_auto_merge(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: Option<bool>,
            _: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn submit_change_request_review(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    #[tokio::test]
    async fn credential_override_reaches_adapter() {
        let adapter = Arc::new(CredentialCapturingAdapter::new());
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let override_cred = domain::ForgeCredential {
            token: Some("per-agent-token".to_string()),
        };

        orchestrator
            .comment_on_change_request(
                comment_test_request(1),
                default_authorized(),
                &override_cred,
            )
            .await
            .expect("should succeed");

        assert_eq!(
            adapter.captured_token(),
            Some("per-agent-token".to_string())
        );
    }

    #[tokio::test]
    async fn credential_none_reaches_adapter() {
        let adapter = Arc::new(CredentialCapturingAdapter::new());
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let no_override = domain::ForgeCredential { token: None };

        orchestrator
            .comment_on_change_request(comment_test_request(1), default_authorized(), &no_override)
            .await
            .expect("should succeed");

        assert_eq!(adapter.captured_token(), None);
    }

    // --- schedule_auto_merge tests ---

    struct AutoMergeTestForgeAdapter {
        allowed_merge_styles: Vec<String>,
        default_delete_branch_after_merge: Option<bool>,
        head_sha: Option<String>,
        recorded_commit_statuses: Mutex<Vec<(String, String)>>,
        recorded_delete_branch_after_merge: Mutex<Vec<Option<bool>>>,
    }

    impl AutoMergeTestForgeAdapter {
        fn new(head_sha: &str) -> Self {
            Self {
                allowed_merge_styles: vec!["rebase".to_string(), "squash".to_string()],
                default_delete_branch_after_merge: Some(true),
                head_sha: Some(head_sha.to_string()),
                recorded_commit_statuses: Mutex::new(Vec::new()),
                recorded_delete_branch_after_merge: Mutex::new(Vec::new()),
            }
        }

        fn recorded_commit_statuses(&self) -> Vec<(String, String)> {
            self.recorded_commit_statuses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn recorded_delete_branch_after_merge(&self) -> Vec<Option<bool>> {
            self.recorded_delete_branch_after_merge
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for AutoMergeTestForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn create_commit_status(
            &self,
            _repository: &RepositoryRef,
            sha: &str,
            context: &str,
            _description: &str,
            _state: &str,
            _credential: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            self.recorded_commit_statuses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((sha.to_string(), context.to_string()));
            Ok(())
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_ci_details(
            &self,
            _repo: &domain::RepositoryRef,
            _head_sha: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Ok(self.allowed_merge_styles.clone())
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
        async fn get_authenticated_user(
            &self,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }

        async fn close_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn comment_on_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn create_change_request(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: String::new(),
                changed_files_count: None,
                commit_count: None,
                head_branch: "agent/fix".to_string(),
                head_sha: self.head_sha.clone(),
                has_conflicts: None,
                index,
                merge_base_sha: None,
                mergeability: Mergeability::Unknown,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: format!("https://forge.example/org/repo/pulls/{index}"),
            })
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_default_merge_style(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Ok(Some("rebase".to_string()))
        }

        async fn get_repository_merge_settings(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Ok(domain::RepositoryMergeSettings {
                allowed_styles: self.allowed_merge_styles.clone(),
                default_delete_branch_after_merge: self.default_delete_branch_after_merge,
                default_merge_style: Some("rebase".to_string()),
            })
        }

        async fn list_change_requests(
            &self,
            _: &RepositoryRef,
            _: Option<&ChangeRequestState>,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn read_repository_file(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            delete_branch_after_merge: Option<bool>,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            self.recorded_delete_branch_after_merge
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(delete_branch_after_merge);
            Ok(())
        }

        async fn submit_change_request_review(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn update_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &domain::ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported(
                "unimplemented in test fake".into(),
            ))
        }
    }

    fn auto_merge_test_request(
        merge_style: &str,
        expected_head_sha: &str,
    ) -> domain::ScheduleAutoMergeRequest {
        domain::ScheduleAutoMergeRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            delete_branch_after_merge: None,
            expected_head_sha: expected_head_sha.to_string(),
            index: 42,
            merge_style: merge_style.to_string(),
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn schedule_auto_merge_valid_merge_style() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter::new("abc123"));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("rebase", "abc123"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");
    }

    #[tokio::test]
    async fn schedule_auto_merge_invalid_merge_style() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter::new("abc123"));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("invalid", "abc123"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("invalid merge style should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn schedule_auto_merge_head_sha_mismatch() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter::new("abc123"));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("rebase", "wrong-sha"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("mismatched head SHA should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn schedule_auto_merge_missing_head_sha() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter {
            allowed_merge_styles: vec!["rebase".to_string(), "squash".to_string()],
            default_delete_branch_after_merge: Some(true),
            head_sha: None,
            recorded_commit_statuses: Mutex::new(Vec::new()),
            recorded_delete_branch_after_merge: Mutex::new(Vec::new()),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("rebase", "abc123"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("missing head SHA should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn schedule_auto_merge_records_audit() {
        let full_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let adapter = Arc::new(AutoMergeTestForgeAdapter::new(full_sha));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("squash", full_sha),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "schedule_auto_merge"
        );
        assert!(
            audit.records().expect("audit records")[0]
                .target
                .contains("squash")
        );
        // Full SHA must be preserved — not truncated
        assert!(
            audit.records().expect("audit records")[0]
                .target
                .contains(&format!("head:{full_sha}"))
        );
        assert!(
            audit.records().expect("audit records")[0]
                .target
                .contains("#42")
        );
    }

    #[tokio::test]
    async fn schedule_auto_merge_rejects_disallowed_strategy() {
        let adapter = AutoMergeTestForgeAdapter::new("abc123");
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::new(adapter), Arc::clone(&audit));

        let err = orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("merge", "abc123"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("disallowed merge style should be rejected");

        match err {
            ServiceError::Validation(msg) => {
                assert!(
                    msg.contains("not allowed"),
                    "expected 'not allowed' in error, got: {msg}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn schedule_auto_merge_uses_repo_default_delete_branch_setting() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter::new("abc123"));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("rebase", "abc123"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(
            adapter.recorded_delete_branch_after_merge(),
            vec![Some(true)]
        );
    }

    #[tokio::test]
    async fn schedule_auto_merge_prefers_explicit_delete_branch_override() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter::new("abc123"));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let mut request = auto_merge_test_request("rebase", "abc123");
        request.delete_branch_after_merge = Some(false);

        orchestrator
            .schedule_auto_merge(
                request,
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(
            adapter.recorded_delete_branch_after_merge(),
            vec![Some(false)]
        );
    }

    #[tokio::test]
    async fn schedule_auto_merge_posts_kick_status() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter::new("abc123"));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        orchestrator
            .schedule_auto_merge(
                auto_merge_test_request("rebase", "abc123"),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        let statuses = adapter.recorded_commit_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].0, "abc123");
        assert_eq!(statuses[0].1, "forge-mcp/auto-merge");
    }

    // --- update_change_request tests ---

    fn update_test_request(title: Option<&str>, body: Option<&str>) -> UpdateChangeRequestRequest {
        UpdateChangeRequestRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            body: body.map(ToString::to_string),
            index: 42,
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            title: title.map(ToString::to_string),
        }
    }

    #[tokio::test]
    async fn update_change_request_rejects_when_both_none() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .update_change_request(
                update_test_request(None, None),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("both None should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn update_change_request_rejects_without_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig {
                branch_prefix: None,
                ..domain::policy::PolicyConfig::default()
            },
        };

        let err = orchestrator
            .update_change_request(
                update_test_request(Some("New title"), None),
                authorized,
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("missing prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn update_change_request_rejects_wrong_prefix() {
        let adapter = Arc::new(CloseTestForgeAdapter {
            head_branch: "other-agent/fix".to_string(),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .update_change_request(
                update_test_request(Some("New title"), None),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("wrong prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn update_change_request_records_audit() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .update_change_request(
                update_test_request(Some("New title"), None),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.index, 42);
        assert_eq!(result.title, "New title");
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "update_change_request"
        );
        assert_eq!(audit.records().expect("audit records")[0].target, "#42");
    }

    // --- update_issue tests ---

    fn update_issue_test_request(
        title: Option<&str>,
        body: Option<&str>,
    ) -> domain::UpdateIssueRequest {
        domain::UpdateIssueRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            body: body.map(ToString::to_string),
            index: 7,
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            title: title.map(ToString::to_string),
        }
    }

    #[tokio::test]
    async fn update_issue_rejects_when_both_none() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .update_issue(
                update_issue_test_request(None, None),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("both None should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().expect("audit records").len(), 0);
    }

    #[tokio::test]
    async fn update_issue_records_audit() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .update_issue(
                update_issue_test_request(Some("New title"), None),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.index, 7);
        assert_eq!(result.title, "New title");
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "update_issue"
        );
        assert_eq!(audit.records().expect("audit records")[0].target, "#7");
    }

    #[tokio::test]
    async fn update_issue_updates_body_only() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let result = orchestrator
            .update_issue(
                update_issue_test_request(None, Some("Updated body")),
                default_authorized(),
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("should succeed");

        assert_eq!(result.body, "Updated body");
        assert_eq!(audit.records().expect("audit records").len(), 1);
    }

    // --- rebase_branch integration tests ---

    /// Set up a bare remote repo with an initial commit, clone it, create a
    /// branch with extra commits, push, and return the remote path + commit SHAs.
    fn setup_rebase_test_repo(branch: &str) -> (tempfile::TempDir, Vec<String>) {
        use std::process::Command;

        fn run(dir: &std::path::Path, args: &[&str]) -> String {
            let out = Command::new("git")
                .current_dir(dir)
                .args(args)
                .output()
                .expect("git command");
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout)
                .expect("git output should be valid UTF-8")
                .trim()
                .to_string()
        }

        let remote_dir = tempfile::TempDir::new().expect("failed to create remote temp dir");
        run(remote_dir.path(), &["init", "--bare", "remote.git"]);
        let remote_path = remote_dir.path().join("remote.git");

        let work_dir = tempfile::TempDir::new().expect("failed to create work temp dir");
        let work = work_dir.path().join("work");
        run(
            work_dir.path(),
            &[
                "clone",
                remote_path
                    .to_str()
                    .expect("remote path should be valid UTF-8"),
                "work",
            ],
        );
        std::fs::write(work.join("README.md"), "# Hello\n").expect("failed to write README.md");
        run(&work, &["add", "README.md"]);
        run(
            &work,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@test",
                "commit",
                "-m",
                "init",
            ],
        );
        run(&work, &["push", "-u", "origin", "HEAD:main"]);

        run(&work, &["checkout", "-b", branch]);
        let mut shas = Vec::new();
        for i in 1..=3 {
            let name = format!("file{i}.txt");
            std::fs::write(work.join(&name), format!("content{i}"))
                .expect("failed to write test file");
            run(&work, &["add", &name]);
            run(
                &work,
                &[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@test",
                    "commit",
                    "-m",
                    &format!("commit {i}"),
                ],
            );
            let sha = run(&work, &["rev-parse", "HEAD"]);
            shas.push(sha);
        }
        run(&work, &["push", "-u", "origin", branch]);

        (remote_dir, shas)
    }

    #[tokio::test]
    async fn rebase_branch_drop_succeeds_through_orchestrator() {
        let branch_name = "agent/test-drop";
        let (remote_dir, shas) = setup_rebase_test_repo(branch_name);

        let remote_path = remote_dir.path().join("remote.git");
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let request = domain::RebaseBranchRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            branch: branch_name.to_string(),
            operations: vec![domain::RebaseOperation::Drop {
                commit: shas[1].clone(),
            }],
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: domain::ForgeKind::Forgejo,
                host: format!(
                    "file://{}",
                    remote_path
                        .parent()
                        .expect("remote path should have parent")
                        .display()
                ),
                name: "remote".to_string(),
                owner: ".".to_string(),
            },
        };

        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig {
                branch_prefix: Some("agent/".to_string()),
                ..domain::policy::PolicyConfig::default()
            },
        };

        let result = orchestrator
            .rebase_branch(
                request,
                authorized,
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("rebase with drop should succeed");

        assert_eq!(result.branch, branch_name);
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "rebase_branch"
        );
    }

    /// Set up a bare remote repo like `setup_rebase_test_repo`, but also
    /// advance `main` after the branch is created, so rebase-onto has work to do.
    fn setup_rebase_onto_test_repo(branch: &str) -> tempfile::TempDir {
        use std::process::Command;

        fn run(dir: &std::path::Path, args: &[&str]) -> String {
            let out = Command::new("git")
                .current_dir(dir)
                .args(args)
                .output()
                .expect("git command");
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout)
                .expect("git output should be valid UTF-8")
                .trim()
                .to_string()
        }

        let remote_dir = tempfile::TempDir::new().expect("failed to create remote temp dir");
        run(remote_dir.path(), &["init", "--bare", "remote.git"]);
        let remote_path = remote_dir.path().join("remote.git");

        // Initial commit on main
        let work_dir = tempfile::TempDir::new().expect("failed to create work temp dir");
        let work = work_dir.path().join("work");
        run(
            work_dir.path(),
            &[
                "clone",
                remote_path
                    .to_str()
                    .expect("remote path should be valid UTF-8"),
                "work",
            ],
        );
        std::fs::write(work.join("README.md"), "# Hello\n").expect("failed to write README.md");
        run(&work, &["add", "README.md"]);
        run(
            &work,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@test",
                "commit",
                "-m",
                "init",
            ],
        );
        run(&work, &["push", "-u", "origin", "HEAD:main"]);

        // Create branch with commits
        run(&work, &["checkout", "-b", branch]);
        for i in 1..=2 {
            let name = format!("branch{i}.txt");
            std::fs::write(work.join(&name), format!("branch-content{i}"))
                .expect("failed to write branch test file");
            run(&work, &["add", &name]);
            run(
                &work,
                &[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@test",
                    "commit",
                    "-m",
                    &format!("branch commit {i}"),
                ],
            );
        }
        run(&work, &["push", "-u", "origin", branch]);

        // Advance main
        run(&work, &["checkout", "main"]);
        std::fs::write(work.join("main-update.txt"), "new main content")
            .expect("failed to write main-update.txt");
        run(&work, &["add", "main-update.txt"]);
        run(
            &work,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@test",
                "commit",
                "-m",
                "advance main",
            ],
        );
        run(&work, &["push", "origin", "main"]);

        remote_dir
    }

    #[tokio::test]
    async fn rebase_branch_rebase_onto_succeeds_through_orchestrator() {
        let branch_name = "agent/test-rebase-onto";
        let remote_dir = setup_rebase_onto_test_repo(branch_name);

        let remote_path = remote_dir.path().join("remote.git");
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let request = domain::RebaseBranchRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            branch: branch_name.to_string(),
            operations: vec![domain::RebaseOperation::RebaseOnto],
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: domain::ForgeKind::Forgejo,
                host: format!(
                    "file://{}",
                    remote_path
                        .parent()
                        .expect("remote path should have parent")
                        .display()
                ),
                name: "remote".to_string(),
                owner: ".".to_string(),
            },
        };

        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig {
                branch_prefix: Some("agent/".to_string()),
                ..domain::policy::PolicyConfig::default()
            },
        };

        let result = orchestrator
            .rebase_branch(
                request,
                authorized,
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect("rebase_onto should succeed");

        assert_eq!(result.branch, branch_name);
        assert_eq!(audit.records().expect("audit records").len(), 1);
        assert_eq!(
            audit.records().expect("audit records")[0].action,
            "rebase_branch"
        );
        assert!(
            audit.records().expect("audit records")[0]
                .target
                .contains("rebase-onto:main")
        );
    }

    #[tokio::test]
    async fn rebase_branch_rebase_onto_rejects_combined_operations() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let request = domain::RebaseBranchRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            branch: "agent/test-combined".to_string(),
            operations: vec![
                domain::RebaseOperation::RebaseOnto,
                domain::RebaseOperation::Drop {
                    commit: "abc123".to_string(),
                },
            ],
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: domain::ForgeKind::Forgejo,
                host: "file:///tmp".to_string(),
                name: "repo".to_string(),
                owner: "owner".to_string(),
            },
        };

        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig {
                branch_prefix: Some("agent/".to_string()),
                ..domain::policy::PolicyConfig::default()
            },
        };

        let err = orchestrator
            .rebase_branch(
                request,
                authorized,
                &domain::ForgeCredential { token: None },
            )
            .await
            .expect_err("should reject combined operations");

        match err {
            ServiceError::Validation(msg) => {
                assert!(
                    msg.contains("cannot be combined"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    // --- validate_rebase_operations tests ---

    #[test]
    fn validate_rebase_operations_rejects_rebase_onto() {
        let ops = vec![domain::RebaseOperation::RebaseOnto];
        let commits = vec!["abc123".to_string()];
        let err = validate_rebase_operations(&ops, &commits).expect_err("should reject RebaseOnto");
        match err {
            ServiceError::Validation(msg) => {
                assert!(
                    msg.contains("cannot appear in commit-level operations"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    // --- resolve_committer_identity tests ---

    #[test]
    fn resolve_committer_identity_uses_forge_user() {
        let user: Result<domain::ForgeUser, String> = Ok(domain::ForgeUser {
            email: "user@forge.example".to_string(),
            username: "forgeuser".to_string(),
        });
        let (name, email) = resolve_committer_identity(user, "agent");
        assert_eq!(name, "forgeuser");
        assert_eq!(email, "user@forge.example");
    }

    #[test]
    fn resolve_committer_identity_falls_back_on_error() {
        let user: Result<domain::ForgeUser, String> =
            Err("unauthorized: token lacks read:user scope".to_string());
        let (name, email) = resolve_committer_identity(user, "claude");
        assert_eq!(name, "claude");
        assert_eq!(email, "claude@forge-mcp");
    }

    #[test]
    fn resolve_committer_identity_falls_back_on_empty_email() {
        let user: Result<domain::ForgeUser, String> = Ok(domain::ForgeUser {
            email: String::new(),
            username: "forgeuser".to_string(),
        });
        let (name, email) = resolve_committer_identity(user, "claude");
        assert_eq!(name, "claude");
        assert_eq!(email, "claude@forge-mcp");
    }

    #[test]
    fn resolve_committer_identity_falls_back_on_empty_username() {
        let user: Result<domain::ForgeUser, String> = Ok(domain::ForgeUser {
            email: "user@forge.example".to_string(),
            username: String::new(),
        });
        let (name, email) = resolve_committer_identity(user, "claude");
        assert_eq!(name, "claude");
        assert_eq!(email, "claude@forge-mcp");
    }

    // --- close_issue orchestrator tests ---

    /// Configurable forge adapter for `close_issue` tests.
    struct CloseIssueTestForgeAdapter {
        state: std::sync::Mutex<CloseIssueAdapterState>,
    }

    struct CloseIssueAdapterState {
        comment_error: bool,
        close_error: bool,
        call_order: Vec<&'static str>,
        comment_body: Option<String>,
    }

    impl CloseIssueTestForgeAdapter {
        fn new(comment_error: bool, close_error: bool) -> Self {
            Self {
                state: std::sync::Mutex::new(CloseIssueAdapterState {
                    comment_error,
                    close_error,
                    call_order: Vec::new(),
                    comment_body: None,
                }),
            }
        }
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for CloseIssueTestForgeAdapter {
        async fn add_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            index: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            let mut state = self.state.lock().expect("poisoned");
            state.call_order.push("close_issue");
            if state.close_error {
                return Err(ForgeError::InvalidPayload("close failed".to_string()));
            }
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index,
                labels: vec![],
                state: "closed".to_string(),
                title: "Issue".to_string(),
                url: format!("https://example.com/issues/{index}"),
            })
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            body: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            let mut state = self.state.lock().expect("poisoned");
            state.call_order.push("comment_on_issue");
            state.comment_body = Some(body.to_string());
            if state.comment_error {
                return Err(ForgeError::InvalidPayload("comment failed".to_string()));
            }
            Ok(IssueComment {
                author: "test-agent".to_string(),
                body: body.to_string(),
                created_at: "2025-01-01T00:00:00Z".to_string(),
                id: 1,
            })
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request_ci_details(
            &self,
            _repo: &RepositoryRef,
            _head_sha: &str,
            _credential: &ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn remove_issue_dependency(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_authenticated_user(
            &self,
            _: &ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn close_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn comment_on_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn create_change_request(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_default_merge_style(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn get_repository_merge_settings(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn list_change_requests(
            &self,
            _: &RepositoryRef,
            _: Option<&ChangeRequestState>,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn read_repository_file(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn schedule_auto_merge(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: Option<bool>,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn submit_change_request_review(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn update_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
        async fn update_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }

        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<Branch>, bool), ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }

        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(ForgeError::Unsupported("test fake".into()))
        }
    }

    fn close_issue_test_repo() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: ForgeKind::Forgejo,
            host: "https://forge.example".to_string(),
            name: "repo".to_string(),
            owner: "org".to_string(),
        }
    }

    fn close_issue_test_request() -> CloseIssueRequest {
        CloseIssueRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            index: 42,
            message: "fixes done".to_string(),
            repository: close_issue_test_repo(),
        }
    }

    // Success path: all four steps complete, two audit records created
    #[tokio::test]
    async fn close_issue_succeeds_and_records_both_audits() {
        let adapter = Arc::new(CloseIssueTestForgeAdapter::new(false, false));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let result = orchestrator
            .close_issue(
                close_issue_test_request(),
                default_authorized(),
                &ForgeCredential { token: None },
            )
            .await
            .expect("close_issue should succeed");

        assert_eq!(result.state, "closed");
        assert_eq!(result.index, 42);

        // Verify both audit records: comment_on_issue first, then close_issue
        let records = audit.records().expect("audit records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, "comment_on_issue");
        assert_eq!(records[0].target, "42");
        assert_eq!(records[1].action, "close_issue");
        assert_eq!(records[1].target, "42");

        // Verify the validated message was passed through and both calls happened in order
        let state = adapter.state.lock().expect("poisoned");
        assert_eq!(
            state.call_order,
            vec!["comment_on_issue", "close_issue"],
            "expected comment then close call order"
        );
        assert_eq!(
            state.comment_body,
            Some("fixes done".to_string()),
            "message should have been propagated to comment"
        );
    }

    // Comment failure: short-circuits after comment_on_issue audit
    #[tokio::test]
    async fn close_issue_fails_on_comment_error() {
        let adapter = Arc::new(CloseIssueTestForgeAdapter::new(true, false));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .close_issue(
                close_issue_test_request(),
                default_authorized(),
                &ForgeCredential { token: None },
            )
            .await
            .expect_err("close_issue should fail");

        assert!(
            matches!(err, ServiceError::Upstream(_)),
            "expected Upstream error, got {err:?}"
        );

        // Only the comment audit should be recorded; close audit must not be reached
        let records = audit.records().expect("audit records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "comment_on_issue");
    }

    // Upstream close failure: both audits recorded, close returns error
    #[tokio::test]
    async fn close_issue_fails_on_close_error() {
        let adapter = Arc::new(CloseIssueTestForgeAdapter::new(false, true));
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .close_issue(
                close_issue_test_request(),
                default_authorized(),
                &ForgeCredential { token: None },
            )
            .await
            .expect_err("close_issue should fail");

        assert!(
            matches!(err, ServiceError::Upstream(_)),
            "expected Upstream error, got {err:?}"
        );

        // Error message should mention the comment may have already been posted
        let err_msg = match err {
            ServiceError::Upstream(ref msg) => msg.as_str(),
            _ => panic!("expected Upstream error"),
        };
        assert!(
            err_msg.contains("closing comment may already have been posted"),
            "error should mention partial success: {err_msg}"
        );

        // Both audit records should be present
        let records = audit.records().expect("audit records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, "comment_on_issue");
        assert_eq!(records[1].action, "close_issue");
    }

    // Audit sink failure: short-circuits on first audit record attempt
    #[tokio::test]
    async fn close_issue_fails_on_first_audit_error() {
        let adapter = Arc::new(CloseIssueTestForgeAdapter::new(false, false));
        let audit = Arc::new(FailingAuditSink);
        let orchestrator = WriteOrchestrator::new(adapter, audit);

        let err = orchestrator
            .close_issue(
                close_issue_test_request(),
                default_authorized(),
                &ForgeCredential { token: None },
            )
            .await
            .expect_err("close_issue should fail on audit error");

        assert!(
            matches!(err, ServiceError::Audit(_)),
            "expected Audit error, got {err:?}"
        );
    }

    /// Audit sink that fails on its Nth call.
    struct ConditionalAuditSink {
        fail_after: Mutex<usize>,
    }

    impl ConditionalAuditSink {
        fn new(fail_after: usize) -> Self {
            Self {
                fail_after: Mutex::new(fail_after),
            }
        }
    }

    #[async_trait::async_trait]
    impl AuditSink for ConditionalAuditSink {
        async fn record(&self, _record: AuditRecord) -> Result<(), AuditError> {
            let mut fail_after = self.fail_after.lock().expect("poisoned");
            *fail_after -= 1;
            if *fail_after == 0 {
                Err(AuditError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    // Close-audit failure: comment posted, second audit fails, upstream close NOT attempted
    #[tokio::test]
    async fn close_issue_fails_on_close_audit_error() {
        let adapter = Arc::new(CloseIssueTestForgeAdapter::new(false, false));
        let audit = Arc::new(ConditionalAuditSink::new(2));
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), audit);

        let err = orchestrator
            .close_issue(
                close_issue_test_request(),
                default_authorized(),
                &ForgeCredential { token: None },
            )
            .await
            .expect_err("close_issue should fail on second audit error");

        assert!(
            matches!(err, ServiceError::Audit(_)),
            "expected Audit error, got {err:?}"
        );

        // Error message must indicate the comment may already have been posted
        let err_msg = match err {
            ServiceError::Audit(ref msg) => msg.as_str(),
            _ => panic!("expected Audit error"),
        };
        assert!(
            err_msg.contains("closing comment may already have been posted"),
            "error should mention partial success: {err_msg}"
        );

        // Only comment_on_issue should have been called; close must NOT be called
        let state = adapter.state.lock().expect("poisoned");
        assert_eq!(state.call_order, vec!["comment_on_issue"]);
        assert_eq!(state.comment_body, Some("fixes done".to_string()));
    }

    struct DependencyTestAdapter {
        state: Mutex<DependencyAdapterState>,
    }

    struct DependencyAdapterState {
        captured_dep_repo: Option<RepositoryRef>,
        captured_dep_for_remove: Option<RepositoryRef>,
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for DependencyTestAdapter {
        async fn add_issue_dependency(
            &self,
            repository: &RepositoryRef,
            index: u64,
            dependency_repository: &RepositoryRef,
            _dependency: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            let mut state = self.state.lock().expect("poisoned");
            state.captured_dep_repo = Some(dependency_repository.clone());
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index,
                labels: vec![],
                state: "open".to_string(),
                title: "Issue".to_string(),
                url: format!(
                    "https://{}/{}/{}/issues/{}",
                    repository.host, repository.owner, repository.name, index
                ),
            })
        }
        async fn add_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn assign_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn close_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn comment_on_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::IssueComment, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn create_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn create_issue(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_combined_commit_status(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::CombinedCommitStatus, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request_ci_details(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::ChangeRequestCiDetails, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_allowed_merge_styles(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_issue_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::IssueComment>, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_issue_dependencies(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<domain::IssueDependencies, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn list_issues(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Issue>, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn list_repositories(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<Vec<domain::Repository>, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn remove_issue_dependency(
            &self,
            repository: &RepositoryRef,
            index: u64,
            dependency_repository: &RepositoryRef,
            _dependency: u64,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            let mut state = self.state.lock().expect("poisoned");
            state.captured_dep_for_remove = Some(dependency_repository.clone());
            Ok(domain::Issue {
                assignees: vec![],
                body: String::new(),
                index,
                labels: vec![],
                state: "open".to_string(),
                title: "Issue".to_string(),
                url: format!(
                    "https://{}/{}/{}/issues/{}",
                    repository.host, repository.owner, repository.name, index
                ),
            })
        }
        async fn remove_issue_label(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_authenticated_user(
            &self,
            _: &ForgeCredential,
        ) -> Result<domain::ForgeUser, ForgeError> {
            Ok(domain::ForgeUser {
                email: "test@test".to_string(),
                username: "test".to_string(),
            })
        }
        async fn close_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn comment_on_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<ChangeRequestComment, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn create_change_request(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &ForgeCredential,
        ) -> Result<String, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn list_change_requests(
            &self,
            _: &RepositoryRef,
            _: Option<&ChangeRequestState>,
            _: &ForgeCredential,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn schedule_auto_merge(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: Option<bool>,
            _: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn submit_change_request_review(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn update_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn update_issue(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: Option<&str>,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::Issue, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn read_repository_file(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: Option<&str>,
            _: &ForgeCredential,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn list_branches(
            &self,
            _: &RepositoryRef,
            _: Option<&str>,
            _: Option<u32>,
            _: &ForgeCredential,
        ) -> Result<(Vec<domain::Branch>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_branch(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: &ForgeCredential,
        ) -> Result<(String, Option<String>, bool), ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_default_merge_style(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
        async fn get_repository_merge_settings(
            &self,
            _: &RepositoryRef,
            _: &ForgeCredential,
        ) -> Result<domain::RepositoryMergeSettings, ForgeError> {
            Err(forge::ForgeError::Unsupported("test fake".into()))
        }
    }

    fn base_repository_ref() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: ForgeKind::Forgejo,
            host: "https://forge.example".to_string(),
            name: "repo".to_string(),
            owner: "org".to_string(),
        }
    }

    fn cross_repo_repository_ref() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: ForgeKind::Forgejo,
            host: "https://forge.example".to_string(),
            name: "other-repo".to_string(),
            owner: "other-org".to_string(),
        }
    }

    fn test_agent() -> AgentIdentity {
        AgentIdentity {
            agent_id: "test-agent".to_string(),
            session_id: "test-session".to_string(),
        }
    }

    // --- Cross-repo audit tests ---

    #[tokio::test]
    async fn add_issue_dependency_audit_same_repo_format() {
        let adapter = DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        };
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::new(adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let req = domain::AddIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: None,
            index: 10,
            repository: repo,
        };

        orchestrator
            .add_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let records = audit.records().expect("audit records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "add_issue_dependency");
        assert_eq!(records[0].target, "#10 depends on #42");
    }

    #[tokio::test]
    async fn add_issue_dependency_audit_cross_repo_format() {
        let adapter = DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        };
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::new(adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let dep_repo = cross_repo_repository_ref();
        let req = domain::AddIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: Some(dep_repo),
            index: 10,
            repository: repo,
        };

        orchestrator
            .add_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let records = audit.records().expect("audit records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "add_issue_dependency");
        assert_eq!(records[0].target, "#10 depends on other-org/other-repo#42");
    }

    #[tokio::test]
    async fn remove_issue_dependency_audit_same_repo_format() {
        let adapter = DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        };
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::new(adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let req = domain::RemoveIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: None,
            index: 10,
            repository: repo,
        };

        orchestrator
            .remove_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let records = audit.records().expect("audit records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "remove_issue_dependency");
        assert_eq!(records[0].target, "#10 no longer depends on #42");
    }

    #[tokio::test]
    async fn remove_issue_dependency_audit_cross_repo_format() {
        let adapter = DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        };
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::new(adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let dep_repo = cross_repo_repository_ref();
        let req = domain::RemoveIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: Some(dep_repo.clone()),
            index: 10,
            repository: repo,
        };

        orchestrator
            .remove_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let records = audit.records().expect("audit records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "remove_issue_dependency");
        assert_eq!(
            records[0].target,
            "#10 no longer depends on other-org/other-repo#42"
        );
    }

    #[tokio::test]
    async fn add_issue_dependency_passes_dep_repo_to_adapter() {
        let adapter = Arc::new(DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let dep_repo = cross_repo_repository_ref();
        let req = domain::AddIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: Some(dep_repo.clone()),
            index: 10,
            repository: repo,
        };

        orchestrator
            .add_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let state = adapter.state.lock().expect("poisoned");
        let captured = state.captured_dep_repo.as_ref().expect("captured dep repo");
        assert_eq!(captured.owner, "other-org");
        assert_eq!(captured.name, "other-repo");
    }

    #[tokio::test]
    async fn add_issue_dependency_same_repo_uses_base_repo_for_adapter() {
        let adapter = Arc::new(DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let req = domain::AddIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: None,
            index: 10,
            repository: repo,
        };

        orchestrator
            .add_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let state = adapter.state.lock().expect("poisoned");
        let captured = state.captured_dep_repo.as_ref().expect("captured dep repo");
        assert_eq!(captured.owner, "org");
        assert_eq!(captured.name, "repo");
    }

    #[tokio::test]
    async fn remove_issue_dependency_passes_dep_repo_to_adapter() {
        let adapter = Arc::new(DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let dep_repo = cross_repo_repository_ref();
        let req = domain::RemoveIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: Some(dep_repo.clone()),
            index: 10,
            repository: repo,
        };

        orchestrator
            .remove_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let state = adapter.state.lock().expect("poisoned");
        let captured = state
            .captured_dep_for_remove
            .as_ref()
            .expect("captured dep repo");
        assert_eq!(captured.owner, "other-org");
        assert_eq!(captured.name, "other-repo");
    }

    #[tokio::test]
    async fn remove_issue_dependency_same_repo_uses_base_repo_for_adapter() {
        let adapter = Arc::new(DependencyTestAdapter {
            state: Mutex::new(DependencyAdapterState {
                captured_dep_repo: None,
                captured_dep_for_remove: None,
            }),
        });
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit));

        let repo = base_repository_ref();
        let req = domain::RemoveIssueDependencyRequest {
            agent: test_agent(),
            dependency: 42,
            dependency_repository: None,
            index: 10,
            repository: repo,
        };

        orchestrator
            .remove_issue_dependency(req, default_authorized(), &ForgeCredential { token: None })
            .await
            .expect("should succeed");

        let state = adapter.state.lock().expect("poisoned");
        let captured = state
            .captured_dep_for_remove
            .as_ref()
            .expect("captured dep repo");
        assert_eq!(captured.owner, "org");
        assert_eq!(captured.name, "repo");
    }
}
