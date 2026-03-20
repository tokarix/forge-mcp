//! Workflow orchestration for forge-mcp.

use std::sync::Arc;

use async_trait::async_trait;
use audit::{AuditRecord, AuditSink};
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestDiff,
    ChangeRequestReview, CloseChangeRequestRequest, CommentOnChangeRequestRequest, ForgeCredential,
    GetChangeRequestCommentsRequest, GetChangeRequestDiffRequest, GetChangeRequestRequest,
    ListChangeRequestsRequest, ReadRepositoryFileRequest, ReadRepositoryFileResponse,
    RebaseBranchRequest, RebaseBranchResponse, RepositoryReadService, ScheduleAutoMergeRequest,
    ServiceError, SubmitChangeRequestReviewRequest, validate_repository_path,
};
use forge::ForgeAdapter;

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
    async fn get_change_request_comments(
        &self,
        request: GetChangeRequestCommentsRequest,
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
            .get_change_request_comments(
                &request.repository,
                request.index,
                &ForgeCredential { token: None },
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn get_change_request_diff(
        &self,
        request: GetChangeRequestDiffRequest,
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
            .get_change_request_diff(&request.repository, request.index)
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
            .get_change_request(
                &request.repository,
                request.index,
                &ForgeCredential { token: None },
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn list_change_requests(
        &self,
        request: ListChangeRequestsRequest,
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
            .list_change_requests(&request.repository, request.state.as_ref())
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
    }

    async fn read_repository_file(
        &self,
        request: ReadRepositoryFileRequest,
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
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
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

    let mut fixup_sources: HashSet<String> = HashSet::new();
    let mut fixup_targets: HashSet<String> = HashSet::new();

    for op in operations {
        match op {
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

        // 3. Clone full depth, check out the branch
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

            // 6. List commits in range and validate operations
            let commits = workspace
                .list_commits_in_range(&mb)
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            validate_rebase_operations(&operations, &commits)?;

            // 7. Capture old HEAD SHA and tree SHA
            let old_head = workspace
                .rev_parse("HEAD")
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;
            let old_tree = workspace
                .rev_parse("HEAD^{tree}")
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            // 8. Convert domain operations to git-exec operations
            let git_ops: Vec<git_exec::RebaseOperation> = operations
                .iter()
                .map(|op| match op {
                    domain::RebaseOperation::Fixup { commit, into } => {
                        git_exec::RebaseOperation::Fixup {
                            commit: commit.clone(),
                            into: into.clone(),
                        }
                    }
                })
                .collect();

            // 9. Run rebase
            workspace
                .rebase_interactive(&mb, &git_ops)
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            // 10. Capture new HEAD SHA and tree SHA
            let new_head = workspace
                .rev_parse("HEAD")
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;
            let new_tree = workspace
                .rev_parse("HEAD^{tree}")
                .map_err(|e| ServiceError::GitExec(e.to_string()))?;

            // 11. Verify tree integrity
            if old_tree != new_tree {
                return Err(ServiceError::Validation(format!(
                    "rebase changed the tree: old={old_tree}, new={new_tree}; \
                     this indicates a conflict or data loss"
                )));
            }

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

        // 12. Audit BEFORE push — failure blocks the write
        let op_count = request.operations.len();
        self.audit_sink
            .record(AuditRecord {
                agent: agent_identity,
                action: "rebase_branch".to_string(),
                repository: repository.clone(),
                target: format!(
                    "{}..{} fixup:{op_count} {branch}",
                    &old_head[..8.min(old_head.len())],
                    &new_head[..8.min(new_head.len())],
                ),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 13. Force push with lease (after audit succeeds)
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

    async fn schedule_auto_merge(
        &self,
        request: ScheduleAutoMergeRequest,
        _authorized: domain::policy::AuthorizedWrite,
        credential: &ForgeCredential,
    ) -> Result<(), ServiceError> {
        // 1. Validate merge_style
        match request.merge_style.as_str() {
            "fast-forward-only" | "merge" | "rebase" | "squash" => {}
            other => {
                return Err(ServiceError::Validation(format!(
                    "invalid merge style '{other}': must be rebase, merge, squash, or fast-forward-only"
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

        // 5. Audit before action
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

        // 6. Call adapter
        self.adapter
            .schedule_auto_merge(
                &request.repository,
                request.index,
                &request.merge_style,
                &current_sha,
                credential,
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use audit::{AuditError, AuditRecord, AuditSink, InMemoryAuditSink};
    use domain::{
        AgentIdentity, ChangeRequest, ChangeRequestCommentDetail, ChangeRequestState,
        CloseChangeRequestRequest, CommentOnChangeRequestRequest, CommitPatchRequest, ForgeKind,
        OpenChangeRequestRequest, ReadRepositoryFileRequest, RepositoryReadService, RepositoryRef,
        RepositoryWriteService, ServiceError, SubmitChangeRequestReviewRequest,
    };
    use forge::{ForgeAdapter, ForgeError};

    use super::{ReadOrchestrator, WriteOrchestrator, sanitize_commit_message};

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
        async fn close_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn comment_on_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            unimplemented!()
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
            unimplemented!()
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
        ) -> Result<String, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            repository: &RepositoryRef,
            path: &str,
            git_ref: Option<&str>,
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
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            unimplemented!()
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _event: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            unimplemented!()
        }
    }

    struct FailingForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for FailingForgeAdapter {
        async fn close_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn comment_on_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            unimplemented!()
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
            unimplemented!()
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
        ) -> Result<String, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(ForgeError::InvalidPayload("test error".to_string()))
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            unimplemented!()
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _event: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            unimplemented!()
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
            .read_repository_file(test_request("README.md"))
            .await
            .expect("read should succeed");

        assert_eq!(response.content, "hello");
        assert_eq!(audit.records().len(), 1);
    }

    #[tokio::test]
    async fn rejects_empty_path() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .read_repository_file(test_request(""))
            .await
            .expect_err("empty path should fail");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .read_repository_file(test_request("../../../etc/passwd"))
            .await
            .expect_err("traversal should fail");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn returns_upstream_error_on_forge_failure() {
        let adapter = Arc::new(FailingForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let err = orchestrator
            .read_repository_file(test_request("README.md"))
            .await
            .expect_err("forge failure should propagate");

        assert!(matches!(err, ServiceError::Upstream(_)));
        // Audit was recorded before the forge call
        assert_eq!(audit.records().len(), 1);
    }

    #[tokio::test]
    async fn returns_audit_error_on_sink_failure() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(FailingAuditSink);
        let orchestrator = ReadOrchestrator::new(adapter, audit);

        let err = orchestrator
            .read_repository_file(test_request("README.md"))
            .await
            .expect_err("audit failure should propagate");

        assert!(matches!(err, ServiceError::Audit(_)));
    }

    // --- WriteOrchestrator tests ---

    struct WriteTestForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for WriteTestForgeAdapter {
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
                index,
                merge_base_sha: None,
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
                index: 1,
                merge_base_sha: None,
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
            unimplemented!()
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
                index,
                merge_base_sha: None,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: format!("https://forge.example/org/repo/pulls/{index}"),
            })
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
        ) -> Result<String, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            unimplemented!()
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            unimplemented!()
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
        assert_eq!(audit.records().len(), 0);
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
        assert_eq!(audit.records().len(), 0);
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
        assert_eq!(audit.records().len(), 0);
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
        assert_eq!(audit.records().len(), 0);
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
        assert_eq!(audit.records().len(), 1);
    }

    // --- close_change_request tests ---

    /// Fake adapter where `get_change_request` returns a PR with a
    /// configurable head branch, so we can test prefix enforcement.
    struct CloseTestForgeAdapter {
        head_branch: String,
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for CloseTestForgeAdapter {
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
                index,
                merge_base_sha: None,
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
            unimplemented!()
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
            unimplemented!()
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            unimplemented!()
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
                index,
                merge_base_sha: None,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: format!("https://forge.example/org/repo/pulls/{index}"),
            })
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
        ) -> Result<String, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            unimplemented!()
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            unimplemented!()
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _event: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            unimplemented!()
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
        assert_eq!(audit.records().len(), 1);
        assert_eq!(audit.records()[0].action, "close_change_request");
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
        assert_eq!(audit.records().len(), 0);
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
        assert_eq!(audit.records().len(), 0);
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
        assert_eq!(audit.records().len(), 1);
        assert_eq!(audit.records()[0].action, "comment_on_change_request");
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
        assert_eq!(audit.records().len(), 1);
        assert_eq!(audit.records()[0].action, "submit_change_request_review");
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
        assert_eq!(audit.records().len(), 0);
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
            match &*self.captured.lock().unwrap() {
                CapturedCredential::NotCalled => panic!("adapter was not called"),
                CapturedCredential::Called(t) => t.clone(),
            }
        }
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for CredentialCapturingAdapter {
        async fn close_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn comment_on_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            credential: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            *self.captured.lock().unwrap() = CapturedCredential::Called(credential.token.clone());
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
            unimplemented!()
        }

        async fn get_change_request_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
        ) -> Result<String, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _: &RepositoryRef,
            _: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            unimplemented!()
        }

        async fn schedule_auto_merge(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
            unimplemented!()
        }

        async fn submit_change_request_review(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestReview, ForgeError> {
            unimplemented!()
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
        head_sha: Option<String>,
    }

    #[async_trait::async_trait]
    impl ForgeAdapter for AutoMergeTestForgeAdapter {
        async fn close_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn comment_on_change_request(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &str,
            _: &domain::ForgeCredential,
        ) -> Result<domain::ChangeRequestComment, ForgeError> {
            unimplemented!()
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
            unimplemented!()
        }

        async fn get_change_request_comments(
            &self,
            _: &RepositoryRef,
            _: u64,
            _: &domain::ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            unimplemented!()
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
                index,
                merge_base_sha: None,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: format!("https://forge.example/org/repo/pulls/{index}"),
            })
        }

        async fn get_change_request_diff(
            &self,
            _: &RepositoryRef,
            _: u64,
        ) -> Result<String, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _: &RepositoryRef,
            _: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _: &RepositoryRef,
            _: &str,
            _: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            unimplemented!()
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _credential: &domain::ForgeCredential,
        ) -> Result<(), ForgeError> {
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
            unimplemented!()
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
        let adapter = Arc::new(AutoMergeTestForgeAdapter {
            head_sha: Some("abc123".to_string()),
        });
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
        let adapter = Arc::new(AutoMergeTestForgeAdapter {
            head_sha: Some("abc123".to_string()),
        });
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
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn schedule_auto_merge_head_sha_mismatch() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter {
            head_sha: Some("abc123".to_string()),
        });
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
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn schedule_auto_merge_missing_head_sha() {
        let adapter = Arc::new(AutoMergeTestForgeAdapter { head_sha: None });
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
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn schedule_auto_merge_records_audit() {
        let full_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let adapter = Arc::new(AutoMergeTestForgeAdapter {
            head_sha: Some(full_sha.to_string()),
        });
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

        assert_eq!(audit.records().len(), 1);
        assert_eq!(audit.records()[0].action, "schedule_auto_merge");
        assert!(audit.records()[0].target.contains("squash"));
        // Full SHA must be preserved — not truncated
        assert!(
            audit.records()[0]
                .target
                .contains(&format!("head:{full_sha}"))
        );
        assert!(audit.records()[0].target.contains("#42"));
    }
}
