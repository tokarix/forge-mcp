//! Workflow orchestration for forge-mcp.

use std::sync::Arc;

use async_trait::async_trait;
use audit::{AuditRecord, AuditSink};
use domain::{
    ChangeRequest, ChangeRequestComment, ChangeRequestDiff, ChangeRequestReview,
    CloseChangeRequestRequest, CommentOnChangeRequestRequest, ForgeCredential,
    GetChangeRequestDiffRequest, GetChangeRequestRequest, ListChangeRequestsRequest,
    ReadRepositoryFileRequest, ReadRepositoryFileResponse, RepositoryReadService, ServiceError,
    SubmitChangeRequestReviewRequest, validate_repository_path,
};
use forge::ForgeAdapter;

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
        let commit_message = request.commit_message.clone();
        let agent_id = request.agent.agent_id.clone();
        let token = credential.token.clone();

        let git_result = tokio::task::spawn_blocking(move || {
            let workspace =
                git_exec::GitWorkspace::clone_repo(&clone_url, &clone_branch, token.as_deref())?;
            if !existing {
                workspace.create_branch(&new_branch)?;
            }
            workspace.apply_patch(&patch)?;
            let result =
                workspace.commit(&commit_message, &agent_id, &format!("{agent_id}@forge-mcp"))?;
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
        AgentIdentity, ChangeRequest, ChangeRequestState, CloseChangeRequestRequest,
        CommentOnChangeRequestRequest, CommitPatchRequest, ForgeKind, OpenChangeRequestRequest,
        ReadRepositoryFileRequest, RepositoryReadService, RepositoryRef, RepositoryWriteService,
        ServiceError, SubmitChangeRequestReviewRequest,
    };
    use forge::{ForgeAdapter, ForgeError};

    use super::{ReadOrchestrator, WriteOrchestrator};

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
}
