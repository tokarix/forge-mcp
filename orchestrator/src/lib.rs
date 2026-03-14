//! Workflow orchestration for forge-mcp.

use std::sync::Arc;

use async_trait::async_trait;
use audit::{AuditRecord, AuditSink};
use domain::{
    ChangeRequest, GetChangeRequestRequest, ListChangeRequestsRequest, ReadRepositoryFileRequest,
    ReadRepositoryFileResponse, RepositoryReadService, ServiceError, validate_repository_path,
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
            .get_change_request(&request.repository, request.index)
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
    forge_token: Option<String>,
    policy_config: domain::policy::PolicyConfig,
}

impl<A, S> WriteOrchestrator<A, S>
where
    A: ForgeAdapter + 'static,
    S: AuditSink + 'static,
{
    #[must_use]
    pub fn new(
        adapter: Arc<A>,
        audit_sink: Arc<S>,
        forge_token: Option<String>,
        policy_config: domain::policy::PolicyConfig,
    ) -> Self {
        Self {
            adapter,
            audit_sink,
            forge_token,
            policy_config,
        }
    }
}

#[async_trait]
impl<A, S> domain::RepositoryWriteService for WriteOrchestrator<A, S>
where
    A: ForgeAdapter + 'static,
    S: AuditSink + 'static,
{
    async fn commit_patch(
        &self,
        request: domain::CommitPatchRequest,
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
        let decision = domain::policy::evaluate(&self.policy_config, &policy_context)
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !decision.is_allowed() {
            return Err(ServiceError::PolicyDenied {
                reasons: decision.reasons.join("; "),
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
        let base_branch = request.base_branch.clone();
        let patch = request.patch.clone();
        let new_branch = request.new_branch.clone();
        let commit_message = request.commit_message.clone();
        let agent_id = request.agent.agent_id.clone();
        let token = self.forge_token.clone();

        let git_result = tokio::task::spawn_blocking(move || {
            let workspace =
                git_exec::GitWorkspace::clone_repo(&clone_url, &base_branch, token.as_deref())?;
            workspace.create_branch(&new_branch)?;
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
    ) -> Result<domain::OpenChangeRequestResponse, ServiceError> {
        // 1. Evaluate policy — enforce branch constraints
        let policy_context = domain::policy::PolicyContext {
            action: "open_change_request".to_string(),
            agent: request.agent.clone(),
            repository: request.repository.clone(),
            target_branch: request.head_branch.clone(),
            touched_paths: Vec::new(),
        };
        let decision = domain::policy::evaluate(&self.policy_config, &policy_context)
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
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        Ok(domain::OpenChangeRequestResponse {
            change_request,
            repository: request.repository,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use audit::{AuditError, AuditRecord, AuditSink, InMemoryAuditSink};
    use domain::{
        AgentIdentity, ChangeRequest, ChangeRequestState, CommitPatchRequest, ForgeKind,
        OpenChangeRequestRequest, ReadRepositoryFileRequest, RepositoryReadService, RepositoryRef,
        RepositoryWriteService, ServiceError,
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

        async fn create_change_request(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _head_branch: &str,
            _base_branch: &str,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }
    }

    struct FailingForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for FailingForgeAdapter {
        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Err(ForgeError::InvalidPayload("test error".to_string()))
        }

        async fn create_change_request(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _head_branch: &str,
            _base_branch: &str,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
        ) -> Result<ChangeRequest, ForgeError> {
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
        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            unimplemented!()
        }

        async fn create_change_request(
            &self,
            repository: &RepositoryRef,
            title: &str,
            body: &str,
            head_branch: &str,
            base_branch: &str,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: base_branch.to_string(),
                body: body.to_string(),
                head_branch: head_branch.to_string(),
                index: 1,
                state: ChangeRequestState::Open,
                title: title.to_string(),
                url: format!(
                    "https://forge.example/{}/{}/pulls/1",
                    repository.owner, repository.name
                ),
            })
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
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

    fn default_policy() -> domain::policy::PolicyConfig {
        domain::policy::PolicyConfig::default()
    }

    #[tokio::test]
    async fn commit_patch_rejects_invalid_diff() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator =
            WriteOrchestrator::new(adapter, Arc::clone(&audit), None, default_policy());

        let mut request = write_test_request();
        request.patch = "\
diff --git a/image.png b/image.png
Binary files /dev/null and b/image.png differ
"
        .to_string();

        let err = orchestrator
            .commit_patch(request)
            .await
            .expect_err("binary diff should be rejected");

        assert!(matches!(err, ServiceError::Validation(_)));
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn commit_patch_rejects_wrong_branch_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator =
            WriteOrchestrator::new(adapter, Arc::clone(&audit), None, default_policy());

        let mut request = write_test_request();
        request.new_branch = "main".to_string();

        let err = orchestrator
            .commit_patch(request)
            .await
            .expect_err("wrong branch prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn commit_patch_rejects_protected_paths() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator =
            WriteOrchestrator::new(adapter, Arc::clone(&audit), None, default_policy());

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
            .commit_patch(request)
            .await
            .expect_err("protected path should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn open_change_request_rejects_wrong_branch_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator =
            WriteOrchestrator::new(adapter, Arc::clone(&audit), None, default_policy());

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
            .open_change_request(request)
            .await
            .expect_err("wrong branch prefix should be rejected");

        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn open_change_request_records_audit_and_creates() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator =
            WriteOrchestrator::new(adapter, Arc::clone(&audit), None, default_policy());

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
            .open_change_request(request)
            .await
            .expect("should succeed");

        assert_eq!(response.change_request.index, 1);
        assert_eq!(audit.records().len(), 1);
    }
}
