//! Read workflow orchestration for Phase 1.

use std::sync::Arc;

use async_trait::async_trait;
use audit::{AuditRecord, AuditSink};
use domain::{
    ReadRepositoryFileRequest, ReadRepositoryFileResponse, RepositoryReadService, ServiceError,
    validate_repository_path,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use audit::{AuditError, AuditRecord, AuditSink, InMemoryAuditSink};
    use domain::{
        AgentIdentity, ChangeRequest, ChangeRequestState, ForgeKind, ReadRepositoryFileRequest,
        RepositoryReadService, RepositoryRef, ServiceError,
    };
    use forge::{ForgeAdapter, ForgeError};

    use super::ReadOrchestrator;

    fn test_request(path: &str) -> ReadRepositoryFileRequest {
        ReadRepositoryFileRequest {
            agent: AgentIdentity {
                agent_id: "codex".to_string(),
                session_id: "test".to_string(),
            },
            repository: RepositoryRef {
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                owner: "org".to_string(),
                name: "repo".to_string(),
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
}
