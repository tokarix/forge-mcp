//! Audit sink interfaces and a simple in-memory sink for Phase 1.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use domain::{AgentIdentity, RepositoryRef};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub agent: AgentIdentity,
    pub action: String,
    pub repository: RepositoryRef,
    pub target: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit sink unavailable")]
    Unavailable,
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Records an audit event for an agent action.
    ///
    /// # Errors
    ///
    /// Returns an error if the sink cannot persist the record.
    async fn record(&self, record: AuditRecord) -> Result<(), AuditError>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryAuditSink {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl InMemoryAuditSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all recorded audit entries.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().expect("audit mutex poisoned").clone()
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn record(&self, record: AuditRecord) -> Result<(), AuditError> {
        let mut records = self.records.lock().map_err(|_| AuditError::Unavailable)?;
        records.push(record);
        Ok(())
    }
}
