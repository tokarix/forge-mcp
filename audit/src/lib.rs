//! Audit sink interfaces and a simple in-memory sink for Phase 1.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub agent_id: String,
    pub action: String,
    pub repository: String,
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

    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        match self.records.lock() {
            Ok(records) => records.clone(),
            Err(_) => Vec::new(),
        }
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
