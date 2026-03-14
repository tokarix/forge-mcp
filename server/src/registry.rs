//! Forge registry — maps aliases to forge instances.

use std::collections::HashMap;
use std::sync::Arc;

use domain::{RepositoryReadService, RepositoryWriteService};
use forge::ForgeAdapter;

/// A single forge instance with its adapter and services.
pub struct ForgeInstance {
    pub adapter: Arc<dyn ForgeAdapter>,
    pub alias: String,
    pub base_url: String,
    pub client: reqwest::Client,
    /// Username for git smart HTTP Basic auth (empty string for Forgejo).
    pub git_auth_user: String,
    pub read_service: Arc<dyn RepositoryReadService>,
    pub token: Option<String>,
    pub write_service: Arc<dyn RepositoryWriteService>,
}

impl std::fmt::Debug for ForgeInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeInstance")
            .field("alias", &self.alias)
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

/// Registry mapping forge aliases to instances.
pub struct ForgeRegistry {
    forges: HashMap<String, ForgeInstance>,
}

impl std::fmt::Debug for ForgeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeRegistry")
            .field("forges", &format_args!("[{} entries]", self.forges.len()))
            .finish()
    }
}

impl ForgeRegistry {
    #[must_use]
    pub fn new(forges: HashMap<String, ForgeInstance>) -> Self {
        Self { forges }
    }

    /// Looks up a forge instance by alias.
    #[must_use]
    pub fn get(&self, alias: &str) -> Option<&ForgeInstance> {
        self.forges.get(alias)
    }

    /// Returns the number of registered forges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.forges.len()
    }

    /// Returns true if no forges are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry() {
        let registry = ForgeRegistry::new(HashMap::new());
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn debug_redacts_tokens() {
        let registry = ForgeRegistry::new(HashMap::new());
        let debug = format!("{registry:?}");
        assert!(debug.contains("ForgeRegistry"));
        assert!(debug.contains("0 entries"));
    }
}
