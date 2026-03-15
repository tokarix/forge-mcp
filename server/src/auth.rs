//! Bearer token authentication for the HTTP control plane.

use std::collections::HashMap;

use domain::{AgentIdentity, policy::PolicyConfig};

/// Extracts the bearer token from the Authorization header.
#[must_use]
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Resolved agent identity and policy from a bearer token.
#[derive(Clone, Debug)]
pub struct ResolvedAgent {
    pub identity: AgentIdentity,
    pub policy: PolicyConfig,
    pub policy_config: crate::config::AgentPolicyConfig,
}

/// Registry mapping bearer tokens to agent identities and policies.
#[derive(Clone)]
pub struct AgentRegistry {
    agents: HashMap<String, ResolvedAgent>,
}

impl std::fmt::Debug for AgentRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRegistry")
            .field("agents", &format_args!("[{} entries]", self.agents.len()))
            .finish()
    }
}

impl AgentRegistry {
    /// Creates a registry from a list of agent configs.
    #[must_use]
    pub fn from_configs(configs: &[crate::config::AgentConfig]) -> Self {
        let mut agents = HashMap::new();
        for agent in configs {
            agents.insert(
                agent.token.clone(),
                ResolvedAgent {
                    identity: AgentIdentity {
                        agent_id: agent.agent_id.clone(),
                        session_id: agent.session_id.clone(),
                    },
                    policy: agent.policy.to_policy_config(),
                    policy_config: agent.policy.clone(),
                },
            );
        }
        Self { agents }
    }

    /// Resolves a bearer token to an agent identity and policy.
    #[must_use]
    pub fn resolve(&self, token: &str) -> Option<&ResolvedAgent> {
        self.agents.get(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, AgentPolicyConfig};

    fn test_configs() -> Vec<AgentConfig> {
        vec![AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["test/org/repo".to_string()],
                branch_prefix: Some("agent/codex/".to_string()),
                protected_paths: vec![".github/".to_string()],
            },
            session_id: "default".to_string(),
            token: "test-token-123".to_string(),
        }]
    }

    #[test]
    fn resolves_valid_token() {
        let registry = AgentRegistry::from_configs(&test_configs());
        let agent = registry.resolve("test-token-123").expect("should resolve");
        assert_eq!(agent.identity.agent_id, "codex");
        assert_eq!(agent.identity.session_id, "default");
        assert_eq!(agent.policy.branch_prefix.as_deref(), Some("agent/codex/"));
    }

    #[test]
    fn returns_none_for_invalid_token() {
        let registry = AgentRegistry::from_configs(&test_configs());
        assert!(registry.resolve("wrong-token").is_none());
    }

    #[test]
    fn returns_none_for_empty_token() {
        let registry = AgentRegistry::from_configs(&test_configs());
        assert!(registry.resolve("").is_none());
    }

    #[test]
    fn debug_redacts_tokens() {
        let registry = AgentRegistry::from_configs(&test_configs());
        let debug = format!("{registry:?}");
        assert!(!debug.contains("test-token-123"));
    }
}
