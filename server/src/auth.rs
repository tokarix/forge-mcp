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

/// Extracts an agent token from either Bearer or Basic auth.
///
/// Git clients send Basic auth (`Authorization: Basic base64(user:pass)`),
/// so the git proxy needs to accept the password field as the agent token.
/// Returns an owned `String` because the Basic auth password is decoded
/// from base64, not borrowed from the header value.
#[must_use]
pub fn extract_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get("authorization").and_then(|v| v.to_str().ok())?;

    if let Some(bearer) = value.strip_prefix("Bearer ") {
        return Some(bearer.to_string());
    }

    if let Some(basic) = value.strip_prefix("Basic ") {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(basic.trim())
            .ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        // Format is "user:password" — the password is the agent token
        let password = decoded_str.split_once(':').map(|(_, p)| p)?;
        if password.is_empty() {
            return None;
        }
        return Some(password.to_string());
    }

    None
}

/// Resolved agent identity and policy from a bearer token.
#[derive(Clone, Debug)]
pub struct ResolvedAgent {
    pub forge_identities: HashMap<String, crate::config::ForgeIdentityConfig>,
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
                    forge_identities: agent.forge_identity.clone(),
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
            forge_identity: std::collections::HashMap::new(),
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
    fn extract_token_from_bearer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer my-token".parse().unwrap());
        assert_eq!(extract_token(&headers).as_deref(), Some("my-token"));
    }

    #[test]
    fn extract_token_from_basic_auth() {
        use base64::Engine;
        // Git sends Basic auth with user:password — password is the agent token
        let encoded = base64::engine::general_purpose::STANDARD.encode("git:my-token");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Basic {encoded}").parse().unwrap());
        assert_eq!(extract_token(&headers).as_deref(), Some("my-token"));
    }

    #[test]
    fn extract_token_rejects_basic_with_empty_password() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("git:");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Basic {encoded}").parse().unwrap());
        assert!(extract_token(&headers).is_none());
    }

    #[test]
    fn extract_token_returns_none_without_header() {
        let headers = axum::http::HeaderMap::new();
        assert!(extract_token(&headers).is_none());
    }

    #[test]
    fn debug_redacts_tokens() {
        let registry = AgentRegistry::from_configs(&test_configs());
        let debug = format!("{registry:?}");
        assert!(!debug.contains("test-token-123"));
    }
}
