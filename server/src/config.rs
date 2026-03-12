//! TOML configuration for the HTTP control plane.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub agents: Vec<AgentConfig>,
    pub forge: ForgeSection,
    pub server: ListenConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default)]
    pub enable_docs: bool,
    pub listen: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ForgeSection {
    pub forgejo: ForgejoSection,
}

#[derive(Clone, Deserialize)]
pub struct ForgejoSection {
    pub base_url: String,
    pub token: String,
}

impl std::fmt::Debug for ForgejoSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgejoSection")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub policy: AgentPolicyConfig,
    pub session_id: String,
    pub token: String,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("agent_id", &self.agent_id)
            .field("policy", &self.policy)
            .field("session_id", &self.session_id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AgentPolicyConfig {
    #[serde(default)]
    pub allowed_repos: Vec<String>,
    pub branch_prefix: Option<String>,
    #[serde(default)]
    pub protected_paths: Vec<String>,
}

impl AgentPolicyConfig {
    /// Converts to the domain policy config type.
    #[must_use]
    pub fn to_policy_config(&self) -> domain::policy::PolicyConfig {
        domain::policy::PolicyConfig {
            branch_prefix: self.branch_prefix.clone(),
            protected_paths: self.protected_paths.clone(),
        }
    }

    /// Returns whether the agent is allowed to access the given `owner/repo`.
    ///
    /// Semantics (deny-by-default):
    /// - `[]` or field omitted → denies all access.
    /// - `["*"]` → allows all repositories (only wildcard form supported).
    /// - `["owner/repo", ...]` → exact `owner/repo` matching, case-sensitive.
    /// - `["*"]` combined with explicit entries is valid but redundant (the
    ///   wildcard dominates).
    /// - No glob patterns beyond `*` are supported. Entries like `org/*`
    ///   are treated as literal strings and will never match.
    #[must_use]
    pub fn is_repo_allowed(&self, owner: &str, repo: &str) -> bool {
        if self.allowed_repos.iter().any(|r| r == "*") {
            return true;
        }
        let full = format!("{owner}/{repo}");
        self.allowed_repos.iter().any(|r| r == &full)
    }
}

/// Parses a TOML configuration string into a `ServerConfig`.
///
/// # Errors
///
/// Returns an error if the TOML is malformed or missing required fields.
pub fn parse_config(toml_str: &str) -> Result<ServerConfig, toml::de::Error> {
    toml::from_str(toml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
[server]
listen = "0.0.0.0:8443"

[forge.forgejo]
base_url = "https://forge.example"
token = "forgejo-api-token"

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo", "org/other-repo"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]

[[agents]]
token = "bearer-token-for-claude"
agent_id = "claude"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo"]
branch_prefix = "agent/claude/"
protected_paths = [".forgejo/", ".github/"]
"#;

    #[test]
    fn parses_valid_config() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert_eq!(config.server.listen, "0.0.0.0:8443");
        assert_eq!(config.forge.forgejo.base_url, "https://forge.example");
        assert_eq!(config.forge.forgejo.token, "forgejo-api-token");
        assert_eq!(config.agents.len(), 2);
        assert_eq!(config.agents[0].agent_id, "codex");
        assert_eq!(config.agents[0].token, "bearer-token-for-codex");
        assert_eq!(
            config.agents[0].policy.branch_prefix.as_deref(),
            Some("agent/codex/")
        );
        assert_eq!(config.agents[1].agent_id, "claude");
    }

    #[test]
    fn converts_policy_to_domain_type() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        let policy = config.agents[0].policy.to_policy_config();
        assert_eq!(policy.branch_prefix.as_deref(), Some("agent/codex/"));
        assert_eq!(policy.protected_paths, vec![".forgejo/", ".github/"]);
    }

    #[test]
    fn repo_allowlist_enforced() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert!(config.agents[0].policy.is_repo_allowed("org", "repo"));
        assert!(config.agents[0].policy.is_repo_allowed("org", "other-repo"));
        assert!(
            !config.agents[0]
                .policy
                .is_repo_allowed("org", "secret-repo")
        );
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.is_repo_allowed("any", "repo"));
    }

    #[test]
    fn wildcard_allowlist_permits_all() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("any", "repo"));
    }

    #[test]
    fn wildcard_with_explicit_entries_still_permits_all() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["org/repo".to_string(), "*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("other", "thing"));
    }

    #[test]
    fn partial_glob_treated_as_literal() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["org/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.is_repo_allowed("org", "repo"));
    }

    #[test]
    fn rejects_missing_server_section() {
        let toml_str = r#"
[forge.forgejo]
base_url = "https://forge.example"
token = "tok"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        assert!(parse_config(toml_str).is_err());
    }

    #[test]
    fn rejects_missing_forge_token() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[forge.forgejo]
base_url = "https://forge.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        assert!(parse_config(toml_str).is_err());
    }

    #[test]
    fn debug_redacts_tokens() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        let debug = format!("{config:?}");
        assert!(!debug.contains("forgejo-api-token"));
        assert!(!debug.contains("bearer-token-for-codex"));
        assert!(!debug.contains("bearer-token-for-claude"));
        assert!(debug.contains("[REDACTED]"));
    }
}
