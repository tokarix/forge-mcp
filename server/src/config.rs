//! TOML configuration for the HTTP control plane.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub agents: Vec<AgentConfig>,
    pub forges: Vec<ForgeConfig>,
    pub server: ListenConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default)]
    pub enable_docs: bool,
    pub listen: String,
}

#[derive(Clone, Deserialize)]
pub struct ForgeConfig {
    pub alias: String,
    pub base_url: String,
    #[serde(rename = "type")]
    pub forge_type: String,
    /// Username for git smart HTTP Basic auth (default: empty string).
    /// Forgejo uses empty username with token as password.
    /// GitHub uses "x-access-token" as username.
    #[serde(default)]
    pub git_auth_user: String,
    pub token: Option<String>,
    pub webhook: Option<ForgeWebhookConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ForgeWebhookConfig {
    pub secret: String,
}

impl std::fmt::Debug for ForgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeConfig")
            .field("alias", &self.alias)
            .field("base_url", &self.base_url)
            .field("forge_type", &self.forge_type)
            .field("git_auth_user", &self.git_auth_user)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("webhook", &self.webhook.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    #[serde(default)]
    pub forge_identity: std::collections::HashMap<String, ForgeIdentityConfig>,
    pub policy: AgentPolicyConfig,
    pub session_id: String,
    pub token: String,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("agent_id", &self.agent_id)
            .field("forge_identity", &self.forge_identity)
            .field("policy", &self.policy)
            .field("session_id", &self.session_id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Per-forge identity credentials for an agent.
#[derive(Clone, Deserialize)]
pub struct ForgeIdentityConfig {
    pub token: String,
}

impl std::fmt::Debug for ForgeIdentityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeIdentityConfig")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Result of extracting forge aliases from an agent's `allowed_repos` patterns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowedForges {
    /// Agent has a `"*"` pattern -- access to all forges.
    All,
    /// Agent has access to specific forge aliases only.
    Specific(std::collections::HashSet<String>),
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

    /// Returns the set of forge aliases this agent may access.
    ///
    /// Extracts unique forge aliases from `allowed_repos` patterns.
    /// A `"*"` pattern grants access to all forges.
    #[must_use]
    pub fn allowed_forge_aliases(&self) -> AllowedForges {
        let mut aliases = std::collections::HashSet::new();
        for pattern in &self.allowed_repos {
            if pattern == "*" {
                return AllowedForges::All;
            }
            if let Some(alias) = pattern.split('/').next()
                && alias != "*"
                && !alias.is_empty()
            {
                aliases.insert(alias.to_string());
            }
        }
        AllowedForges::Specific(aliases)
    }

    /// Returns whether the agent can list repositories on the given forge,
    /// optionally restricted to an owner filter.
    ///
    /// Authorization rules:
    /// - `"*"` or `"alias/*"` — allowed with any (or no) owner filter
    /// - `"alias/owner/*"` — allowed only when `owner_filter` matches the
    ///   pattern's namespace
    /// - Exact repo patterns — never sufficient for listing
    #[must_use]
    pub fn can_list_repositories(&self, forge_alias: &str, owner_filter: Option<&str>) -> bool {
        self.allowed_repos.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            let Some((alias, rest)) = pattern.split_once('/') else {
                return false;
            };
            if alias != forge_alias {
                return false;
            }
            if rest == "*" {
                return true;
            }
            let Some((namespace, repo_pattern)) = rest.rsplit_once('/') else {
                return false;
            };
            // Only wildcard repo patterns grant listing rights.
            if repo_pattern != "*" {
                return false;
            }
            // Namespace wildcard: owner filter must match the namespace.
            match owner_filter {
                Some(owner) => namespace == owner,
                None => false,
            }
        })
    }

    /// Returns whether the agent is allowed to access the given repo.
    ///
    /// Patterns use `forge/namespace/repo` paths with wildcard support:
    /// - `"*"` — all repos on all forges
    /// - `"alias/*"` — all repos on a specific forge
    /// - `"alias/owner/*"` — all repos under an owner/namespace
    /// - `"alias/owner/repo"` — exact match
    /// - `"alias/group/subgroup/repo"` — exact match with nested namespace
    /// - `"alias/group/subgroup/*"` — all repos under a nested namespace
    #[must_use]
    pub fn is_repo_allowed(&self, forge_alias: &str, owner: &str, repo: &str) -> bool {
        self.allowed_repos.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            let Some((alias, rest)) = pattern.split_once('/') else {
                return false;
            };
            if alias != forge_alias {
                return false;
            }
            if rest == "*" {
                return true;
            }
            let Some((namespace, repo_pattern)) = rest.rsplit_once('/') else {
                return false;
            };
            if repo_pattern == "*" {
                namespace == owner
            } else {
                namespace == owner && repo_pattern == repo
            }
        })
    }
}

/// Validates a forge alias: must match `[a-z0-9][a-z0-9-]*`.
///
/// # Errors
///
/// Returns a description if the alias is invalid.
pub fn validate_forge_alias(alias: &str) -> Result<(), String> {
    if alias.is_empty() {
        return Err("forge alias must not be empty".to_string());
    }
    let first = alias.as_bytes()[0];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(format!(
            "forge alias '{alias}' must start with a lowercase letter or digit"
        ));
    }
    if !alias
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "forge alias '{alias}' may only contain lowercase letters, digits, and hyphens"
        ));
    }
    Ok(())
}

/// Validates the parsed config for semantic correctness.
///
/// # Errors
///
/// Returns a description of the first validation error found.
pub fn validate_config(config: &ServerConfig) -> Result<(), String> {
    const SUPPORTED_FORGE_TYPES: &[&str] = &["forgejo", "gitlab"];

    let mut seen_aliases = std::collections::HashSet::new();
    for forge in &config.forges {
        validate_forge_alias(&forge.alias)?;
        if !seen_aliases.insert(&forge.alias) {
            return Err(format!("duplicate forge alias '{}'", forge.alias));
        }
        if !SUPPORTED_FORGE_TYPES.contains(&forge.forge_type.as_str()) {
            return Err(format!(
                "unsupported forge type '{}' for alias '{}' (supported: {})",
                forge.forge_type,
                forge.alias,
                SUPPORTED_FORGE_TYPES.join(", ")
            ));
        }
        if let Some(webhook) = &forge.webhook
            && webhook.secret.trim().is_empty()
        {
            return Err(format!(
                "forge '{}' webhook secret must not be empty",
                forge.alias
            ));
        }
    }

    for agent in &config.agents {
        for forge_alias in agent.forge_identity.keys() {
            if !seen_aliases.contains(forge_alias) {
                return Err(format!(
                    "agent '{}' has forge_identity for unknown forge alias '{forge_alias}'",
                    agent.agent_id
                ));
            }
        }

        for pattern in &agent.policy.allowed_repos {
            if pattern == "*" {
                continue;
            }
            // Validate pattern shape: alias/*, alias/ns/*, alias/ns/repo,
            // or alias/group/subgroup/repo (variable-depth namespace).
            let Some((forge_part, rest)) = pattern.split_once('/') else {
                return Err(format!(
                    "agent '{}' has malformed allowed_repos pattern '{pattern}' \
                     (expected alias/*, alias/namespace/*, or alias/namespace/repo)",
                    agent.agent_id
                ));
            };
            // After the alias, we need at least one segment (the wildcard or
            // a namespace/repo pair).
            if rest.is_empty() {
                return Err(format!(
                    "agent '{}' has malformed allowed_repos pattern '{pattern}' \
                     (expected alias/*, alias/namespace/*, or alias/namespace/repo)",
                    agent.agent_id
                ));
            }
            if forge_part != "*" && !seen_aliases.contains(&forge_part.to_string()) {
                return Err(format!(
                    "agent '{}' references unknown forge alias '{forge_part}' in allowed_repos pattern '{pattern}'",
                    agent.agent_id
                ));
            }
        }
    }

    Ok(())
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
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://forge.example"
token = "forgejo-api-token"

[[forges]]
alias = "client-a"
type = "forgejo"
base_url = "https://client.example"
token = "client-token"

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["internal/org/repo", "internal/org/other-repo", "client-a/org/*"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]

[agents.forge_identity.internal]
token = "codex-bot-forgejo-token"

[[agents]]
token = "bearer-token-for-claude"
agent_id = "claude"
session_id = "default"

[agents.policy]
allowed_repos = ["internal/org/repo"]
branch_prefix = "agent/claude/"
protected_paths = [".forgejo/", ".github/"]

[agents.forge_identity.internal]
token = "claude-bot-forgejo-token"
"#;

    #[test]
    fn parses_valid_config() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert_eq!(config.server.listen, "0.0.0.0:8443");
        assert_eq!(config.forges.len(), 2);
        assert_eq!(config.forges[0].alias, "internal");
        assert_eq!(config.forges[0].forge_type, "forgejo");
        assert_eq!(config.forges[0].base_url, "https://forge.example");
        assert_eq!(config.forges[0].token.as_deref(), Some("forgejo-api-token"));
        assert_eq!(config.forges[1].alias, "client-a");
        assert_eq!(config.agents.len(), 2);
        // Verify forge_identity parsing
        assert_eq!(config.agents[0].forge_identity.len(), 1);
        assert!(config.agents[0].forge_identity.contains_key("internal"));
        assert_eq!(config.agents[1].forge_identity.len(), 1);
        assert!(config.agents[1].forge_identity.contains_key("internal"));
    }

    #[test]
    fn parses_forge_without_token() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "public"
type = "forgejo"
base_url = "https://public.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(config.forges[0].token.is_none());
    }

    #[test]
    fn parses_forge_webhook_config() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "public"
type = "forgejo"
base_url = "https://public.example"

[forges.webhook]
secret = "super-secret"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert_eq!(
            config.forges[0]
                .webhook
                .as_ref()
                .map(|webhook| webhook.secret.as_str()),
            Some("super-secret")
        );
    }

    #[test]
    fn converts_policy_to_domain_type() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        let policy = config.agents[0].policy.to_policy_config();
        assert_eq!(policy.branch_prefix.as_deref(), Some("agent/codex/"));
        assert_eq!(policy.protected_paths, vec![".forgejo/", ".github/"]);
    }

    #[test]
    fn repo_exact_match() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert!(
            config.agents[0]
                .policy
                .is_repo_allowed("internal", "org", "repo")
        );
        assert!(
            config.agents[0]
                .policy
                .is_repo_allowed("internal", "org", "other-repo")
        );
        assert!(
            !config.agents[0]
                .policy
                .is_repo_allowed("internal", "org", "secret")
        );
    }

    #[test]
    fn repo_owner_wildcard() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert!(
            config.agents[0]
                .policy
                .is_repo_allowed("client-a", "org", "any-repo")
        );
        assert!(
            !config.agents[0]
                .policy
                .is_repo_allowed("client-a", "other-org", "repo")
        );
    }

    #[test]
    fn repo_forge_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("internal", "any", "repo"));
        assert!(!policy.is_repo_allowed("other", "any", "repo"));
    }

    #[test]
    fn repo_global_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("any-forge", "any", "repo"));
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.is_repo_allowed("forge", "any", "repo"));
    }

    #[test]
    fn partial_glob_treated_as_literal() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/repo-*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.is_repo_allowed("internal", "org", "repo-foo"));
    }

    #[test]
    fn validates_forge_alias_format() {
        assert!(validate_forge_alias("internal").is_ok());
        assert!(validate_forge_alias("client-a").is_ok());
        assert!(validate_forge_alias("forge123").is_ok());
        assert!(validate_forge_alias("a").is_ok());
        assert!(validate_forge_alias("-bad").is_err());
        assert!(validate_forge_alias("").is_err());
        assert!(validate_forge_alias("BAD").is_err());
        assert!(validate_forge_alias("has/slash").is_err());
        assert!(validate_forge_alias("has.dot").is_err());
    }

    #[test]
    fn rejects_duplicate_forge_aliases() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "dupe"
type = "forgejo"
base_url = "https://a.example"

[[forges]]
alias = "dupe"
type = "forgejo"
base_url = "https://b.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_empty_webhook_secret() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://a.example"

[forges.webhook]
secret = "   "

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        let err = validate_config(&config).expect_err("should reject empty secret");
        assert!(err.contains("webhook secret"));
    }

    #[test]
    fn rejects_invalid_forge_alias_in_allowed_repos() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://a.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
allowed_repos = ["nonexistent/org/repo"]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_missing_forges_section() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        assert!(parse_config(toml_str).is_err());
    }

    #[test]
    fn rejects_unsupported_forge_type() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "bitbucket"
base_url = "https://a.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        let err = validate_config(&config).expect_err("should reject unknown type");
        assert!(err.contains("unsupported forge type 'bitbucket'"));
        assert!(err.contains("internal"));
    }

    #[test]
    fn accepts_gitlab_forge_type() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "gl"
type = "gitlab"
base_url = "https://gitlab.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_forge_identity_unknown_alias() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://a.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
allowed_repos = ["internal/*"]

[agents.forge_identity.nonexistent]
token = "some-token"
"#;
        let config = parse_config(toml_str).expect("should parse");
        let err = validate_config(&config).expect_err("should reject unknown forge alias");
        assert!(err.contains("nonexistent"));
        assert!(err.contains("forge_identity"));
    }

    #[test]
    fn allowed_forge_aliases_global_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert_eq!(policy.allowed_forge_aliases(), AllowedForges::All);
    }

    #[test]
    fn allowed_forge_aliases_specific() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![
                "internal/org/repo".to_string(),
                "internal/org/other".to_string(),
                "external/*".to_string(),
            ],
            branch_prefix: None,
            protected_paths: vec![],
        };
        let result = policy.allowed_forge_aliases();
        match result {
            AllowedForges::Specific(set) => {
                assert_eq!(set.len(), 2);
                assert!(set.contains("internal"));
                assert!(set.contains("external"));
            }
            AllowedForges::All => panic!("expected Specific"),
        }
    }

    #[test]
    fn allowed_forge_aliases_empty() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert_eq!(
            policy.allowed_forge_aliases(),
            AllowedForges::Specific(std::collections::HashSet::new())
        );
    }

    #[test]
    fn rejects_malformed_allowed_repos_pattern() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://a.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
allowed_repos = ["internal"]
"#;
        let config = parse_config(toml_str).expect("should parse");
        let err = validate_config(&config).expect_err("should reject bare alias");
        assert!(err.contains("malformed"));
        assert!(err.contains("internal"));
    }

    #[test]
    fn repo_nested_namespace_exact_match() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["gl/group/subgroup/repo".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("gl", "group/subgroup", "repo"));
        assert!(!policy.is_repo_allowed("gl", "group", "subgroup"));
        assert!(!policy.is_repo_allowed("gl", "group/subgroup", "other"));
    }

    #[test]
    fn repo_nested_namespace_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["gl/group/subgroup/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("gl", "group/subgroup", "any-repo"));
        assert!(!policy.is_repo_allowed("gl", "group", "any-repo"));
        assert!(!policy.is_repo_allowed("other", "group/subgroup", "repo"));
    }

    #[test]
    fn repo_deeply_nested_namespace() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["gl/a/b/c/repo".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("gl", "a/b/c", "repo"));
        assert!(!policy.is_repo_allowed("gl", "a/b", "repo"));
    }

    #[test]
    fn allowed_forge_aliases_nested_namespace() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![
                "gl/group/subgroup/repo".to_string(),
                "internal/org/repo".to_string(),
            ],
            branch_prefix: None,
            protected_paths: vec![],
        };
        let result = policy.allowed_forge_aliases();
        match result {
            AllowedForges::Specific(set) => {
                assert_eq!(set.len(), 2);
                assert!(set.contains("gl"));
                assert!(set.contains("internal"));
            }
            AllowedForges::All => panic!("expected Specific"),
        }
    }

    #[test]
    fn validates_nested_namespace_pattern() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "gl"
type = "gitlab"
base_url = "https://gitlab.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
allowed_repos = ["gl/group/subgroup/repo", "gl/group/subgroup/*"]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn can_list_repos_global_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.can_list_repositories("any-forge", None));
        assert!(policy.can_list_repositories("any-forge", Some("any-owner")));
    }

    #[test]
    fn can_list_repos_forge_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.can_list_repositories("internal", None));
        assert!(policy.can_list_repositories("internal", Some("any-owner")));
        assert!(!policy.can_list_repositories("other", None));
    }

    #[test]
    fn can_list_repos_owner_wildcard_requires_owner_filter() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        // Must provide matching owner filter.
        assert!(policy.can_list_repositories("internal", Some("org")));
        // Without owner filter, denied.
        assert!(!policy.can_list_repositories("internal", None));
        // Wrong owner, denied.
        assert!(!policy.can_list_repositories("internal", Some("other-org")));
        // Wrong forge, denied.
        assert!(!policy.can_list_repositories("other", Some("org")));
    }

    #[test]
    fn can_list_repos_exact_match_denied() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/repo".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.can_list_repositories("internal", None));
        assert!(!policy.can_list_repositories("internal", Some("org")));
    }

    #[test]
    fn can_list_repos_empty_denied() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.can_list_repositories("any", None));
    }

    #[test]
    fn can_list_repos_nested_namespace_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["gl/group/subgroup/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.can_list_repositories("gl", Some("group/subgroup")));
        assert!(!policy.can_list_repositories("gl", Some("group")));
        assert!(!policy.can_list_repositories("gl", None));
    }

    #[test]
    fn debug_redacts_tokens() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        let debug = format!("{config:?}");
        assert!(!debug.contains("forgejo-api-token"));
        assert!(!debug.contains("client-token"));
        assert!(!debug.contains("bearer-token-for-codex"));
        assert!(!debug.contains("bearer-token-for-claude"));
        assert!(!debug.contains("codex-bot-forgejo-token"));
        assert!(!debug.contains("claude-bot-forgejo-token"));
        assert!(debug.contains("[REDACTED]"));
    }
}
