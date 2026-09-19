//! TOML configuration for the HTTP control plane.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub agents: Vec<AgentConfig>,
    pub forges: Vec<ForgeConfig>,
    pub server: ListenConfig,
}

#[derive(Clone, Deserialize)]
pub struct ListenConfig {
    #[serde(default)]
    pub file_read_diagnostics: FileReadDiagnosticsConfig,
    #[serde(default)]
    pub commit_author_email: Option<String>,
    #[serde(default)]
    pub commit_author_name: Option<String>,
    #[serde(default)]
    pub enable_docs: bool,
    pub listen: String,
}

impl std::fmt::Debug for ListenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenConfig")
            .field("file_read_diagnostics", &"[REDACTED]")
            .field(
                "commit_author_email",
                &self.commit_author_email.as_ref().map(|_| "[REDACTED]"),
            )
            .field("commit_author_name", &self.commit_author_name)
            .field("enable_docs", &self.enable_docs)
            .field("listen", &self.listen)
            .finish()
    }
}

impl ListenConfig {
    /// Returns the normalized global commit identity after configuration
    /// validation.
    #[must_use]
    pub fn commit_author(&self) -> Option<domain::CommitAuthor> {
        self.commit_author_name
            .as_deref()
            .zip(self.commit_author_email.as_deref())
            .map(|(name, email)| domain::CommitAuthor {
                name: name.trim().to_string(),
                email: email.trim().to_string(),
            })
    }
}

/// Exact repository-scoped disclosure approvals. Disabled by default.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReadDiagnosticsConfig {
    #[serde(default)]
    pub repositories: Vec<FileReadDiagnosticRepository>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReadDiagnosticRepository {
    pub forge: String,
    pub owner: String,
    pub repo: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub refs: Vec<String>,
}

impl FileReadDiagnosticsConfig {
    /// Validate bounded configuration without echoing sensitive entries.
    ///
    /// # Errors
    /// Returns a fixed description if any entry is unsafe or excessive.
    pub fn validate(&self) -> Result<(), String> {
        if self.repositories.len() > 64 {
            return Err("too many file diagnostic repositories (maximum 64)".into());
        }
        let mut seen = std::collections::HashSet::new();
        for entry in &self.repositories {
            if ![&entry.forge, &entry.owner, &entry.repo].iter().all(|s| {
                !s.is_empty()
                    && s.len() <= 128
                    && s.as_str() != "."
                    && s.as_str() != ".."
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            }) || !seen.insert((&entry.forge, &entry.owner, &entry.repo))
            {
                return Err("invalid or duplicate file diagnostic repository".into());
            }
            if entry.paths.len() > 128 || entry.refs.len() > 128 {
                return Err("too many file diagnostic values (maximum 128 per field)".into());
            }
            if entry
                .paths
                .iter()
                .chain(&entry.refs)
                .any(|s| !safe_file_diagnostic_value(s))
            {
                return Err("invalid file diagnostic value".into());
            }
        }
        Ok(())
    }
}

/// Conservative ASCII values only; no recursive decoding or truncation.
pub(crate) fn safe_file_diagnostic_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[derive(Clone, Deserialize)]
pub struct ForgeConfig {
    pub alias: String,
    /// Optional REST API root when it differs from `base_url`.
    /// Defaults to `https://api.github.com` for GitHub.com and
    /// `{base_url}/api/v3` for GitHub Enterprise Server.
    pub api_url: Option<String>,
    pub base_url: String,
    #[serde(rename = "type")]
    pub forge_type: String,
    /// Username for git smart HTTP Basic auth (default: empty string).
    /// Forgejo uses empty username with token as password.
    /// GitHub uses "x-access-token" as username.
    #[serde(default)]
    pub git_auth_user: String,
    pub github_app: Option<GitHubAppConfig>,
    pub token: Option<String>,
    pub woodpecker_url: Option<String>,
    pub woodpecker_token: Option<String>,
    pub webhook: Option<ForgeWebhookConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ForgeWebhookConfig {
    #[serde(default = "default_webhook_auto_merge")]
    pub auto_merge: bool,
    pub secret: String,
}

const fn default_webhook_auto_merge() -> bool {
    true
}

/// Credentials for a GitHub App installation.
#[derive(Clone, Debug, Deserialize)]
pub struct GitHubAppConfig {
    pub app_id: u64,
    pub installation_id: u64,
    pub private_key_path: String,
}

impl std::fmt::Debug for ForgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeConfig")
            .field("alias", &self.alias)
            .field("api_url", &self.api_url)
            .field("base_url", &self.base_url)
            .field("forge_type", &self.forge_type)
            .field("git_auth_user", &self.git_auth_user)
            .field("github_app", &self.github_app)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("woodpecker_url", &self.woodpecker_url)
            .field(
                "woodpecker_token",
                &self.woodpecker_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("webhook", &self.webhook.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl ForgeConfig {
    /// Resolves the GitHub REST API root for GitHub.com or GHES.
    #[must_use]
    pub fn github_api_url(&self) -> String {
        self.api_url.clone().unwrap_or_else(|| {
            if self.base_url.trim_end_matches('/') == "https://github.com" {
                "https://api.github.com".to_string()
            } else {
                format!("{}/api/v3", self.base_url.trim_end_matches('/'))
            }
        })
    }
}

#[derive(Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    #[serde(default)]
    pub forge_identity: std::collections::HashMap<String, ForgeIdentityConfig>,
    /// Per-GitHub-forge App installation identities for this agent.
    #[serde(default)]
    pub github_app: std::collections::HashMap<String, GitHubAppConfig>,
    pub policy: AgentPolicyConfig,
    pub session_id: String,
    pub token: String,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("agent_id", &self.agent_id)
            .field("forge_identity", &self.forge_identity)
            .field("github_app", &self.github_app)
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

    /// Returns the owner namespaces the agent can access on the given forge,
    /// derived from `allowed_repos` patterns.
    ///
    /// Returns:
    /// - `None` — no matching patterns for this forge (no access)
    /// - `Some(empty)` — unscoped access (`"*"` or `"alias/*"`)
    /// - `Some(non-empty)` — scoped to these specific owners
    #[must_use]
    pub fn listable_owners(&self, forge_alias: &str) -> Option<std::collections::BTreeSet<String>> {
        let mut owners = std::collections::BTreeSet::new();
        let mut has_unscoped = false;

        for pattern in &self.allowed_repos {
            if pattern == "*" {
                has_unscoped = true;
                continue;
            }
            let Some((alias, rest)) = pattern.split_once('/') else {
                continue;
            };
            if alias != forge_alias {
                continue;
            }
            if rest == "*" {
                has_unscoped = true;
                continue;
            }
            let Some((namespace, _repo_pattern)) = rest.rsplit_once('/') else {
                continue;
            };
            // Both wildcard and exact repo patterns contribute the namespace.
            owners.insert(namespace.to_string());
        }

        if has_unscoped {
            Some(owners)
        } else if owners.is_empty() {
            None
        } else {
            Some(owners)
        }
    }

    /// Returns whether the given owner is accessible by this agent on the
    /// given forge.
    ///
    /// Returns `true` if the agent has unscoped access (`"*"` or
    /// `"alias/*"`) or if the owner is in the set of listable owners.
    #[must_use]
    pub fn is_owner_accessible(&self, forge_alias: &str, owner: &str) -> bool {
        match self.listable_owners(forge_alias) {
            None => false,
            Some(ref owners) if owners.is_empty() => true,
            Some(ref owners) => owners.contains(owner),
        }
    }

    /// Returns whether the agent can list repositories on the given forge.
    ///
    /// Authorization rules:
    /// - `"*"` or `"alias/*"` — allowed
    /// - `"alias/owner/*"` — allowed (owners are resolved via `listable_owners`)
    /// - Exact repo patterns — allowed (handler will fetch specific repos)
    #[must_use]
    pub fn can_list_repositories(&self, forge_alias: &str) -> bool {
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
            let Some((_namespace, repo_pattern)) = rest.rsplit_once('/') else {
                return false;
            };
            if repo_pattern == "*" {
                // Owner wildcard: allowed regardless of owner filter.
                return true;
            }
            // Exact repo pattern: allowed (handler will fetch specific repos).
            true
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

fn validate_github_app(
    app: &GitHubAppConfig,
    owner_kind: &str,
    owner_name: &str,
) -> Result<(), String> {
    if app.app_id == 0 || app.installation_id == 0 {
        return Err(format!(
            "GitHub App {owner_kind} '{owner_name}' requires non-zero app_id and installation_id"
        ));
    }
    if app.private_key_path.trim().is_empty() {
        return Err(format!(
            "GitHub App {owner_kind} '{owner_name}' private_key_path must not be empty"
        ));
    }
    Ok(())
}

fn validate_commit_author(server: &ListenConfig) -> Result<(), String> {
    match (
        server.commit_author_name.as_deref(),
        server.commit_author_email.as_deref(),
    ) {
        (Some(_), None) => {
            Err("server.commit_author_email is required with server.commit_author_name".to_string())
        }
        (None, Some(_)) => {
            Err("server.commit_author_name is required with server.commit_author_email".to_string())
        }
        (Some(name), Some(_)) if name.trim().is_empty() => {
            Err("server.commit_author_name must not be blank".to_string())
        }
        (Some(_), Some(email)) if email.trim().is_empty() => {
            Err("server.commit_author_email must not be blank".to_string())
        }
        (None, None) | (Some(_), Some(_)) => Ok(()),
    }
}

/// Validates the parsed config for semantic correctness.
///
/// # Errors
///
/// Returns a description of the first validation error found.
pub fn validate_config(config: &ServerConfig) -> Result<(), String> {
    const SUPPORTED_FORGE_TYPES: &[&str] = &["forgejo", "github", "gitlab"];
    validate_commit_author(&config.server)?;
    config.server.file_read_diagnostics.validate()?;

    let mut seen_aliases = std::collections::HashSet::new();
    let mut forge_types = std::collections::HashMap::new();
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
        forge_types.insert(forge.alias.clone(), forge.forge_type.as_str());
        if let Some(app) = &forge.github_app {
            if forge.forge_type != "github" {
                return Err(format!(
                    "forge '{}' configures github_app but has type '{}'",
                    forge.alias, forge.forge_type
                ));
            }
            if forge.token.is_some() {
                return Err(format!(
                    "GitHub App forge '{}' must not also configure token",
                    forge.alias
                ));
            }
            validate_github_app(app, "forge", &forge.alias)?;
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

    let mut agent_github_app_owners = std::collections::HashMap::new();
    for agent in &config.agents {
        for forge_alias in agent.forge_identity.keys() {
            if !seen_aliases.contains(forge_alias) {
                return Err(format!(
                    "agent '{}' has forge_identity for unknown forge alias '{forge_alias}'",
                    agent.agent_id
                ));
            }
            if agent.github_app.contains_key(forge_alias) {
                return Err(format!(
                    "agent '{}' must not configure both forge_identity and github_app for forge '{forge_alias}'",
                    agent.agent_id
                ));
            }
        }

        for (forge_alias, app) in &agent.github_app {
            let Some(forge_type) = forge_types.get(forge_alias) else {
                return Err(format!(
                    "agent '{}' has github_app for unknown forge alias '{forge_alias}'",
                    agent.agent_id
                ));
            };
            if *forge_type != "github" {
                return Err(format!(
                    "agent '{}' configures github_app for forge '{forge_alias}' of type '{forge_type}'",
                    agent.agent_id
                ));
            }
            validate_github_app(
                app,
                "agent identity",
                &format!("{}:{forge_alias}", agent.agent_id),
            )?;
            let identity_key = (forge_alias.clone(), app.app_id);
            if let Some(existing_agent) = agent_github_app_owners.get(&identity_key)
                && existing_agent != &agent.agent_id
            {
                return Err(format!(
                    "agents '{existing_agent}' and '{}' use the same GitHub App ID {} for forge '{forge_alias}'; distinct review identities require separate GitHub Apps",
                    agent.agent_id, app.app_id
                ));
            }
            agent_github_app_owners.insert(identity_key, agent.agent_id.clone());
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
enable_docs = true
commit_author_name = "  Test Author  "
commit_author_email = "  author@example.test  "

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://forge.example"
token = "forgejo-api-token"
git_auth_user = "test-bot"
woodpecker_url = "https://ci.example"
woodpecker_token = "synthetic-ci-token"

[forges.webhook]
secret = "distinctive-webhook-secret"

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

    fn config_with_commit_author(name: Option<&str>, email: Option<&str>) -> ServerConfig {
        ServerConfig {
            agents: Vec::new(),
            forges: Vec::new(),
            server: ListenConfig {
                file_read_diagnostics: FileReadDiagnosticsConfig::default(),
                commit_author_email: email.map(str::to_string),
                commit_author_name: name.map(str::to_string),
                enable_docs: false,
                listen: "127.0.0.1:8443".to_string(),
            },
        }
    }

    #[test]
    fn file_diagnostics_are_default_off_bounded_and_fail_closed() {
        let listen: ListenConfig = toml::from_str("listen = '127.0.0.1:8443'").expect("old config");
        assert!(listen.file_read_diagnostics.repositories.is_empty());
        let valid = FileReadDiagnosticRepository {
            forge: "forge".into(),
            owner: "org".into(),
            repo: "repo".into(),
            paths: vec!["src/nested/module.rs".into()],
            refs: vec!["main".into(), "HEAD".into()],
        };
        assert!(
            FileReadDiagnosticsConfig {
                repositories: vec![valid.clone()]
            }
            .validate()
            .is_ok()
        );
        for value in [
            String::new(),
            "/absolute".into(),
            "a//b".into(),
            "a/./b".into(),
            "a/../b".into(),
            "a%2Fb".into(),
            "a%252Fb".into(),
            "a\nb".into(),
            "a\rb".into(),
            "a\u{1b}b".into(),
            "界".into(),
            "a b".into(),
            "*".into(),
            "x".repeat(257),
        ] {
            for is_path in [true, false] {
                let mut entry = valid.clone();
                if is_path {
                    entry.paths = vec![value.clone()];
                } else {
                    entry.refs = vec![value.clone()];
                }
                let result = FileReadDiagnosticsConfig {
                    repositories: vec![entry],
                }
                .validate();
                assert_eq!(result, Err("invalid file diagnostic value".into()));
            }
        }
        assert!(safe_file_diagnostic_value(&"x".repeat(256)));
        let mut entry = valid.clone();
        entry.paths = vec!["x".into(); 129];
        assert!(
            FileReadDiagnosticsConfig {
                repositories: vec![entry]
            }
            .validate()
            .is_err()
        );
        assert!(
            FileReadDiagnosticsConfig {
                repositories: vec![valid.clone(); 65]
            }
            .validate()
            .is_err()
        );
        assert!(
            FileReadDiagnosticsConfig {
                repositories: vec![valid.clone(), valid]
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn validates_and_trims_global_commit_author() {
        let config =
            config_with_commit_author(Some("  Forge MCP  "), Some("  commits@example.test  "));

        validate_config(&config).expect("validate commit author");
        assert_eq!(
            config.server.commit_author(),
            Some(domain::CommitAuthor {
                name: "Forge MCP".to_string(),
                email: "commits@example.test".to_string(),
            })
        );
    }

    #[test]
    fn accepts_omitted_global_commit_author() {
        let config = config_with_commit_author(None, None);

        validate_config(&config).expect("validate omitted commit author");
        assert_eq!(config.server.commit_author(), None);
    }

    #[test]
    fn rejects_global_commit_author_name_without_email() {
        let config = config_with_commit_author(Some("Forge MCP"), None);

        let error = validate_config(&config).expect_err("reject missing email");
        assert!(error.contains("commit_author_email"));
    }

    #[test]
    fn rejects_global_commit_author_email_without_name() {
        let config = config_with_commit_author(None, Some("commits@example.test"));

        let error = validate_config(&config).expect_err("reject missing name");
        assert!(error.contains("commit_author_name"));
    }

    #[test]
    fn rejects_blank_global_commit_author_name() {
        let config = config_with_commit_author(Some("  "), Some("commits@example.test"));

        let error = validate_config(&config).expect_err("reject blank name");
        assert!(error.contains("commit_author_name must not be blank"));
    }

    #[test]
    fn rejects_blank_global_commit_author_email() {
        let config = config_with_commit_author(Some("Forge MCP"), Some("  "));

        let error = validate_config(&config).expect_err("reject blank email");
        assert!(error.contains("commit_author_email must not be blank"));
    }

    #[test]
    fn listen_config_debug_redacts_global_commit_author_email() {
        let config =
            config_with_commit_author(Some("Forge MCP"), Some("sensitive-commits@example.test"));

        let debug = format!("{:?}", config.server);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("sensitive-commits@example.test"));
    }

    #[test]
    fn parses_valid_config() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        validate_config(&config).expect("validate full config");
        assert_eq!(config.server.listen, "0.0.0.0:8443");
        assert!(config.server.enable_docs);
        assert_eq!(
            config.server.commit_author(),
            Some(domain::CommitAuthor {
                name: "Test Author".to_string(),
                email: "author@example.test".to_string(),
            })
        );
        assert_eq!(config.forges.len(), 2);
        assert_eq!(config.forges[0].alias, "internal");
        assert_eq!(config.forges[0].forge_type, "forgejo");
        assert_eq!(config.forges[0].base_url, "https://forge.example");
        assert_eq!(config.forges[0].token.as_deref(), Some("forgejo-api-token"));
        assert_eq!(config.forges[0].git_auth_user, "test-bot");
        assert_eq!(
            config.forges[0].woodpecker_url.as_deref(),
            Some("https://ci.example")
        );
        assert_eq!(
            config.forges[0].woodpecker_token.as_deref(),
            Some("synthetic-ci-token")
        );
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
        validate_config(&config).expect("validate default config");
        assert!(!config.server.enable_docs);
        assert!(config.server.commit_author_name.is_none());
        assert!(config.server.commit_author_email.is_none());
        assert!(config.forges[0].token.is_none());
        assert!(config.forges[0].api_url.is_none());
        assert!(config.forges[0].git_auth_user.is_empty());
        assert!(config.forges[0].github_app.is_none());
        assert!(config.forges[0].woodpecker_url.is_none());
        assert!(config.forges[0].woodpecker_token.is_none());
        assert!(config.forges[0].webhook.is_none());
        assert!(config.agents[0].forge_identity.is_empty());
        assert!(config.agents[0].github_app.is_empty());
        assert!(config.agents[0].policy.allowed_repos.is_empty());
        assert!(config.agents[0].policy.branch_prefix.is_none());
        assert!(config.agents[0].policy.protected_paths.is_empty());
    }

    #[test]
    fn rejects_malformed_toml_with_source_location() {
        let input = VALID_CONFIG.replace("[server]", "[server");
        let error: toml::de::Error = parse_config(&input).expect_err("reject malformed table");
        assert!(error.span().is_some());
        assert!(error.to_string().contains("line"));
    }

    #[test]
    fn rejects_duplicate_keys_and_tables() {
        for (original, duplicate) in [
            (
                "enable_docs = true",
                "enable_docs = true\nenable_docs = false",
            ),
            ("[server]", "[server]\n[server]"),
            (
                "branch_prefix = \"agent/codex/\"",
                "branch_prefix = \"agent/codex/\"\nbranch_prefix = \"other/\"",
            ),
        ] {
            let input = VALID_CONFIG.replace(original, duplicate);
            let error = parse_config(&input).expect_err("reject duplicate definition");
            assert!(error.span().is_some());
        }
    }

    #[test]
    fn rejects_wrong_field_types() {
        for (original, invalid) in [
            ("enable_docs = true", "enable_docs = \"true\""),
            ("listen = \"0.0.0.0:8443\"", "listen = 8443"),
            ("token = \"forgejo-api-token\"", "token = 42"),
            (
                "protected_paths = [\".forgejo/\", \".github/\"]",
                "protected_paths = [42]",
            ),
            (
                "secret = \"distinctive-webhook-secret\"",
                "secret = \"synthetic-secret\"\nauto_merge = \"false\"",
            ),
        ] {
            let input = VALID_CONFIG.replace(original, invalid);
            let error = parse_config(&input).expect_err("reject wrong field type");
            assert!(error.span().is_some());
        }
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
        assert!(
            config.forges[0]
                .webhook
                .as_ref()
                .expect("webhook")
                .auto_merge
        );
    }

    #[test]
    fn parses_disabled_forge_webhook_auto_merge() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "public"
type = "forgejo"
base_url = "https://public.example"

[forges.webhook]
secret = "super-secret"
auto_merge = false

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(
            !config.forges[0]
                .webhook
                .as_ref()
                .expect("webhook")
                .auto_merge
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
        assert!(policy.can_list_repositories("any-forge"));
    }

    #[test]
    fn can_list_repos_forge_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.can_list_repositories("internal"));
        assert!(!policy.can_list_repositories("other"));
    }

    #[test]
    fn can_list_repos_owner_wildcard_allows_without_filter() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.can_list_repositories("internal"));
        // Wrong forge, denied.
        assert!(!policy.can_list_repositories("other"));
    }

    #[test]
    fn can_list_repos_exact_match_allows_without_filter() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/repo".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        // Exact match is allowed (handler fetches specific repos).
        assert!(policy.can_list_repositories("internal"));
    }

    #[test]
    fn can_list_repos_empty_denied() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.can_list_repositories("any"));
    }

    #[test]
    fn can_list_repos_nested_namespace_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["gl/group/subgroup/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.can_list_repositories("gl"));
        assert!(policy.can_list_repositories("gl"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listable_owners_global_wildcard_returns_empty() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        let owners = policy.listable_owners("any-forge");
        assert!(owners.is_some());
        assert!(owners.expect("should be Some").is_empty());
    }

    #[test]
    fn listable_owners_forge_wildcard_returns_empty() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        // For matching forge, unscoped access (empty set).
        let owners = policy.listable_owners("internal");
        assert!(owners.is_some());
        assert!(owners.expect("should be Some").is_empty());
        // For non-matching forge, no access (None).
        assert!(policy.listable_owners("other").is_none());
    }

    #[test]
    fn listable_owners_owner_wildcard_returns_owners() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        let owners = policy
            .listable_owners("internal")
            .expect("should have owners");
        assert_eq!(owners.len(), 1);
        assert!(owners.contains("org"));
    }

    #[test]
    fn listable_owners_exact_match_returns_owner() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/repo".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        let owners = policy
            .listable_owners("internal")
            .expect("should have owners");
        assert_eq!(owners.len(), 1);
        assert!(owners.contains("org"));
    }

    #[test]
    fn listable_owners_multiple_patterns_returns_all_owners() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![
                "internal/org1/*".to_string(),
                "internal/org2/*".to_string(),
                "internal/org3/repo".to_string(),
            ],
            branch_prefix: None,
            protected_paths: vec![],
        };
        let owners = policy
            .listable_owners("internal")
            .expect("should have owners");
        assert_eq!(owners.len(), 3);
        assert!(owners.contains("org1"));
        assert!(owners.contains("org2"));
        assert!(owners.contains("org3"));
    }

    #[test]
    fn listable_owners_nested_namespace_returns_full_path() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["gl/group/subgroup/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        let owners = policy.listable_owners("gl").expect("should have owners");
        assert_eq!(owners.len(), 1);
        assert!(owners.contains("group/subgroup"));
    }

    #[test]
    fn listable_owners_mixed_unscoped_for_other_forge() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/*".to_string(), "other/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        // Has scoped access for "internal".
        let owners = policy
            .listable_owners("internal")
            .expect("should have owners");
        assert_eq!(owners.len(), 1);
        assert!(owners.contains("org"));
        // For "other" forge, has unscoped access (empty set).
        let owners = policy.listable_owners("other");
        assert!(owners.is_some());
        assert!(owners.expect("should be Some").is_empty());
    }

    #[test]
    fn listable_owners_wrong_forge_returns_none() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.listable_owners("other").is_none());
    }

    #[test]
    fn is_owner_accessible_global_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_owner_accessible("any-forge", "any-owner"));
    }

    #[test]
    fn is_owner_accessible_forge_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_owner_accessible("internal", "any-owner"));
        assert!(!policy.is_owner_accessible("other", "any-owner"));
    }

    #[test]
    fn is_owner_accessible_scoped_owner() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_owner_accessible("internal", "org"));
        assert!(!policy.is_owner_accessible("internal", "other-org"));
    }

    #[test]
    fn is_owner_accessible_no_matching_patterns() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.is_owner_accessible("other", "any-owner"));
    }

    #[test]
    fn accepts_github_and_resolves_github_com_api_url() {
        let config = parse_config(
            r#"
[server]
listen = "127.0.0.1:8443"

[[forges]]
alias = "github"
type = "github"
base_url = "https://github.com"

[[agents]]
token = "agent-token"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["github/org/repo"]
"#,
        )
        .expect("parse GitHub config");
        validate_config(&config).expect("validate GitHub config");
        assert_eq!(config.forges[0].github_api_url(), "https://api.github.com");
    }

    #[test]
    fn github_enterprise_api_url_can_be_derived_or_overridden() {
        let mut config = parse_config(
            r#"
[server]
listen = "127.0.0.1:8443"

[[forges]]
alias = "github"
type = "github"
base_url = "https://github.example/"

[[agents]]
token = "agent-token"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["github/org/repo"]
"#,
        )
        .expect("parse GHES config");
        assert_eq!(
            config.forges[0].github_api_url(),
            "https://github.example/api/v3"
        );
        config.forges[0].api_url = Some("https://api.proxy.example/github".to_string());
        assert_eq!(
            config.forges[0].github_api_url(),
            "https://api.proxy.example/github"
        );
    }

    #[test]
    fn accepts_github_app_without_per_agent_identity() {
        let config = parse_config(
            r#"
[server]
listen = "127.0.0.1:8443"

[[forges]]
alias = "github"
type = "github"
base_url = "https://github.com"

[forges.github_app]
app_id = 123
installation_id = 456
private_key_path = "/run/secrets/github-app.pem"

[[agents]]
token = "agent-token"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["github/org/repo"]
"#,
        )
        .expect("parse GitHub App config");
        validate_config(&config).expect("validate GitHub App config");
        let app = config.forges[0]
            .github_app
            .as_ref()
            .expect("GitHub App config");
        assert_eq!(app.app_id, 123);
        assert_eq!(app.installation_id, 456);
    }

    #[test]
    fn accepts_distinct_per_agent_github_apps() {
        let config = parse_config(
            r#"
[server]
listen = "127.0.0.1:8443"

[[forges]]
alias = "github"
type = "github"
base_url = "https://github.com"

[[agents]]
token = "codex-token"
agent_id = "codex"
session_id = "default"

[agents.github_app.github]
app_id = 123
installation_id = 456
private_key_path = "/run/secrets/stintel-codex.pem"

[agents.policy]
allowed_repos = ["github/org/repo"]

[[agents]]
token = "qwen-token"
agent_id = "qwen"
session_id = "default"

[agents.github_app.github]
app_id = 789
installation_id = 101112
private_key_path = "/run/secrets/stintel-qwen.pem"

[agents.policy]
allowed_repos = ["github/org/repo"]
"#,
        )
        .expect("parse per-agent GitHub App config");
        validate_config(&config).expect("validate per-agent GitHub App config");
        assert_eq!(config.agents[0].github_app["github"].app_id, 123);
        assert_eq!(config.agents[1].github_app["github"].app_id, 789);
    }

    #[test]
    fn rejects_two_agent_identity_modes_for_same_forge() {
        let config = parse_config(
            r#"
[server]
listen = "127.0.0.1:8443"

[[forges]]
alias = "github"
type = "github"
base_url = "https://github.com"

[[agents]]
token = "agent-token"
agent_id = "codex"
session_id = "default"

[agents.forge_identity.github]
token = "ambiguous-token"

[agents.github_app.github]
app_id = 123
installation_id = 456
private_key_path = "/run/secrets/stintel-codex.pem"

[agents.policy]
allowed_repos = ["github/org/repo"]
"#,
        )
        .expect("parse conflicting agent identities");
        let error = validate_config(&config).expect_err("reject conflicting agent identities");
        assert!(error.contains("both forge_identity and github_app"));
    }

    #[test]
    fn rejects_reusing_one_github_app_for_distinct_agents() {
        let config = parse_config(
            r#"
[server]
listen = "127.0.0.1:8443"

[[forges]]
alias = "github"
type = "github"
base_url = "https://github.com"

[[agents]]
token = "codex-token"
agent_id = "codex"
session_id = "default"

[agents.github_app.github]
app_id = 123
installation_id = 456
private_key_path = "/run/secrets/stintel-codex.pem"

[agents.policy]
allowed_repos = ["github/org/repo"]

[[agents]]
token = "qwen-token"
agent_id = "qwen"
session_id = "default"

[agents.github_app.github]
app_id = 123
installation_id = 456
private_key_path = "/run/secrets/stintel-codex.pem"

[agents.policy]
allowed_repos = ["github/org/repo"]
"#,
        )
        .expect("parse reused GitHub App config");
        let error = validate_config(&config).expect_err("reject reused GitHub App identity");
        assert!(error.contains("distinct review identities require separate GitHub Apps"));
    }

    #[test]
    fn rejects_github_app_with_static_forge_token() {
        let config = parse_config(
            r#"
[server]
listen = "127.0.0.1:8443"

[[forges]]
alias = "github"
type = "github"
base_url = "https://github.com"
token = "conflicting-token"

[forges.github_app]
app_id = 123
installation_id = 456
private_key_path = "/run/secrets/github-app.pem"

[[agents]]
token = "agent-token"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["github/org/repo"]
"#,
        )
        .expect("parse GitHub App config");
        let error = validate_config(&config).expect_err("reject conflicting credential modes");
        assert!(error.contains("must not also configure token"));
    }

    #[test]
    fn example_config_parses_and_validates() {
        let config = parse_config(include_str!("../../forge-mcp.example.toml"))
            .expect("parse example config");
        validate_config(&config).expect("validate example config");
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
        assert!(!debug.contains("distinctive-webhook-secret"));
        assert!(!debug.contains("synthetic-ci-token"));
        assert!(debug.contains("[REDACTED]"));
    }
}
