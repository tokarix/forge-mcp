//! Policy engine — pure, deterministic policy evaluation.
//!
//! Evaluates whether an agent action is allowed based on configurable
//! rules. The engine is synchronous and has no side effects.

use thiserror::Error;

use crate::{AgentIdentity, RepositoryRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub reasons: Vec<String>,
}

impl PolicyDecision {
    #[must_use]
    pub fn allow() -> Self {
        Self {
            effect: PolicyEffect::Allow,
            reasons: Vec::new(),
        }
    }

    #[must_use]
    pub fn deny(reasons: Vec<String>) -> Self {
        Self {
            effect: PolicyEffect::Deny,
            reasons,
        }
    }

    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.effect == PolicyEffect::Allow
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyContext {
    pub action: String,
    pub agent: AgentIdentity,
    pub repository: RepositoryRef,
    pub target_branch: String,
    pub touched_paths: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy configuration error: {0}")]
    Configuration(String),
}

/// Proof that the handler layer evaluated policy for this write operation.
/// The orchestrator uses the contained policy config for write-side invariant
/// checks (diff validation, branch prefix, protected paths).
#[derive(Clone, Debug)]
pub struct AuthorizedWrite {
    pub policy: PolicyConfig,
}

/// Policy rule configuration.
#[derive(Clone, Debug)]
pub struct PolicyConfig {
    /// Required prefix for agent-created branches (e.g. "agent/").
    pub branch_prefix: Option<String>,
    /// Paths that agents are not allowed to modify.
    pub protected_paths: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            branch_prefix: Some("agent/".to_string()),
            protected_paths: vec![
                ".forgejo/".to_string(),
                ".gitea/".to_string(),
                ".github/".to_string(),
                ".gitlab/".to_string(),
            ],
        }
    }
}

/// Evaluates a policy context against the given configuration.
///
/// # Errors
///
/// Returns a `PolicyError` if the configuration is invalid.
pub fn evaluate(
    config: &PolicyConfig,
    context: &PolicyContext,
) -> Result<PolicyDecision, PolicyError> {
    let mut deny_reasons = Vec::new();

    // Check branch prefix
    if let Some(prefix) = &config.branch_prefix
        && !context.target_branch.starts_with(prefix.as_str())
    {
        deny_reasons.push(format!(
            "branch '{}' does not start with required prefix '{prefix}'",
            context.target_branch
        ));
    }

    // Check protected paths
    for touched in &context.touched_paths {
        for protected in &config.protected_paths {
            if touched.starts_with(protected.as_str()) || touched == protected.trim_end_matches('/')
            {
                deny_reasons.push(format!(
                    "path '{touched}' is under protected path '{protected}'"
                ));
            }
        }
    }

    if deny_reasons.is_empty() {
        Ok(PolicyDecision::allow())
    } else {
        Ok(PolicyDecision::deny(deny_reasons))
    }
}

#[cfg(test)]
mod tests {
    use crate::{AgentIdentity, ForgeKind, RepositoryRef};

    use super::*;

    fn test_context(branch: &str, paths: Vec<&str>) -> PolicyContext {
        PolicyContext {
            action: "commit_patch".to_string(),
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            repository: RepositoryRef {
                alias: "test".to_string(),
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            target_branch: branch.to_string(),
            touched_paths: paths.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn allows_valid_branch_and_paths() {
        let config = PolicyConfig::default();
        let ctx = test_context("agent/fix-typo", vec!["README.md", "src/main.rs"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(decision.is_allowed());
    }

    #[test]
    fn denies_wrong_branch_prefix() {
        let config = PolicyConfig::default();
        let ctx = test_context("main", vec!["README.md"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
        assert!(decision.reasons[0].contains("does not start with"));
    }

    #[test]
    fn denies_protected_github_path() {
        let config = PolicyConfig::default();
        let ctx = test_context("agent/fix", vec![".github/workflows/ci.yml"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
        assert!(decision.reasons[0].contains("protected path"));
    }

    #[test]
    fn denies_protected_forgejo_path() {
        let config = PolicyConfig::default();
        let ctx = test_context("agent/fix", vec![".forgejo/workflows/ci.yml"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
    }

    #[test]
    fn allows_when_no_branch_prefix_configured() {
        let config = PolicyConfig {
            branch_prefix: None,
            protected_paths: Vec::new(),
        };
        let ctx = test_context("main", vec!["anything.txt"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(decision.is_allowed());
    }

    #[test]
    fn collects_multiple_deny_reasons() {
        let config = PolicyConfig::default();
        let ctx = test_context("main", vec![".github/workflows/ci.yml"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
        assert!(decision.reasons.len() >= 2); // branch + path
    }

    #[test]
    fn default_config_has_expected_protected_paths() {
        let config = PolicyConfig::default();
        assert_eq!(config.protected_paths.len(), 4);
        assert!(config.protected_paths.contains(&".forgejo/".to_string()));
        assert!(config.protected_paths.contains(&".gitea/".to_string()));
        assert!(config.protected_paths.contains(&".github/".to_string()));
        assert!(config.protected_paths.contains(&".gitlab/".to_string()));
    }
}
