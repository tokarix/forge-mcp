//! Repository and branch authorization for pull request creation.

use crate::{
    AgentIdentity, ForgeKind, OpenChangeRequestRequest, RepositoryRef, ServiceError, policy,
};

/// Trusted identity, grants and branch policy resolved by authentication.
#[derive(Clone, Debug)]
pub struct PullAuthorization {
    pub agent: AgentIdentity,
    pub grants: Vec<String>,
    pub policy: policy::PolicyConfig,
}

impl PullAuthorization {
    /// Check an exact requested or provider-canonical repository path.
    ///
    /// # Errors
    ///
    /// Returns a policy denial when the repository is outside the grants.
    pub fn require_repository(&self, repository: &RepositoryRef) -> Result<(), ServiceError> {
        if policy::is_repo_allowed(
            &self.grants,
            &repository.alias,
            &repository.owner,
            &repository.name,
        ) {
            return Ok(());
        }
        Err(ServiceError::PolicyDenied {
            reasons: format!(
                "agent '{}' is not authorized for repository '{}/{}'",
                self.agent.agent_id, repository.owner, repository.name,
            ),
        })
    }

    /// Apply the PR write policy to the short head branch.
    ///
    /// # Errors
    ///
    /// Returns a policy denial or a policy configuration error.
    pub fn require_branch(
        &self,
        repository: &RepositoryRef,
        branch: &str,
    ) -> Result<(), ServiceError> {
        let context = policy::PolicyContext {
            action: "open_change_request".into(),
            agent: self.agent.clone(),
            repository: repository.clone(),
            target_branch: branch.into(),
            touched_paths: Vec::new(),
        };
        let decision = policy::evaluate(&self.policy, &context)
            .map_err(|error| ServiceError::Validation(error.to_string()))?;
        if decision.is_allowed() {
            return Ok(());
        }
        Err(ServiceError::PolicyDenied {
            reasons: decision.reasons.join("; "),
        })
    }
}

/// The exact instance attached to a registered write service.
#[derive(Clone, Debug)]
pub struct PullForgeBinding {
    pub alias: String,
    pub host: String,
    pub kind: ForgeKind,
}

impl PullForgeBinding {
    /// Whether this repository names the forge served by the adapter.
    #[must_use]
    pub fn matches(&self, repository: &RepositoryRef) -> bool {
        self.alias == repository.alias
            && self.host == repository.host
            && self.kind == repository.forge
    }
}

/// GitHub-qualified head, split into the requested source and literal short branch.
#[derive(Debug)]
pub struct ForkPullHead<'a> {
    pub repository: RepositoryRef,
    pub branch: &'a str,
}

impl OpenChangeRequestRequest {
    /// Interpret GitHub's qualified head syntax and derive the requested source.
    ///
    /// # Errors
    ///
    /// Rejects invalid coordinates, literal branch names and misplaced selectors.
    pub fn fork_head(&self) -> Result<Option<ForkPullHead<'_>>, ServiceError> {
        let qualified = (self.repository.forge == ForgeKind::GitHub)
            .then(|| self.head_branch.split_once(':'))
            .flatten();
        let Some((owner, branch)) = qualified else {
            if self.head_repo.is_some() {
                return Err(ServiceError::Validation(
                    "head_repo requires a GitHub head in OWNER:BRANCH form".into(),
                ));
            }
            return Ok(None);
        };
        let name = self.head_repo.as_deref().unwrap_or(&self.repository.name);
        if !valid_github_path(owner, name)
            || !valid_github_path(&self.repository.owner, &self.repository.name)
            || !valid_short_branch(branch)
            || !valid_short_branch(&self.base_branch)
        {
            return Err(ServiceError::Validation(
                "qualified GitHub pulls require OWNER:BRANCH, short GitHub repository names and literal short head/base branches".into(),
            ));
        }
        Ok(Some(ForkPullHead {
            repository: RepositoryRef {
                owner: owner.into(),
                name: name.into(),
                ..self.repository.clone()
            },
            branch,
        }))
    }
}

/// Validate the two GitHub path components before using them as coordinates.
#[must_use]
pub fn valid_github_path(owner: &str, name: &str) -> bool {
    !owner.is_empty()
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !matches!(name, "" | "." | "..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

// Git's .lock suffix rule uses case-sensitive refname matching.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn valid_short_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch != "@"
        && branch != "HEAD"
        && !branch.starts_with('-')
        && !branch.starts_with("refs/")
        && !branch.ends_with('.')
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch
            .bytes()
            .any(|byte| byte <= b' ' || byte == 127 || b"~^:?*[\\".contains(&byte))
        && branch
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

/// Repository identity pinned during fork pull request resolution.
#[derive(Debug)]
pub struct PinnedPullRepository {
    pub canonical: RepositoryRef,
    pub id: String,
}

/// Fork and destination verified before recording the create intent.
#[derive(Debug)]
pub struct PinnedPullRepositories {
    pub source: PinnedPullRepository,
    pub destination: PinnedPullRepository,
}
