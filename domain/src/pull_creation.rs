//! Interpretation of GitHub fork pull request heads.

use crate::{ForgeKind, OpenChangeRequestRequest, RepositoryRef, ServiceError};

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
