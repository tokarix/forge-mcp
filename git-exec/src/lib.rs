//! Git execution via CLI subprocess.
//!
//! All operations run in ephemeral temporary directories and use HTTPS
//! with token authentication via `http.extraHeader` (never in argv or URLs).
//! Designed to be called behind `tokio::task::spawn_blocking`.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use tempfile::TempDir;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitExecError {
    #[error("git command failed: {command}\nstderr: {stderr}")]
    CommandFailed { command: String, stderr: String },
    #[error("failed to spawn git: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("failed to create temporary directory: {0}")]
    TempDir(String),
}

/// Result of a successful commit + push operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommitResult {
    pub commit_sha: String,
}

/// Builds the `http.extraHeader` value for git token authentication.
/// Uses HTTP Basic auth with "forge-mcp" as the username.
fn auth_header(token: &str) -> String {
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("forge-mcp:{token}"));
    format!("Authorization: Basic {credentials}")
}

/// A workspace backed by a temporary directory for git operations.
pub struct GitWorkspace {
    _temp_dir: TempDir,
    auth_env: Vec<(String, String)>,
    repo_path: PathBuf,
}

impl GitWorkspace {
    /// Clones a repository into a temporary directory.
    ///
    /// The `base_branch` parameter specifies which branch to check out.
    /// Authentication is handled via `http.extraHeader` environment
    /// variables — the token never appears in process arguments or URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if cloning fails.
    pub fn clone_repo(
        clone_url: &str,
        base_branch: &str,
        token: Option<&str>,
    ) -> Result<Self, GitExecError> {
        let temp_dir = TempDir::new().map_err(|e| GitExecError::TempDir(e.to_string()))?;
        let repo_path = temp_dir.path().join("repo");

        let auth_env: Vec<(String, String)> = if let Some(token) = token {
            vec![
                ("GIT_CONFIG_COUNT".to_string(), "1".to_string()),
                (
                    "GIT_CONFIG_KEY_0".to_string(),
                    "http.extraHeader".to_string(),
                ),
                ("GIT_CONFIG_VALUE_0".to_string(), auth_header(token)),
            ]
        } else {
            Vec::new()
        };

        run_git(
            temp_dir.path(),
            &[
                "clone",
                "--branch",
                base_branch,
                "--depth=1",
                clone_url,
                "repo",
            ],
            &auth_env,
        )?;

        Ok(Self {
            _temp_dir: temp_dir,
            auth_env,
            repo_path,
        })
    }

    /// Creates a new branch from the current HEAD (which is `base_branch`).
    ///
    /// # Errors
    ///
    /// Returns an error if branch creation fails.
    pub fn create_branch(&self, branch_name: &str) -> Result<(), GitExecError> {
        run_git(
            &self.repo_path,
            &["checkout", "-b", branch_name],
            &self.auth_env,
        )
        .map(|_| ())
    }

    /// Applies a unified diff patch to the working directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the patch cannot be applied.
    pub fn apply_patch(&self, patch: &str) -> Result<(), GitExecError> {
        run_git_with_stdin(
            &self.repo_path,
            &["apply", "--index", "-"],
            patch,
            &self.auth_env,
        )
        .map(|_| ())
    }

    /// Creates a commit with the given message.
    ///
    /// # Errors
    ///
    /// Returns an error if the commit fails.
    pub fn commit(
        &self,
        message: &str,
        author_name: &str,
        author_email: &str,
    ) -> Result<GitCommitResult, GitExecError> {
        run_git(
            &self.repo_path,
            &[
                "-c",
                &format!("user.name={author_name}"),
                "-c",
                &format!("user.email={author_email}"),
                "commit",
                "-m",
                message,
            ],
            &self.auth_env,
        )?;

        let sha = run_git(&self.repo_path, &["rev-parse", "HEAD"], &self.auth_env)?;

        Ok(GitCommitResult {
            commit_sha: sha.trim().to_string(),
        })
    }

    /// Pushes the current branch to the remote.
    ///
    /// # Errors
    ///
    /// Returns an error if the push fails.
    pub fn push_branch(&self, branch_name: &str) -> Result<(), GitExecError> {
        run_git(
            &self.repo_path,
            &["push", "-u", "origin", branch_name],
            &self.auth_env,
        )
        .map(|_| ())
    }
}

fn run_git(
    cwd: &Path,
    args: &[&str],
    extra_env: &[(String, String)],
) -> Result<String, GitExecError> {
    let mut cmd = Command::new("git");
    cmd.current_dir(cwd).args(args);
    cmd.env("GIT_TERMINAL_PROMPT", "0");

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(GitExecError::CommandFailed {
            command: format!("git {}", args.join(" ")),
            stderr,
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_git_with_stdin(
    cwd: &Path,
    args: &[&str],
    stdin_data: &str,
    extra_env: &[(String, String)],
) -> Result<String, GitExecError> {
    use std::io::Write;
    use std::process::Stdio;

    let mut cmd = Command::new("git");
    cmd.current_dir(cwd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("GIT_TERMINAL_PROMPT", "0");

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data.as_bytes())
            .map_err(GitExecError::Spawn)?;
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(GitExecError::CommandFailed {
            command: format!("git {}", args.join(" ")),
            stderr,
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_header_encodes_correctly() {
        let header = auth_header("test-token");
        assert!(header.starts_with("Authorization: Basic "));
        let encoded = header.strip_prefix("Authorization: Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "forge-mcp:test-token");
    }

    #[test]
    fn full_workflow_with_local_repo() {
        let empty_env = Vec::new();

        // Create a bare "remote" repo
        let remote_dir = TempDir::new().unwrap();
        run_git(
            remote_dir.path(),
            &["init", "--bare", "remote.git"],
            &empty_env,
        )
        .unwrap();
        let remote_path = remote_dir.path().join("remote.git");

        // Create initial commit in a working copy
        let init_dir = TempDir::new().unwrap();
        let init_path = init_dir.path().join("work");
        run_git(
            init_dir.path(),
            &["clone", remote_path.to_str().unwrap(), "work"],
            &empty_env,
        )
        .unwrap();
        std::fs::write(init_path.join("README.md"), "# Hello\n").unwrap();
        run_git(&init_path, &["add", "README.md"], &empty_env).unwrap();
        run_git(
            &init_path,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@test",
                "commit",
                "-m",
                "init",
            ],
            &empty_env,
        )
        .unwrap();
        run_git(
            &init_path,
            &["push", "-u", "origin", "HEAD:main"],
            &empty_env,
        )
        .unwrap();

        // Now test our workspace — clone from base_branch "main"
        let workspace =
            GitWorkspace::clone_repo(&format!("file://{}", remote_path.display()), "main", None)
                .unwrap();

        workspace.create_branch("agent/test-branch").unwrap();

        let patch = "\
diff --git a/README.md b/README.md
index 7e59600..1234567 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # Hello
+World
";
        workspace.apply_patch(patch).unwrap();

        let result = workspace
            .commit("test: add world", "Test Agent", "agent@test")
            .unwrap();
        assert!(!result.commit_sha.is_empty());

        workspace.push_branch("agent/test-branch").unwrap();

        // Verify the branch exists on the remote
        let branches = run_git(&remote_path, &["branch"], &empty_env).unwrap();
        assert!(branches.contains("agent/test-branch"));
    }
}
