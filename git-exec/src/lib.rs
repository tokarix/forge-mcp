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

/// An operation to apply during an interactive rebase.
#[derive(Clone, Debug)]
pub enum RebaseOperation {
    Fixup { commit: String, into: String },
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
    /// When `shallow` is true the clone uses `--depth=1`; when false it
    /// performs a full clone so all branches and history are available.
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
        shallow: bool,
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

        let mut args = vec!["clone", "--branch", base_branch];
        if shallow {
            args.push("--depth=1");
        }
        args.push(clone_url);
        args.push("repo");

        run_git(temp_dir.path(), &args, &auth_env)?;

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

    /// Force-pushes a branch using `--force-with-lease` to guard against
    /// concurrent updates.
    ///
    /// # Errors
    ///
    /// Returns an error if the push fails or the lease check rejects it.
    pub fn force_push_with_lease(
        &self,
        branch: &str,
        expected_old_sha: &str,
    ) -> Result<(), GitExecError> {
        run_git(
            &self.repo_path,
            &[
                "push",
                &format!("--force-with-lease=refs/heads/{branch}:{expected_old_sha}"),
                "origin",
                branch,
            ],
            &self.auth_env,
        )
        .map(|_| ())
    }

    /// Returns `true` if there are merge commits between `base` and HEAD.
    ///
    /// # Errors
    ///
    /// Returns an error if the git command fails.
    pub fn has_merge_commits(&self, base: &str) -> Result<bool, GitExecError> {
        let output = run_git(
            &self.repo_path,
            &["rev-list", "--merges", &format!("{base}..HEAD")],
            &self.auth_env,
        )?;
        Ok(!output.trim().is_empty())
    }

    /// Lists commit SHAs between `base` and HEAD in chronological order.
    ///
    /// # Errors
    ///
    /// Returns an error if the git command fails.
    pub fn list_commits_in_range(&self, base: &str) -> Result<Vec<String>, GitExecError> {
        let output = run_git(
            &self.repo_path,
            &["rev-list", "--reverse", &format!("{base}..HEAD")],
            &self.auth_env,
        )?;
        Ok(output
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// Finds the merge base of two refs.
    ///
    /// # Errors
    ///
    /// Returns an error if the git command fails.
    pub fn merge_base(&self, ref_a: &str, ref_b: &str) -> Result<String, GitExecError> {
        let output = run_git(
            &self.repo_path,
            &["merge-base", ref_a, ref_b],
            &self.auth_env,
        )?;
        Ok(output.trim().to_string())
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

    /// Runs an interactive rebase with programmatic operations.
    ///
    /// Uses a Python script as `GIT_SEQUENCE_EDITOR` to transform the
    /// todo list, supporting fixup operations that squash a commit into
    /// another.
    ///
    /// # Errors
    ///
    /// Returns an error if the rebase fails. On failure, the rebase is
    /// automatically aborted.
    pub fn rebase_interactive(
        &self,
        merge_base: &str,
        operations: &[RebaseOperation],
        committer_name: &str,
        committer_email: &str,
    ) -> Result<(), GitExecError> {
        use std::fmt::Write;

        let mut py_script = String::from(
            r"#!/usr/bin/env python3
import sys

with open(sys.argv[1]) as f:
    lines = f.readlines()

# Parse operations
fixups = {}  # commit_prefix -> into_prefix
",
        );

        for op in operations {
            match op {
                RebaseOperation::Fixup { commit, into } => {
                    // Use full SHAs — git's todo uses abbreviated SHAs which are
                    // prefixes of these, so startswith() matching still works.
                    let _ = writeln!(py_script, "fixups['{commit}'] = '{into}'");
                }
            }
        }

        py_script.push_str(
            r"
# First pass: separate fixup lines from regular lines
regular = []
fixup_by_target = {}  # into_prefix -> [fixup_lines]

for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        regular.append(line)
        continue

    parts = stripped.split(None, 2)
    if len(parts) < 2:
        regular.append(line)
        continue

    action, sha = parts[0], parts[1]

    # Check if this commit should be a fixup (full SHA starts with todo's abbreviated SHA)
    matched_full_sha = None
    for full_sha in fixups:
        if full_sha.startswith(sha):
            matched_full_sha = full_sha
            break

    if matched_full_sha:
        into_full_sha = fixups[matched_full_sha]
        fixup_line = line.replace(action, 'fixup', 1)
        fixup_by_target.setdefault(into_full_sha, []).append(fixup_line)
    else:
        regular.append(line)

# Second pass: insert fixup lines after their targets
result = []
for line in regular:
    result.append(line)
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        continue
    parts = stripped.split(None, 2)
    if len(parts) < 2:
        continue
    sha = parts[1]
    for full_sha, fixup_lines in list(fixup_by_target.items()):
        if full_sha.startswith(sha):
            result.extend(fixup_lines)

with open(sys.argv[1], 'w') as f:
    f.writelines(result)
",
        );

        // Write the script to a temp file
        let script_path = self.repo_path.join(".rebase-editor.py");
        std::fs::write(&script_path, &py_script).map_err(GitExecError::Spawn)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .map_err(GitExecError::Spawn)?;
        }

        // Run rebase with our sequence editor
        let editor_path = script_path.to_string_lossy().to_string();

        let mut cmd = Command::new("git");
        cmd.current_dir(&self.repo_path)
            .args([
                "-c",
                &format!("user.name={committer_name}"),
                "-c",
                &format!("user.email={committer_email}"),
                "rebase",
                "-i",
                merge_base,
            ])
            .env("GIT_SEQUENCE_EDITOR", &editor_path)
            .env("GIT_TERMINAL_PROMPT", "0");

        for (key, value) in &self.auth_env {
            cmd.env(key, value);
        }

        let output = cmd.output().map_err(GitExecError::Spawn)?;

        // Clean up script
        let _ = std::fs::remove_file(&script_path);

        if !output.status.success() {
            // Abort the rebase if it failed
            let _ = run_git(&self.repo_path, &["rebase", "--abort"], &self.auth_env);
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(GitExecError::CommandFailed {
                command: "git rebase -i".to_string(),
                stderr,
            });
        }

        Ok(())
    }

    /// Resolves a refspec to a full SHA.
    ///
    /// # Errors
    ///
    /// Returns an error if the git command fails.
    pub fn rev_parse(&self, refspec: &str) -> Result<String, GitExecError> {
        let output = run_git(&self.repo_path, &["rev-parse", refspec], &self.auth_env)?;
        Ok(output.trim().to_string())
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
        let workspace = GitWorkspace::clone_repo(
            &format!("file://{}", remote_path.display()),
            "main",
            None,
            true,
        )
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

    /// Helper: create a bare remote with an initial commit on "main".
    fn setup_remote_with_initial_commit() -> (TempDir, PathBuf) {
        let empty_env = Vec::new();
        let remote_dir = TempDir::new().unwrap();
        run_git(
            remote_dir.path(),
            &["init", "--bare", "remote.git"],
            &empty_env,
        )
        .unwrap();
        let remote_path = remote_dir.path().join("remote.git");

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

        (remote_dir, remote_path)
    }

    /// Helper: add a commit to a workspace.
    fn add_commit(
        workspace: &GitWorkspace,
        filename: &str,
        content: &str,
        message: &str,
    ) -> String {
        std::fs::write(workspace.repo_path.join(filename), content).unwrap();
        run_git(
            &workspace.repo_path,
            &["add", filename],
            &workspace.auth_env,
        )
        .unwrap();
        workspace
            .commit(message, "Test", "test@test")
            .unwrap()
            .commit_sha
    }

    #[test]
    fn rebase_fixup_squashes_commit_into_target() {
        let (_remote_dir, remote_path) = setup_remote_with_initial_commit();
        let remote_url = format!("file://{}", remote_path.display());

        // Clone, create branch, add 3 commits
        let ws = GitWorkspace::clone_repo(&remote_url, "main", None, false).unwrap();
        ws.create_branch("agent/test-rebase").unwrap();

        let sha1 = add_commit(&ws, "file1.txt", "content1", "commit 1");
        let sha2 = add_commit(&ws, "file2.txt", "content2", "commit 2");
        let sha3 = add_commit(&ws, "file3.txt", "content3", "commit 3");

        ws.push_branch("agent/test-rebase").unwrap();

        // Capture tree before rebase
        let tree_before = ws.rev_parse("HEAD^{tree}").unwrap();

        // Compute merge base
        let mb = ws.merge_base("HEAD", "origin/main").unwrap();

        // Verify we have 3 commits
        let commits = ws.list_commits_in_range(&mb).unwrap();
        assert_eq!(commits.len(), 3);
        assert_eq!(commits[0], sha1);
        assert_eq!(commits[1], sha2);
        assert_eq!(commits[2], sha3);

        // Fixup commit 3 into commit 1
        ws.rebase_interactive(
            &mb,
            &[RebaseOperation::Fixup {
                commit: sha3.clone(),
                into: sha1.clone(),
            }],
            "Test Committer",
            "committer@test",
        )
        .unwrap();

        // Tree should be identical
        let tree_after = ws.rev_parse("HEAD^{tree}").unwrap();
        assert_eq!(tree_before, tree_after);

        // Should now have 2 commits
        let commits_after = ws.list_commits_in_range(&mb).unwrap();
        assert_eq!(commits_after.len(), 2);
    }

    #[test]
    fn rebase_fixup_multiple_into_same_target() {
        let (_remote_dir, remote_path) = setup_remote_with_initial_commit();
        let remote_url = format!("file://{}", remote_path.display());

        let ws = GitWorkspace::clone_repo(&remote_url, "main", None, false).unwrap();
        ws.create_branch("agent/test-multi-fixup").unwrap();

        let sha1 = add_commit(&ws, "file1.txt", "content1", "commit 1");
        let sha2 = add_commit(&ws, "file2.txt", "content2", "commit 2");
        let sha3 = add_commit(&ws, "file3.txt", "content3", "commit 3");

        let tree_before = ws.rev_parse("HEAD^{tree}").unwrap();
        let mb = ws.merge_base("HEAD", "origin/main").unwrap();

        // Fixup both 2 and 3 into 1 — should result in single commit
        ws.rebase_interactive(
            &mb,
            &[
                RebaseOperation::Fixup {
                    commit: sha2.clone(),
                    into: sha1.clone(),
                },
                RebaseOperation::Fixup {
                    commit: sha3.clone(),
                    into: sha1.clone(),
                },
            ],
            "Test Committer",
            "committer@test",
        )
        .unwrap();

        let tree_after = ws.rev_parse("HEAD^{tree}").unwrap();
        assert_eq!(tree_before, tree_after);

        let commits_after = ws.list_commits_in_range(&mb).unwrap();
        assert_eq!(commits_after.len(), 1);
    }

    #[test]
    fn rebase_no_merge_commits() {
        let (_remote_dir, remote_path) = setup_remote_with_initial_commit();
        let remote_url = format!("file://{}", remote_path.display());

        let ws = GitWorkspace::clone_repo(&remote_url, "main", None, false).unwrap();
        ws.create_branch("agent/test-linear").unwrap();
        add_commit(&ws, "file1.txt", "c1", "commit 1");

        let mb = ws.merge_base("HEAD", "origin/main").unwrap();
        assert!(!ws.has_merge_commits(&mb).unwrap());
    }
}
