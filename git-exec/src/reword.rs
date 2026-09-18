//! Message-only replay with complete series verification before ref updates.

use super::{GitExecError, GitWorkspace, identity_env, run_git};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Clone, Debug)]
pub struct RewordOperation {
    pub commit: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitMapping {
    pub old_commit_sha: String,
    pub new_commit_sha: String,
}

/// Validate submitted UTF-8 bytes before terminal-newline normalization.
///
/// # Errors
/// Returns a static diagnostic, never including the submitted message.
pub fn validate_reword_message(message: &str) -> Result<(), &'static str> {
    if message.trim().is_empty() {
        return Err("reword message must not be empty or whitespace-only");
    }
    if message.contains('\0') {
        return Err("reword message must not contain NUL");
    }
    if message.len() > 65_536 {
        return Err("reword message exceeds 65536 UTF-8 bytes");
    }
    Ok(())
}

fn invalid(reason: &str) -> GitExecError {
    GitExecError::CommandFailed {
        command: "reword".into(),
        stderr: reason.into(),
    }
}

#[derive(Debug)]
struct Snapshot {
    sha: String,
    parent: String,
    tree: String,
    author: String,
    message: Vec<u8>,
}

impl GitWorkspace {
    // Bytes are essential here: Git messages need not be UTF-8. Do not expose
    // subprocess stderr, which can contain a message printed by a Git hook.
    fn reword_git(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
        env: &[(String, String)],
    ) -> Result<Vec<u8>, GitExecError> {
        let mut command = Command::new("git");
        command
            .current_dir(&self.repo_path)
            .args([
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_AUTHOR_DATE")
            .env_remove("GIT_COMMITTER_DATE")
            .envs(env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let write_result = if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.unwrap_or_default())
        } else {
            Ok(())
        };
        let output = child.wait_with_output()?;
        write_result?;
        if !output.status.success() {
            return Err(invalid("Git replay or metadata command failed"));
        }
        Ok(output.stdout)
    }

    fn reword_snapshot(&self, sha: &str) -> Result<Snapshot, GitExecError> {
        let raw = self.reword_git(&["cat-file", "commit", sha], None, &self.auth_env)?;
        let separator = raw
            .windows(2)
            .position(|w| w == b"\n\n")
            .ok_or_else(|| invalid("invalid commit metadata"))?;
        let headers = std::str::from_utf8(&raw[..separator])
            .map_err(|_| invalid("unsupported non-UTF-8 commit metadata"))?;
        let mut tree = None;
        let mut parent = None;
        let mut author = None;
        let mut signature = false;
        for line in headers.lines() {
            if signature && line.starts_with(' ') {
                continue;
            }
            signature = false;
            let (key, value) = line
                .split_once(' ')
                .ok_or_else(|| invalid("invalid commit header"))?;
            match key {
                "tree" if tree.is_none() => tree = Some(value.to_owned()),
                "parent" if parent.is_none() => parent = Some(value.to_owned()),
                "author" if author.is_none() => author = Some(value.to_owned()),
                "committer" => {}
                "gpgsig" | "gpgsig-sha256" => signature = true,
                _ => return Err(invalid("unsupported commit metadata or merge history")),
            }
        }
        let snapshot = Snapshot {
            sha: sha.into(),
            parent: parent.ok_or_else(|| invalid("expected a single parent"))?,
            tree: tree.ok_or_else(|| invalid("missing tree"))?,
            author: author.ok_or_else(|| invalid("missing author"))?,
            message: raw[separator + 2..].to_vec(),
        };
        if snapshot.message.contains(&0) {
            return Err(invalid("unsupported NUL in original commit message"));
        }
        snapshot.author_env(&self.auth_env, ("unused", "unused"))?;
        Ok(snapshot)
    }

    fn replay_reword(
        &self,
        snapshot: &Snapshot,
        message: &[u8],
        env: &[(String, String)],
    ) -> Result<(), GitExecError> {
        self.reword_git(
            &[
                "cherry-pick",
                "--allow-empty",
                "--allow-empty-message",
                "--keep-redundant-commits",
                &snapshot.sha,
            ],
            None,
            env,
        )?;
        self.reword_git(
            &[
                "commit",
                "--amend",
                "--allow-empty",
                "--allow-empty-message",
                "--cleanup=verbatim",
                "--file=-",
            ],
            Some(message),
            env,
        )?;
        // Git's porcelain may recode a legacy non-UTF-8 message. Keep the
        // freshly created headers (including the new committer), but restore
        // the exact message bytes using Git's object writer if that happened.
        let head = self.rev_parse("HEAD")?;
        let mut raw = self.reword_git(&["cat-file", "commit", &head], None, env)?;
        let offset = raw
            .windows(2)
            .position(|w| w == b"\n\n")
            .ok_or_else(|| invalid("invalid replayed commit"))?
            + 2;
        if &raw[offset..] != message {
            raw.truncate(offset);
            raw.extend_from_slice(message);
            let id = self.reword_git(
                &["hash-object", "-w", "-t", "commit", "--stdin"],
                Some(&raw),
                env,
            )?;
            let id = std::str::from_utf8(&id).map_err(|_| invalid("invalid object ID"))?;
            self.reword_git(&["reset", "--hard", id.trim()], None, env)?;
        }
        Ok(())
    }

    /// Reword distinct full IDs in a linear merge-base..HEAD series.
    /// Returns the complete, independently verified mapping in series order.
    /// Supplied trailing newlines are retained; otherwise one LF is appended.
    /// Original messages and authors (including dates) are preserved exactly.
    /// Recreated commits use the supplied committer and lose old signatures.
    ///
    /// # Errors
    /// Rejects invalid targets/messages/metadata before replay. Any later failure
    /// restores the original workspace branch and head; this never pushes.
    pub fn reword_series(
        &self,
        merge_base: &str,
        operations: &[RewordOperation],
        committer_name: &str,
        committer_email: &str,
    ) -> Result<Vec<CommitMapping>, GitExecError> {
        let commits = self.list_commits_in_range(merge_base)?;
        let mut replacements = HashMap::new();
        for operation in operations {
            validate_reword_message(&operation.message).map_err(invalid)?;
            if !commits.contains(&operation.commit) {
                return Err(invalid(
                    "reword target must be an exact full ID in the branch range",
                ));
            }
            let mut message = operation.message.as_bytes().to_vec();
            if !message.ends_with(b"\n") {
                message.push(b'\n');
            }
            if replacements
                .insert(operation.commit.as_str(), message)
                .is_some()
            {
                return Err(invalid("duplicate reword target"));
            }
        }
        let first = commits
            .iter()
            .position(|sha| replacements.contains_key(sha.as_str()))
            .ok_or_else(|| invalid("reword operations must not be empty"))?;
        let snapshots = commits
            .iter()
            .map(|sha| self.reword_snapshot(sha))
            .collect::<Result<Vec<_>, _>>()?;
        check_chain(&snapshots, merge_base)?;
        let branch = run_git(
            &self.repo_path,
            &["symbolic-ref", "--short", "HEAD"],
            &self.auth_env,
        )?;
        let branch = branch.trim();
        let original_head = self.rev_parse("HEAD")?;
        let result = (|| {
            self.reword_git(
                &["checkout", "--detach", &snapshots[first].parent],
                None,
                &self.auth_env,
            )?;
            for snapshot in &snapshots[first..] {
                let env = snapshot.author_env(&self.auth_env, (committer_name, committer_email))?;
                let message = replacements
                    .get(snapshot.sha.as_str())
                    .map_or(snapshot.message.as_slice(), Vec::as_slice);
                self.replay_reword(snapshot, message, &env)?;
            }
            let rewritten = self
                .list_commits_in_range(merge_base)?
                .iter()
                .map(|sha| self.reword_snapshot(sha))
                .collect::<Result<Vec<_>, _>>()?;
            verify_series(&snapshots, &rewritten, merge_base, &replacements, first)?;
            let mapping = snapshots
                .iter()
                .zip(&rewritten)
                .map(|(old, new)| CommitMapping {
                    old_commit_sha: old.sha.clone(),
                    new_commit_sha: new.sha.clone(),
                })
                .collect();
            let new_head = self.rev_parse("HEAD")?;
            self.reword_git(
                &[
                    "update-ref",
                    &format!("refs/heads/{branch}"),
                    &new_head,
                    &original_head,
                ],
                None,
                &self.auth_env,
            )?;
            self.reword_git(&["checkout", branch], None, &self.auth_env)?;
            Ok(mapping)
        })();
        if result.is_err() {
            let _ = self.reword_git(&["cherry-pick", "--abort"], None, &self.auth_env);
            // Attempt every restoration step, even if one fails. Restore the
            // named ref explicitly in case the final checkout failed after
            // update-ref; resetting a detached HEAD alone is insufficient.
            let reset = self.reword_git(&["reset", "--hard", &original_head], None, &self.auth_env);
            let restore_ref = self.reword_git(
                &[
                    "update-ref",
                    &format!("refs/heads/{branch}"),
                    &original_head,
                ],
                None,
                &self.auth_env,
            );
            let checkout = self.reword_git(&["checkout", "-f", branch], None, &self.auth_env);
            reset?;
            restore_ref?;
            checkout?;
        }
        result
    }
}

impl Snapshot {
    fn author_env(
        &self,
        base: &[(String, String)],
        committer: (&str, &str),
    ) -> Result<Vec<(String, String)>, GitExecError> {
        let (identity, date) = self
            .author
            .rsplit_once("> ")
            .ok_or_else(|| invalid("unsupported author metadata"))?;
        let (name, email) = identity
            .rsplit_once(" <")
            .ok_or_else(|| invalid("unsupported author identity"))?;
        let (timestamp, timezone) = date
            .split_once(' ')
            .ok_or_else(|| invalid("unsupported author date"))?;
        let valid_timezone = timezone.len() == 5
            && matches!(timezone.as_bytes()[0], b'+' | b'-')
            && timezone.as_bytes()[1..].iter().all(u8::is_ascii_digit);
        if name.trim() != name
            || email.trim() != email
            || name.is_empty()
            || email.is_empty()
            || name.contains(['\0', '<', '>', '\r', '\n'])
            || email.contains(['\0', '<', '>', '\r', '\n'])
            || timestamp.parse::<u64>().is_err()
            || !valid_timezone
        {
            return Err(invalid("unsupported author metadata"));
        }
        let mut env = identity_env(base, Some((name, email)), committer);
        env.push(("GIT_AUTHOR_DATE".into(), date.into()));
        Ok(env)
    }
}

fn check_chain(series: &[Snapshot], base: &str) -> Result<(), GitExecError> {
    let mut parent = base;
    for commit in series {
        if commit.parent != parent {
            return Err(invalid(
                "series is not a single-parent chain rooted at merge base",
            ));
        }
        parent = &commit.sha;
    }
    Ok(())
}

fn verify_series(
    old: &[Snapshot],
    new: &[Snapshot],
    base: &str,
    replacements: &HashMap<&str, Vec<u8>>,
    first: usize,
) -> Result<(), GitExecError> {
    check_chain(new, base)?;
    if old.len() != new.len() {
        return Err(invalid("reword changed commit count"));
    }
    for (index, (old, new)) in old.iter().zip(new).enumerate() {
        let message = replacements.get(old.sha.as_str()).unwrap_or(&old.message);
        if old.tree != new.tree
            || old.author != new.author
            || *message != new.message
            || (index < first && old.sha != new.sha)
        {
            return Err(invalid("reword series verification failed"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture(format: &str) -> (GitWorkspace, String, Vec<String>) {
        let dir = TempDir::new().expect("temporary repo");
        run_git(
            dir.path(),
            &[
                "init",
                "--initial-branch=agent/test",
                &format!("--object-format={format}"),
            ],
            &[],
        )
        .expect("init");
        let repo_path = dir.path().to_owned();
        let workspace = GitWorkspace {
            _temp_dir: dir,
            auth_env: vec![],
            repo_path,
        };
        let mut env = identity_env(
            &[],
            Some(("Original Author", "author@example.test")),
            ("Original Committer", "old@example.test"),
        );
        env.push(("GIT_AUTHOR_DATE".into(), "1234567890 +0545".into()));
        env.push(("GIT_COMMITTER_DATE".into(), "1234567891 -0330".into()));
        run_git(
            &workspace.repo_path,
            &["commit", "--allow-empty", "-m", "base"],
            &env,
        )
        .expect("base");
        let base = workspace.rev_parse("HEAD").expect("base id");
        for index in 0..4 {
            // Two intentionally empty commits interspersed with file changes.
            if index % 2 == 0 {
                std::fs::write(workspace.repo_path.join("file"), index.to_string()).expect("file");
                run_git(&workspace.repo_path, &["add", "file"], &env).expect("add");
            }
            run_git(
                &workspace.repo_path,
                &[
                    "commit",
                    "--allow-empty",
                    "-m",
                    &format!("commit {index}\n\nOriginal body"),
                ],
                &env,
            )
            .expect("commit");
        }
        let commits = workspace.list_commits_in_range(&base).expect("series");
        (workspace, base, commits)
    }

    #[test]
    fn reword_positions_messages_empty_commits_and_object_formats() {
        for format in ["sha1", "sha256"] {
            for targets in [vec![0], vec![1], vec![3], vec![3, 1]] {
                let (workspace, base, commits) = fixture(format);
                let old = commits
                    .iter()
                    .map(|sha| workspace.reword_snapshot(sha).expect("snapshot"))
                    .collect::<Vec<_>>();
                let message = "  Unicode café 🦀\n\n# comment\n`touch SENTINEL`; $(touch SENTINEL) \"quotes\" $HOME\n--option\n\n ";
                let operations = targets
                    .iter()
                    .map(|i| RewordOperation {
                        commit: commits[*i].clone(),
                        message: message.into(),
                    })
                    .collect::<Vec<_>>();
                let mapping = workspace
                    .reword_series(&base, &operations, "New Committer", "new@example.test")
                    .expect("reword");
                assert_eq!(mapping.len(), commits.len());
                assert!(!workspace.repo_path.join("SENTINEL").exists());
                let first = *targets.iter().min().expect("first target");
                for (index, pair) in mapping.iter().enumerate() {
                    assert_eq!(pair.old_commit_sha, commits[index]);
                    let new = workspace
                        .reword_snapshot(&pair.new_commit_sha)
                        .expect("new snapshot");
                    assert_eq!(new.tree, old[index].tree);
                    assert_eq!(new.author, old[index].author);
                    assert_eq!(
                        new.parent,
                        if index == 0 {
                            &base
                        } else {
                            &mapping[index - 1].new_commit_sha
                        }
                        .as_str()
                    );
                    if index < first {
                        assert_eq!(pair.old_commit_sha, pair.new_commit_sha);
                    } else {
                        assert_ne!(pair.old_commit_sha, pair.new_commit_sha);
                        let raw = workspace
                            .reword_git(&["cat-file", "commit", &pair.new_commit_sha], None, &[])
                            .expect("raw");
                        let raw = String::from_utf8(raw).expect("UTF-8");
                        assert!(raw.contains("committer New Committer <new@example.test>"));
                        assert!(!raw.contains("1234567891 -0330"));
                    }
                    assert_eq!(
                        new.message,
                        if targets.contains(&index) {
                            format!("{message}\n").into_bytes()
                        } else {
                            old[index].message.clone()
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn unsupported_author_and_message_metadata_is_preflighted() {
        let (workspace, base, commits) = fixture("sha1");
        let original = workspace.rev_parse("HEAD").expect("head");
        let snapshot = workspace.reword_snapshot(&original).expect("snapshot");
        for (author, message) in [
            (
                "Author <author@test> invalid +0000",
                b"message\n".as_slice(),
            ),
            (
                "Author <author@test> 1234567890 BAD",
                b"message\n".as_slice(),
            ),
            (
                "Author <author@test> 1234567890 +0000",
                b"message\0\n".as_slice(),
            ),
        ] {
            let mut raw = format!("tree {}\nparent {}\nauthor {author}\ncommitter Original <old@test> 1234567891 +0000\n\n", snapshot.tree, snapshot.parent).into_bytes();
            raw.extend_from_slice(message);
            let id = workspace
                .reword_git(
                    &[
                        "hash-object",
                        "--literally",
                        "-w",
                        "-t",
                        "commit",
                        "--stdin",
                    ],
                    Some(&raw),
                    &[],
                )
                .expect("object");
            let id = String::from_utf8(id).expect("id").trim().to_owned();
            run_git(&workspace.repo_path, &["update-ref", "HEAD", &id], &[]).expect("head");
            assert!(
                workspace
                    .reword_series(
                        &base,
                        &[RewordOperation {
                            commit: commits[1].clone(),
                            message: "replacement".into()
                        }],
                        "New",
                        "new@test"
                    )
                    .is_err()
            );
            assert_eq!(workspace.rev_parse("HEAD").expect("head"), id);
            assert_eq!(
                run_git(
                    &workspace.repo_path,
                    &["symbolic-ref", "--short", "HEAD"],
                    &[]
                )
                .expect("branch")
                .trim(),
                "agent/test"
            );
        }
    }

    #[test]
    fn preserves_empty_and_unterminated_original_messages() {
        for message in [
            b"".as_slice(),
            b"unterminated".as_slice(),
            b"legacy \xff".as_slice(),
        ] {
            let (workspace, base, commits) = fixture("sha1");
            let tip = workspace.reword_snapshot(&commits[3]).expect("tip");
            let mut raw = format!(
                "tree {}\nparent {}\nauthor {}\ncommitter Old <old@test> 1234567891 +0000\n\n",
                tip.tree, tip.parent, tip.author
            )
            .into_bytes();
            raw.extend_from_slice(message);
            let sha = workspace
                .reword_git(
                    &["hash-object", "-w", "-t", "commit", "--stdin"],
                    Some(&raw),
                    &[],
                )
                .expect("object");
            let sha = String::from_utf8(sha).expect("id").trim().to_owned();
            run_git(&workspace.repo_path, &["reset", "--hard", &sha], &[]).expect("reset");
            let mapping = workspace
                .reword_series(
                    &base,
                    &[RewordOperation {
                        commit: commits[1].clone(),
                        message: "new message".into(),
                    }],
                    "New",
                    "new@test",
                )
                .expect("reword");
            assert_eq!(
                workspace
                    .reword_snapshot(&mapping[3].new_commit_sha)
                    .expect("new tip")
                    .message,
                message
            );
        }
    }

    #[test]
    fn raw_messages_signatures_and_unsupported_headers() {
        for extra_header in [
            "gpgsig fake-signature\n continuation\n",
            "encoding ISO-8859-1\n",
            "unknown metadata\n",
            "parent invalid\n",
        ] {
            let (workspace, base, commits) = fixture("sha1");
            let extra_header = extra_header.replace("parent invalid", &format!("parent {base}"));
            let tip = workspace.reword_snapshot(&commits[3]).expect("tip");
            let mut raw = format!("tree {}\nparent {}\nauthor {}\ncommitter Original <old@test> 1234567891 -0330\n{extra_header}\n", tip.tree, tip.parent, tip.author).into_bytes();
            raw.extend_from_slice(b"raw non-UTF-8: \xff\n\n");
            let sha = workspace
                .reword_git(
                    &["hash-object", "-w", "-t", "commit", "--stdin"],
                    Some(&raw),
                    &[],
                )
                .expect("object");
            let sha = String::from_utf8(sha).expect("id").trim().to_owned();
            run_git(&workspace.repo_path, &["reset", "--hard", &sha], &[]).expect("reset");
            let result = workspace.reword_series(
                &base,
                &[RewordOperation {
                    commit: commits[1].clone(),
                    message: "new message".into(),
                }],
                "New",
                "new@test",
            );
            if extra_header.starts_with("gpgsig") {
                let mapping = result.expect("signature dropped during replay");
                let new = workspace
                    .reword_git(
                        &["cat-file", "commit", &mapping[3].new_commit_sha],
                        None,
                        &[],
                    )
                    .expect("new object");
                assert!(new.ends_with(b"raw non-UTF-8: \xff\n\n"));
                assert!(!new.windows(6).any(|w| w == b"gpgsig"));
            } else {
                assert!(result.is_err());
                assert_eq!(workspace.rev_parse("HEAD").expect("head"), sha);
            }
        }
    }

    #[test]
    fn preserves_newlines_unchanged_messages_and_limit() {
        for message in [
            "subject".to_owned(),
            "subject\n".into(),
            "subject\n\n\n".into(),
            "é".repeat(32_768),
            "commit 3\n\nOriginal body\n".into(),
        ] {
            let (workspace, base, commits) = fixture("sha1");
            let mapping = workspace
                .reword_series(
                    &base,
                    &[RewordOperation {
                        commit: commits[3].clone(),
                        message: message.clone(),
                    }],
                    "New",
                    "new@test",
                )
                .expect("reword");
            let stored = workspace
                .reword_snapshot(&mapping[3].new_commit_sha)
                .expect("snapshot");
            let expected = if message.ends_with('\n') {
                message
            } else {
                format!("{message}\n")
            };
            assert_eq!(stored.message, expected.as_bytes());
        }
    }

    #[test]
    fn validation_does_not_mutate_head_or_branch() {
        let (workspace, base, commits) = fixture("sha1");
        let old_head = workspace.rev_parse("HEAD").expect("head");
        for message in [
            String::new(),
            " \n\t".into(),
            "bad\0message".into(),
            "é".repeat(32_769),
        ] {
            assert!(
                workspace
                    .reword_series(
                        &base,
                        &[RewordOperation {
                            commit: commits[1].clone(),
                            message
                        }],
                        "New",
                        "new@test"
                    )
                    .is_err()
            );
        }
        for target in [
            &base,
            "HEAD",
            "--all",
            "HEAD~1",
            &commits[0][..7],
            &"0".repeat(40),
        ] {
            assert!(
                workspace
                    .reword_series(
                        &base,
                        &[RewordOperation {
                            commit: target.into(),
                            message: "message".into()
                        }],
                        "New",
                        "new@test"
                    )
                    .is_err()
            );
        }
        let operation = RewordOperation {
            commit: commits[0].clone(),
            message: "message".into(),
        };
        assert!(
            workspace
                .reword_series(&base, &[operation.clone(), operation], "New", "new@test")
                .is_err()
        );
        assert_eq!(workspace.rev_parse("HEAD").expect("head"), old_head);
        assert_eq!(
            workspace
                .rev_parse("refs/heads/agent/test")
                .expect("branch"),
            old_head
        );
    }

    #[test]
    fn rejects_corrupted_verification_and_rolls_back_failed_replay() {
        let (workspace, base, commits) = fixture("sha1");
        let old = commits
            .iter()
            .map(|sha| workspace.reword_snapshot(sha).expect("snapshot"))
            .collect::<Vec<_>>();
        for corruption in 0..5 {
            let mut new = commits
                .iter()
                .map(|sha| workspace.reword_snapshot(sha).expect("snapshot"))
                .collect::<Vec<_>>();
            match corruption {
                0 => new[1].tree = base.clone(),
                1 => new[1].author.push('x'),
                2 => new[1].message.push(b'x'),
                3 => new[0].parent = commits[2].clone(),
                _ => {
                    new.pop();
                }
            }
            assert!(verify_series(&old, &new, &base, &HashMap::new(), 0).is_err());
        }
        // Empty committer identity makes cherry-pick fail after detaching.
        assert!(
            workspace
                .reword_series(
                    &base,
                    &[RewordOperation {
                        commit: commits[1].clone(),
                        message: "new".into()
                    }],
                    "",
                    ""
                )
                .is_err()
        );
        assert_eq!(workspace.rev_parse("HEAD").expect("head"), commits[3]);
        assert_eq!(
            run_git(
                &workspace.repo_path,
                &["symbolic-ref", "--short", "HEAD"],
                &[]
            )
            .expect("branch")
            .trim(),
            "agent/test"
        );
    }
}
