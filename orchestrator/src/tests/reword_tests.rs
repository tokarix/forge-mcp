use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("output")
        .trim()
        .into()
}

fn authorized(prefix: Option<&str>) -> domain::policy::AuthorizedWrite {
    domain::policy::AuthorizedWrite {
        policy: domain::policy::PolicyConfig {
            branch_prefix: prefix.map(str::to_owned),
            ..Default::default()
        },
    }
}

fn request(remote: &Path, branch: &str, target: &str) -> domain::RebaseBranchRequest {
    domain::RebaseBranchRequest {
        agent: AgentIdentity {
            agent_id: "test-agent".into(),
            session_id: "test".into(),
        },
        repository: RepositoryRef {
            alias: "test".into(),
            forge: ForgeKind::Forgejo,
            host: format!("file://{}", remote.parent().expect("parent").display()),
            owner: ".".into(),
            name: "remote".into(),
        },
        base_branch: "main".into(),
        branch: branch.into(),
        operations: vec![domain::RebaseOperation::Reword {
            commit: target.into(),
            message: "private message\n\n# body\n".into(),
        }],
    }
}

#[tokio::test]
async fn reword_preserves_series_and_uses_existing_identity_policy() {
    for configured in [false, true] {
        let branch = "agent/reword";
        let (dir, shas) = setup_rebase_test_repo(branch);
        let remote = dir.path().join("remote.git");
        git(&remote, &["config", "core.logAllRefUpdates", "true"]);
        let adapter = Arc::new(FakeForgeAdapter::default());
        let audit = Arc::new(InMemoryAuditSink::new());
        let identity = configured.then(|| domain::CommitAuthor {
            name: "Configured".into(),
            email: "configured@test".into(),
        });
        let service = WriteOrchestrator::new(Arc::clone(&adapter), Arc::clone(&audit), identity);
        let result = service
            .rebase_branch(
                request(&remote, branch, &shas[1]),
                authorized(Some("agent/")),
                &ForgeCredential { token: None },
            )
            .await
            .expect("reword");
        assert_eq!(result.old_commit_sha.as_ref(), Some(&shas[2]));
        assert_eq!(result.branch, branch);
        assert_eq!(git(&remote, &["rev-parse", branch]), result.commit_sha);
        let pairs = result.commit_mapping.expect("complete mapping");
        assert_eq!(pairs.len(), 3);
        for (index, pair) in pairs.iter().enumerate() {
            assert_eq!(pair.old_commit_sha, shas[index]);
            assert_eq!(
                git(
                    &remote,
                    &[
                        "show",
                        "-s",
                        "--format=%T%n%an%n%ae%n%at%n%ai",
                        &pair.old_commit_sha
                    ]
                ),
                git(
                    &remote,
                    &[
                        "show",
                        "-s",
                        "--format=%T%n%an%n%ae%n%at%n%ai",
                        &pair.new_commit_sha
                    ]
                )
            );
        }
        assert_eq!(pairs[0].old_commit_sha, pairs[0].new_commit_sha);
        assert_eq!(
            adapter.authenticated_user_lookups(),
            usize::from(!configured)
        );
        if configured {
            assert_eq!(bare_commit_identity(&remote, branch).2, "Configured");
        }
        let records = audit.records().expect("audit");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "rebase_branch");
        assert!(records[0].target.contains("reword:1"));
        assert!(records[0].target.contains(&shas[2]));
        assert!(records[0].target.contains(&result.commit_sha));
        assert!(!records[0].target.contains("private message"));
        assert_eq!(
            git(&remote, &["reflog", "show", "--format=%H", branch])
                .lines()
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn reword_rejects_prefixes_and_invalid_requests_before_publication() {
    let branch = "agent/reword";
    let (dir, shas) = setup_rebase_test_repo(branch);
    let remote = dir.path().join("remote.git");
    let audit = Arc::new(InMemoryAuditSink::new());
    let service = WriteOrchestrator::new(
        Arc::new(FakeForgeAdapter::default()),
        Arc::clone(&audit),
        None,
    );
    for prefix in [None, Some(""), Some("other/")] {
        assert!(matches!(
            service
                .rebase_branch(
                    request(&remote, branch, &shas[1]),
                    authorized(prefix),
                    &ForgeCredential { token: None }
                )
                .await,
            Err(ServiceError::PolicyDenied { .. })
        ));
    }
    assert!(matches!(
        service
            .rebase_branch(
                request(&remote, "main", &shas[1]),
                authorized(Some("agent/")),
                &ForgeCredential { token: None }
            )
            .await,
        Err(ServiceError::PolicyDenied { .. })
    ));
    for target in [
        "HEAD",
        "--all",
        &shas[1][..7],
        &"0".repeat(40),
        &git(&remote, &["rev-parse", "main"]),
    ] {
        assert!(
            service
                .rebase_branch(
                    request(&remote, branch, target),
                    authorized(Some("agent/")),
                    &ForgeCredential { token: None }
                )
                .await
                .is_err()
        );
    }
    for message in [
        String::new(),
        " \n".into(),
        "private\0message".into(),
        "x".repeat(65_537),
    ] {
        let mut req = request(&remote, branch, &shas[1]);
        req.operations = vec![domain::RebaseOperation::Reword {
            commit: shas[1].clone(),
            message,
        }];
        assert!(
            service
                .rebase_branch(
                    req,
                    authorized(Some("agent/")),
                    &ForgeCredential { token: None }
                )
                .await
                .is_err()
        );
    }
    for additional in [
        domain::RebaseOperation::Drop {
            commit: shas[0].clone(),
        },
        domain::RebaseOperation::Fixup {
            commit: shas[2].clone(),
            into: shas[0].clone(),
        },
        domain::RebaseOperation::RebaseOnto,
        domain::RebaseOperation::Reword {
            commit: shas[1].clone(),
            message: "duplicate".into(),
        },
    ] {
        let mut req = request(&remote, branch, &shas[1]);
        req.operations.push(additional);
        assert!(
            service
                .rebase_branch(
                    req,
                    authorized(Some("agent/")),
                    &ForgeCredential { token: None }
                )
                .await
                .is_err()
        );
    }
    assert!(audit.records().expect("audit").is_empty());
    assert_eq!(git(&remote, &["rev-parse", branch]), shas[2]);
}

struct RacingAudit {
    remote: PathBuf,
    branch: String,
    old: String,
    competing: String,
}

#[async_trait::async_trait]
impl AuditSink for RacingAudit {
    async fn record(&self, record: AuditRecord) -> Result<(), AuditError> {
        assert!(record.target.contains(&self.old));
        git(
            &self.remote,
            &[
                "update-ref",
                &format!("refs/heads/{}", self.branch),
                &self.competing,
                &self.old,
            ],
        );
        Ok(())
    }
}

#[tokio::test]
async fn audit_failure_and_lease_race_preserve_remote() {
    let branch = "agent/reword";
    let (dir, shas) = setup_rebase_test_repo(branch);
    let remote = dir.path().join("remote.git");
    let adapter = Arc::new(FakeForgeAdapter::default());
    let service = WriteOrchestrator::new(Arc::clone(&adapter), Arc::new(FailingAuditSink), None);
    assert!(matches!(
        service
            .rebase_branch(
                request(&remote, branch, &shas[1]),
                authorized(Some("agent/")),
                &ForgeCredential { token: None }
            )
            .await,
        Err(ServiceError::Audit(_))
    ));
    assert_eq!(git(&remote, &["rev-parse", branch]), shas[2]);
    // Create a genuine competing descendant without publishing it yet.
    let tree = git(&remote, &["rev-parse", &format!("{}^{{tree}}", shas[2])]);
    let competing = git(
        &remote,
        &[
            "-c",
            "user.name=Competitor",
            "-c",
            "user.email=competitor@test",
            "commit-tree",
            &tree,
            "-p",
            &shas[2],
            "-m",
            "competing update",
        ],
    );
    git(&remote, &["config", "core.logAllRefUpdates", "true"]);
    let sink = Arc::new(RacingAudit {
        remote: remote.clone(),
        branch: branch.into(),
        old: shas[2].clone(),
        competing: competing.clone(),
    });
    let service = WriteOrchestrator::new(adapter, sink, None);
    assert!(matches!(
        service
            .rebase_branch(
                request(&remote, branch, &shas[1]),
                authorized(Some("agent/")),
                &ForgeCredential { token: None }
            )
            .await,
        Err(ServiceError::GitExec(_))
    ));
    assert_eq!(git(&remote, &["rev-parse", branch]), competing);
    assert_eq!(
        git(&remote, &["reflog", "show", "--format=%H", branch])
            .lines()
            .count(),
        1
    );
}

#[tokio::test]
async fn failed_rewrite_and_rejected_push_preserve_remote() {
    let branch = "agent/reword";
    let (dir, shas) = setup_rebase_test_repo(branch);
    let remote = dir.path().join("remote.git");
    for fail_rewrite in [true, false] {
        let audit = Arc::new(InMemoryAuditSink::new());
        let identity = domain::CommitAuthor {
            name: if fail_rewrite { "" } else { "Valid" }.into(),
            email: "valid@test".into(),
        };
        let service = WriteOrchestrator::new(
            Arc::new(FakeForgeAdapter::default()),
            Arc::clone(&audit),
            Some(identity),
        );
        git(&remote, &["config", "receive.denyNonFastForwards", "true"]);
        assert!(
            service
                .rebase_branch(
                    request(&remote, branch, &shas[1]),
                    authorized(Some("agent/")),
                    &ForgeCredential { token: None }
                )
                .await
                .is_err()
        );
        assert_eq!(
            audit.records().expect("audit").len(),
            usize::from(!fail_rewrite)
        );
        assert_eq!(git(&remote, &["rev-parse", branch]), shas[2]);
    }
}

#[test]
fn exact_ids_including_sha256_and_ambiguous_prefixes() {
    for length in [40, 64] {
        let commits = vec![
            format!("{}1", "a".repeat(length - 1)),
            format!("{}2", "a".repeat(length - 1)),
        ];
        for target in [
            &commits[0][..7],
            &commits[0][..length - 1],
            "HEAD~1",
            "--all",
            "unknown",
        ] {
            assert!(
                validate_rebase_operations(
                    &[domain::RebaseOperation::Reword {
                        commit: target.into(),
                        message: "message".into()
                    }],
                    &commits
                )
                .is_err()
            );
        }
        assert!(
            validate_rebase_operations(
                &[domain::RebaseOperation::Reword {
                    commit: commits[1].clone(),
                    message: "é".repeat(32_768)
                }],
                &commits
            )
            .is_ok()
        );
    }
}

#[tokio::test]
async fn merge_history_is_rejected_without_audit_or_push() {
    let branch = "agent/reword";
    let (dir, shas) = setup_rebase_test_repo(branch);
    let remote = dir.path().join("remote.git");
    let tree = git(&remote, &["rev-parse", &format!("{}^{{tree}}", shas[2])]);
    let base = git(&remote, &["rev-parse", "main"]);
    let merge = git(
        &remote,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@test",
            "commit-tree",
            &tree,
            "-p",
            &shas[2],
            "-p",
            &base,
            "-m",
            "merge",
        ],
    );
    git(
        &remote,
        &["update-ref", &format!("refs/heads/{branch}"), &merge],
    );
    let audit = Arc::new(InMemoryAuditSink::new());
    let service = WriteOrchestrator::new(
        Arc::new(FakeForgeAdapter::default()),
        Arc::clone(&audit),
        None,
    );
    assert!(matches!(
        service
            .rebase_branch(
                request(&remote, branch, &shas[1]),
                authorized(Some("agent/")),
                &ForgeCredential { token: None }
            )
            .await,
        Err(ServiceError::Validation(_))
    ));
    assert!(audit.records().expect("audit").is_empty());
    assert_eq!(git(&remote, &["rev-parse", branch]), merge);
}
