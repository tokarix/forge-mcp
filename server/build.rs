use std::path::Path;
use std::process::Command;

fn main() {
    let git_commit_short = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_COMMIT_SHORT={git_commit_short}");

    // Always re-run when HEAD itself changes (branch switch or detached HEAD).
    println!("cargo:rerun-if-changed=../.git/HEAD");

    // When HEAD is a symbolic ref (e.g. "ref: refs/heads/master"), also watch
    // the branch tip file so that new commits on the same branch trigger a
    // rebuild.
    let git_head = Path::new("../.git/HEAD");
    if let Ok(contents) = std::fs::read_to_string(git_head)
        && let Some(ref_path) = contents.trim().strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed=../.git/{ref_path}");
    }
}
