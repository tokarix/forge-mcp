//! Diff validation — a first-class security boundary.
//!
//! Parses unified diff headers to extract touched file paths and validates
//! them against the repository path rules. Rejects binary markers, symlink
//! mode changes, submodule diffs, and patches exceeding a size budget.

use thiserror::Error;

use crate::validate_repository_path;

/// Maximum number of files allowed in a single patch.
const MAX_DIFF_FILES: usize = 100;

/// Maximum total bytes allowed in a single patch.
const MAX_DIFF_BYTES: usize = 1_048_576; // 1 MiB

#[derive(Debug, Error)]
pub enum DiffError {
    #[error("binary file detected: {path}")]
    BinaryFile { path: String },
    #[error("diff exceeds maximum size of {max} bytes")]
    ExceedsBudget { max: usize },
    #[error("invalid diff header: {reason}")]
    InvalidHeader { reason: String },
    #[error("invalid path in diff: {reason}")]
    InvalidPath { reason: String },
    #[error("submodule change detected: {path}")]
    SubmoduleChange { path: String },
    #[error("symlink mode change detected: {path}")]
    SymlinkChange { path: String },
    #[error("too many files in diff: {count} exceeds limit of {max}")]
    TooManyFiles { count: usize, max: usize },
}

/// A single file touched by the diff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffFileSummary {
    pub is_deleted: bool,
    pub is_new: bool,
    pub path: String,
}

/// Result of validating a unified diff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffValidationResult {
    pub files: Vec<DiffFileSummary>,
    pub total_bytes: usize,
}

/// Returns the path of the last file in the list, or `"<unknown>"`.
fn last_file_path(files: &[DiffFileSummary]) -> String {
    files
        .last()
        .map_or_else(|| "<unknown>".to_string(), |f| f.path.clone())
}

/// Validates a unified diff patch string.
///
/// Parses diff headers, extracts file paths, and checks each path against
/// repository path rules. Rejects binary content, symlink mode changes,
/// submodule diffs, oversized patches, and patches touching too many files.
///
/// # Errors
///
/// Returns a `DiffError` if the patch violates any validation rule.
pub fn validate_diff(patch: &str) -> Result<DiffValidationResult, DiffError> {
    let total_bytes = patch.len();
    if total_bytes > MAX_DIFF_BYTES {
        return Err(DiffError::ExceedsBudget {
            max: MAX_DIFF_BYTES,
        });
    }

    let mut files = Vec::new();

    for line in patch.lines() {
        // Detect binary file markers
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            return Err(DiffError::BinaryFile {
                path: line.to_string(),
            });
        }

        // Detect submodule changes
        if line.starts_with("Subproject commit ") {
            return Err(DiffError::SubmoduleChange {
                path: last_file_path(&files),
            });
        }

        // Detect symlink mode changes (mode 120000)
        if line.starts_with("old mode 120000")
            || line.starts_with("new mode 120000")
            || line.starts_with("new file mode 120000")
            || line.starts_with("deleted file mode 120000")
        {
            return Err(DiffError::SymlinkChange {
                path: last_file_path(&files),
            });
        }

        // Parse diff headers: "diff --git a/path b/path"
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let (a_path, b_path) = parse_diff_header(rest)?;
            // Use b_path as the canonical path (destination)
            let file_path = if b_path == "/dev/null" {
                a_path
            } else {
                b_path
            };
            files.push(DiffFileSummary {
                is_deleted: false,
                is_new: false,
                path: file_path,
            });
        }

        // Detect new/deleted files from subsequent header lines
        if line.starts_with("new file mode")
            && let Some(last) = files.last_mut()
        {
            last.is_new = true;
        }
        if line.starts_with("deleted file mode")
            && let Some(last) = files.last_mut()
        {
            last.is_deleted = true;
        }
    }

    if files.len() > MAX_DIFF_FILES {
        return Err(DiffError::TooManyFiles {
            count: files.len(),
            max: MAX_DIFF_FILES,
        });
    }

    // Validate all paths
    for file in &files {
        validate_repository_path(&file.path).map_err(|reason| DiffError::InvalidPath { reason })?;
    }

    Ok(DiffValidationResult { files, total_bytes })
}

/// Parses "a/path b/path" from a diff --git header line.
fn parse_diff_header(header: &str) -> Result<(String, String), DiffError> {
    // Handle quoted paths (git uses quotes for special characters)
    // Simple case: "a/foo b/bar"
    // The a/ and b/ prefixes are standard git diff prefixes
    let parts: Vec<&str> = header.splitn(2, " b/").collect();
    if parts.len() != 2 {
        return Err(DiffError::InvalidHeader {
            reason: format!("cannot parse diff header: {header}"),
        });
    }

    let a_path = parts[0].strip_prefix("a/").unwrap_or(parts[0]).to_string();
    let b_path = parts[1].to_string();

    Ok((a_path, b_path))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    #[test]
    fn validates_simple_patch() {
        let patch = "\
diff --git a/README.md b/README.md
index abc123..def456 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,4 @@
 # Hello
+New line
 World
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "README.md");
        assert!(!result.files[0].is_new);
        assert!(!result.files[0].is_deleted);
    }

    #[test]
    fn validates_new_file_patch() {
        let patch = "\
diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+content
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].is_new);
    }

    #[test]
    fn validates_deleted_file_patch() {
        let patch = "\
diff --git a/old.txt b/old.txt
deleted file mode 100644
index abc1234..0000000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-content
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "old.txt");
        assert!(result.files[0].is_deleted);
    }

    #[test]
    fn validates_multi_file_patch() {
        let patch = "\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-old
+new
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -1 +1 @@
-old
+new
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 2);
        assert_eq!(result.files[0].path, "a.txt");
        assert_eq!(result.files[1].path, "b.txt");
    }

    #[test]
    fn rejects_binary_file() {
        let patch = "\
diff --git a/image.png b/image.png
Binary files /dev/null and b/image.png differ
";
        let err = validate_diff(patch).expect_err("binary should be rejected");
        assert!(matches!(err, DiffError::BinaryFile { .. }));
    }

    #[test]
    fn rejects_git_binary_patch() {
        let patch = "\
diff --git a/data.bin b/data.bin
GIT binary patch
literal 1234
";
        let err = validate_diff(patch).expect_err("git binary should be rejected");
        assert!(matches!(err, DiffError::BinaryFile { .. }));
    }

    #[test]
    fn rejects_symlink() {
        let patch = "\
diff --git a/link b/link
new file mode 120000
";
        let err = validate_diff(patch).expect_err("symlink should be rejected");
        assert!(matches!(err, DiffError::SymlinkChange { .. }));
    }

    #[test]
    fn rejects_submodule() {
        let patch = "\
diff --git a/vendor/lib b/vendor/lib
Subproject commit bbbbbbb
";
        let err = validate_diff(patch).expect_err("submodule should be rejected");
        assert!(matches!(err, DiffError::SubmoduleChange { .. }));
    }

    #[test]
    fn rejects_path_traversal_in_diff() {
        let patch = "\
diff --git a/../../../etc/passwd b/../../../etc/passwd
--- a/../../../etc/passwd
+++ b/../../../etc/passwd
@@ -1 +1 @@
-old
+new
";
        let err = validate_diff(patch).expect_err("traversal should be rejected");
        assert!(matches!(err, DiffError::InvalidPath { .. }));
    }

    #[test]
    fn rejects_oversized_patch() {
        let patch = "x".repeat(MAX_DIFF_BYTES + 1);
        let err = validate_diff(&patch).expect_err("oversized should be rejected");
        assert!(matches!(err, DiffError::ExceedsBudget { .. }));
    }

    #[test]
    fn rejects_too_many_files() {
        let mut patch = String::new();
        for i in 0..=MAX_DIFF_FILES {
            let _ = write!(
                patch,
                "diff --git a/file{i}.txt b/file{i}.txt\n--- a/file{i}.txt\n+++ b/file{i}.txt\n"
            );
        }
        let err = validate_diff(&patch).expect_err("too many files should be rejected");
        assert!(matches!(err, DiffError::TooManyFiles { .. }));
    }

    #[test]
    fn rejects_invalid_diff_header() {
        let patch = "diff --git broken\n";
        let err = validate_diff(patch).expect_err("invalid header should be rejected");
        assert!(matches!(err, DiffError::InvalidHeader { .. }));
    }
}
