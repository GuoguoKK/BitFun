//! Sandbox path guard: checks whether a write target is allowed by the sandbox policy.

use crate::policy::{SandboxMode, SandboxPolicy};
use std::path::{Path, PathBuf};

/// Result of a sandbox path check.
#[derive(Debug, Clone)]
pub struct PathCheckResult {
    /// Whether the path is allowed.
    pub allowed: bool,
    /// Reason for denial (if not allowed).
    pub reason: Option<String>,
}

/// Check whether a write target path is allowed by the sandbox policy.
///
/// - `WorkspaceWrite`: allow writes to writable_roots and extra_writable_roots,
///   deny writes to denied_write_paths.
/// - `ReadOnly`: deny all writes.
/// - `FullAccess`: allow everything.
pub fn is_path_allowed(target: &Path, policy: &SandboxPolicy, project_dir: &Path) -> PathCheckResult {
    match policy.mode {
        SandboxMode::FullAccess => PathCheckResult {
            allowed: true,
            reason: None,
        },
        SandboxMode::WorkspaceWrite => {
            let normalized = normalize_path(target);

            // Check denied paths first
            for denied in &policy.denied_write_paths {
                let normalized_denied = normalize_path(denied);
                if is_subpath(&normalized_denied, &normalized) || normalized == normalized_denied {
                    return PathCheckResult {
                        allowed: false,
                        reason: Some(format!(
                            "path is in the denied zone: {}",
                            denied.display()
                        )),
                    };
                }
            }

            // Check writable roots
            for root in policy.all_writable_paths() {
                let normalized_root = normalize_path(root);
                if is_subpath(&normalized_root, &normalized) {
                    return PathCheckResult {
                        allowed: true,
                        reason: None,
                    };
                }
            }

            PathCheckResult {
                allowed: false,
                reason: Some("path is outside the allowed project directory".to_string()),
            }
        }
        SandboxMode::ReadOnly => PathCheckResult {
            allowed: false,
            reason: Some(
                "sandbox is in read-only mode, all writes are blocked".to_string(),
            ),
        },
    }
}

/// Normalize a path for comparison (case-insensitive on Windows).
fn normalize_path(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    if cfg!(windows) {
        s.replace('\\', "/").to_lowercase()
    } else {
        s
    }
}

/// Check if `parent` is a parent directory of `child` (or they are equal).
fn is_subpath(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    child.starts_with(parent) && child.as_bytes().get(parent.len()) == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_access_allows_everything() {
        let policy = SandboxPolicy::new_full_access();
        let result = is_path_allowed(
            Path::new("C:/Users/admin/Desktop/test.txt"),
            &policy,
            Path::new("D:/project"),
        );
        assert!(result.allowed);
    }

    #[test]
    fn read_only_blocks_everything() {
        let policy = SandboxPolicy::new_read_only();
        let result = is_path_allowed(
            Path::new("D:/project/test.txt"),
            &policy,
            Path::new("D:/project"),
        );
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("read-only"));
    }

    #[test]
    fn workspace_write_allows_project_dir() {
        let policy = SandboxPolicy::new_workspace_write(PathBuf::from("D:/project"));
        let result = is_path_allowed(
            Path::new("D:/project/src/lib.rs"),
            &policy,
            Path::new("D:/project"),
        );
        assert!(result.allowed);
    }

    #[test]
    fn workspace_write_denies_desktop() {
        let policy = SandboxPolicy::new_workspace_write(PathBuf::from("D:/project"));
        let result = is_path_allowed(
            Path::new("C:/Users/admin/Desktop/test.txt"),
            &policy,
            Path::new("D:/project"),
        );
        assert!(!result.allowed);
    }

    #[test]
    fn workspace_write_denies_explicit_denied_path() {
        let mut policy = SandboxPolicy::new_workspace_write(PathBuf::from("D:/project"));
        policy.denied_write_paths.push(PathBuf::from("D:/secrets"));
        let result = is_path_allowed(
            Path::new("D:/secrets/key.pem"),
            &policy,
            Path::new("D:/project"),
        );
        assert!(!result.allowed);
    }
}
