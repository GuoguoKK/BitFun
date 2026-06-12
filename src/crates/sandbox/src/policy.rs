//! Sandbox policy definition and parsing.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Sandbox mode determining the level of filesystem restriction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxMode {
    /// Only allow writes to project directory and temp directories.
    WorkspaceWrite,
    /// No writes allowed at all (read-only access).
    ReadOnly,
    /// No restrictions — run without sandboxing.
    FullAccess,
}

impl Default for SandboxMode {
    fn default() -> Self {
        SandboxMode::WorkspaceWrite
    }
}

/// Network access policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    /// Network access is blocked.
    Restricted,
    /// Network access is allowed.
    Enabled,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy::Restricted
    }
}

/// Sandbox policy describing filesystem and network restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Sandbox mode.
    pub mode: SandboxMode,
    /// Directories that are writable (project dir, worktree, tmp).
    pub writable_roots: Vec<PathBuf>,
    /// Additional writable paths from user configuration.
    pub extra_writable_roots: Vec<PathBuf>,
    /// Paths that are explicitly denied for writing (Desktop, Documents, etc.).
    pub denied_write_paths: Vec<PathBuf>,
    /// Network access policy.
    pub network: NetworkPolicy,
}

impl SandboxPolicy {
    /// Create a workspace-write policy for the given project directory.
    pub fn new_workspace_write(workspace_dir: PathBuf) -> Self {
        let mut writable_roots = vec![workspace_dir.clone()];
        // Allow TEMP/TMP directories
        for key in ["TEMP", "TMP", "TMPDIR"] {
            if let Ok(v) = std::env::var(key) {
                let p = PathBuf::from(v);
                if p.exists() {
                    writable_roots.push(p);
                }
            }
        }
        // Deny sensitive user directories
        let denied_write_paths = Self::default_denied_paths();
        Self {
            mode: SandboxMode::WorkspaceWrite,
            writable_roots,
            extra_writable_roots: Vec::new(),
            denied_write_paths,
            network: NetworkPolicy::Restricted,
        }
    }

    /// Create a read-only policy.
    pub fn new_read_only() -> Self {
        Self {
            mode: SandboxMode::ReadOnly,
            writable_roots: Vec::new(),
            extra_writable_roots: Vec::new(),
            denied_write_paths: Vec::new(),
            network: NetworkPolicy::Restricted,
        }
    }

    /// Create a full-access policy (no sandboxing).
    pub fn new_full_access() -> Self {
        Self {
            mode: SandboxMode::FullAccess,
            writable_roots: Vec::new(),
            extra_writable_roots: Vec::new(),
            denied_write_paths: Vec::new(),
            network: NetworkPolicy::Enabled,
        }
    }

    /// Returns all writable paths (roots + extra).
    pub fn all_writable_paths(&self) -> Vec<&PathBuf> {
        self.writable_roots
            .iter()
            .chain(self.extra_writable_roots.iter())
            .collect()
    }

    /// Default denied paths: Desktop, Documents, Downloads, Pictures, Music, Videos.
    fn default_denied_paths() -> Vec<PathBuf> {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .or_else(|_| std::env::var("HOMEDIR"))
            .unwrap_or_default();
        if home.is_empty() {
            return Vec::new();
        }
        let mut paths = Vec::new();
        for dir in ["Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"] {
            let p = PathBuf::from(format!("{home}/{dir}"));
            if p.exists() {
                paths.push(p);
            }
        }
        paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_workspace_write_policy() {
        let json = r#"{
            "mode": "workspace-write",
            "writable_roots": ["D:/code/project"],
            "extra_writable_roots": [],
            "denied_write_paths": ["C:/Users/admin/Desktop"],
            "network": "restricted"
        }"#;
        let policy: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.mode, SandboxMode::WorkspaceWrite);
        assert_eq!(policy.writable_roots.len(), 1);
        assert_eq!(policy.denied_write_paths.len(), 1);
    }

    #[test]
    fn parse_read_only_policy() {
        let json = r#"{
            "mode": "read-only",
            "writable_roots": [],
            "extra_writable_roots": [],
            "denied_write_paths": [],
            "network": "restricted"
        }"#;
        let policy: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.mode, SandboxMode::ReadOnly);
    }

    #[test]
    fn parse_full_access_policy() {
        let json = r#"{
            "mode": "full-access",
            "writable_roots": [],
            "extra_writable_roots": [],
            "denied_write_paths": [],
            "network": "enabled"
        }"#;
        let policy: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.mode, SandboxMode::FullAccess);
    }

    #[test]
    fn new_workspace_write_includes_temp() {
        let policy = SandboxPolicy::new_workspace_write(PathBuf::from("/tmp/test-project"));
        assert_eq!(policy.mode, SandboxMode::WorkspaceWrite);
        assert!(policy.writable_roots.iter().any(|p| p.to_string_lossy().contains("test-project")));
    }

    #[test]
    fn new_full_access_policy() {
        let policy = SandboxPolicy::new_full_access();
        assert_eq!(policy.mode, SandboxMode::FullAccess);
        assert_eq!(policy.network, NetworkPolicy::Enabled);
    }
}
