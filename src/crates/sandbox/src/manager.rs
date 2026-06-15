//! Sandbox manager: selects platform sandbox type and orchestrates execution.

use crate::common::{run_unsandboxed, ExecResult};
use crate::platform::run_sandboxed;
use crate::policy::{NetworkPolicy, SandboxMode, SandboxPolicy};
use anyhow::Result;
use std::path::Path;

/// The type of OS-level sandbox to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxType {
    /// No sandboxing.
    None,
    /// macOS sandbox-exec (Seatbelt).
    MacosSeatbelt,
    /// Linux Landlock LSM + bubblewrap.
    LinuxLandlock,
    /// Windows Restricted Token + ACL.
    WindowsRestrictedToken,
}

impl SandboxType {
    /// Returns a metric tag for the sandbox type.
    pub fn as_metric_tag(self) -> &'static str {
        match self {
            SandboxType::None => "none",
            SandboxType::MacosSeatbelt => "seatbelt",
            SandboxType::LinuxLandlock => "landlock",
            SandboxType::WindowsRestrictedToken => "windows_restricted_token",
        }
    }

    /// Returns the platform-default sandbox type, if available.
    pub fn platform_default() -> Option<SandboxType> {
        if cfg!(target_os = "macos") {
            Some(SandboxType::MacosSeatbelt)
        } else if cfg!(target_os = "linux") {
            Some(SandboxType::LinuxLandlock)
        } else if cfg!(target_os = "windows") {
            Some(SandboxType::WindowsRestrictedToken)
        } else {
            None
        }
    }
}

/// Preference for sandboxing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SandboxablePreference {
    /// Automatically decide based on policy.
    #[default]
    Auto,
    /// Require sandboxing.
    Require,
    /// Forbid sandboxing.
    Forbid,
}

/// Manages sandbox selection and command execution.
#[derive(Default)]
pub struct SandboxManager;

impl SandboxManager {
    /// Create a new sandbox manager.
    pub fn new() -> Self {
        Self
    }

    /// Select the sandbox type based on policy and preference.
    pub fn select_sandbox_type(
        &self,
        policy: &SandboxPolicy,
        pref: SandboxablePreference,
    ) -> SandboxType {
        match pref {
            SandboxablePreference::Forbid => SandboxType::None,
            SandboxablePreference::Require => {
                SandboxType::platform_default().unwrap_or(SandboxType::None)
            }
            SandboxablePreference::Auto => {
                if policy.mode == SandboxMode::FullAccess {
                    SandboxType::None
                } else {
                    SandboxType::platform_default().unwrap_or(SandboxType::None)
                }
            }
        }
    }

    /// Execute a command with the given sandbox policy.
    ///
    /// If the policy is `FullAccess`, runs unsandboxed.
    /// Otherwise, runs through the platform-specific sandbox.
    pub fn execute(
        &self,
        policy: SandboxPolicy,
        command: &[String],
        cwd: &Path,
        env_args: &[String],
        timeout_ms: u64,
    ) -> Result<ExecResult> {
        if command.is_empty() {
            anyhow::bail!("no command to execute");
        }

        log::info!(
            "SandboxManager: mode={:?}, network={:?}, command={}",
            policy.mode,
            policy.network,
            command.first().map(|s| s.as_str()).unwrap_or("")
        );

        if policy.mode == SandboxMode::FullAccess {
            log::debug!("SandboxManager: full-access mode, running unsandboxed");
            run_unsandboxed(command, cwd, env_args, timeout_ms)
        } else {
            log::debug!("SandboxManager: running in platform sandbox");
            run_sandboxed(policy, command, cwd, env_args, timeout_ms)
        }
    }

    /// Execute a command with auto-detected sandbox type.
    pub fn execute_auto(
        &self,
        policy: SandboxPolicy,
        command: &[String],
        cwd: &Path,
        env_args: &[String],
        timeout_ms: u64,
    ) -> Result<ExecResult> {
        self.execute(policy, command, cwd, env_args, timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn select_sandbox_forbid_returns_none() {
        let manager = SandboxManager::new();
        let policy = SandboxPolicy::new_workspace_write(PathBuf::from("/tmp/test"));
        let sandbox_type = manager.select_sandbox_type(&policy, SandboxablePreference::Forbid);
        assert_eq!(sandbox_type, SandboxType::None);
    }

    #[test]
    fn select_sandbox_full_access_auto_returns_none() {
        let manager = SandboxManager::new();
        let policy = SandboxPolicy::new_full_access();
        let sandbox_type = manager.select_sandbox_type(&policy, SandboxablePreference::Auto);
        assert_eq!(sandbox_type, SandboxType::None);
    }

    #[test]
    fn select_sandbox_workspace_write_auto_returns_platform() {
        let manager = SandboxManager::new();
        let policy = SandboxPolicy::new_workspace_write(PathBuf::from("/tmp/test"));
        let sandbox_type = manager.select_sandbox_type(&policy, SandboxablePreference::Auto);
        // On Windows, should be WindowsRestrictedToken
        #[cfg(target_os = "windows")]
        assert_eq!(sandbox_type, SandboxType::WindowsRestrictedToken);
        #[cfg(target_os = "linux")]
        assert_eq!(sandbox_type, SandboxType::LinuxLandlock);
        #[cfg(target_os = "macos")]
        assert_eq!(sandbox_type, SandboxType::MacosSeatbelt);
    }

    #[test]
    fn execute_full_access_runs_unsandboxed() {
        let manager = SandboxManager::new();
        let policy = SandboxPolicy::new_full_access();
        let mut command = vec![
            if cfg!(windows) { "cmd".to_string() } else { "echo".to_string() },
            if cfg!(windows) { "/C".to_string() } else { "hello".to_string() },
        ];
        if cfg!(windows) {
            command.push("echo hello".to_string());
        }
        // This test would need proper command construction per platform
        // For now just verify it doesn't panic
        let _ = manager.execute(
            policy,
            &command,
            Path::new("."),
            &[],
            5000,
        );
    }
}
