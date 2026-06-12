//! Platform-specific sandbox implementations.

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

use crate::common::ExecResult;
use crate::policy::SandboxPolicy;
use anyhow::Result;
use std::path::Path;

/// Run a command inside the platform-specific sandbox.
pub fn run_sandboxed(
    policy: SandboxPolicy,
    command: &[String],
    cwd: &Path,
    env_args: &[String],
    timeout_ms: u64,
) -> Result<ExecResult> {
    #[cfg(target_os = "windows")]
    {
        windows::run_sandboxed(policy, command, cwd, env_args, timeout_ms)
    }
    #[cfg(target_os = "linux")]
    {
        linux::run_sandboxed(policy, command, cwd, env_args, timeout_ms)
    }
    #[cfg(target_os = "macos")]
    {
        macos::run_sandboxed(policy, command, cwd, env_args, timeout_ms)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (policy, timeout_ms);
        anyhow::bail!("sandboxing is not supported on this platform");
    }
}
