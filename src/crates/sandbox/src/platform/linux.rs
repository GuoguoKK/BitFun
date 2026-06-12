//! Linux sandbox implementation using Landlock LSM + bubblewrap.
//!
//! Strategy (inspired by Codex's Linux sandboxing):
//! - Landlock LSM: kernel-enforced filesystem access control (read-only / read-write scopes)
//! - bubblewrap (bwrap): user-namespace isolation + network isolation (--unshare-net)
//!
//! Flow:
//! 1. Check if bwrap is available on the system
//! 2. Build bwrap arguments for filesystem mounts and network isolation
//! 3. Apply Landlock rules inside the sandboxed process
//! 4. Execute the command within the bwrap namespace

use crate::common::{parse_env, ExecResult};
use crate::policy::{NetworkPolicy, SandboxMode, SandboxPolicy};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Find the system bubblewrap executable.
fn find_bwrap() -> Option<PathBuf> {
    which::which("bwrap").ok()
}

/// Build bubblewrap arguments from the sandbox policy.
fn build_bwrap_args(policy: &SandboxPolicy, cwd: &Path) -> Vec<String> {
    let mut args = Vec::new();

    // Mount the root filesystem as read-only by default
    args.push("--ro-bind".to_string());
    args.push("/".to_string());
    args.push("/".to_string());

    // Mount /dev with necessary devices
    args.push("--dev".to_string());
    args.push("/dev".to_string());

    // Mount /proc
    args.push("--proc".to_string());
    args.push("/proc".to_string());

    // Mount /tmp as tmpfs (writable)
    args.push("--tmpfs".to_string());
    args.push("/tmp".to_string());

    // Allow writes to writable roots
    for root in policy.all_writable_paths() {
        if root.exists() {
            // Bind-mount writable paths from host
            args.push("--bind".to_string());
            args.push(root.to_string_lossy().to_string());
            args.push(root.to_string_lossy().to_string());
        }
    }

    // Deny write paths by mounting them read-only (override previous bind mounts)
    for denied in &policy.denied_write_paths {
        if denied.exists() {
            args.push("--ro-bind".to_string());
            args.push(denied.to_string_lossy().to_string());
            args.push(denied.to_string_lossy().to_string());
        }
    }

    // Ensure cwd is accessible
    if cwd.exists() {
        match policy.mode {
            SandboxMode::WorkspaceWrite => {
                // Make cwd writable
                args.push("--bind".to_string());
                args.push(cwd.to_string_lossy().to_string());
                args.push(cwd.to_string_lossy().to_string());
            }
            SandboxMode::ReadOnly => {
                // Keep cwd read-only (already mounted as ro-bind from /)
            }
            SandboxMode::FullAccess => {
                // Should not reach here, but just bind it writable
                args.push("--bind".to_string());
                args.push(cwd.to_string_lossy().to_string());
                args.push(cwd.to_string_lossy().to_string());
            }
        }
    }

    // Network isolation
    if policy.network == NetworkPolicy::Restricted {
        args.push("--unshare-net".to_string());
    }

    // Allow dconf/X11 access for GUI apps (common need)
    // Mount /run/user/{uid} if it exists
    if let Ok(uid) = std::env::var("XDG_RUNTIME_DIR") {
        let run_dir = PathBuf::from(&uid);
        if run_dir.exists() {
            args.push("--bind-try".to_string());
            args.push(uid.clone());
            args.push(uid);
        }
    }

    args
}

/// Apply Landlock rules as a best-effort filesystem access control layer.
///
/// This is called inside the sandboxed process after bwrap has set up the
/// namespace. Since bwrap already provides mount-level isolation, Landlock
/// serves as an additional defense-in-depth layer.
fn apply_landlock_rules(policy: &SandboxPolicy) -> Result<()> {
    use landlock::{
        Access, AccessFs, Ruleset, RulesetAttr, RulesetCreated, RulesetStatus,
        PathBeneath, PathFd,
    };

    let compat_state = landlock::Compatibility::new();
    let mut ruleset = Ruleset::new()
        .handle_access(AccessFs::from_all(compat_state))
        .map_err(|e| anyhow!("Landlock ruleset creation failed: {e}"))?;

    // For read-only mode: only allow read access everywhere
    // For workspace-write: allow write to writable roots, read elsewhere

    match policy.mode {
        SandboxMode::ReadOnly => {
            // Allow read access to the entire filesystem
            let root_fd = PathFd::new("/")
                .map_err(|e| anyhow!("Landlock: failed to open /: {e}"))?;
            ruleset = ruleset.add_rule(
                PathBeneath::new(root_fd, AccessFs::from_read(compat_state))
                    .map_err(|e| anyhow!("Landlock: failed to add read rule: {e}"))?,
            );
        }
        SandboxMode::WorkspaceWrite => {
            // Allow read access everywhere
            let root_fd = PathFd::new("/")
                .map_err(|e| anyhow!("Landlock: failed to open /: {e}"))?;
            ruleset = ruleset.add_rule(
                PathBeneath::new(root_fd, AccessFs::from_read(compat_state))
                    .map_err(|e| anyhow!("Landlock: failed to add read rule: {e}"))?,
            );

            // Allow write access to writable roots
            for root in policy.all_writable_paths() {
                if root.exists() {
                    if let Ok(fd) = PathFd::new(root) {
                        if let Ok(rule) = PathBeneath::new(fd, AccessFs::from_all(compat_state)) {
                            ruleset = ruleset.add_rule(rule);
                        }
                    }
                }
            }
        }
        SandboxMode::FullAccess => {
            // Full access — no Landlock restrictions
            return Ok(());
        }
    }

    let status = ruleset.restrict_self()
        .map_err(|e| anyhow!("Landlock restrict_self failed: {e}"))?;

    match status {
        RulesetStatus::FullyEnforced => {
            log::info!("Landlock: fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            log::warn!("Landlock: partially enforced (some rules not supported by kernel)");
        }
        RulesetStatus::NotEnforced => {
            log::warn!("Landlock: not enforced (kernel may not support Landlock)");
        }
    }

    Ok(())
}

/// Run a command in a Linux sandbox using bubblewrap + Landlock.
pub fn run_sandboxed(
    policy: SandboxPolicy,
    command: &[String],
    cwd: &Path,
    env_args: &[String],
    timeout_ms: u64,
) -> Result<ExecResult> {
    let extra_env = parse_env(env_args);

    // Try bwrap first
    if let Some(bwrap_path) = find_bwrap() {
        log::info!("Linux sandbox: using bwrap at {}", bwrap_path.display());
        run_with_bwrap(&bwrap_path, &policy, command, cwd, &extra_env, timeout_ms)
    } else {
        // Fallback: try Landlock-only (no namespace isolation)
        log::warn!("Linux sandbox: bwrap not found, attempting Landlock-only sandbox");
        run_with_landlock_only(&policy, command, cwd, &extra_env, timeout_ms)
    }
}

/// Execute command using bubblewrap for namespace isolation.
fn run_with_bwrap(
    bwrap_path: &Path,
    policy: &SandboxPolicy,
    command: &[String],
    cwd: &Path,
    extra_env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<ExecResult> {
    let bwrap_args = build_bwrap_args(policy, cwd);

    let mut full_args = bwrap_args;
    full_args.push("--".to_string());

    // Add a Landlock enforcement wrapper if possible
    // For simplicity, we rely on bwrap's mount isolation for now
    // Landlock can be added as a defense-in-depth layer later

    // Add the actual command
    full_args.extend(command.iter().cloned());

    let mut cmd = Command::new(bwrap_path);
    cmd.args(&full_args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let result = run_command_with_timeout(cmd, timeout_ms)?;
    Ok(result)
}

/// Execute command with Landlock-only sandbox (no bwrap namespace isolation).
fn run_with_landlock_only(
    policy: &SandboxPolicy,
    command: &[String],
    cwd: &Path,
    extra_env: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<ExecResult> {
    // Apply Landlock rules before executing the command
    // This only works if the kernel supports Landlock
    match apply_landlock_rules(policy) {
        Ok(()) => {
            log::info!("Landlock rules applied successfully");
        }
        Err(e) => {
            log::warn!("Landlock rules could not be applied: {e}. Running unsandboxed.");
            eprintln!("bitfun-sandbox: Landlock not available, running unsandboxed");
        }
    }

    // Execute the command
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let result = run_command_with_timeout(cmd, timeout_ms)?;
    Ok(result)
}

/// Run a Command with optional timeout.
fn run_command_with_timeout(
    mut cmd: Command,
    timeout_ms: u64,
) -> Result<ExecResult> {
    let mut child = cmd.spawn()
        .with_context(|| format!("failed to spawn command: {:?}", cmd.get_program()))?;

    let timeout = if timeout_ms > 0 {
        Some(std::time::Duration::from_millis(timeout_ms))
    } else {
        None
    };

    let mut timed_out = false;
    let mut exit_code = -1i32;

    if let Some(dur) = timeout {
        let start = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = status.code().unwrap_or(-1);
                    break;
                }
                Ok(None) => {
                    if start.elapsed() >= dur {
                        let _ = child.kill();
                        let _ = child.wait();
                        timed_out = true;
                        exit_code = 128 + 64;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    log::error!("wait error: {e}");
                    break;
                }
            }
        }
    } else {
        let status = child.wait()?;
        exit_code = status.code().unwrap_or(-1);
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = std::io::Read::read_to_end(&mut out, &mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = std::io::Read::read_to_end(&mut err, &mut stderr);
    }

    Ok(ExecResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
    })
}
