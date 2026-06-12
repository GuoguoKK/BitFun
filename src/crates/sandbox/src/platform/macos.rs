//! macOS sandbox implementation using sandbox-exec (Seatbelt).
//!
//! Strategy (inspired by Codex's Seatbelt sandboxing):
//! - Use /usr/bin/sandbox-exec (hardcoded path to prevent PATH injection)
//! - Generate a Seatbelt SBPL policy from the SandboxPolicy
//! - Execute the command under sandbox-exec with the generated policy
//!
//! Policy generation:
//! - workspace-write: allow file-write* to writable roots, deny elsewhere
//! - read-only: allow file-read* only, deny all file-write*
//! - full-access: no sandbox (handled by caller)

use crate::common::{parse_env, ExecResult};
use crate::policy::{NetworkPolicy, SandboxMode, SandboxPolicy};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Hardcoded path to sandbox-exec to prevent PATH injection.
/// If /usr/bin/sandbox-exec has been tampered with, the attacker already has root.
const MACOS_PATH_TO_SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

/// Base Seatbelt policy (embedded from seatbelt_base_policy.sbpl).
const SEATBELT_BASE_POLICY: &str = include_str!("seatbelt_base_policy.sbpl");

/// Network policy additions (embedded from seatbelt_network_policy.sbpl).
const SEATBELT_NETWORK_POLICY: &str = include_str!("seatbelt_network_policy.sbpl");

/// Generate a Seatbelt SBPL policy string from the SandboxPolicy.
fn generate_seatbelt_policy(policy: &SandboxPolicy, cwd: &Path) -> (String, Vec<(String, PathBuf)>) {
    let mut policy_sections = Vec::new();
    let mut params: Vec<(String, PathBuf)> = Vec::new();

    // Start with base policy
    policy_sections.push(SEATBELT_BASE_POLICY.to_string());

    // File read policy: allow reading from the entire filesystem
    let file_read_policy = "; allow read-only file operations\n(allow file-read*)".to_string();
    policy_sections.push(file_read_policy);

    // File write policy based on mode
    let file_write_policy = match policy.mode {
        SandboxMode::WorkspaceWrite => {
            let mut writable_entries = Vec::new();

            // Add cwd as writable
            if let Some(canonical) = canonicalize_path(cwd) {
                let param_key = format!("WRITABLE_ROOT_{}", writable_entries.len());
                params.push((param_key.clone(), canonical.clone()));
                writable_entries.push(format!("(subpath (param \"{param_key}\"))"));
            }

            // Add writable roots
            for (i, root) in policy.all_writable_paths().iter().enumerate() {
                if let Some(canonical) = canonicalize_path(root) {
                    let param_key = format!("WRITABLE_ROOT_{}", writable_entries.len());
                    params.push((param_key.clone(), canonical.clone()));
                    writable_entries.push(format!("(subpath (param \"{param_key}\"))"));
                }
            }

            if writable_entries.is_empty() {
                String::new()
            } else {
                format!(
                    "(allow file-write*\n{}\n)",
                    writable_entries.join("\n")
                )
            }
        }
        SandboxMode::ReadOnly => {
            // No file-write* allowed
            String::new()
        }
        SandboxMode::FullAccess => {
            // Should not reach here, but just in case
            r#"(allow file-write* (regex #"^/"))"#.to_string()
        }
    };
    policy_sections.push(file_write_policy);

    // Network policy
    let network_policy = match policy.network {
        NetworkPolicy::Enabled => {
            let mut policy = String::from("(allow network-outbound)\n(allow network-inbound)\n");
            policy.push_str(SEATBELT_NETWORK_POLICY);
            policy
        }
        NetworkPolicy::Restricted => {
            // No network access — the base policy already denies default
            String::new()
        }
    };
    policy_sections.push(network_policy);

    let full_policy = policy_sections.join("\n");
    (full_policy, params)
}

/// Canonicalize a path, falling back to the original on failure.
fn canonicalize_path(p: &Path) -> Option<PathBuf> {
    p.canonicalize().ok().or_else(|| {
        if p.is_absolute() {
            Some(p.to_path_buf())
        } else {
            None
        }
    })
}

/// Run a command in a macOS sandbox using sandbox-exec (Seatbelt).
pub fn run_sandboxed(
    policy: SandboxPolicy,
    command: &[String],
    cwd: &Path,
    env_args: &[String],
    timeout_ms: u64,
) -> Result<ExecResult> {
    let extra_env = parse_env(env_args);

    // Generate Seatbelt policy
    let (seatbelt_policy, dir_params) = generate_seatbelt_policy(&policy, cwd);

    // Build sandbox-exec arguments
    let mut seatbelt_args: Vec<String> = vec![
        "-p".to_string(),
        seatbelt_policy,
    ];

    // Add directory parameter definitions
    for (key, value) in &dir_params {
        seatbelt_args.push(format!("-D{key}={}", value.to_string_lossy()));
    }

    // Add command separator and the actual command
    seatbelt_args.push("--".to_string());
    seatbelt_args.extend(command.iter().cloned());

    log::info!(
        "macOS sandbox: executing via {} with {} dir params",
        MACOS_PATH_TO_SEATBELT_EXECUTABLE,
        dir_params.len()
    );

    let mut cmd = Command::new(MACOS_PATH_TO_SEATBELT_EXECUTABLE);
    cmd.args(&seatbelt_args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in &extra_env {
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
        .with_context(|| format!("failed to spawn sandbox-exec: {:?}", cmd.get_program()))?;

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
        let _ = Read::read_to_end(&mut out, &mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = Read::read_to_end(&mut err, &mut stderr);
    }

    Ok(ExecResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
    })
}
