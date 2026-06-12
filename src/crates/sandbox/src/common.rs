//! Common utilities: unsandboxed execution, shared helpers.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

/// Result of a sandboxed or unsandboxed command execution.
#[derive(Debug)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

/// Parse KEY=VALUE environment variable strings into a HashMap.
pub fn parse_env(env_args: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for arg in env_args {
        if let Some((key, value)) = arg.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

/// Run a command without any sandboxing (full-access mode).
pub fn run_unsandboxed(
    command: &[String],
    cwd: &Path,
    env_args: &[String],
    timeout_ms: u64,
) -> Result<ExecResult> {
    if command.is_empty() {
        anyhow::bail!("no command to execute");
    }

    let extra_env = parse_env(env_args);
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in &extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn command: {}", command[0]))?;

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
                        exit_code = 128 + 64; // SIGKILL equivalent
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    exit_code = -1;
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
        let _ = out.read_to_end(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_end(&mut stderr);
    }

    Ok(ExecResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
    })
}
