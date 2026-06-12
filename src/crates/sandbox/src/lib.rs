//! BitFun Sandbox: OS-level sandbox for command execution.
//!
//! Runs a command inside a platform-native sandbox that restricts filesystem
//! and network access based on a policy. On Windows this uses Restricted Tokens
//! + ACLs, on Linux it uses Landlock LSM + bubblewrap, and on macOS it uses
//! sandbox-exec (Seatbelt).

pub mod common;
pub mod guard;
pub mod manager;
pub mod policy;
pub mod platform;
pub mod shell_parser;

pub use common::ExecResult;
pub use guard::{PathCheckResult, is_path_allowed};
pub use manager::{SandboxManager, SandboxType, SandboxablePreference};
pub use policy::{NetworkPolicy, SandboxMode, SandboxPolicy};
pub use shell_parser::{extract_write_paths, has_interpreter_inline_code, is_dangerous_command, is_null_device};
