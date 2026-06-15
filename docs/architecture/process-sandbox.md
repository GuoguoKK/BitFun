# Process Sandbox Architecture

## Scope

The process sandbox restricts what filesystem locations AI-driven tool calls can
write to, and blocks commands that could bypass those restrictions. It is a
**new isolation layer** that complements — but does **not** replace — existing
protections:

- MiniApp iframe sandbox
- `ToolRuntimeRestrictions` / `ToolPathPolicy` path enforcement
- Confirmation gates (tool confirmation dialog)

The sandbox is opt-out: it is **enabled by default** in `workspace-write` mode
for new sessions and configs.

## Goals

1. Prevent AI agents from writing outside the workspace (Desktop, Documents,
   system directories, etc.) via Bash redirects, PowerShell cmdlets, file
   tools, or interpreter inline code.
2. Block escape attempts — ACL modification (`icacls`, `cacls`), privilege
   escalation (`sudo`, `runas`, `Start-Process -Verb RunAs`).
3. Provide an in-product escape hatch: every denial surfaces a clickable link
   to the sandbox settings tab.
4. Stay platform-agnostic at the policy layer; platform-specific OS isolation
   lives in `bitfun-sandbox`.

## Non-goals

- Replacing the existing MiniApp iframe sandbox or confirmation gates.
- Sandboxing remote (SSH) workspaces — those stay contained to the remote
  project tree via `is_remote_posix_path_within_root`.
- A full shell parser. `shell_parser` is a lightweight regex-based extractor
  that covers common write patterns, not a complete grammar.

## Architecture

The sandbox has two enforcement layers that run **before** the OS-level sandbox
(`bitfun-sandbox` Restricted Token + ACL):

```
Tool call
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ 1. Pre-execution path guard (Rust, in-process)          │
│    shell_parser → extract write paths                   │
│    guard → is_path_allowed(paths, policy)               │
│    deny on policy violation                             │
└─────────────────────────────────────────────────────────┘
  │ (paths allowed)
  ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Dangerous-command block (Rust, in-process)           │
│    is_dangerous_command → icacls / sudo / RunAs / ...   │
│    deny outright                                        │
└─────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│ 3. OS-level sandbox (bitfun-sandbox, native)            │
│    Windows: Restricted Token + Deny ACEs                │
│    Linux:   Landlock + bubblewrap                       │
│    macOS:   sandbox-exec (Seatbelt)                     │
└─────────────────────────────────────────────────────────┘
  │
  ▼
command executes
```

Layer 1–2 are the primary defense because the local Bash tool runs commands in
a persistent **Terminal session** (not via `WorkspaceShell`), so the OS sandbox
(layer 3) only applies to the `exec_with_options` path used by remote
workspaces. The pre-execution guard (layer 1–2) runs inside `bash_tool::call`
regardless of which execution path the command takes.

## Configuration

The sandbox mode is stored in **`app.ai_experience`** (the same section the UI
settings page writes to), not in `ai`. This is intentional — the UI settings
panel (`AIExperienceConfigService`) owns this config.

| Field | Path | Values |
|---|---|---|
| `sandbox_mode` | `app.ai_experience.sandbox_mode` | `disabled` \| `workspace-write` (default) \| `read-only` \| `full-access` |
| `sandbox_extra_writable_roots` | `app.ai_experience.sandbox_extra_writable_roots` | `Vec<PathBuf>` — additional writable roots |
| `sandbox_denied_write_paths` | `app.ai_experience.sandbox_denied_write_paths` | `Vec<PathBuf>` — explicitly denied paths |

### Default

`SandboxModeConfig::default()` and `default_sandbox_mode()` both return
`WorkspaceWrite`. This means:

- New users / fresh configs get `workspace-write` by default.
- Existing configs that already have a `sandbox_mode` value are preserved
  (serde deserializes the stored value; the default only applies when the field
  is absent).

## Key modules

### `src/crates/sandbox/src/`

| File | Responsibility |
|---|---|
| `policy.rs` | `SandboxPolicy`, `SandboxMode`, `NetworkPolicy`. Factory methods `new_workspace_write`, `new_read_only`, `new_full_access`. |
| `guard.rs` | `is_path_allowed(target, policy, project_dir)` → `PathCheckResult`. Mode-aware allow/deny logic. |
| `shell_parser.rs` | `extract_write_paths(command, cwd)`, `has_interpreter_inline_code`, `is_dangerous_command`. Lightweight regex extraction. |
| `manager.rs` | `SandboxManager` — selects platform sandbox type and dispatches to `run_sandboxed` / `run_unsandboxed`. |
| `platform/{windows,linux,macos}.rs` | Native OS isolation. Windows uses Restricted Token + Deny ACEs (DISABLE_MAX_PRIVILEGE, no WRITE_RESTRICTED). |

### `src/crates/core/src/agentic/tools/`

| Location | Responsibility |
|---|---|
| `tool_context_runtime.rs` `sandbox_policy()` | Reads `app.ai_experience` config, builds `SandboxPolicy`. Returns `None` when disabled or remote. |
| `tool_context_runtime.rs` `enforce_sandbox_path_policy()` | Checks a list of write paths against the policy; returns `BitFunError` with a settings link on denial. |
| `implementations/bash_tool.rs` | Calls `extract_write_paths` + `enforce_sandbox_path_policy` + `is_dangerous_command` before execution. |
| `implementations/file_write_tool.rs`, `file_edit_tool.rs`, `delete_file_tool.rs` | Call `enforce_sandbox_path_policy` after `enforce_path_operation`. |

### `src/crates/runtime-ports/src/lib.rs`

`WorkspaceCommandOptions.sandbox_policy: Option<SandboxPolicy>` — when `Some`,
`LocalWorkspaceShell::exec_with_options` routes through `exec_sandboxed`
(bitfun-sandbox) instead of `exec_unsandboxed`.

### Settings UI

| File | Responsibility |
|---|---|
| `src/web-ui/src/infrastructure/config/components/SessionConfig.tsx` | Switch + mode select + full-access warning under the "Permissions" tab (`session-permissions`). |
| `src/web-ui/src/infrastructure/config/services/AIExperienceConfigService.ts` | `sandbox_mode` type and default (`workspace-write`). |

## Shell parser coverage

`extract_write_paths` recognizes these write patterns (after `$env:VAR`,
`${VAR}`, `$VAR`, `%VAR%`, and `~` expansion):

| Pattern | Example |
|---|---|
| Redirect | `> file`, `>> file` |
| `tee` | `tee /path/file` |
| `dd` | `dd of=/path/file` |
| `cp` / `mv` / `install` | last non-flag arg is destination |
| `mkdir` | `mkdir -p /path/dir` |
| `touch` | `touch /path/file` |
| PowerShell `New-Item` | `New-Item -Path "..." -ItemType File` |
| PowerShell `Set-Content` / `Add-Content` / `Out-File` | `-Path` / `-FilePath` |
| PowerShell `Copy-Item` / `Move-Item` | `-Destination` |
| PowerShell `Remove-Item` | `-Path` |
| cmd.exe | `type nul > file` |
| Interpreter inline | `node -e`, `python -c`, `perl -e`, `ruby -e`, `php -r` (static write-call extraction) |

`has_interpreter_inline_code` + empty extracted paths → default-deny (the
sandbox cannot statically verify the safety of inline code).

### Dangerous commands

`is_dangerous_command` blocks outright (no path extraction):

- ACL / permission: `icacls`, `cacls`, `chmod`, `chown`, `chgrp`, `setfacl`, `getfacl`
- Elevation: `sudo`, `su`, `runas`, `Start-Process`, `-Verb RunAs`
- Security descriptor: `secedit`, `auditpol`

## Denial UX

Denial error messages include a markdown link:
`[Settings](settings:session-permissions)`.

The Markdown renderer (`src/web-ui/src/component-library/components/Markdown/Markdown.tsx`)
recognizes the `settings:` protocol and calls `onSettingsOpen(tab)`, which:

```ts
useSettingsStore.getState().setActiveTab(tab);   // 'session-permissions'
useSceneStore.getState().openScene('settings');
```

Tool error cards render the error via `MarkdownRenderer` when the message
contains `settings:`, so the link is clickable directly in the error card
(not only in AI-prose, which the model may rephrase away):

- `TerminalToolCard.tsx` (`renderTerminalErrorContent`)
- `DefaultToolCard.tsx`
- `FileOperationToolCard.tsx` (`renderErrorContent`)

## Verification

1. `cargo check --workspace` — backend compiles.
2. `pnpm run type-check:web` — frontend type-checks.
3. Manual (desktop:dev, sandbox enabled = default):
   - `echo x > ~/Desktop/t.txt` → denied, error card shows Settings link.
   - `New-Item -Path "$env:USERPROFILE\Desktop\t.txt" -ItemType File` → denied.
   - `icacls ... /grant` → denied as dangerous command.
   - Write tool to `~/Desktop/t.txt` → denied.
   - Write tool to a file inside the workspace → succeeds.
   - Disable sandbox in settings → all above succeed.
4. `cargo test -p bitfun-sandbox` — shell_parser / guard unit tests.
