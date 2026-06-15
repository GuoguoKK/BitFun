# sandbox Agent Guide

Scope: this guide applies to `src/crates/sandbox`.

`bitfun-sandbox` owns OS-level process sandboxing for command execution and the
pre-execution path/shell guards. It is a **new isolation layer** that complements
— but does **not** replace — the MiniApp iframe sandbox, `ToolRuntimeRestrictions`,
or confirmation gates.

See `docs/architecture/process-sandbox.md` for the full design.

## Modules

- `policy.rs` — `SandboxPolicy`, `SandboxMode`, `NetworkPolicy` + factory methods.
- `guard.rs` — `is_path_allowed(target, policy, project_dir)` pre-execution path check.
- `shell_parser.rs` — `extract_write_paths`, `has_interpreter_inline_code`,
  `is_dangerous_command`. Lightweight regex extraction, NOT a full shell parser.
- `manager.rs` — `SandboxManager` selects platform sandbox type and dispatches
  to `run_sandboxed` / `run_unsandboxed`.
- `platform/{windows,linux,macos}.rs` — native isolation.
- `common.rs` — `ExecResult`, `run_unsandboxed`, env parsing.

## Guardrails

- Do NOT depend on `bitfun-core`, app crates, or Tauri. This crate is consumed
  by core and runtime-ports; it must stay low in the dependency graph.
- Keep the policy/guard/shell_parser layer platform-agnostic. Platform-specific
  code goes under `platform/` behind `cfg(target_os = ...)`.
- The shell parser is intentionally a best-effort regex extractor. When you add
  write patterns, also add a unit test in `shell_parser.rs`. When extraction is
  uncertain (interpreter inline code with no extractable path), default to deny.
- `SandboxMode::FullAccess` must run unsandboxed — it is the explicit opt-out.

## Config ownership

The sandbox mode is configured in **`app.ai_experience.sandbox_mode`** (written
by the Web UI settings page), read via `ToolUseContext::sandbox_policy()` in
core. Do not move it to the `ai` config section — that mismatch was the root
cause of the sandbox silently no-op-ing.

Default: `workspace-write` (see `default_sandbox_mode`).

## Windows approach

Restricted Token with `DISABLE_MAX_PRIVILEGE` only — **no** `WRITE_RESTRICTED`.
`WRITE_RESTRICTED` blocks all writes (including to anonymous pipes), breaking
`CreateProcessAsUserW`. Instead, protection comes from explicit **Deny ACEs** on
sensitive user directories (Desktop, Documents, Downloads, …) and policy-denied
paths. A permissive default DACL grants `GENERIC_ALL` to the user/logon SIDs so
sandboxed processes can still create pipes and IPC objects.

## Verification

```bash
cargo test -p bitfun-sandbox          # shell_parser / guard / policy / manager tests
cargo check --workspace
```
