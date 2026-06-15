//! Shell command parser for extracting write target paths.
//!
//! Analyzes bash/shell commands to determine which filesystem paths
//! will be written to, so the sandbox guard can block unauthorized writes.

use std::path::{Path, PathBuf};

/// Extract write target paths from a shell command string.
///
/// Covers common write patterns:
/// - Redirects: `> file`, `>> file`
/// - `tee file`
/// - `dd of=file`
/// - `cp/mv/install` destination
/// - `mkdir dir`
/// - `touch file`
/// - Interpreter inline code: `node -e`, `python -c`, etc.
pub fn extract_write_paths(command: &str, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let expanded = expand_env_vars(command.trim());

    // Redirect: > file or >> file
    if let Ok(re) = regex::Regex::new(r"(?:>{1,2})\s*([^\s;&|]+)") {
        for cap in re.captures_iter(&expanded) {
            let file = cap[1].trim().to_string();
            if !is_null_device(&file) && !file.is_empty() {
                paths.push(resolve_arg(&file, cwd));
            }
        }
    }

    // tee file
    if let Ok(re) = regex::Regex::new(r"\btee\s+(?:(?:-[aAiz]+)\s+)*([^\s;&|>]+)") {
        if let Some(cap) = re.captures(&expanded) {
            let file = cap[1].to_string();
            if !is_null_device(&file) {
                paths.push(resolve_arg(&file, cwd));
            }
        }
    }

    // dd of=file
    if let Ok(re) = regex::Regex::new(r"\bdd\s+.*\bof\s*=\s*([^\s;&|]+)") {
        if let Some(cap) = re.captures(&expanded) {
            let file = cap[1].to_string();
            if !is_null_device(&file) {
                paths.push(resolve_arg(&file, cwd));
            }
        }
    }

    // cp / mv / install: last non-flag argument is destination
    for cmd in &["cp", "mv", "install"] {
        let pattern = format!(
            r"\b{}\b(?:\s+(?:-[\w]+|--[\w-]+))*\s+(.+)",
            regex::escape(cmd)
        );
        if let Ok(re) = regex::Regex::new(&pattern) {
            if let Some(cap) = re.captures(&expanded) {
                let args = split_args(&cap[1]);
                if args.len() >= 2 {
                    let last = args.last().unwrap();
                    if !last.starts_with('-') && !is_null_device(last) {
                        paths.push(resolve_arg(last, cwd));
                    }
                }
            }
        }
    }

    // mkdir dir
    if let Ok(re) = regex::Regex::new(r"\bmkdir\s+(?:(?:-[pvm]+)\s+)*([^\s;&|>]+)") {
        if let Some(cap) = re.captures(&expanded) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // touch file
    if let Ok(re) = regex::Regex::new(r"\btouch\s+(?:(?:-[\w]+)\s+)*([^\s;&|>]+)") {
        if let Some(cap) = re.captures(&expanded) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // ── PowerShell write commands ───────────────────────────────────────

    // New-Item -Path "file" -ItemType File  (quoted path)
    if let Ok(re) = regex::Regex::new(
        r#"(?i)\bNew-Item\s+(?:.*?\s+)?-Path\s+["']([^"']+)["']"#,
    ) {
        for cap in re.captures_iter(&expanded) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }
    // New-Item -Path file  (unquoted path, next token until -Param or space)
    if let Ok(re) = regex::Regex::new(
        r#"(?i)\bNew-Item\s+(?:.*?\s+)?-Path\s+([^\s;|&"']+)"#,
    ) {
        for cap in re.captures_iter(&expanded) {
            let p = &cap[1];
            // Skip if it looks like a PowerShell parameter (starts with -)
            if !p.starts_with('-') {
                paths.push(resolve_arg(p, cwd));
            }
        }
    }
    // New-Item "file" (positional -Path, quoted)
    if let Ok(re) = regex::Regex::new(
        r#"(?i)\bNew-Item\s+["']([^"']+)["']"#,
    ) {
        for cap in re.captures_iter(&expanded) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // Set-Content / Add-Content / Out-File -FilePath/-Path "file"
    for cmd in &["Set-Content", "Add-Content", "Out-File", "sc", "ac"] {
        // Quoted path
        let pattern_quoted = format!(
            r#"(?i)\b{}\s+(?:.*?\s+)?-(?:FilePath|Path)\s+["']([^"']+)["']"#,
            regex::escape(cmd)
        );
        if let Ok(re) = regex::Regex::new(&pattern_quoted) {
            for cap in re.captures_iter(&expanded) {
                paths.push(resolve_arg(&cap[1], cwd));
            }
        }
        // Unquoted path
        let pattern_unquoted = format!(
            r#"(?i)\b{}\s+(?:.*?\s+)?-(?:FilePath|Path)\s+([^\s;|&"']+)"#,
            regex::escape(cmd)
        );
        if let Ok(re) = regex::Regex::new(&pattern_unquoted) {
            for cap in re.captures_iter(&expanded) {
                if !cap[1].starts_with('-') {
                    paths.push(resolve_arg(&cap[1], cwd));
                }
            }
        }
    }

    // Copy-Item / Move-Item -Destination "path"
    for cmd in &["Copy-Item", "Move-Item", "cpi", "mi"] {
        // Quoted destination
        let pattern_quoted = format!(
            r#"(?i)\b{}\s+(?:.*?\s+)?-Destination\s+["']([^"']+)["']"#,
            regex::escape(cmd)
        );
        if let Ok(re) = regex::Regex::new(&pattern_quoted) {
            for cap in re.captures_iter(&expanded) {
                paths.push(resolve_arg(&cap[1], cwd));
            }
        }
        // Unquoted destination
        let pattern_unquoted = format!(
            r#"(?i)\b{}\s+(?:.*?\s+)?-Destination\s+([^\s;|&"']+)"#,
            regex::escape(cmd)
        );
        if let Ok(re) = regex::Regex::new(&pattern_unquoted) {
            for cap in re.captures_iter(&expanded) {
                if !cap[1].starts_with('-') {
                    paths.push(resolve_arg(&cap[1], cwd));
                }
            }
        }
    }

    // Remove-Item -Path "path"
    if let Ok(re) = regex::Regex::new(
        r#"(?i)\bRemove-Item\s+(?:.*?\s+)?-Path\s+["']([^"']+)["']"#,
    ) {
        for cap in re.captures_iter(&expanded) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // type nul > file  (cmd.exe pattern)
    if let Ok(re) = regex::Regex::new(r"(?i)\btype\s+\S+\s+>\s*([^\s;&|]+)") {
        if let Some(cap) = re.captures(&expanded) {
            let file = cap[1].trim().to_string();
            if !is_null_device(&file) && !file.is_empty() {
                paths.push(resolve_arg(&file, cwd));
            }
        }
    }

    // Interpreter inline scripts
    let interpreter_paths = extract_interpreter_write_paths(&expanded, cwd);
    paths.extend(interpreter_paths);

    // Deduplicate
    paths.sort();
    paths.dedup();
    paths
}

/// Null device paths to skip during write path extraction.
const NULL_DEVICES: &[&str] = &["/dev/null", "NUL", "CON", "nul", "con"];

/// Check if a path is a null device (should be skipped).
pub fn is_null_device(p: &str) -> bool {
    NULL_DEVICES.iter().any(|&d| d.eq_ignore_ascii_case(p))
}

/// Dangerous commands that can bypass the sandbox by modifying ACLs,
/// permissions, or executing with elevated privileges.
///
/// These commands should be blocked entirely when the sandbox is enabled,
/// regardless of their target paths.
const DANGEROUS_COMMANDS: &[&str] = &[
    // ACL / permission modification
    "icacls", "cacls", "chmod", "chown", "chgrp", "setfacl", "getfacl",
    // Elevation / privilege escalation
    "sudo", "su", "runas", "Start-Process",
    // RunAs Verb
    "-Verb RunAs",
    // Security descriptor manipulation
    "secedit", "auditpol",
    // PowerShell UAC bypass patterns
    "RunAs", "Elevate",
];

/// Check if a command contains a dangerous system command that can bypass
/// the sandbox (e.g., ACL modification, privilege escalation).
pub fn is_dangerous_command(command: &str) -> bool {
    let expanded = expand_env_vars(command.trim());

    // Check for dangerous command names
    for cmd in DANGEROUS_COMMANDS {
        // Match as a standalone command or sub-command
        if expanded.contains(cmd) {
            // For short command names, verify they are actual commands (not substrings)
            if cmd.len() <= 5 {
                let pattern = format!(r"\b{}\b", regex::escape(cmd));
                if let Ok(re) = regex::Regex::new(&pattern) {
                    if re.is_match(&expanded) {
                        return true;
                    }
                }
            } else {
                // Longer patterns like "-Verb RunAs" are specific enough
                return true;
            }
        }
    }

    // Check for PowerShell -Verb RunAs pattern specifically
    if let Ok(re) = regex::Regex::new(r"(?i)-Verb\s+RunAs") {
        if re.is_match(&expanded) {
            return true;
        }
    }

    false
}

/// Detect whether a command contains an interpreter inline code snippet.
///
/// Covers: node -e, bun -e, deno -e, python -c, perl -e, ruby -e, php -r
pub fn has_interpreter_inline_code(command: &str) -> bool {
    let expanded = expand_env_vars(command.trim());

    let patterns: &[&str] = &[
        r#"\b(node|bun|deno)\s+(?:-[eE]\s+|--eval\s+)["']"#,
        r#"\bdeno\s+eval\s+["']"#,
        r#"\bpython[23]?\s+(?:-[cC]\s+)["']"#,
        r#"\bperl\s+(?:-[eE]\s+)["']"#,
        r#"\bruby\s+(?:-[eE]\s+)["']"#,
        r#"\bphp\s+(?:-[rR]\s+)["']"#,
    ];

    for pat in patterns {
        if let Ok(re) = regex::Regex::new(pat) {
            if re.is_match(&expanded) {
                return true;
            }
        }
    }
    false
}

/// Extract write paths from interpreter inline code.
fn extract_interpreter_write_paths(command: &str, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let expanded = expand_env_vars(command.trim());

    // JS: node/bun/deno -e "code" or --eval "code"
    let js_patterns: &[&str] = &[
        r#"\b(?:node|bun|deno)\s+(?:-[eE]\s+|--eval\s+)(["'])(.+?)\1"#,
        r#"\bdeno\s+eval\s+(["'])(.+?)\1"#,
    ];
    for pat in js_patterns {
        if let Ok(re) = regex::Regex::new(pat) {
            if let Some(cap) = re.captures(&expanded) {
                let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                paths.extend(extract_js_write_paths(code, cwd));
            }
        }
    }

    // Python: python -c "code"
    if let Ok(re) = regex::Regex::new(r#"\bpython[23]?\s+(?:-[cC]\s+)(["'])(.+?)\1"#) {
        if let Some(cap) = re.captures(&expanded) {
            let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            paths.extend(extract_python_write_paths(code, cwd));
        }
    }

    // Perl: perl -e "code"
    if let Ok(re) = regex::Regex::new(r#"\bperl\s+(?:-[eE]\s+)(["'])(.+?)\1"#) {
        if let Some(cap) = re.captures(&expanded) {
            let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            paths.extend(extract_perl_write_paths(code, cwd));
        }
    }

    // Ruby: ruby -e "code"
    if let Ok(re) = regex::Regex::new(r#"\bruby\s+(?:-[eE]\s+)(["'])(.+?)\1"#) {
        if let Some(cap) = re.captures(&expanded) {
            let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            paths.extend(extract_ruby_write_paths(code, cwd));
        }
    }

    // PHP: php -r "code"
    if let Ok(re) = regex::Regex::new(r#"\bphp\s+(?:-[rR]\s+)(["'])(.+?)\1"#) {
        if let Some(cap) = re.captures(&expanded) {
            let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            paths.extend(extract_php_write_paths(code, cwd));
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

/// Extract write paths from JS inline code.
fn extract_js_write_paths(code: &str, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // fs.writeFile / fs.writeFileSync / fs.appendFile / fs.appendFileSync
    if let Ok(re) =
        regex::Regex::new(r#"(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*["']([^"']+)["']"#)
    {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // Bun.write(path, data)
    if let Ok(re) = regex::Regex::new(r#"Bun\.write\s*\(\s*["']([^"']+)["']"#) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // Deno.writeTextFile / Deno.writeFileSync
    if let Ok(re) =
        regex::Regex::new(r#"Deno\.write(?:TextFile|Sync)\s*\(\s*["']([^"']+)["']"#)
    {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // require('fs').writeFileSync(...)
    if let Ok(re) = regex::Regex::new(
        r#"require\s*\(\s*["']fs["']\s*\)\s*\.\s*(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*["']([^"']+)["']"#,
    ) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    paths
}

/// Extract write paths from Python inline code.
fn extract_python_write_paths(code: &str, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // open(path, 'w') or open(path, 'a')
    if let Ok(re) = regex::Regex::new(r#"\bopen\s*\(\s*["']([^"']+)["']\s*,\s*["'][wa]["']"#) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // pathlib.Path(path).write_text() / .write_bytes()
    if let Ok(re) =
        regex::Regex::new(r#"Path\s*\(\s*["']([^"']+)["']\s*\)\s*\.\s*write_(?:text|bytes)"#)
    {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    paths
}

/// Extract write paths from Perl inline code.
fn extract_perl_write_paths(code: &str, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // open(FH, '>', path) or open(FH, '>>', path)
    if let Ok(re) =
        regex::Regex::new(r#"\bopen\s*\([^,]+,\s*["']>{1,2}["']\s*,\s*["']([^"']+)["']"#)
    {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    paths
}

/// Extract write paths from Ruby inline code.
fn extract_ruby_write_paths(code: &str, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // File.write(path, ...)
    if let Ok(re) = regex::Regex::new(r#"File\.write\s*\(\s*["']([^"']+)["']"#) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // File.open(path, 'w')
    if let Ok(re) = regex::Regex::new(r#"File\.open\s*\(\s*["']([^"']+)["']\s*,\s*["'][wa]["']"#) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // IO.write(path, ...)
    if let Ok(re) = regex::Regex::new(r#"IO\.write\s*\(\s*["']([^"']+)["']"#) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    paths
}

/// Extract write paths from PHP inline code.
fn extract_php_write_paths(code: &str, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // file_put_contents(path, ...)
    if let Ok(re) = regex::Regex::new(r#"\bfile_put_contents\s*\(\s*["']([^"']+)["']"#) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    // fopen(path, 'w') or fopen(path, 'a')
    if let Ok(re) = regex::Regex::new(r#"\bfopen\s*\(\s*["']([^"']+)["']\s*,\s*["'][wa]["']"#) {
        for cap in re.captures_iter(code) {
            paths.push(resolve_arg(&cap[1], cwd));
        }
    }

    paths
}

/// Expand environment variables and ~ in a command string.
fn expand_env_vars(command: &str) -> String {
    let mut result = command.to_string();

    // Expand PowerShell $env:VAR syntax (must be before $VAR)
    if let Ok(re) = regex::Regex::new(r"\$env:([A-Za-z_][A-Za-z0-9_]*)") {
        result = re
            .replace_all(&result, |caps: &regex::Captures| {
                std::env::var(&caps[1]).unwrap_or_default()
            })
            .to_string();
    }

    // Expand ${VAR}
    if let Ok(re) = regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}") {
        result = re
            .replace_all(&result, |caps: &regex::Captures| {
                std::env::var(&caps[1]).unwrap_or_default()
            })
            .to_string();
    }

    // Expand $VAR (not followed by / or alphanumeric)
    if let Ok(re) = regex::Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)(?=[\s/\\;&|>]|$)") {
        result = re
            .replace_all(&result, |caps: &regex::Captures| {
                std::env::var(&caps[1]).unwrap_or_default()
            })
            .to_string();
    }

    // Expand Windows %VAR% syntax
    if let Ok(re) = regex::Regex::new(r"%([A-Za-z_][A-Za-z0-9_]*)%") {
        result = re
            .replace_all(&result, |caps: &regex::Captures| {
                std::env::var(&caps[1]).unwrap_or_default()
            })
            .to_string();
    }

    // Expand ~ to home directory
    if let Some(home) = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .or_else(|_| std::env::var("HOMEDIR"))
        .ok()
    {
        result = result.replace('~', &home);
    }

    result
}

/// Split a string into shell-like arguments respecting quotes.
fn split_args(args_str: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for ch in args_str.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
            if !current.is_empty() {
                args.push(current.clone());
                current.clear();
            }
        } else if ch == ' ' || ch == '\t' {
            if !current.is_empty() {
                args.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// Resolve a shell argument to an absolute path.
fn resolve_arg(arg: &str, cwd: &Path) -> PathBuf {
    // Strip surrounding quotes
    let stripped = arg.trim_matches(|c| c == '"' || c == '\'');
    let path = PathBuf::from(stripped);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_write() {
        let paths = extract_write_paths("echo hello > /tmp/test.txt", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/test.txt")));
    }

    #[test]
    fn test_redirect_append() {
        let paths = extract_write_paths("echo hello >> /tmp/log.txt", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/log.txt")));
    }

    #[test]
    fn test_redirect_null_device() {
        let paths = extract_write_paths("echo hello > /dev/null", Path::new("/workspace"));
        assert!(!paths.iter().any(|p| p.to_string_lossy().contains("null")));
    }

    #[test]
    fn test_tee_write() {
        let paths = extract_write_paths("echo hello | tee /tmp/tee.txt", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/tee.txt")));
    }

    #[test]
    fn test_cp_destination() {
        let paths = extract_write_paths("cp src.txt /tmp/dst.txt", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/dst.txt")));
    }

    #[test]
    fn test_mv_destination() {
        let paths = extract_write_paths("mv old.txt /tmp/new.txt", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/new.txt")));
    }

    #[test]
    fn test_mkdir() {
        let paths = extract_write_paths("mkdir -p /tmp/newdir", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/newdir")));
    }

    #[test]
    fn test_touch() {
        let paths = extract_write_paths("touch /tmp/file.txt", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/file.txt")));
    }

    #[test]
    fn test_relative_path() {
        let paths = extract_write_paths("echo hello > output.txt", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/workspace/output.txt")));
    }

    #[test]
    fn test_has_interpreter_inline_node() {
        assert!(has_interpreter_inline_code("node -e \"require('fs').writeFileSync('/tmp/test', 'hi')\""));
    }

    #[test]
    fn test_has_interpreter_inline_python() {
        assert!(has_interpreter_inline_code("python -c \"open('/tmp/test', 'w')\""));
    }

    #[test]
    fn test_no_interpreter_inline() {
        assert!(!has_interpreter_inline_code("echo hello"));
    }

    #[test]
    fn test_js_write_paths() {
        let paths = extract_write_paths(
            "node -e \"require('fs').writeFileSync('/tmp/test', 'hi')\"",
            Path::new("/workspace"),
        );
        eprintln!("DEBUG js paths = {:?}", paths);
        assert!(paths.contains(&PathBuf::from("/tmp/test")));
    }

    #[test]
    fn test_python_write_paths() {
        let paths = extract_write_paths(
            "python -c \"open('/tmp/test', 'w')\"",
            Path::new("/workspace"),
        );
        assert!(paths.contains(&PathBuf::from("/tmp/test")));
    }

    #[test]
    fn test_dd_write() {
        let paths = extract_write_paths("dd if=/dev/zero of=/tmp/disk.img bs=1M count=10", Path::new("/workspace"));
        assert!(paths.contains(&PathBuf::from("/tmp/disk.img")));
    }

    #[test]
    fn test_null_device_nul() {
        assert!(is_null_device("NUL"));
        assert!(is_null_device("nul"));
        assert!(!is_null_device("/tmp/test"));
    }
}
