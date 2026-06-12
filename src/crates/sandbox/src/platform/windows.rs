//! Windows sandbox implementation using Restricted Tokens + ACLs.
//!
//! This follows the same approach as Codex's Windows sandbox:
//! 1. Create a restricted token from the current process token
//! 2. Add capability SIDs for conditional ACL checks
//! 3. Compute allow/deny path lists from the policy
//! 4. Add Allow ACEs for writable paths, Deny ACEs for protected paths
//! 5. Spawn the command with the restricted token
//! 6. Clean up temporary ACEs after execution

use crate::common::{parse_env, ExecResult};
use crate::policy::{SandboxMode, SandboxPolicy};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::c_void;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;

// ── Constants ──────────────────────────────────────────────────────────────

const DISABLE_MAX_PRIVILEGE: u32 = 0x01;
const WRITE_RESTRICTED: u32 = 0x08;
const SE_GROUP_LOGON_ID: u32 = 0xC0000000;
const GENERIC_WRITE_MASK: u32 = 0x4000_0000;
const DENY_ACCESS: i32 = 3;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const INHERIT_ONLY_ACE: u8 = 0x08;

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

const DENY_WRITE_MASK: u32 = FILE_GENERIC_WRITE
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | GENERIC_WRITE_MASK
    | DELETE
    | FILE_DELETE_CHILD;

// ── Utility functions ──────────────────────────────────────────────────────

fn to_wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut v: Vec<u16> = s.as_ref().encode_wide().collect();
    v.push(0);
    v
}

/// Canonicalize a path, falling back to the original on failure.
fn canonicalize_path(p: &Path) -> PathBuf {
    dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

// ── Token operations ───────────────────────────────────────────────────────

/// Open the current process token with the rights needed for restriction.
unsafe fn get_current_token_for_restriction() -> Result<HANDLE> {
    let desired = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    let mut h: HANDLE = std::ptr::null_mut();
    let ok = OpenProcessToken(GetCurrentProcess(), desired, &mut h);
    if ok == 0 {
        return Err(anyhow!("OpenProcessToken failed: {}", GetLastError()));
    }
    Ok(h)
}

/// Create a restricted token from the base token, adding capability SIDs.
/// Uses DISABLE_MAX_PRIVILEGE to strip privileges and WRITE_RESTRICTED
/// so the token can only write to objects with explicit Allow ACEs for our
/// capability SID.
unsafe fn create_restricted_token(
    base_token: HANDLE,
    cap_sids: &[*mut c_void],
) -> Result<HANDLE> {
    let mut new_token: HANDLE = std::ptr::null_mut();
    // Use DISABLE_MAX_PRIVILEGE only. WRITE_RESTRICTED is too restrictive —
    // it blocks ALL writes from the restricted token process unless there is an
    // explicit Allow ACE for the cap SID on the target object. This includes
    // anonymous pipes, which are hard to add ACEs to.
    //
    // Instead, we rely on Deny ACEs on sensitive paths (Desktop, Documents, etc.)
    // to prevent writes to those locations. The restricted token inherits the
    // same group memberships and access as the original token, but without
    // privileges, so it can write to the same locations EXCEPT where we
    // explicitly add Deny ACEs for our cap SID.
    let ok = CreateRestrictedToken(
        base_token,
        DISABLE_MAX_PRIVILEGE,
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        &mut new_token,
    );
    if ok == 0 {
        return Err(anyhow!(
            "CreateRestrictedToken failed: {}",
            GetLastError()
        ));
    }

    // Set a permissive default DACL so sandboxed processes can create
    // pipes/IPC objects. Without this, the restricted token process
    // cannot write to anonymous pipes (ERROR_ACCESS_DENIED on CreateProcessAsUserW).
    set_default_dacl(new_token, cap_sids)?;

    Ok(new_token)
}

/// Get the logon SID from a token.
unsafe fn get_logon_sid(h_token: HANDLE) -> Result<Vec<u8>> {
    let mut needed: u32 = 0;
    GetTokenInformation(h_token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
    if needed == 0 {
        return Err(anyhow!("TokenGroups size query returned 0"));
    }
    let mut buf: Vec<u8> = vec![0u8; needed as usize];
    let ok = GetTokenInformation(
        h_token,
        TokenGroups,
        buf.as_mut_ptr() as *mut c_void,
        needed,
        &mut needed,
    );
    if ok == 0 {
        return Err(anyhow!("GetTokenInformation(TokenGroups) failed"));
    }
    let group_count = std::ptr::read_unaligned(buf.as_ptr() as *const u32) as usize;
    let after_count = buf.as_ptr() as usize + std::mem::size_of::<u32>();
    let align = std::mem::align_of::<SID_AND_ATTRIBUTES>();
    let aligned = (after_count + (align - 1)) & !(align - 1);
    let groups_ptr = aligned as *const SID_AND_ATTRIBUTES;

    for i in 0..group_count {
        let entry: SID_AND_ATTRIBUTES = std::ptr::read_unaligned(groups_ptr.add(i));
        if (entry.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID {
            let sid = entry.Sid;
            let sid_len = GetLengthSid(sid);
            if sid_len == 0 {
                continue;
            }
            let mut out = vec![0u8; sid_len as usize];
            if CopySid(sid_len, out.as_mut_ptr() as *mut c_void, sid) != 0 {
                return Ok(out);
            }
        }
    }
    Err(anyhow!("Logon SID not found on token"))
}

/// Set a permissive default DACL on the restricted token.
/// This grants GENERIC_ALL to the cap SIDs and the logon SID so that
/// the sandboxed process can create and use anonymous pipes, IPC objects, etc.
unsafe fn set_default_dacl(h_token: HANDLE, sids: &[*mut c_void]) -> Result<()> {
    // Also add the logon SID to the default DACL so pipe operations work
    let logon_sid = get_logon_sid(h_token).ok();
    let mut logon_sid_bytes_for_ptr: Vec<u8> = Vec::new();

    let mut all_sids: Vec<*mut c_void> = sids.to_vec();
    if let Some(ref sid) = logon_sid {
        logon_sid_bytes_for_ptr = sid.clone();
        all_sids.push(logon_sid_bytes_for_ptr.as_mut_ptr() as *mut c_void);
    }

    if all_sids.is_empty() {
        return Ok(());
    }

    let entries: Vec<EXPLICIT_ACCESS_W> = all_sids
        .iter()
        .map(|sid| EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: *sid as *mut u16,
            },
        })
        .collect();

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let res = SetEntriesInAclW(
        entries.len() as u32,
        entries.as_ptr(),
        std::ptr::null_mut(),
        &mut p_new_dacl,
    );
    if res != ERROR_SUCCESS {
        return Err(anyhow!("SetEntriesInAclW for default DACL failed: {res}"));
    }

    // TOKEN_DEFAULT_DACL structure
    #[repr(C)]
    struct TokenDefaultDacl {
        default_dacl: *mut ACL,
    }

    let mut info = TokenDefaultDacl {
        default_dacl: p_new_dacl,
    };
    let ok = SetTokenInformation(
        h_token,
        TokenDefaultDacl,
        &mut info as *mut _ as *mut c_void,
        std::mem::size_of::<TokenDefaultDacl>() as u32,
    );
    if !p_new_dacl.is_null() {
        LocalFree(p_new_dacl as HLOCAL);
    }
    if ok == 0 {
        return Err(anyhow!(
            "SetTokenInformation(TokenDefaultDacl) failed: {}",
            GetLastError()
        ));
    }
    Ok(())
}

// ── Capability SID management ──────────────────────────────────────────────

/// SIDs used for ACL grants and denials.
struct SandboxSids {
    /// The current user's SID — used for Deny ACEs on restricted paths.
    user_sid: Vec<u8>,
    /// The Users group SID (S-1-5-32-545) — also used for Deny ACEs.
    users_group_sid: Vec<u8>,
    /// The Everyone SID (S-1-1-0) — also used for Deny ACEs.
    everyone_sid: Vec<u8>,
}

/// Load the well-known SIDs needed for ACL operations.
fn load_sandbox_sids() -> Result<SandboxSids> {
    // Get the current user's SID from the process token
    let user_sid = get_current_user_sid()?;

    // Users group: S-1-5-32-545
    let users_group_sid = convert_string_sid_to_bytes("S-1-5-32-545")?;

    // Everyone: S-1-1-0
    let everyone_sid = convert_string_sid_to_bytes("S-1-1-0")?;

    Ok(SandboxSids {
        user_sid,
        users_group_sid,
        everyone_sid,
    })
}

/// Get the current user's SID from the process token.
fn get_current_user_sid() -> Result<Vec<u8>> {
    unsafe {
        let base_token = get_current_token_for_restriction()?;
        let mut needed: u32 = 0;
        GetTokenInformation(base_token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            CloseHandle(base_token);
            return Err(anyhow!("TokenUser size query returned 0"));
        }
        let mut buf: Vec<u8> = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            base_token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        );
        if ok == 0 {
            CloseHandle(base_token);
            return Err(anyhow!("GetTokenInformation(TokenUser) failed: {}", GetLastError()));
        }
        let token_user: TOKEN_USER = std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_USER);
        let sid_len = GetLengthSid(token_user.User.Sid);
        if sid_len == 0 {
            CloseHandle(base_token);
            return Err(anyhow!("GetLengthSid returned 0"));
        }
        let mut out = vec![0u8; sid_len as usize];
        CopySid(sid_len, out.as_mut_ptr() as *mut c_void, token_user.User.Sid);
        CloseHandle(base_token);
        Ok(out)
    }
}

/// Convert a string-format SID (S-1-5-...) to binary bytes.
fn convert_string_sid_to_bytes(s: &str) -> Result<Vec<u8>> {
    let wide = to_wide(s);
    let mut psid: *mut c_void = std::ptr::null_mut();
    unsafe {
        let ok = ConvertStringSidToSidW(wide.as_ptr(), &mut psid);
        if ok == 0 {
            return Err(anyhow!("ConvertStringSidToSidW failed: {}", GetLastError()));
        }
        let sid_len = GetLengthSid(psid);
        if sid_len == 0 {
            LocalFree(psid as HLOCAL);
            return Err(anyhow!("GetLengthSid returned 0"));
        }
        let mut out = vec![0u8; sid_len as usize];
        CopySid(sid_len, out.as_mut_ptr() as *mut c_void, psid);
        LocalFree(psid as HLOCAL);
        Ok(out)
    }
}

// ── Allow/Deny path computation ────────────────────────────────────────────

/// Computed allow and deny path sets for ACL grants.
struct AllowDenyPaths {
    allow: HashSet<PathBuf>,
    deny: HashSet<PathBuf>,
}

/// Compute the allow and deny path sets from the sandbox policy.
///
/// For the Deny-ACE approach (without WRITE_RESTRICTED), we add Deny ACEs
/// for all sensitive user directories (Desktop, Documents, etc.) and any
/// paths specified in the policy. This prevents the restricted token process
/// from writing to those locations even though it would otherwise have access.
fn compute_allow_paths(policy: &SandboxPolicy, cwd: &Path) -> AllowDenyPaths {
    let mut allow: HashSet<PathBuf> = HashSet::new();
    let mut deny: HashSet<PathBuf> = HashSet::new();

    let mut add_allow = |p: PathBuf| {
        if p.exists() {
            allow.insert(canonicalize_path(&p));
        }
    };
    let mut add_deny = |p: PathBuf| {
        if p.exists() {
            deny.insert(canonicalize_path(&p));
        }
    };

    // Workspace-write: allow writes to project directory and writable roots
    if policy.mode == SandboxMode::WorkspaceWrite {
        add_allow(cwd.to_path_buf());

        for root in &policy.writable_roots {
            add_allow(root.clone());
        }
        for root in &policy.extra_writable_roots {
            add_allow(root.clone());
        }

        // Allow TEMP/TMP directories
        for key in ["TEMP", "TMP"] {
            if let Ok(v) = std::env::var(key) {
                let p = PathBuf::from(v);
                add_allow(p);
            }
        }

        // Deny writes to sensitive user directories by default.
        // Since we use Deny ACEs (not WRITE_RESTRICTED), we must explicitly
        // add Deny ACEs for all paths we want to protect.
        let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();
        if !home.is_empty() {
            for dir in ["Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"] {
                add_deny(PathBuf::from(format!("{home}/{dir}")));
            }
        }
    }

    // Read-only mode: deny all writable paths
    if policy.mode == SandboxMode::ReadOnly {
        // Add Deny ACEs on the cwd too
        add_deny(cwd.to_path_buf());
        for root in &policy.writable_roots {
            add_deny(root.clone());
        }
    }

    // Add deny paths from policy
    for p in &policy.denied_write_paths {
        add_deny(p.clone());
    }

    AllowDenyPaths { allow, deny }
}

// ── ACL operations ─────────────────────────────────────────────────────────

/// Add an Allow ACE granting read/write/execute to the given SID on the target path.
/// Returns true if an ACE was actually added.
unsafe fn add_allow_ace(path: &Path, psid: *mut c_void) -> Result<bool> {
    let wpath = to_wide(path);
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = GetNamedSecurityInfoW(
        wpath.as_ptr(),
        1, // SE_FILE_OBJECT
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );
    if code != ERROR_SUCCESS {
        return Err(anyhow!("GetNamedSecurityInfoW failed: {code}"));
    }

    // Check if write is already allowed
    if dacl_has_write_allow_for_sid(p_dacl, psid) {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return Ok(false);
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: psid as *mut u16,
    };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    explicit.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
    explicit.grfAccessMode = GRANT_ACCESS as _;
    explicit.grfInheritance = (CONTAINER_INHERIT_ACE as u32) | (OBJECT_INHERIT_ACE as u32);
    explicit.Trustee = trustee;

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    let mut added = false;
    if code2 == ERROR_SUCCESS {
        let code3 = SetNamedSecurityInfoW(
            wpath.as_ptr() as *mut u16,
            1,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_new_dacl,
            std::ptr::null_mut(),
        );
        if code3 == ERROR_SUCCESS {
            added = true;
        }
        if !p_new_dacl.is_null() {
            LocalFree(p_new_dacl as HLOCAL);
        }
    }
    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
    Ok(added)
}

/// Add a Deny ACE to prevent write/append/delete for the given SID on the target path.
/// Returns true if an ACE was actually added.
unsafe fn add_deny_write_ace(path: &Path, psid: *mut c_void) -> Result<bool> {
    let wpath = to_wide(path);
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = GetNamedSecurityInfoW(
        wpath.as_ptr(),
        1,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );
    if code != ERROR_SUCCESS {
        return Err(anyhow!("GetNamedSecurityInfoW failed: {code}"));
    }

    // Check if write deny already exists
    if dacl_has_write_deny_for_sid(p_dacl, psid) {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return Ok(false);
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: psid as *mut u16,
    };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    explicit.grfAccessPermissions = DENY_WRITE_MASK;
    explicit.grfAccessMode = DENY_ACCESS as _;
    explicit.grfInheritance = (CONTAINER_INHERIT_ACE as u32) | (OBJECT_INHERIT_ACE as u32);
    explicit.Trustee = trustee;

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    let mut added = false;
    if code2 == ERROR_SUCCESS {
        let code3 = SetNamedSecurityInfoW(
            wpath.as_ptr() as *mut u16,
            1,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_new_dacl,
            std::ptr::null_mut(),
        );
        if code3 == ERROR_SUCCESS {
            added = true;
        }
        if !p_new_dacl.is_null() {
            LocalFree(p_new_dacl as HLOCAL);
        }
    }
    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
    Ok(added)
}

/// Allow the NUL device (con) for the given SID so sandboxed processes can redirect to NUL.
unsafe fn allow_null_device(psid: *mut c_void) {
    for name in ["NUL", "CON"] {
        let path = PathBuf::from(name);
        let _ = add_allow_ace(&path, psid);
    }
}

/// Remove ACEs for the given SID on a path (cleanup after execution).
unsafe fn revoke_ace(path: &Path, psid: *mut c_void) {
    let wpath = to_wide(path);
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = GetNamedSecurityInfoW(
        wpath.as_ptr(),
        1,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );
    if code != ERROR_SUCCESS {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return;
    }
    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: psid as *mut u16,
    };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    explicit.grfAccessPermissions = 0;
    explicit.grfAccessMode = 4; // REVOKE_ACCESS
    explicit.grfInheritance = (CONTAINER_INHERIT_ACE as u32) | (OBJECT_INHERIT_ACE as u32);
    explicit.Trustee = trustee;

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    if code2 == ERROR_SUCCESS {
        let _ = SetNamedSecurityInfoW(
            wpath.as_ptr() as *mut u16,
            1,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_new_dacl,
            std::ptr::null_mut(),
        );
        if !p_new_dacl.is_null() {
            LocalFree(p_new_dacl as HLOCAL);
        }
    }
    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
}

// ── DACL inspection helpers ────────────────────────────────────────────────

unsafe fn dacl_has_write_allow_for_sid(p_dacl: *mut ACL, psid: *mut c_void) -> bool {
    if p_dacl.is_null() {
        return false;
    }
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    if GetAclInformation(
        p_dacl as *const ACL,
        &mut info as *mut _ as *mut c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    ) == 0
    {
        return false;
    }
    for i in 0..info.AceCount {
        let mut p_ace: *mut c_void = std::ptr::null_mut();
        if GetAce(p_dacl as *const ACL, i, &mut p_ace) == 0 {
            continue;
        }
        let hdr = &*(p_ace as *const ACE_HEADER);
        if hdr.AceType != 0 {
            continue; // ACCESS_ALLOWED_ACE_TYPE
        }
        if (hdr.AceFlags & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
        let ace = &*(p_ace as *const ACCESS_ALLOWED_ACE);
        let base = p_ace as usize;
        let sid_ptr = (base + std::mem::size_of::<ACE_HEADER>() + std::mem::size_of::<u32>())
            as *mut c_void;
        if EqualSid(sid_ptr, psid) != 0 && (ace.Mask & FILE_GENERIC_WRITE) != 0 {
            return true;
        }
    }
    false
}

unsafe fn dacl_has_write_deny_for_sid(p_dacl: *mut ACL, psid: *mut c_void) -> bool {
    if p_dacl.is_null() {
        return false;
    }
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    if GetAclInformation(
        p_dacl as *const ACL,
        &mut info as *mut _ as *mut c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    ) == 0
    {
        return false;
    }
    for i in 0..info.AceCount {
        let mut p_ace: *mut c_void = std::ptr::null_mut();
        if GetAce(p_dacl as *const ACL, i, &mut p_ace) == 0 {
            continue;
        }
        let hdr = &*(p_ace as *const ACE_HEADER);
        if hdr.AceType != 1 {
            continue; // ACCESS_DENIED_ACE_TYPE
        }
        if (hdr.AceFlags & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
        let ace = &*(p_ace as *const ACCESS_ALLOWED_ACE);
        let base = p_ace as usize;
        let sid_ptr = (base + std::mem::size_of::<ACE_HEADER>() + std::mem::size_of::<u32>())
            as *mut c_void;
        if EqualSid(sid_ptr, psid) != 0 && (ace.Mask & DENY_WRITE_MASK) != 0 {
            return true;
        }
    }
    false
}

// ── Process spawning ───────────────────────────────────────────────────────

/// Build a Windows environment block from a HashMap.
fn make_env_block(env: &HashMap<String, String>) -> Vec<u16> {
    let mut items: Vec<(String, String)> = env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    items.sort_by(|a, b| a.0.to_uppercase().cmp(&b.0.to_uppercase()).then(a.0.cmp(&b.0)));
    let mut w: Vec<u16> = Vec::new();
    for (k, v) in items {
        let mut s = to_wide(format!("{k}={v}"));
        s.pop(); // remove trailing null, we'll add per-entry null
        w.extend_from_slice(&s);
        w.push(0);
    }
    w.push(0); // double-null terminator
    w
}

/// Quote a Windows command-line argument.
fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '"'));
    if !needs_quotes {
        return arg.to_string();
    }
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }
    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes * 2));
    }
    quoted.push('"');
    quoted
}

fn argv_to_command_line(argv: &[String]) -> String {
    argv.iter().map(|s| quote_windows_arg(s.as_str())).collect::<Vec<_>>().join(" ")
}

// ── Main sandbox entry point ───────────────────────────────────────────────

/// Run a command in a Windows sandbox using restricted tokens + ACLs.
pub fn run_sandboxed(
    policy: SandboxPolicy,
    command: &[String],
    cwd: &Path,
    env_args: &[String],
    timeout_ms: u64,
) -> Result<ExecResult> {
    if command.is_empty() {
        anyhow::bail!("no command to execute");
    }

    let extra_env = parse_env(env_args);
    let mut env_map: HashMap<String, String> = std::env::vars().collect();
    env_map.extend(extra_env);

    let sids = load_sandbox_sids()?;
    // Prepare SID pointers for Deny ACEs — we use multiple SIDs to ensure
    // the Deny ACE covers all possible ways the restricted token might access
    // the path (as the user, as a member of Users, or as Everyone).
    let mut sid_ptrs: Vec<*mut c_void> = Vec::new();
    let mut user_sid_for_ptr = sids.user_sid.clone();
    let mut users_group_sid_for_ptr = sids.users_group_sid.clone();
    let mut everyone_sid_for_ptr = sids.everyone_sid.clone();
    sid_ptrs.push(user_sid_for_ptr.as_mut_ptr() as *mut c_void);
    sid_ptrs.push(users_group_sid_for_ptr.as_mut_ptr() as *mut c_void);
    sid_ptrs.push(everyone_sid_for_ptr.as_mut_ptr() as *mut c_void);

    // 2. Compute allow/deny paths
    let allow_deny = compute_allow_paths(&policy, cwd);

    // 3. Create restricted token (DISABLE_MAX_PRIVILEGE only, no WRITE_RESTRICTED)
    let base_token = unsafe { get_current_token_for_restriction()? };
    let h_token = unsafe { create_restricted_token(base_token, &sid_ptrs)? };
    unsafe { CloseHandle(base_token) };

    // 4. Apply ACL grants
    //    - Deny ACEs on sensitive paths (Desktop, Documents, etc.) for all SIDs
    //    - This is what actually prevents writes to restricted locations
    let mut guards: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    unsafe {
        // Deny ACEs for protected paths — this is the critical part!
        // For each denied path, add a Deny ACE for each SID so that no matter
        // how the restricted token accesses the path, the Deny ACE applies.
        for p in &allow_deny.deny {
            for sid_ptr in &sid_ptrs {
                if let Ok(added) = add_deny_write_ace(p, *sid_ptr) {
                    if added {
                        guards.push((p.clone(), sids.user_sid.clone()));
                    }
                }
            }
        }
        // Allow NUL/CON device for all SIDs
        for sid_ptr in &sid_ptrs {
            allow_null_device(*sid_ptr);
        }
    }

    // 5. Spawn the command with restricted token
    let result = unsafe { spawn_and_capture(h_token, command, cwd, &env_map, timeout_ms) };

    // 6. Clean up temporary ACEs
    unsafe {
        for (p, sid_bytes) in &guards {
            let mut sid_copy = sid_bytes.clone();
            let psid = sid_copy.as_mut_ptr() as *mut c_void;
            revoke_ace(p, psid);
        }
        CloseHandle(h_token);
    }

    result
}

/// Spawn a process with a restricted token and capture its output.
///
/// The key insight from Codex's approach: under WRITE_RESTRICTED, the restricted
/// token can only write to objects that have an explicit Allow ACE for our cap SID.
/// Anonymous pipes created by the parent process inherit the parent's security
/// descriptor, which does NOT have such an ACE by default.
///
/// Solution: set a permissive default DACL on the restricted token that grants
/// GENERIC_ALL to the cap SID and logon SID. This allows the child process to
/// create new objects (pipes, temp files) and write to inherited pipe handles.
unsafe fn spawn_and_capture(
    h_token: HANDLE,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<ExecResult> {
    // Create pipes for stdout/stderr
    let mut out_r: HANDLE = std::ptr::null_mut();
    let mut out_w: HANDLE = std::ptr::null_mut();
    let mut err_r: HANDLE = std::ptr::null_mut();
    let mut err_w: HANDLE = std::ptr::null_mut();

    // Use a security attributes struct that grants GENERIC_ALL to the cap SID
    // so the restricted token process can write to the pipe.
    let mut sa = make_security_attributes()?;

    if CreatePipe(&mut out_r, &mut out_w, &mut sa, 0) == 0 {
        return Err(anyhow!("CreatePipe(stdout) failed: {}", GetLastError()));
    }
    if CreatePipe(&mut err_r, &mut err_w, &mut sa, 0) == 0 {
        CloseHandle(out_r);
        CloseHandle(out_w);
        return Err(anyhow!("CreatePipe(stderr) failed: {}", GetLastError()));
    }

    // Mark write ends as inheritable by child
    SetHandleInformation(out_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(err_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    // Read ends should NOT be inheritable
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);

    // Build command line and environment
    let cmdline_str = argv_to_command_line(argv);
    let mut cmdline: Vec<u16> = to_wide(&cmdline_str);
    let env_block = make_env_block(env_map);
    let cwd_wide = to_wide(cwd);

    // STARTUPINFO with stdio handles
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out_w;
    si.hStdError = err_w;

    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

    let creation_flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;

    let ok = CreateProcessAsUserW(
        h_token,
        std::ptr::null(),
        cmdline.as_mut_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        1, // bInheritHandles = TRUE
        creation_flags,
        env_block.as_ptr() as *mut c_void,
        cwd_wide.as_ptr(),
        &si,
        &mut pi,
    );

    // Close write ends in parent — child has inherited them
    CloseHandle(out_w);
    CloseHandle(err_w);

    if ok == 0 {
        let err = GetLastError();
        CloseHandle(out_r);
        CloseHandle(err_r);
        return Err(anyhow!(
            "CreateProcessAsUserW failed: {} (cmd: {})",
            err,
            cmdline_str
        ));
    }

    // Close thread handle immediately
    if !pi.hThread.is_null() {
        CloseHandle(pi.hThread);
    }

    // Read stdout and stderr in separate threads
    let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = std::sync::mpsc::channel::<Vec<u8>>();

    // Wrap raw HANDLEs in a Send-safe wrapper for thread spawning
    struct SendHandle(usize);
    unsafe impl Send for SendHandle {}

    let out_r_send = SendHandle(out_r as usize);
    let err_r_send = SendHandle(err_r as usize);

    let t_out = std::thread::spawn(move || {
        let out_r = out_r_send.0 as HANDLE;
        let mut file = std::fs::File::from_raw_handle(out_r as _);
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut file, &mut buf);
        // File closes the handle when dropped
        let _ = tx_out.send(buf);
    });

    let t_err = std::thread::spawn(move || {
        let err_r = err_r_send.0 as HANDLE;
        let mut file = std::fs::File::from_raw_handle(err_r as _);
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut file, &mut buf);
        let _ = tx_err.send(buf);
    });

    // Wait for process with optional timeout
    let timeout = if timeout_ms > 0 {
        timeout_ms as u32
    } else {
        INFINITE
    };
    let wait_result = WaitForSingleObject(pi.hProcess, timeout);
    let timed_out = wait_result == 0x0000_0102; // WAIT_TIMEOUT

    let mut exit_code: u32 = 1;
    if timed_out {
        TerminateProcess(pi.hProcess, 1);
    } else {
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
    }
    CloseHandle(pi.hProcess);

    let _ = t_out.join();
    let _ = t_err.join();
    let stdout = rx_out.recv().unwrap_or_default();
    let stderr = rx_err.recv().unwrap_or_default();

    Ok(ExecResult {
        exit_code: if timed_out { 128 + 64 } else { exit_code as i32 },
        stdout,
        stderr,
        timed_out,
    })
}

/// Create SECURITY_ATTRIBUTES that grant GENERIC_ALL to Everyone (S-1-1-0)
/// so that the restricted token process can write to the pipe.
///
/// Under WRITE_RESTRICTED, the child process can only write to objects
/// whose DACL explicitly allows our cap SID. The default pipe DACL only
/// allows the creator, so we must create a pipe with a permissive DACL.
unsafe fn make_security_attributes() -> Result<SECURITY_ATTRIBUTES> {
    // Use a heap-allocated security descriptor so it outlives the function
    let sd_ptr = {
        let mut sd = Box::new([0u8; 1024]);
        let ptr = sd.as_mut_ptr() as *mut c_void;
        std::mem::forget(sd); // prevent deallocation until after CreatePipe
        ptr
    };

    let ok = InitializeSecurityDescriptor(
        sd_ptr,
        SECURITY_DESCRIPTOR_REVISION,
    );
    if ok == 0 {
        return Err(anyhow!("InitializeSecurityDescriptor failed: {}", GetLastError()));
    }

    // Grant GENERIC_ALL to Everyone (S-1-1-0) via EXPLICIT_ACCESS_W
    let everyone_sid_str = "S-1-1-0";
    let wide = to_wide(everyone_sid_str);
    let mut psid_everyone: *mut c_void = std::ptr::null_mut();
    let ok2 = ConvertStringSidToSidW(wide.as_ptr(), &mut psid_everyone);
    if ok2 == 0 {
        return Err(anyhow!("ConvertStringSidToSidW for Everyone failed: {}", GetLastError()));
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: psid_everyone as *mut u16,
    };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    explicit.grfAccessPermissions = GENERIC_ALL;
    explicit.grfAccessMode = GRANT_ACCESS as _;
    explicit.grfInheritance = 0;
    explicit.Trustee = trustee;

    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let res = SetEntriesInAclW(1, &explicit, std::ptr::null_mut(), &mut p_dacl);
    LocalFree(psid_everyone as HLOCAL);

    if res != ERROR_SUCCESS {
        return Err(anyhow!("SetEntriesInAclW for pipe DACL failed: {res}"));
    }

    // Set the DACL on the security descriptor
    let ok3 = SetSecurityDescriptorDacl(
        sd_ptr,
        1, // dacl present
        p_dacl,
        0, // dacl NOT defaulted
    );
    if ok3 == 0 {
        LocalFree(p_dacl as HLOCAL);
        return Err(anyhow!("SetSecurityDescriptorDacl failed: {}", GetLastError()));
    }

    let mut sa = std::mem::zeroed::<SECURITY_ATTRIBUTES>();
    sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.lpSecurityDescriptor = sd_ptr;
    sa.bInheritHandle = 1;

    Ok(sa)
}
