// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};

#[cfg(unix)]
pub fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

pub fn find_in_path(program: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let base = dir.join(program);
        if is_executable_file(&base) {
            return Some(base);
        }
        #[cfg(windows)]
        {
            for ext in ["exe", "cmd", "bat", "com"] {
                let cand = base.with_extension(ext);
                if is_executable_file(&cand) {
                    return Some(cand);
                }
            }
        }
    }
    None
}

pub fn find_next_to_current_exe(program: &str) -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let dir = exe.parent()?;
    let base = dir.join(program);
    if is_executable_file(&base) {
        return Some(base);
    }
    #[cfg(windows)]
    {
        for ext in ["exe", "cmd", "bat", "com"] {
            let cand = base.with_extension(ext);
            if is_executable_file(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

/// Prefer programs shipped next to the current executable. Only allow PATH fallback in debug.
pub fn find_program(program: &str) -> Option<PathBuf> {
    find_next_to_current_exe(program).or_else(|| {
        if cfg!(debug_assertions) {
            find_in_path(program)
        } else {
            None
        }
    })
}

pub fn find_signer_binary() -> Option<PathBuf> {
    find_program("phantom-signer")
}
