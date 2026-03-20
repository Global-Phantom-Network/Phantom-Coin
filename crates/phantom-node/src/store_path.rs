// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) const LEGACY_STORE_DIR_SENTINEL: &str = "pc-data";
pub(crate) const LEGACY_MEMPOOL_DIR_SENTINEL: &str = "pc-data/mempool";
const APP_DIR_UNIX: &str = "phantom-coin";
const APP_DIR_HUMAN: &str = "Phantom-Coin";

fn fallback_runtime_store_dir() -> PathBuf {
    std::env::temp_dir().join(APP_DIR_UNIX).join("data")
}

fn repo_root_from(mut dir: PathBuf, max_depth: usize) -> Option<PathBuf> {
    for _ in 0..max_depth {
        let cargo = dir.join("Cargo.toml");
        if cargo.is_file()
            && std::fs::read_to_string(&cargo)
                .ok()
                .map(|raw| raw.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

fn repo_root_from_cwd() -> Option<PathBuf> {
    repo_root_from(std::env::current_dir().ok()?, 10)
}

fn repo_root_from_exe() -> Option<PathBuf> {
    repo_root_from(std::env::current_exe().ok()?.parent()?.to_path_buf(), 12)
}

fn current_repo_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for root in [repo_root_from_exe(), repo_root_from_cwd()]
        .into_iter()
        .flatten()
    {
        if !roots.iter().any(|existing| existing == &root) {
            roots.push(root);
        }
    }
    roots
}

fn canonicalize_allow_missing(path: &Path) -> Result<PathBuf> {
    let mut probe = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    while !probe.exists() {
        let Some(name) = probe.file_name() else {
            break;
        };
        tail.push(name.to_os_string());
        probe = probe
            .parent()
            .ok_or_else(|| anyhow!("Pfad '{}' ist ungültig", path.display()))?
            .to_path_buf();
    }
    let mut canon = std::fs::canonicalize(&probe).map_err(|e| {
        anyhow!(
            "Pfad '{}' kann nicht aufgelöst werden: {e}",
            probe.display()
        )
    })?;
    for comp in tail.iter().rev() {
        canon.push(comp);
    }
    Ok(canon)
}

fn reject_repo_local_path(path: &Path) -> Result<()> {
    for root in current_repo_roots() {
        if path.starts_with(&root) {
            return Err(anyhow!(
                "Runtime-Pfad im Repository-Baum ist nicht erlaubt: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME ist nicht gesetzt"))
}

fn default_data_home() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        return Ok(home_dir()?.join("Library").join("Application Support"));
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Ok(PathBuf::from(appdata));
        }
        if let Some(userprofile) = std::env::var_os("USERPROFILE") {
            return Ok(PathBuf::from(userprofile).join("AppData").join("Roaming"));
        }
        return Err(anyhow!("APPDATA/USERPROFILE ist nicht gesetzt"));
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(xdg));
        }
        Ok(home_dir()?.join(".local").join("share"))
    }
}

pub(crate) fn default_runtime_store_dir() -> Result<PathBuf> {
    if let Some(raw) = std::env::var_os("PHANTOM_STORE_DIR") {
        let raw = raw.to_string_lossy().trim().to_string();
        if !raw.is_empty() {
            return resolve_explicit_dir_value(&raw, false, "PHANTOM_STORE_DIR");
        }
    }
    let dir = default_data_home()?.join(if cfg!(target_os = "windows") {
        APP_DIR_HUMAN
    } else {
        APP_DIR_UNIX
    });
    let dir = dir.join("data");
    reject_repo_local_path(&dir)?;
    Ok(dir)
}

pub(crate) fn default_runtime_store_dir_pathbuf() -> PathBuf {
    default_runtime_store_dir().unwrap_or_else(|_| fallback_runtime_store_dir())
}

pub(crate) fn default_runtime_store_dir_string() -> String {
    default_runtime_store_dir_pathbuf()
        .to_string_lossy()
        .to_string()
}

pub(crate) fn default_runtime_mempool_dir_string() -> String {
    default_runtime_store_dir_pathbuf()
        .join("mempool")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn resolve_explicit_dir_value(
    raw: &str,
    unsafe_confirm: bool,
    label: &str,
) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{label} ist leer"));
    }
    let path = PathBuf::from(trimmed);
    let resolved = if path.is_absolute() {
        canonicalize_allow_missing(&path)?
    } else {
        if !unsafe_confirm {
            return Err(anyhow!(
                "{label} muss ein absoluter Pfad sein oder weggelassen werden"
            ));
        }
        let cwd = std::env::current_dir().map_err(|e| anyhow!("cwd read failed: {e}"))?;
        canonicalize_allow_missing(&cwd.join(path))?
    };
    reject_repo_local_path(&resolved)?;
    Ok(resolved)
}

pub(crate) fn resolve_store_dir_value(raw: &str, unsafe_confirm: bool) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == LEGACY_STORE_DIR_SENTINEL {
        return default_runtime_store_dir();
    }
    resolve_explicit_dir_value(trimmed, unsafe_confirm, "store_dir")
}

pub(crate) fn resolve_mempool_dir_value(
    raw: &str,
    store_dir: &Path,
    unsafe_confirm: bool,
) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == LEGACY_MEMPOOL_DIR_SENTINEL {
        let dir = store_dir.join("mempool");
        reject_repo_local_path(&dir)?;
        return Ok(dir);
    }
    resolve_explicit_dir_value(trimmed, unsafe_confirm, "mempool_dir")
}

pub(crate) fn resolve_store_dir_legacy(raw: &str) -> Result<String> {
    Ok(resolve_store_dir_value(raw, false)?
        .to_string_lossy()
        .to_string())
}
