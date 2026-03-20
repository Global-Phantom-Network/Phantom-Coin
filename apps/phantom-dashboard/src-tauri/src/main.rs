#![forbid(unsafe_code)]

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{command, Manager};

use bech32::FromBase32 as _;
use bip39::{Language, Mnemonic};
use rand_core::{OsRng as AeadOsRng, RngCore};
use zeroize::Zeroizing;

use pc_consensus::attestation::{committee_precommit_message, committee_vote_message};
use pc_types::{
    digest_genesis_note, AnchorHeaderV2, AnchorId, GenesisNote, ParentList,
    GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
};
use phantom_signer::walletdb;

mod helpers;
use helpers::*;
mod node_service;
use node_service::*;

#[derive(Debug, Deserialize)]
struct HttpGetArgs {
    url: String,
    #[serde(alias = "bearerToken", alias = "bearer_token")]
    bearer_token: Option<String>,
    #[serde(alias = "timeoutMs", alias = "timeout_ms")]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct DashboardSmokeHttpRequest {
    url: String,
    bearer_token: Option<String>,
    expect_body_includes: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DashboardSmokeHttpResult {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    body_preview: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletCreateArgs {
    wallet_name: String,
    hrp: String,
    mnemonic: String,
    password: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WalletKind {
    Hot,
    BitboxWatchOnly,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletCreateWatchOnlyArgs {
    wallet_name: String,
    hrp: String,
    xpub: String,
    derivation: String,
    #[serde(default)]
    fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct WalletStatus {
    exists: bool,
    wallet_name: Option<String>,
    wallet_kind: Option<WalletKind>,
    watch_only: bool,
    hrp: Option<String>,
    address: Option<String>,
    lock_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct WalletAddrView {
    addr: String,
    hrp: String,
    change: u32,
    index: u32,
    xpub_derivation: String,
    fingerprint: Option<String>,
    label: Option<String>,
    lock_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct WalletUnlockResp {
    ok: bool,
    wallet_name: String,
    wallet_kind: WalletKind,
    watch_only: bool,
    addrs: Vec<WalletAddrView>,
    selected_addr: Option<String>,
    selected_lock_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletProfileDisk {
    version: u32,
    wallet_name: String,
    wallet_kind: WalletKind,
    hrp: String,
    address: Option<String>,
    lock_hex: Option<String>,
    #[serde(default)]
    xpubstore_path: Option<String>,
    #[serde(default)]
    derivation: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
}

struct WalletUnlocked {
    wallet_name: String,
    wallet_kind: WalletKind,
    passphrase: Zeroizing<String>,
    selected_addr: String,
    selected_lock_hex: String,
}

#[derive(Default)]
struct WalletService {
    inner: std::sync::Mutex<Option<WalletUnlocked>>,
}

fn app_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let Some(dir) = app.path_resolver().app_data_dir() else {
        return Err("Kein App-Datenordner verfügbar".to_string());
    };
    fs::create_dir_all(&dir).map_err(|e| format!("App-Datenordner nicht erstellbar: {e}"))?;
    Ok(dir)
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let meta = fs::metadata(path).map_err(|e| format!("Datei nicht lesbar: {e}"))?;
    const MAX_JSON_BYTES: u64 = 1_048_576; // 1 MiB
    if meta.len() > MAX_JSON_BYTES {
        return Err(format!(
            "Datei ist zu groß: {} bytes (max {} bytes)",
            meta.len(),
            MAX_JSON_BYTES
        ));
    }
    let data = fs::read(path).map_err(|e| format!("Datei nicht lesbar: {e}"))?;
    serde_json::from_slice(&data).map_err(|e| format!("JSON ungültig: {e}"))
}

fn write_json_file_atomic<T: Serialize>(path: &Path, val: &T) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "Dateipfad ist ungültig".to_string())?;

    let data = serde_json::to_vec_pretty(val).map_err(|e| format!("JSON nicht erzeugbar: {e}"))?;

    // Create a uniquely named temp file in the same directory.
    // Use create_new to avoid symlink/clobber races in attacker-controlled directories.
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "data.json".to_string());

    let mut last_err: Option<String> = None;
    for _ in 0..16 {
        let mut nonce = [0u8; 8];
        AeadOsRng.fill_bytes(&mut nonce);
        let tmp_name = format!(".{file_name}.{}.tmp", hex::encode(nonce));
        let tmp_path = dir.join(tmp_name);

        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path);

        let mut f = match opened {
            Ok(h) => h,
            Err(e) => {
                last_err = Some(format!("Temp-Datei nicht anlegbar: {e}"));
                continue;
            }
        };

        if let Err(e) = f.write_all(&data) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Datei nicht schreibbar: {e}"));
        }
        let _ = f.sync_all(); // best-effort durability
        drop(f);

        // On Windows, rename fails if destination exists. Best-effort remove and retry.
        if let Err(e) = fs::rename(&tmp_path, path) {
            #[cfg(windows)]
            {
                if path.exists() {
                    let _ = fs::remove_file(path);
                }
                if let Err(e2) = fs::rename(&tmp_path, path) {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(format!("Datei nicht ersetzbar: {e2}"));
                }
                return Ok(());
            }

            #[cfg(not(windows))]
            {
                let _ = fs::remove_file(&tmp_path);
                return Err(format!("Datei nicht ersetzbar: {e}"));
            }
        }

        return Ok(());
    }

    Err(last_err.unwrap_or_else(|| "Temp-Datei konnte nicht angelegt werden".to_string()))
}

fn normalize_name(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Name darf nicht leer sein".to_string());
    }
    if s.len() > 64 {
        return Err("Name ist zu lang".to_string());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err("Name enthält ungültige Zeichen".to_string());
    }
    Ok(s.to_string())
}

fn phantom_home_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME ist nicht gesetzt".to_string())?;
    Ok(PathBuf::from(home).join(".phantom"))
}

fn default_walletdb_path(wallet_name: &str) -> Result<PathBuf, String> {
    let wallet_name = normalize_name(wallet_name)?;
    Ok(phantom_home_dir()?.join("wallets").join(wallet_name))
}

fn default_seedstore_path(wallet_name: &str) -> Result<PathBuf, String> {
    let wallet_name = normalize_name(wallet_name)?;
    Ok(phantom_home_dir()?
        .join("seeds")
        .join(format!("{wallet_name}.toml")))
}

fn default_xpubstore_path(wallet_name: &str) -> Result<PathBuf, String> {
    let wallet_name = normalize_name(wallet_name)?;
    Ok(phantom_home_dir()?
        .join("xpubs")
        .join(format!("{wallet_name}.toml")))
}

fn default_watch_only_secret_path(wallet_name: &str) -> Result<PathBuf, String> {
    let wallet_name = normalize_name(wallet_name)?;
    Ok(phantom_home_dir()?
        .join("watch-only-secrets")
        .join(format!("{wallet_name}.secret")))
}

fn default_wallet_profile_path(wallet_name: &str) -> Result<PathBuf, String> {
    let wallet_name = normalize_name(wallet_name)?;
    Ok(phantom_home_dir()?
        .join("wallet-meta")
        .join(format!("{wallet_name}.json")))
}

fn load_wallet_profile(wallet_name: &str) -> Result<Option<WalletProfileDisk>, String> {
    let path = default_wallet_profile_path(wallet_name)?;
    if !path.exists() {
        return Ok(None);
    }
    read_json_file(&path).map(Some)
}

fn save_wallet_profile(profile: &WalletProfileDisk) -> Result<(), String> {
    let path = default_wallet_profile_path(&profile.wallet_name)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Wallet-Metadaten-Ordner nicht erstellbar: {e}"))?;
    }
    write_json_file_atomic(&path, profile)?;
    harden_private_file(&path)
}

fn detect_wallet_kind(wallet_name: &str) -> Result<WalletKind, String> {
    if let Some(profile) = load_wallet_profile(wallet_name)? {
        return Ok(profile.wallet_kind);
    }
    if default_seedstore_path(wallet_name)?.exists() {
        return Ok(WalletKind::Hot);
    }
    Ok(WalletKind::BitboxWatchOnly)
}

fn build_wallet_status(
    wallet_name: &str,
    wallet_kind: WalletKind,
    hrp: Option<String>,
    address: Option<String>,
    lock_hex: Option<String>,
) -> WalletStatus {
    WalletStatus {
        exists: true,
        wallet_name: Some(wallet_name.to_string()),
        wallet_kind: Some(wallet_kind),
        watch_only: wallet_kind != WalletKind::Hot,
        hrp,
        address,
        lock_hex,
    }
}

fn generate_watch_only_secret() -> String {
    let mut secret = [0u8; 32];
    AeadOsRng.fill_bytes(&mut secret);
    hex::encode(secret)
}

fn write_secret_file_atomic(path: &Path, secret: &str) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "Secret-Pfad ist ungültig".to_string())?;
    fs::create_dir_all(dir).map_err(|e| format!("Secret-Ordner nicht erstellbar: {e}"))?;

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "watch-only.secret".to_string());

    let mut last_err: Option<String> = None;
    for _ in 0..16 {
        let mut nonce = [0u8; 8];
        AeadOsRng.fill_bytes(&mut nonce);
        let tmp_path = dir.join(format!(".{file_name}.{}.tmp", hex::encode(nonce)));

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }

        let mut fh = match opts.open(&tmp_path) {
            Ok(fh) => fh,
            Err(e) => {
                last_err = Some(format!("Temp-Secret-Datei nicht anlegbar: {e}"));
                continue;
            }
        };

        if let Err(e) = fh.write_all(secret.as_bytes()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Secret-Datei nicht schreibbar: {e}"));
        }
        if let Err(e) = fh.write_all(b"\n") {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Secret-Datei nicht schreibbar: {e}"));
        }
        let _ = fh.sync_all();
        drop(fh);

        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Secret-Datei nicht finalisierbar: {e}"));
        }

        return harden_private_file(path);
    }

    Err(last_err.unwrap_or_else(|| "Secret-Datei nicht anlegbar".to_string()))
}

fn load_watch_only_secret(wallet_name: &str) -> Result<String, String> {
    let path = default_watch_only_secret_path(wallet_name)?;
    let secret = fs::read_to_string(&path)
        .map_err(|e| format!("Watch-only-Secret nicht lesbar: {}: {e}", path.display()))?;
    let secret = secret.trim().to_string();
    if secret.len() < 16 {
        return Err("Watch-only-Secret ist ungültig".to_string());
    }
    Ok(secret)
}

fn verified_wallet_selection(
    wallet_db_dir: &Path,
    passphrase: &str,
    preferred_addr: Option<&str>,
) -> Result<Option<(String, String, String)>, String> {
    let wdb = walletdb::WalletDb::open_locked(wallet_db_dir, passphrase)
        .map_err(|e| format!("Wallet öffnen fehlgeschlagen: {e}"))?;

    if let Some(addr) = preferred_addr.filter(|addr| !addr.trim().is_empty()) {
        if let Some(meta) = wdb
            .get_address(addr)
            .map_err(|e| format!("Wallet-Adresse nicht prüfbar: {e}"))?
        {
            let lock_hex = hex::encode(lock_from_bech32m_v1_addr(&meta.addr)?);
            return Ok(Some((meta.addr, meta.hrp, lock_hex)));
        }
    }

    let mut addrs = wdb
        .all_addresses()
        .map_err(|e| format!("Wallet-Adressen nicht lesbar: {e}"))?;
    addrs.sort_by(|a, b| (a.change, a.index).cmp(&(b.change, b.index)));
    let Some(meta) = addrs.into_iter().next() else {
        return Ok(None);
    };
    let lock_hex = hex::encode(lock_from_bech32m_v1_addr(&meta.addr)?);
    Ok(Some((meta.addr, meta.hrp, lock_hex)))
}

fn lock_from_bech32m_v1_addr(addr: &str) -> Result<[u8; 32], String> {
    let (hrp, data, variant) =
        bech32::decode(addr.trim()).map_err(|e| format!("Adresse ungültig (bech32): {e}"))?;
    if hrp.len() > 83 {
        return Err("Adresse ungültig (HRP zu lang)".to_string());
    }
    if variant != bech32::Variant::Bech32m {
        return Err("Adresse ungültig (Bech32m erwartet)".to_string());
    }
    let (ver, prog_u5) = data
        .split_first()
        .ok_or_else(|| "Adresse ungültig (kein Witness-Header)".to_string())?;
    if ver.to_u8() != 1 {
        return Err("Adresse ungültig (nur Witness v1 unterstützt)".to_string());
    }
    let prog: Vec<u8> =
        Vec::<u8>::from_base32(prog_u5).map_err(|e| format!("Adresse ungültig (program): {e}"))?;
    if prog.len() != 32 {
        return Err(format!(
            "Adresse ungültig (program length {}, erwartet 32)",
            prog.len()
        ));
    }
    let mut lock = [0u8; 32];
    lock.copy_from_slice(&prog);
    Ok(lock)
}

fn with_temp_secret_file<R, F>(prefix: &str, secret: &str, f: F) -> Result<R, String>
where
    F: FnOnce(&Path) -> Result<R, String>,
{
    let mut file = None;
    for _ in 0..16 {
        let mut rnd = [0u8; 16];
        AeadOsRng.fill_bytes(&mut rnd);
        let name = format!("{}_{}.secret", prefix, hex::encode(rnd));
        let path = std::env::temp_dir().join(name);

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(fh) => {
                file = Some((path, fh));
                break;
            }
            Err(_) => continue,
        }
    }

    let (path, mut fh) = file.ok_or_else(|| {
        format!(
            "Temp-Secret-Datei nicht erzeugbar: {}",
            std::env::temp_dir().display()
        )
    })?;

    fh.write_all(secret.as_bytes())
        .map_err(|e| format!("Temp-Secret-Datei nicht schreibbar: {e}"))?;
    fh.write_all(b"\n")
        .map_err(|e| format!("Temp-Secret-Datei nicht schreibbar: {e}"))?;
    let _ = fh.flush();
    drop(fh);

    let res = f(&path);
    let _ = std::fs::remove_file(&path);
    res
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootstrapPeerEntryDisk {
    addr: String,
    cert_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootstrapPeersFileDisk {
    peers: Vec<BootstrapPeerEntryDisk>,
}

#[derive(Debug, Deserialize)]
struct BootstrapPeersLoadArgs {
    store_dir: String,
}

#[derive(Debug, Serialize)]
struct BootstrapPeersLoadResp {
    path: String,
    peers: Vec<BootstrapPeerEntryDisk>,
}

#[derive(Debug, Deserialize)]
struct BootstrapPeersSaveArgs {
    store_dir: String,
    peers: Vec<BootstrapPeerEntryDisk>,
}

#[derive(Debug, Serialize)]
struct BootstrapPeersSaveResp {
    path: String,
    peers_written: usize,
}

fn resolve_store_dir_path_for_app(
    app: &tauri::AppHandle,
    store_dir: &str,
) -> Result<PathBuf, String> {
    let trimmed = store_dir.trim();
    if trimmed.is_empty() {
        return Err("Store-Verzeichnis ist leer".to_string());
    }
    if trimmed.len() > 4096 {
        return Err("Store-Verzeichnis ist zu lang".to_string());
    }
    if trimmed.contains('\0') {
        return Err("Store-Verzeichnis ist ungültig".to_string());
    }

    let p = PathBuf::from(trimmed);

    let reject_store_dir_in_repo_tree = |canon: &Path| -> Result<(), String> {
        if let Some(root) = repo_root() {
            if let Ok(root_canon) = fs::canonicalize(root) {
                if canon.starts_with(&root_canon) {
                    return Err(
                        "Store-Verzeichnis im Repository-Quellbaum ist nicht erlaubt".to_string(),
                    );
                }
            }
        }
        Ok(())
    };

    if p.is_absolute() {
        let canon = fs::canonicalize(&p)
            .map_err(|e| format!("Store-Verzeichnis existiert nicht oder ist nicht lesbar: {e}"))?;
        let meta = fs::metadata(&canon)
            .map_err(|e| format!("Store-Verzeichnis existiert nicht oder ist nicht lesbar: {e}"))?;
        if !meta.is_dir() {
            return Err("Store-Verzeichnis ist kein Ordner".to_string());
        }
        reject_store_dir_in_repo_tree(&canon)?;
        return Ok(canon);
    }

    // Relative Store-Dirs are resolved below app data to avoid accidental source-tree usage.
    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            Component::CurDir => {}
            _ => {
                return Err(
                    "Relativer Store-Pfad ist ungültig (keine '..', Root oder Prefix)".to_string(),
                )
            }
        }
    }

    let app_data = app_data_dir(app)?;
    let app_data_canon =
        fs::canonicalize(&app_data).map_err(|e| format!("App-Datenordner ist ungültig: {e}"))?;
    let joined = app_data.join(&p);

    // Relative Store-Dirs may be newly created.
    if !joined.exists() {
        fs::create_dir_all(&joined)
            .map_err(|e| format!("Store-Verzeichnis konnte nicht erstellt werden: {e}"))?;
    }

    let canon = fs::canonicalize(&joined)
        .map_err(|e| format!("Store-Verzeichnis ist nicht lesbar: {e}"))?;

    if !canon.starts_with(&app_data_canon) {
        return Err(
            "Relatives Store-Verzeichnis entkommt dem App-Datenordner (Symlink?)".to_string(),
        );
    }
    reject_store_dir_in_repo_tree(&canon)?;

    let meta = fs::metadata(&canon)
        .map_err(|e| format!("Store-Verzeichnis existiert nicht oder ist nicht lesbar: {e}"))?;
    if !meta.is_dir() {
        return Err("Store-Verzeichnis ist kein Ordner".to_string());
    }
    Ok(canon)
}

fn resolve_existing_store_dir_path_for_app(
    app: &tauri::AppHandle,
    store_dir: &str,
) -> Result<PathBuf, String> {
    let trimmed = store_dir.trim();
    if trimmed.is_empty() {
        return Err("Store-Verzeichnis ist leer".to_string());
    }
    if trimmed.len() > 4096 {
        return Err("Store-Verzeichnis ist zu lang".to_string());
    }
    if trimmed.contains('\0') {
        return Err("Store-Verzeichnis ist ungültig".to_string());
    }

    let p = PathBuf::from(trimmed);
    let reject_store_dir_in_repo_tree = |canon: &Path| -> Result<(), String> {
        if let Some(root) = repo_root() {
            if let Ok(root_canon) = fs::canonicalize(root) {
                if canon.starts_with(&root_canon) {
                    return Err(
                        "Store-Verzeichnis im Repository-Quellbaum ist nicht erlaubt".to_string(),
                    );
                }
            }
        }
        Ok(())
    };
    if p.is_absolute() {
        let canon = fs::canonicalize(&p)
            .map_err(|e| format!("Store-Verzeichnis existiert nicht oder ist nicht lesbar: {e}"))?;
        let meta = fs::metadata(&canon)
            .map_err(|e| format!("Store-Verzeichnis existiert nicht oder ist nicht lesbar: {e}"))?;
        if !meta.is_dir() {
            return Err("Store-Verzeichnis ist kein Ordner".to_string());
        }
        reject_store_dir_in_repo_tree(&canon)?;
        return Ok(canon);
    }

    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            Component::CurDir => {}
            _ => {
                return Err(
                    "Relativer Store-Pfad ist ungültig (keine '..', Root oder Prefix)".to_string(),
                )
            }
        }
    }

    let app_data = app_data_dir(app)?;
    let app_data_canon =
        fs::canonicalize(&app_data).map_err(|e| format!("App-Datenordner ist ungültig: {e}"))?;
    let joined = app_data.join(&p);

    let canon = fs::canonicalize(&joined)
        .map_err(|e| format!("Store-Verzeichnis existiert nicht oder ist nicht lesbar: {e}"))?;
    if !canon.starts_with(&app_data_canon) {
        return Err(
            "Relatives Store-Verzeichnis entkommt dem App-Datenordner (Symlink?)".to_string(),
        );
    }
    reject_store_dir_in_repo_tree(&canon)?;
    let meta = fs::metadata(&canon)
        .map_err(|e| format!("Store-Verzeichnis existiert nicht oder ist nicht lesbar: {e}"))?;
    if !meta.is_dir() {
        return Err("Store-Verzeichnis ist kein Ordner".to_string());
    }
    Ok(canon)
}

#[command]
fn bootstrap_peers_load(
    app: tauri::AppHandle,
    args: BootstrapPeersLoadArgs,
) -> Result<BootstrapPeersLoadResp, String> {
    let store_dir = resolve_store_dir_path_for_app(&app, &args.store_dir)?;
    let path = store_dir.join("bootstrap_peers.json");

    if !path.exists() {
        // No sample seeding here: v1 wants no implicit example peers. Create an empty file instead.
        let empty = BootstrapPeersFileDisk { peers: Vec::new() };
        write_json_file_atomic(&path, &empty)?;
    }

    let parsed = read_json_file::<BootstrapPeersFileDisk>(&path)?;
    Ok(BootstrapPeersLoadResp {
        path: path.to_string_lossy().to_string(),
        peers: parsed.peers,
    })
}

#[command]
fn bootstrap_peers_save(
    app: tauri::AppHandle,
    args: BootstrapPeersSaveArgs,
) -> Result<BootstrapPeersSaveResp, String> {
    let store_dir = resolve_store_dir_path_for_app(&app, &args.store_dir)?;
    let path = store_dir.join("bootstrap_peers.json");

    const MAX_PEERS: usize = 256;
    const MAX_ADDR_LEN: usize = 1024;
    const MAX_CERT_LEN: usize = 4096;

    let mut peers: Vec<BootstrapPeerEntryDisk> = Vec::new();
    for p in args.peers.into_iter() {
        let addr = p.addr.trim().to_string();
        let cert_file = p.cert_file.trim().to_string();
        if addr.is_empty() || cert_file.is_empty() {
            continue;
        }
        if addr.len() > MAX_ADDR_LEN {
            return Err(format!("Adresse ist zu lang (max {MAX_ADDR_LEN} Zeichen)"));
        }
        if cert_file.len() > MAX_CERT_LEN {
            return Err(format!(
                "Zertifikat-Datei ist zu lang (max {MAX_CERT_LEN} Zeichen)"
            ));
        }
        peers.push(BootstrapPeerEntryDisk { addr, cert_file });
        if peers.len() > MAX_PEERS {
            return Err(format!("Zu viele Bootstrap-Peers (max {MAX_PEERS})"));
        }
    }

    let doc = BootstrapPeersFileDisk { peers };
    let peers_written = doc.peers.len();
    write_json_file_atomic(&path, &doc)?;

    Ok(BootstrapPeersSaveResp {
        path: path.to_string_lossy().to_string(),
        peers_written,
    })
}

#[command]
async fn wallet_generate_mnemonic() -> Result<String, String> {
    let mut entropy = [0u8; 32];
    AeadOsRng.fill_bytes(&mut entropy);
    let m = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| format!("Seed nicht erzeugbar: {e}"))?;
    Ok(m.to_string())
}

#[command]
async fn wallet_create(
    app: tauri::AppHandle,
    state: tauri::State<'_, WalletService>,
    args: WalletCreateArgs,
) -> Result<WalletStatus, String> {
    let wallet_name = normalize_name(&args.wallet_name)?;
    let hrp = normalize_name(&args.hrp)?;
    let passphrase = args.password;
    if passphrase.trim().len() < 8 {
        return Err("Passphrase muss mindestens 8 Zeichen haben".to_string());
    }

    let mnemonic = Mnemonic::parse_in(Language::English, args.mnemonic.trim())
        .map_err(|_| "Seed Phrase ist ungültig".to_string())?;
    if mnemonic.word_count() != 24 {
        return Err("Seed Phrase muss 24 Wörter enthalten".to_string());
    }

    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let seed_store_path = default_seedstore_path(&wallet_name)?;
    let wallet_profile = default_wallet_profile_path(&wallet_name)?;
    if wallet_db_dir.exists() || seed_store_path.exists() {
        return Err("Wallet existiert bereits".to_string());
    }
    if wallet_profile.exists() {
        return Err("Wallet-Metadaten existieren bereits".to_string());
    }

    let signer_path = find_phantom_signer_binary()?;

    let first_addr = with_temp_secret_file(
        "phantom_wallet_passphrase",
        passphrase.trim(),
        |pass_path| {
            let mut cmd = Command::new(&signer_path);
            cmd.arg("wallet-restore")
                .arg("--hrp")
                .arg(hrp.trim())
                .arg("--wallet-name")
                .arg(wallet_name.trim())
                .arg("--passphrase-file")
                .arg(pass_path)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            let mut child = cmd
                .spawn()
                .map_err(|e| format!("phantom-signer Start fehlgeschlagen: {e}"))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(mnemonic.to_string().as_bytes())
                    .map_err(|e| format!("phantom-signer stdin write failed: {e}"))?;
                stdin
                    .write_all(b"\n")
                    .map_err(|e| format!("phantom-signer stdin write failed: {e}"))?;
            }
            let out = child
                .wait_with_output()
                .map_err(|e| format!("phantom-signer wait failed: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !out.status.success() {
                let msg = stderr.trim();
                return Err(if msg.is_empty() {
                    "phantom-signer wallet-restore fehlgeschlagen".to_string()
                } else {
                    format!("phantom-signer wallet-restore fehlgeschlagen: {msg}")
                });
            }
            let addr = stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .last()
                .unwrap_or("")
                .to_string();
            if addr.is_empty() {
                return Err("phantom-signer wallet-restore: keine Adresse in stdout".to_string());
            }
            Ok(addr)
        },
    )?;

    let lock_hex = hex::encode(lock_from_bech32m_v1_addr(&first_addr)?);
    let profile = WalletProfileDisk {
        version: 1,
        wallet_name: wallet_name.clone(),
        wallet_kind: WalletKind::Hot,
        hrp: hrp.clone(),
        address: Some(first_addr.clone()),
        lock_hex: Some(lock_hex.clone()),
        xpubstore_path: None,
        derivation: None,
        fingerprint: None,
    };
    save_wallet_profile(&profile)?;

    {
        let mut inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        *inner = Some(WalletUnlocked {
            wallet_name: wallet_name.clone(),
            wallet_kind: WalletKind::Hot,
            passphrase: Zeroizing::new(passphrase),
            selected_addr: first_addr.clone(),
            selected_lock_hex: lock_hex.clone(),
        });
    }

    let _ = app; // reserved for future: wallet create may depend on app paths

    Ok(build_wallet_status(
        &wallet_name,
        WalletKind::Hot,
        Some(hrp),
        Some(first_addr),
        Some(lock_hex),
    ))
}

#[command]
async fn wallet_create_watch_only(
    state: tauri::State<'_, WalletService>,
    args: WalletCreateWatchOnlyArgs,
) -> Result<WalletStatus, String> {
    let wallet_name = normalize_name(&args.wallet_name)?;
    let hrp = normalize_name(&args.hrp)?;
    if args.xpub.trim().is_empty() {
        return Err("Xpub darf nicht leer sein".to_string());
    }
    if args.derivation.trim().is_empty() {
        return Err("Derivation darf nicht leer sein".to_string());
    }

    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let seed_store_path = default_seedstore_path(&wallet_name)?;
    let xpub_store_path = default_xpubstore_path(&wallet_name)?;
    let watch_only_secret_path = default_watch_only_secret_path(&wallet_name)?;
    let wallet_profile = default_wallet_profile_path(&wallet_name)?;
    if wallet_db_dir.exists()
        || seed_store_path.exists()
        || xpub_store_path.exists()
        || watch_only_secret_path.exists()
    {
        return Err("Wallet existiert bereits".to_string());
    }
    if wallet_profile.exists() {
        return Err("Wallet-Metadaten existieren bereits".to_string());
    }
    if let Some(parent) = xpub_store_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Xpub-Store-Ordner nicht erstellbar: {e}"))?;
    }
    let watch_only_secret = generate_watch_only_secret();
    write_secret_file_atomic(&watch_only_secret_path, &watch_only_secret)?;

    let signer_path = find_phantom_signer_binary()?;
    let first_addr = with_temp_secret_file(
        "phantom_watch_only_secret",
        &watch_only_secret,
        |pass_path| {
            let mut import_cmd = Command::new(&signer_path);
            import_cmd
                .arg("import-xpub")
                .arg("--algo")
                .arg("schnorr")
                .arg("--xpub")
                .arg(args.xpub.trim())
                .arg("--derivation")
                .arg(args.derivation.trim())
                .arg("--out")
                .arg(xpub_store_path.to_string_lossy().to_string())
                .arg("--hrp")
                .arg(hrp.trim())
                .arg("--passphrase-file")
                .arg(pass_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if let Some(fingerprint) = args
                .fingerprint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                import_cmd.arg("--fingerprint").arg(fingerprint);
            }
            let import_out = import_cmd
                .output()
                .map_err(|e| format!("phantom-signer import-xpub fehlgeschlagen: {e}"))?;
            if !import_out.status.success() {
                let stderr = String::from_utf8_lossy(&import_out.stderr)
                    .trim()
                    .to_string();
                return Err(if stderr.is_empty() {
                    "phantom-signer import-xpub fehlgeschlagen".to_string()
                } else {
                    format!("phantom-signer import-xpub fehlgeschlagen: {stderr}")
                });
            }

            let mut addr_cmd = Command::new(&signer_path);
            addr_cmd
                .arg("addr-from-xpub")
                .arg("--xpubstore")
                .arg(xpub_store_path.to_string_lossy().to_string())
                .arg("--wallet-db")
                .arg(wallet_db_dir.to_string_lossy().to_string())
                .arg("--change")
                .arg("0")
                .arg("--index")
                .arg("0")
                .arg("--label")
                .arg("bitbox-receive-0")
                .arg("--passphrase-file")
                .arg(pass_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let addr_out = addr_cmd
                .output()
                .map_err(|e| format!("phantom-signer addr-from-xpub fehlgeschlagen: {e}"))?;
            if !addr_out.status.success() {
                let stderr = String::from_utf8_lossy(&addr_out.stderr).trim().to_string();
                return Err(if stderr.is_empty() {
                    "phantom-signer addr-from-xpub fehlgeschlagen".to_string()
                } else {
                    format!("phantom-signer addr-from-xpub fehlgeschlagen: {stderr}")
                });
            }
            let stdout = String::from_utf8_lossy(&addr_out.stdout).to_string();
            let addr = stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .last()
                .unwrap_or("")
                .to_string();
            if addr.is_empty() {
                return Err("phantom-signer addr-from-xpub: keine Adresse in stdout".to_string());
            }
            Ok(addr)
        },
    );

    let first_addr = match first_addr {
        Ok(addr) => addr,
        Err(err) => {
            let _ = fs::remove_file(&xpub_store_path);
            let _ = fs::remove_dir_all(&wallet_db_dir);
            let _ = fs::remove_file(&watch_only_secret_path);
            return Err(err);
        }
    };

    let lock_hex = hex::encode(lock_from_bech32m_v1_addr(&first_addr)?);
    let profile = WalletProfileDisk {
        version: 1,
        wallet_name: wallet_name.clone(),
        wallet_kind: WalletKind::BitboxWatchOnly,
        hrp: hrp.clone(),
        address: Some(first_addr.clone()),
        lock_hex: Some(lock_hex.clone()),
        xpubstore_path: Some(xpub_store_path.to_string_lossy().to_string()),
        derivation: Some(args.derivation.trim().to_string()),
        fingerprint: args
            .fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
    };
    if let Err(err) = save_wallet_profile(&profile) {
        let _ = fs::remove_file(&xpub_store_path);
        let _ = fs::remove_dir_all(&wallet_db_dir);
        let _ = fs::remove_file(&watch_only_secret_path);
        return Err(err);
    }

    {
        let mut inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        *inner = Some(WalletUnlocked {
            wallet_name: wallet_name.clone(),
            wallet_kind: WalletKind::BitboxWatchOnly,
            passphrase: Zeroizing::new(watch_only_secret),
            selected_addr: first_addr.clone(),
            selected_lock_hex: lock_hex.clone(),
        });
    }

    Ok(build_wallet_status(
        &wallet_name,
        WalletKind::BitboxWatchOnly,
        Some(hrp),
        Some(first_addr),
        Some(lock_hex),
    ))
}

#[command]
async fn wallet_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, WalletService>,
    wallet_name: String,
) -> Result<WalletStatus, String> {
    let wallet_name = normalize_name(&wallet_name)?;
    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    if !wallet_db_dir.exists() {
        return Ok(WalletStatus {
            exists: false,
            wallet_name: None,
            wallet_kind: None,
            watch_only: false,
            hrp: None,
            address: None,
            lock_hex: None,
        });
    }

    let profile = load_wallet_profile(&wallet_name)?;
    let wallet_kind = {
        let inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(w) = inner.as_ref().filter(|w| w.wallet_name == wallet_name) {
            w.wallet_kind
        } else {
            profile
                .as_ref()
                .map(|p| p.wallet_kind)
                .unwrap_or(detect_wallet_kind(&wallet_name)?)
        }
    };
    let unlocked = {
        let inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(w) = inner.as_ref().filter(|w| w.wallet_name == wallet_name) {
            Some((w.selected_addr.clone(), w.selected_lock_hex.clone()))
        } else {
            None
        }
    };
    let (addr, hrp, lock_hex) = if let Some((addr, lock_hex)) = unlocked {
        let hrp = bech32::decode(&addr).ok().map(|(h, _, _)| h);
        (Some(addr), hrp, Some(lock_hex))
    } else if wallet_kind == WalletKind::BitboxWatchOnly {
        let preferred_addr = profile.as_ref().and_then(|p| p.address.as_deref());
        match load_watch_only_secret(&wallet_name)
            .and_then(|secret| verified_wallet_selection(&wallet_db_dir, &secret, preferred_addr))
        {
            Ok(Some((addr, hrp, lock_hex))) => (Some(addr), Some(hrp), Some(lock_hex)),
            Ok(None) => (None, profile.as_ref().map(|p| p.hrp.clone()), None),
            Err(_) => (None, profile.as_ref().map(|p| p.hrp.clone()), None),
        }
    } else {
        (None, profile.as_ref().map(|p| p.hrp.clone()), None)
    };

    let _ = app; // reserved for future: wallet status may depend on app paths
    Ok(build_wallet_status(
        &wallet_name,
        wallet_kind,
        hrp,
        addr,
        lock_hex,
    ))
}

#[command]
fn wallet_unlock(
    state: tauri::State<'_, WalletService>,
    wallet_name: String,
    passphrase: String,
) -> Result<WalletUnlockResp, String> {
    let wallet_name = normalize_name(&wallet_name)?;
    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    if !wallet_db_dir.exists() {
        return Err(format!(
            "Wallet-DB nicht gefunden: {}",
            wallet_db_dir.display()
        ));
    }
    let wallet_kind = detect_wallet_kind(&wallet_name)?;
    let effective_passphrase = match wallet_kind {
        WalletKind::Hot => {
            if passphrase.trim().len() < 8 {
                return Err("Passphrase muss mindestens 8 Zeichen haben".to_string());
            }
            passphrase.trim().to_string()
        }
        WalletKind::BitboxWatchOnly => load_watch_only_secret(&wallet_name)?,
    };

    let wdb = walletdb::WalletDb::open_locked(&wallet_db_dir, effective_passphrase.as_str())
        .map_err(|e| format!("Wallet öffnen fehlgeschlagen: {e}"))?;
    let mut addrs: Vec<walletdb::WalletAddrMeta> = wdb
        .all_addresses()
        .map_err(|e| format!("Wallet-Adressen nicht lesbar: {e}"))?;
    addrs.sort_by(|a, b| (a.change, a.index).cmp(&(b.change, b.index)));

    let mut out: Vec<WalletAddrView> = Vec::new();
    for meta in addrs.into_iter() {
        let lock_hex = hex::encode(lock_from_bech32m_v1_addr(&meta.addr)?);
        out.push(WalletAddrView {
            addr: meta.addr,
            hrp: meta.hrp,
            change: meta.change,
            index: meta.index,
            xpub_derivation: meta.xpub_derivation,
            fingerprint: meta.fingerprint,
            label: meta.label,
            lock_hex,
        });
    }

    let (selected_addr, selected_lock_hex) = match out.first() {
        Some(a) => (Some(a.addr.clone()), Some(a.lock_hex.clone())),
        None => (None, None),
    };

    {
        let mut inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let (Some(ref addr), Some(ref lock_hex)) = (&selected_addr, &selected_lock_hex) {
            *inner = Some(WalletUnlocked {
                wallet_name: wallet_name.clone(),
                wallet_kind,
                passphrase: Zeroizing::new(effective_passphrase),
                selected_addr: addr.clone(),
                selected_lock_hex: lock_hex.clone(),
            });
        } else {
            *inner = None;
        }
    }

    if let (Some(addr), Some(lock_hex)) = (selected_addr.as_ref(), selected_lock_hex.as_ref()) {
        let mut profile = load_wallet_profile(&wallet_name)?.unwrap_or(WalletProfileDisk {
            version: 1,
            wallet_name: wallet_name.clone(),
            wallet_kind,
            hrp: out
                .first()
                .map(|a| a.hrp.clone())
                .unwrap_or_else(|| "pc".to_string()),
            address: None,
            lock_hex: None,
            xpubstore_path: None,
            derivation: None,
            fingerprint: None,
        });
        profile.wallet_kind = wallet_kind;
        profile.address = Some(addr.clone());
        profile.lock_hex = Some(lock_hex.clone());
        if let Some(first) = out.first() {
            profile.hrp = first.hrp.clone();
        }
        save_wallet_profile(&profile)?;
    }

    Ok(WalletUnlockResp {
        ok: true,
        wallet_name,
        wallet_kind,
        watch_only: wallet_kind != WalletKind::Hot,
        addrs: out,
        selected_addr,
        selected_lock_hex,
    })
}

#[command]
fn wallet_lock(state: tauri::State<'_, WalletService>) -> Result<(), String> {
    let mut inner = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    *inner = None;
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct WalletSelectAddrArgs {
    wallet_name: String,
    addr: String,
}

#[command]
fn wallet_select_addr(
    state: tauri::State<'_, WalletService>,
    args: WalletSelectAddrArgs,
) -> Result<WalletStatus, String> {
    let wallet_name = normalize_name(&args.wallet_name)?;
    let addr = args.addr.trim().to_string();
    if addr.is_empty() {
        return Err("Adresse ist leer".to_string());
    }
    let lock_hex = hex::encode(lock_from_bech32m_v1_addr(&addr)?);
    let hrp = bech32::decode(&addr).ok().map(|(h, _, _)| h);

    let (wallet_kind, passphrase) = {
        let inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let Some(w) = inner.as_ref() else {
            return Err("Wallet ist nicht entsperrt".to_string());
        };
        if w.wallet_name != wallet_name {
            return Err("Falsches Wallet aktiv".to_string());
        }
        (w.wallet_kind, w.passphrase.clone())
    };

    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let wdb = walletdb::WalletDb::open_locked(&wallet_db_dir, passphrase.trim())
        .map_err(|e| format!("Wallet öffnen fehlgeschlagen: {e}"))?;
    if wdb
        .get_address(&addr)
        .map_err(|e| format!("Wallet-Adresse nicht prüfbar: {e}"))?
        .is_none()
    {
        return Err("Adresse gehört nicht zur Wallet-DB".to_string());
    }

    let mut inner = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let Some(w) = inner.as_mut() else {
        return Err("Wallet ist nicht entsperrt".to_string());
    };
    if w.wallet_name != wallet_name {
        return Err("Falsches Wallet aktiv".to_string());
    }
    w.selected_addr = addr.clone();
    w.selected_lock_hex = lock_hex.clone();
    drop(inner);

    let mut profile = load_wallet_profile(&wallet_name)?.unwrap_or(WalletProfileDisk {
        version: 1,
        wallet_name: wallet_name.clone(),
        wallet_kind,
        hrp: hrp.clone().unwrap_or_else(|| "pc".to_string()),
        address: None,
        lock_hex: None,
        xpubstore_path: None,
        derivation: None,
        fingerprint: None,
    });
    profile.wallet_kind = wallet_kind;
    if let Some(ref hrp_val) = hrp {
        profile.hrp = hrp_val.clone();
    }
    profile.address = Some(addr.clone());
    profile.lock_hex = Some(lock_hex.clone());
    save_wallet_profile(&profile)?;

    Ok(build_wallet_status(
        &wallet_name,
        wallet_kind,
        hrp,
        Some(addr),
        Some(lock_hex),
    ))
}

#[derive(Debug, Clone, Deserialize)]
struct WalletSendArgs {
    from_addr: String,
    to_addr: String,
    amount: u64,
    #[serde(default)]
    fee: u64,
    #[serde(default)]
    change_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SignerCmdResp {
    ok: bool,
    stdout: String,
    stderr: String,
}

#[command]
fn wallet_send(
    app: tauri::AppHandle,
    node_state: tauri::State<'_, NodeService>,
    wallet_state: tauri::State<'_, WalletService>,
    args: WalletSendArgs,
) -> Result<SignerCmdResp, String> {
    let (wallet_name, wallet_kind, passphrase) = {
        let inner = match wallet_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let w = inner
            .as_ref()
            .ok_or_else(|| "Wallet ist nicht entsperrt".to_string())?;
        (w.wallet_name.clone(), w.wallet_kind, w.passphrase.clone())
    };
    if wallet_kind != WalletKind::Hot {
        return Err(
            "Watch-only-/BitBox-Wallet kann derzeit nicht direkt signieren. Senden ist nur mit verschlüsselter Hotwallet verfügbar.".to_string()
        );
    }

    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let seed_store_path = default_seedstore_path(&wallet_name)?;
    if !wallet_db_dir.exists() {
        return Err(format!("Wallet-DB fehlt: {}", wallet_db_dir.display()));
    }
    if !seed_store_path.exists() {
        return Err(format!("Seed-Store fehlt: {}", seed_store_path.display()));
    }

    let (status_http_addr, store_dir_abs) = {
        let inner = match node_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let h = inner
            .as_ref()
            .ok_or_else(|| "Node läuft nicht (Dashboard-managed)".to_string())?;
        let addr = h
            .cfg
            .status_http_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "StatusHTTP ist nicht aktiv".to_string())?;
        (addr.to_string(), h.store_dir_abs.clone())
    };

    let tls_ca_path = store_dir_abs.join("server.crt");
    if !tls_ca_path.exists() {
        return Err(format!(
            "TLS-CA fehlt (StatusHTTP): {}",
            tls_ca_path.display()
        ));
    }

    let auth_token_file = app_data_dir(&app)?.join("status_auth_token.txt");
    if !auth_token_file.exists() {
        return Err("Auth-Token-Datei fehlt (Node nicht via Dashboard gestartet?)".to_string());
    }

    let signer_path = find_phantom_signer_binary()?;
    let node_url = format!("https://{}", status_http_addr);

    let from_addr = args.from_addr.trim().to_string();
    let to_addr = args.to_addr.trim().to_string();
    if from_addr.is_empty() || to_addr.is_empty() {
        return Err("from_addr/to_addr sind leer".to_string());
    }

    let change_addr = args
        .change_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&from_addr)
        .to_string();

    with_temp_secret_file(
        "phantom_wallet_passphrase",
        passphrase.trim(),
        |pass_path| {
            let mut cmd = Command::new(&signer_path);
            cmd.arg("wallet-send")
                .arg("--from-addr")
                .arg(&from_addr)
                .arg("--to-addr")
                .arg(&to_addr)
                .arg("--amount")
                .arg(args.amount.to_string())
                .arg("--fee")
                .arg(args.fee.to_string())
                .arg("--change-addr")
                .arg(&change_addr)
                .arg("--wallet-db")
                .arg(wallet_db_dir.to_string_lossy().to_string())
                .arg("--seed-store")
                .arg(seed_store_path.to_string_lossy().to_string())
                .arg("--node")
                .arg(&node_url)
                .arg("--auth-token-file")
                .arg(auth_token_file.to_string_lossy().to_string())
                .arg("--tls-ca")
                .arg(tls_ca_path.to_string_lossy().to_string())
                .arg("--passphrase-file")
                .arg(pass_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            let out = cmd
                .output()
                .map_err(|e| format!("phantom-signer Aufruf fehlgeschlagen: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !out.status.success() {
                return Ok(SignerCmdResp {
                    ok: false,
                    stdout,
                    stderr,
                });
            }
            Ok(SignerCmdResp {
                ok: true,
                stdout,
                stderr,
            })
        },
    )
}

#[derive(Debug, Clone, Deserialize)]
struct WalletBackupArgs {
    wallet_name: String,
    dst_dir: String,
}

#[derive(Debug, Clone, Serialize)]
struct WalletBackupResp {
    ok: bool,
    backup_dir: String,
}

#[derive(Debug, Clone, Serialize)]
struct WalletBackupMetaV1 {
    version: u32,
    wallet_name: String,
    wallet_kind: WalletKind,
    has_seed_store: bool,
    has_xpub_store: bool,
    has_watch_only_secret: bool,
    created_at: u64,
}

#[command]
fn wallet_backup_to_dir(
    state: tauri::State<'_, WalletService>,
    args: WalletBackupArgs,
) -> Result<WalletBackupResp, String> {
    let _locked_guard = {
        let inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        // Backups should not depend on unlocked state; allow either.
        inner
    };

    let wallet_name = normalize_name(&args.wallet_name)?;
    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let seed_store_path = default_seedstore_path(&wallet_name)?;
    let watch_only_secret_path = default_watch_only_secret_path(&wallet_name)?;
    let wallet_kind = detect_wallet_kind(&wallet_name)?;
    let wallet_profile_path = default_wallet_profile_path(&wallet_name)?;
    let wallet_profile = load_wallet_profile(&wallet_name)?;
    if !wallet_db_dir.exists() {
        return Err(format!("Wallet-DB fehlt: {}", wallet_db_dir.display()));
    }
    let xpub_store_path = wallet_profile
        .as_ref()
        .and_then(|p| p.xpubstore_path.as_ref())
        .map(PathBuf::from)
        .unwrap_or(default_xpubstore_path(&wallet_name)?);
    let has_seed_store = seed_store_path.exists();
    let has_xpub_store = xpub_store_path.exists();
    let has_watch_only_secret = watch_only_secret_path.exists();
    match wallet_kind {
        WalletKind::Hot if !has_seed_store => {
            return Err(format!("Seed-Store fehlt: {}", seed_store_path.display()));
        }
        WalletKind::BitboxWatchOnly if !has_xpub_store => {
            return Err(format!("Xpub-Store fehlt: {}", xpub_store_path.display()));
        }
        WalletKind::BitboxWatchOnly if !has_watch_only_secret => {
            return Err(format!(
                "Watch-only-Secret fehlt: {}",
                watch_only_secret_path.display()
            ));
        }
        _ => {}
    }

    let dst_dir_s = args.dst_dir.trim();
    if dst_dir_s.is_empty() {
        return Err("Backup-Ziel ist leer".to_string());
    }
    if dst_dir_s.len() > 4096 || dst_dir_s.contains('\0') {
        return Err("Backup-Ziel ist ungültig".to_string());
    }
    let dst_dir = PathBuf::from(dst_dir_s);
    if !dst_dir.is_absolute() {
        return Err("Backup-Ziel muss ein absoluter Pfad sein".to_string());
    }
    let meta = fs::metadata(&dst_dir).map_err(|e| format!("Backup-Ziel ist nicht lesbar: {e}"))?;
    if !meta.is_dir() {
        return Err("Backup-Ziel ist kein Ordner".to_string());
    }

    let mut nonce = [0u8; 4];
    AeadOsRng.fill_bytes(&mut nonce);
    let backup_dir = dst_dir.join(format!(
        "phantom-wallet-backup-{wallet_name}-{}-{}",
        now_secs_u64(),
        hex::encode(nonce)
    ));

    let dst_wallet = backup_dir.join("wallets").join(&wallet_name);
    let dst_seed = backup_dir.join("seeds").join(format!("{wallet_name}.toml"));
    let dst_xpub = backup_dir.join("xpubs").join(format!("{wallet_name}.toml"));
    let dst_watch_secret = backup_dir
        .join("watch-only-secrets")
        .join(format!("{wallet_name}.secret"));
    let dst_profile = backup_dir
        .join("wallet-meta")
        .join(format!("{wallet_name}.json"));
    fs::create_dir_all(dst_wallet.parent().unwrap_or(&backup_dir))
        .map_err(|e| format!("Backup-Ordner nicht erstellbar: {e}"))?;
    if has_seed_store {
        fs::create_dir_all(dst_seed.parent().unwrap_or(&backup_dir))
            .map_err(|e| format!("Backup-Ordner nicht erstellbar: {e}"))?;
    }
    if has_xpub_store {
        fs::create_dir_all(dst_xpub.parent().unwrap_or(&backup_dir))
            .map_err(|e| format!("Backup-Ordner nicht erstellbar: {e}"))?;
    }
    if has_watch_only_secret {
        fs::create_dir_all(dst_watch_secret.parent().unwrap_or(&backup_dir))
            .map_err(|e| format!("Backup-Ordner nicht erstellbar: {e}"))?;
    }
    if wallet_profile_path.exists() {
        fs::create_dir_all(dst_profile.parent().unwrap_or(&backup_dir))
            .map_err(|e| format!("Backup-Ordner nicht erstellbar: {e}"))?;
    }

    copy_dir_recursive(&wallet_db_dir, &dst_wallet)?;
    if has_seed_store {
        fs::copy(&seed_store_path, &dst_seed).map_err(|e| {
            format!(
                "Seed-Store konnte nicht kopiert werden: {} -> {}: {e}",
                seed_store_path.display(),
                dst_seed.display()
            )
        })?;
    }
    if has_xpub_store {
        fs::copy(&xpub_store_path, &dst_xpub).map_err(|e| {
            format!(
                "Xpub-Store konnte nicht kopiert werden: {} -> {}: {e}",
                xpub_store_path.display(),
                dst_xpub.display()
            )
        })?;
    }
    if has_watch_only_secret {
        fs::copy(&watch_only_secret_path, &dst_watch_secret).map_err(|e| {
            format!(
                "Watch-only-Secret konnte nicht kopiert werden: {} -> {}: {e}",
                watch_only_secret_path.display(),
                dst_watch_secret.display()
            )
        })?;
    }
    if wallet_profile_path.exists() {
        fs::copy(&wallet_profile_path, &dst_profile).map_err(|e| {
            format!(
                "Wallet-Metadaten konnten nicht kopiert werden: {} -> {}: {e}",
                wallet_profile_path.display(),
                dst_profile.display()
            )
        })?;
    }

    let meta = WalletBackupMetaV1 {
        version: 1,
        wallet_name: wallet_name.clone(),
        wallet_kind,
        has_seed_store,
        has_xpub_store,
        has_watch_only_secret,
        created_at: now_secs_u64(),
    };
    write_json_file_atomic(&backup_dir.join("backup.json"), &meta)?;
    harden_private_tree(&backup_dir)?;

    Ok(WalletBackupResp {
        ok: true,
        backup_dir: backup_dir.to_string_lossy().to_string(),
    })
}

#[derive(Debug, Clone, Deserialize)]
struct WalletRestoreArgs {
    wallet_name: String,
    src_dir: String,
    #[serde(default)]
    force: bool,
}

#[command]
fn wallet_restore_from_dir(
    state: tauri::State<'_, WalletService>,
    args: WalletRestoreArgs,
) -> Result<WalletStatus, String> {
    {
        let inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if inner.is_some() {
            return Err("Wallet ist entsperrt. Bitte zuerst sperren.".to_string());
        }
    }

    let wallet_name = normalize_name(&args.wallet_name)?;

    let src_dir_s = args.src_dir.trim();
    if src_dir_s.is_empty() {
        return Err("Restore-Quelle ist leer".to_string());
    }
    if src_dir_s.len() > 4096 || src_dir_s.contains('\0') {
        return Err("Restore-Quelle ist ungültig".to_string());
    }
    let src_dir = PathBuf::from(src_dir_s);
    if !src_dir.is_absolute() {
        return Err("Restore-Quelle muss ein absoluter Pfad sein".to_string());
    }

    let src_wallet = src_dir.join("wallets").join(&wallet_name);
    let src_seed = src_dir.join("seeds").join(format!("{wallet_name}.toml"));
    let src_xpub = src_dir.join("xpubs").join(format!("{wallet_name}.toml"));
    let src_watch_secret = src_dir
        .join("watch-only-secrets")
        .join(format!("{wallet_name}.secret"));
    let src_profile = src_dir
        .join("wallet-meta")
        .join(format!("{wallet_name}.json"));
    let src_wallet_meta = fs::metadata(&src_wallet)
        .map_err(|e| format!("Backup-Wallet-DB fehlt: {}: {e}", src_wallet.display()))?;
    if !src_wallet_meta.is_dir() {
        return Err("Backup-Wallet-DB ist kein Ordner".to_string());
    }
    let has_seed_backup = src_seed.is_file();
    let has_xpub_backup = src_xpub.is_file();
    let has_watch_only_secret_backup = src_watch_secret.is_file();
    if !has_seed_backup && !has_xpub_backup {
        return Err("Backup enthält weder Seed-Store noch Xpub-Store".to_string());
    }
    if !has_seed_backup && !has_watch_only_secret_backup {
        return Err("Watch-only-Backup enthält kein lokales Secret".to_string());
    }

    let dst_wallet = default_walletdb_path(&wallet_name)?;
    let dst_seed = default_seedstore_path(&wallet_name)?;
    let dst_xpub = default_xpubstore_path(&wallet_name)?;
    let dst_watch_secret = default_watch_only_secret_path(&wallet_name)?;
    let dst_profile = default_wallet_profile_path(&wallet_name)?;

    if (dst_wallet.exists()
        || dst_seed.exists()
        || dst_xpub.exists()
        || dst_watch_secret.exists()
        || dst_profile.exists())
        && !args.force
    {
        return Err("Wallet existiert bereits (force aktivieren, um zu überschreiben)".to_string());
    }

    // Restore wallet DB directory via temp dir + rename (best-effort atomic).
    let dst_wallet_parent = dst_wallet
        .parent()
        .ok_or_else(|| "Wallet-DB Zielpfad ist ungültig".to_string())?;
    fs::create_dir_all(dst_wallet_parent).map_err(|e| {
        format!(
            "Wallet-DB Zielordner nicht erstellbar: {}: {e}",
            dst_wallet_parent.display()
        )
    })?;

    let mut nonce = [0u8; 8];
    AeadOsRng.fill_bytes(&mut nonce);
    let tmp_wallet =
        dst_wallet_parent.join(format!(".{wallet_name}.restore.{}", hex::encode(nonce)));
    if tmp_wallet.exists() {
        let _ = fs::remove_dir_all(&tmp_wallet);
    }
    copy_dir_recursive(&src_wallet, &tmp_wallet)?;

    if dst_wallet.exists() {
        let _ = fs::remove_dir_all(&dst_wallet);
    }
    fs::rename(&tmp_wallet, &dst_wallet).map_err(|e| {
        let _ = fs::remove_dir_all(&tmp_wallet);
        format!(
            "Wallet-DB konnte nicht finalisiert werden: {} -> {}: {e}",
            tmp_wallet.display(),
            dst_wallet.display()
        )
    })?;
    harden_private_tree(&dst_wallet)?;

    if has_seed_backup {
        copy_file_atomic(&src_seed, &dst_seed)?;
        harden_private_file(&dst_seed)?;
    } else if dst_seed.exists() {
        let _ = fs::remove_file(&dst_seed);
    }

    if has_xpub_backup {
        copy_file_atomic(&src_xpub, &dst_xpub)?;
        harden_private_file(&dst_xpub)?;
    } else if dst_xpub.exists() {
        let _ = fs::remove_file(&dst_xpub);
    }

    if has_watch_only_secret_backup {
        copy_file_atomic(&src_watch_secret, &dst_watch_secret)?;
        harden_private_file(&dst_watch_secret)?;
    } else if dst_watch_secret.exists() {
        let _ = fs::remove_file(&dst_watch_secret);
    }

    let mut profile = if src_profile.is_file() {
        let mut profile: WalletProfileDisk = read_json_file(&src_profile)?;
        profile.wallet_name = wallet_name.clone();
        profile
    } else {
        WalletProfileDisk {
            version: 1,
            wallet_name: wallet_name.clone(),
            wallet_kind: if has_seed_backup {
                WalletKind::Hot
            } else {
                WalletKind::BitboxWatchOnly
            },
            hrp: "pc".to_string(),
            address: None,
            lock_hex: None,
            xpubstore_path: None,
            derivation: None,
            fingerprint: None,
        }
    };
    profile.wallet_kind = if has_seed_backup {
        WalletKind::Hot
    } else {
        WalletKind::BitboxWatchOnly
    };
    profile.address = None;
    profile.lock_hex = None;
    if has_xpub_backup {
        profile.xpubstore_path = Some(dst_xpub.to_string_lossy().to_string());
    }
    save_wallet_profile(&profile)?;

    let _ = state;
    let WalletProfileDisk {
        wallet_kind,
        hrp,
        address,
        lock_hex,
        ..
    } = profile;
    Ok(build_wallet_status(
        &wallet_name,
        wallet_kind,
        Some(hrp),
        address,
        lock_hex,
    ))
}

#[derive(Debug, Clone, Deserialize)]
struct CsvHistoryEvent {
    anchor_index: u64,
    event_type: String,
    direction: String,
    amount: u64,
    lock: String,
    outpoint: String,
    staked: bool,
    #[serde(default)]
    timestamp_local: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletHistoryCsvArgs {
    wallet_name: String,
    events: Vec<CsvHistoryEvent>,
}

#[derive(Debug, Clone, Serialize)]
struct WalletHistoryCsvResp {
    written: usize,
}

const CSV_HEADER: &str = "Datum;Typ;Richtung;Betrag;Lock;Outpoint;Staked;Anchor;Timestamp\n";

#[command]
fn wallet_history_csv_append(
    app: tauri::AppHandle,
    args: WalletHistoryCsvArgs,
) -> Result<WalletHistoryCsvResp, String> {
    use std::collections::HashMap;
    use std::io::Write as _;

    let wallet_name = args.wallet_name.trim().to_string();
    if wallet_name.is_empty() || wallet_name.len() > 128 {
        return Err("Wallet-Name ungültig".to_string());
    }

    if args.events.is_empty() {
        return Ok(WalletHistoryCsvResp { written: 0 });
    }

    let base = app_data_dir(&app)?
        .join("wallet_history")
        .join(&wallet_name);
    fs::create_dir_all(&base).map_err(|e| format!("CSV-Ordner nicht erstellbar: {e}"))?;

    let mut by_day: HashMap<String, Vec<String>> = HashMap::new();
    let mut by_year: HashMap<String, Vec<String>> = HashMap::new();

    let now_fallback = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for ev in &args.events {
        let ts = if ev.timestamp_local > 0 {
            ev.timestamp_local
        } else {
            now_fallback
        };
        let dt = safe_naive_timestamp(ts as i64);
        let year = dt.format("%Y").to_string();
        let month_dir = dt.format("%Y-%m").to_string();
        let day_file = dt.format("%Y-%m-%d").to_string();
        let date_str = dt.format("%Y-%m-%d %H:%M:%S").to_string();

        let typ = match ev.event_type.as_str() {
            "mint" => "Mining-Reward",
            "micro_tx" => "Transaktion",
            _ => &ev.event_type,
        };
        let dir = match ev.direction.as_str() {
            "in" => "Eingang",
            "out" => "Ausgang",
            _ => &ev.direction,
        };
        let amount_pc = ev.amount as f64 / 1_000_000.0;
        let line = format!(
            "{};{};{};{:.6};{};{};{};{};{}\n",
            date_str,
            typ,
            dir,
            amount_pc,
            ev.lock,
            ev.outpoint,
            if ev.staked { "Ja" } else { "Nein" },
            ev.anchor_index,
            ev.timestamp_local,
        );

        by_day
            .entry(format!("{}/{}/{}", year, month_dir, day_file))
            .or_default()
            .push(line.clone());
        by_year.entry(year).or_default().push(line);
    }

    let mut total = 0usize;

    // Write day CSVs
    for (key, lines) in &by_day {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() != 3 {
            continue;
        }
        let dir_path = base.join(parts[0]).join(parts[1]);
        fs::create_dir_all(&dir_path)
            .map_err(|e| format!("CSV-Ordner {}: {e}", dir_path.display()))?;
        let csv_path = dir_path.join(format!("{}.csv", parts[2]));
        let is_new = !csv_path.exists();
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&csv_path)
            .map_err(|e| format!("CSV {}: {e}", csv_path.display()))?;
        if is_new {
            f.write_all(CSV_HEADER.as_bytes())
                .map_err(|e| format!("CSV header: {e}"))?;
        }
        for line in lines {
            f.write_all(line.as_bytes())
                .map_err(|e| format!("CSV write: {e}"))?;
        }
        total += lines.len();
    }

    // Write yearly aggregates
    for (year, lines) in &by_year {
        let dir_path = base.join(year);
        fs::create_dir_all(&dir_path)
            .map_err(|e| format!("CSV-Ordner {}: {e}", dir_path.display()))?;
        let csv_path = dir_path.join(format!("{}.csv", year));
        let is_new = !csv_path.exists();
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&csv_path)
            .map_err(|e| format!("CSV {}: {e}", csv_path.display()))?;
        if is_new {
            f.write_all(CSV_HEADER.as_bytes())
                .map_err(|e| format!("CSV header: {e}"))?;
        }
        for line in lines {
            f.write_all(line.as_bytes())
                .map_err(|e| format!("CSV write: {e}"))?;
        }
    }

    Ok(WalletHistoryCsvResp { written: total })
}

#[derive(Debug, Clone, Deserialize)]
struct WalletCsvFolderArgs {
    wallet_name: String,
}

#[command]
fn wallet_history_csv_open_folder(
    app: tauri::AppHandle,
    args: WalletCsvFolderArgs,
) -> Result<String, String> {
    let wallet_name = args.wallet_name.trim().to_string();
    if wallet_name.is_empty() || wallet_name.len() > 128 {
        return Err("Wallet-Name ungültig".to_string());
    }
    let base = app_data_dir(&app)?
        .join("wallet_history")
        .join(&wallet_name);
    fs::create_dir_all(&base).map_err(|e| format!("CSV-Ordner nicht erstellbar: {e}"))?;
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&base)
            .spawn()
            .map_err(|e| format!("Finder öffnen fehlgeschlagen: {e}"))?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&base)
            .spawn()
            .map_err(|e| format!("Explorer öffnen fehlgeschlagen: {e}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&base)
            .spawn()
            .map_err(|e| format!("Dateimanager öffnen fehlgeschlagen: {e}"))?;
    }
    Ok(base.display().to_string())
}

#[derive(Debug, Clone, Deserialize)]
struct WalletCsvRangeArgs {
    wallet_name: String,
    from_ts: u64,
    to_ts: u64,
}

fn safe_naive_timestamp(ts: i64) -> chrono::NaiveDateTime {
    if let Some(dt) = chrono::DateTime::from_timestamp(ts, 0) {
        return dt.naive_utc();
    }
    if let Some(dt) = chrono::DateTime::from_timestamp(0, 0) {
        return dt.naive_utc();
    }
    chrono::NaiveDateTime::MIN
}

#[command]
fn wallet_history_csv_range(
    app: tauri::AppHandle,
    args: WalletCsvRangeArgs,
) -> Result<String, String> {
    let wallet_name = args.wallet_name.trim().to_string();
    if wallet_name.is_empty() || wallet_name.len() > 128 {
        return Err("Wallet-Name ungültig".to_string());
    }
    if args.from_ts > args.to_ts {
        return Err("Ungültiger Zeitraum: Von > Bis".to_string());
    }

    let store_dir = app_data_dir(&app)?;
    let journal = store_dir
        .join("pc-data")
        .join("mempool")
        .join("wallet_history.v1.jsonl");
    if !journal.exists() {
        return Err("Wallet-History-Journal nicht gefunden".to_string());
    }

    let raw = fs::read(&journal).map_err(|e| format!("Journal lesen: {e}"))?;

    let mut csv = String::from("Datum;Typ;Richtung;Betrag;Lock;Outpoint;Staked;Anchor;Timestamp\n");

    let now_fallback = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut rows: Vec<(u64, String)> = Vec::new();

    for line in raw.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let ev: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let version = ev.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if version != 1 {
            continue;
        }

        let ts_raw = ev
            .get("timestamp_local")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let ts = if ts_raw > 0 { ts_raw } else { now_fallback };

        if ts < args.from_ts || ts > args.to_ts {
            continue;
        }

        let anchor_index = ev.get("anchor_index").and_then(|v| v.as_u64()).unwrap_or(0);
        let event_type = ev.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
        let direction = ev.get("direction").and_then(|v| v.as_str()).unwrap_or("");
        let amount = ev.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let staked = ev.get("staked").and_then(|v| v.as_bool()).unwrap_or(false);

        let lock_arr = ev.get("lock").and_then(|v| v.as_array());
        let lock_hex = lock_arr
            .map(|a| {
                a.iter()
                    .map(|b| format!("{:02x}", b.as_u64().unwrap_or(0) as u8))
                    .collect::<String>()
            })
            .unwrap_or_default();

        let op_txid_arr = ev.get("outpoint_txid").and_then(|v| v.as_array());
        let op_txid = op_txid_arr
            .map(|a| {
                a.iter()
                    .map(|b| format!("{:02x}", b.as_u64().unwrap_or(0) as u8))
                    .collect::<String>()
            })
            .unwrap_or_default();
        let op_vout = ev
            .get("outpoint_vout")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let outpoint = format!("{op_txid}:{op_vout}");

        let dt = safe_naive_timestamp(ts as i64);
        let date_str = dt.format("%Y-%m-%d %H:%M:%S").to_string();

        let typ = match event_type {
            "mint" => "Mining-Reward",
            "micro_tx" => "Transaktion",
            _ => event_type,
        };
        let dir = match direction {
            "in" => "Eingang",
            "out" => "Ausgang",
            _ => direction,
        };
        let amount_pc = amount as f64 / 1_000_000.0;

        rows.push((
            anchor_index,
            format!(
                "{};{};{};{:.6};{};{};{};{};{}\n",
                date_str,
                typ,
                dir,
                amount_pc,
                lock_hex,
                outpoint,
                if staked { "Ja" } else { "Nein" },
                anchor_index,
                ts,
            ),
        ));
    }

    rows.sort_by_key(|r| r.0);
    for (_, row) in &rows {
        csv.push_str(row);
    }

    Ok(csv)
}

fn normalize_bitbox_transport(input: &str) -> String {
    match input.trim().to_lowercase().as_str() {
        "usb" => "usb".to_string(),
        "bridge" => "bridge".to_string(),
        _ => "auto".to_string(),
    }
}

fn normalize_bitbox_bridge_url(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    let with_scheme = if trimmed.is_empty() {
        "http://127.0.0.1:8178".to_string()
    } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    };
    validate_loopback_base_url(&with_scheme)
}

fn bitbox_bridge_opt_in_enabled() -> bool {
    matches!(
        std::env::var("PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE"),
        Ok(v) if matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    )
}

fn ensure_bitbox_bridge_opt_in() -> Result<(), String> {
    if bitbox_bridge_opt_in_enabled() {
        return Ok(());
    }
    Err(
        "BitBox bridge ist standardmäßig deaktiviert; setze PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE=1 für ein explizites Opt-in".to_string(),
    )
}

#[derive(Debug, Clone, Deserialize)]
struct BitboxSettingsArgs {
    transport: String,
    bridge_url: String,
}

#[derive(Debug, Deserialize)]
struct BridgeDeviceInfo {
    product: String,
}

#[derive(Debug, Deserialize)]
struct BridgeDevicesResponse {
    devices: Vec<BridgeDeviceInfo>,
}

#[command]
async fn bitbox_bridge_status(args: BitboxSettingsArgs) -> Result<String, String> {
    let transport = normalize_bitbox_transport(&args.transport);
    if transport == "usb" {
        return Ok("Bridge deaktiviert (Transport: USB)".to_string());
    }
    ensure_bitbox_bridge_opt_in()?;

    let base = normalize_bitbox_bridge_url(&args.bridge_url)?;
    let endpoint = format!("{}/api/v1/devices", base.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(800))
        .connect_timeout(Duration::from_millis(500))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Bridge-Client Fehler: {e}"))?;

    let resp = client
        .get(endpoint)
        .send()
        .await
        .map_err(|e| format!("Bridge nicht erreichbar: {e}"))?;
    let status = resp.status();
    let txt = resp
        .text()
        .await
        .map_err(|e| format!("Bridge Antwort nicht lesbar: {e}"))?;

    if !status.is_success() {
        return Ok(format!("Bridge Antwort: {}", status.as_u16()));
    }

    match serde_json::from_str::<BridgeDevicesResponse>(&txt) {
        Ok(data) => {
            let count = data.devices.len();
            let has_bitbox = data
                .devices
                .iter()
                .any(|d| d.product.to_lowercase().contains("bitbox02"));
            if count == 0 {
                Ok("Bridge erreichbar (0 Geräte)".to_string())
            } else if has_bitbox {
                Ok(format!(
                    "Bridge erreichbar ({} Geräte, BitBox02 erkannt)",
                    count
                ))
            } else {
                Ok(format!(
                    "Bridge erreichbar ({} Geräte, keine BitBox02)",
                    count
                ))
            }
        }
        Err(e) => Ok(format!("Bridge erreichbar, aber Antwort unlesbar: {e}")),
    }
}

#[command]
fn bitbox_hwi_enumerate(args: BitboxSettingsArgs) -> Result<SignerCmdResp, String> {
    let signer_path = find_phantom_signer_binary()?;
    let transport = normalize_bitbox_transport(&args.transport);
    if transport == "bridge" {
        ensure_bitbox_bridge_opt_in()?;
    }
    let bridge_url = normalize_bitbox_bridge_url(&args.bridge_url)?;

    let out = Command::new(&signer_path)
        .arg("hwi-enumerate")
        .env("PHANTOM_BITBOX_TRANSPORT", &transport)
        .env("PHANTOM_BITBOX_BRIDGE_URL", &bridge_url)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("phantom-signer Aufruf fehlgeschlagen: {e}"))?;

    Ok(SignerCmdResp {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

#[derive(Debug, Clone, Deserialize)]
struct BitboxGetXpubArgs {
    transport: String,
    bridge_url: String,
    #[serde(default)]
    fingerprint: Option<String>,
    derivation: String,
}

#[command]
fn bitbox_hwi_get_xpub(args: BitboxGetXpubArgs) -> Result<SignerCmdResp, String> {
    let signer_path = find_phantom_signer_binary()?;
    let transport = normalize_bitbox_transport(&args.transport);
    if transport == "bridge" {
        ensure_bitbox_bridge_opt_in()?;
    }
    let bridge_url = normalize_bitbox_bridge_url(&args.bridge_url)?;

    let derivation = args.derivation.trim().to_string();
    if derivation.is_empty() {
        return Err("derivation ist leer".to_string());
    }
    if derivation.len() > 256 || derivation.chars().any(|c| c.is_control()) {
        return Err("derivation ist ungültig".to_string());
    }

    let mut cmd = Command::new(&signer_path);
    cmd.arg("hwi-get-xpub")
        .arg("--derivation")
        .arg(&derivation)
        .env("PHANTOM_BITBOX_TRANSPORT", &transport)
        .env("PHANTOM_BITBOX_BRIDGE_URL", &bridge_url)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(fp) = args
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        cmd.arg("--fingerprint").arg(fp);
    }

    let out = cmd
        .output()
        .map_err(|e| format!("phantom-signer Aufruf fehlgeschlagen: {e}"))?;
    Ok(SignerCmdResp {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

#[derive(Debug, Clone, Copy)]
enum ValidatorKeystoreLocation {
    StoreDir,
    GlobalFallback,
    Missing,
}

fn validator_keystore_store_path(store_dir_abs: &Path) -> PathBuf {
    store_dir_abs.join("validator_bls.ks.toml")
}

fn validator_keystore_global_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|home| {
        PathBuf::from(home)
            .join(".phantom")
            .join("keystores")
            .join("validator_bls.ks.toml")
    })
}

fn resolve_validator_keystore_path(store_dir_abs: &Path) -> (PathBuf, ValidatorKeystoreLocation) {
    let store_path = validator_keystore_store_path(store_dir_abs);
    if store_path.exists() {
        return (store_path, ValidatorKeystoreLocation::StoreDir);
    }
    if let Some(global_path) = validator_keystore_global_path() {
        if global_path.exists() {
            return (global_path, ValidatorKeystoreLocation::GlobalFallback);
        }
    }
    (store_path, ValidatorKeystoreLocation::Missing)
}

fn last_nonempty_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .last()
        .unwrap_or("")
        .to_string()
}

#[derive(Debug, Clone, Deserialize)]
struct ValidatorKeygenBlsArgs {
    store_dir: String,
    passphrase: String,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    use_passphrase_role: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ValidatorBlsInfoArgs {
    store_dir: String,
    passphrase: String,
    #[serde(default)]
    use_passphrase_role: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ValidatorBlsInfoResp {
    ok: bool,
    keystore_path: String,
    keystore_location: String,
    bls_pk: String,
    bls_pop: String,
}

fn validator_bls_pub_inner(signer_path: &Path, keystore_path: &Path) -> Result<String, String> {
    // export-pub does not need the keystore passphrase.
    let out_pk = Command::new(signer_path)
        .arg("export-pub")
        .arg("--keystore")
        .arg(keystore_path.to_string_lossy().to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("phantom-signer export-pub failed: {e}"))?;
    let pk_stdout = String::from_utf8_lossy(&out_pk.stdout).to_string();
    let pk_stderr = String::from_utf8_lossy(&out_pk.stderr).to_string();
    if !out_pk.status.success() {
        let msg = pk_stderr.trim();
        return Err(if msg.is_empty() {
            "phantom-signer export-pub fehlgeschlagen".to_string()
        } else {
            format!("phantom-signer export-pub fehlgeschlagen: {msg}")
        });
    }
    let bls_pk = last_nonempty_line(&pk_stdout);
    if bls_pk.len() != 96 {
        return Err(format!(
            "BLS PubKey hat unerwartete Länge ({}).",
            bls_pk.len()
        ));
    }
    Ok(bls_pk)
}

fn validator_bls_info_inner(
    signer_path: &Path,
    keystore_path: &Path,
    passphrase: &str,
    use_passphrase_role: bool,
) -> Result<(String, String), String> {
    let bls_pk = validator_bls_pub_inner(signer_path, keystore_path)?;

    let run_bls_pop = |role_validator: bool| -> Result<String, String> {
        with_temp_secret_file(
            "phantom_validator_passphrase",
            passphrase.trim(),
            |pass_path| {
                let mut cmd = Command::new(signer_path);
                cmd.arg("bls-pop")
                    .arg("--keystore")
                    .arg(keystore_path.to_string_lossy().to_string())
                    .arg("--passphrase-file")
                    .arg(pass_path);
                if role_validator {
                    cmd.arg("--passphrase-role").arg("validator");
                }
                cmd.stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());
                let out = cmd
                    .output()
                    .map_err(|e| format!("phantom-signer bls-pop failed: {e}"))?;
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if !out.status.success() {
                    let msg = stderr.trim();
                    return Err(if msg.is_empty() {
                        "phantom-signer bls-pop fehlgeschlagen".to_string()
                    } else {
                        format!("phantom-signer bls-pop fehlgeschlagen: {msg}")
                    });
                }
                Ok(last_nonempty_line(&stdout))
            },
        )
    };

    let bls_pop = match run_bls_pop(use_passphrase_role) {
        Ok(pop) => pop,
        Err(e1) => {
            // Common operator issue: the checkbox for --passphrase-role=validator is wrong.
            // If decryption fails, try once with the opposite mode.
            let decrypt_failed = e1.to_lowercase().contains("decrypt failed");
            if decrypt_failed {
                match run_bls_pop(!use_passphrase_role) {
                    Ok(pop) => {
                        eprintln!(
                            "[NODE] bls-pop fallback erfolgreich (passphrase-role validator={})",
                            !use_passphrase_role
                        );
                        pop
                    }
                    Err(_e2) => {
                        return Err(
                            "phantom-signer bls-pop fehlgeschlagen: decrypt failed (Passphrase oder passphrase-role=validator ist falsch)"
                                .to_string(),
                        );
                    }
                }
            } else {
                return Err(e1);
            }
        }
    };
    if bls_pop.len() != 192 {
        return Err(format!(
            "BLS PoP hat unerwartete Länge ({}).",
            bls_pop.len()
        ));
    }
    Ok((bls_pk, bls_pop))
}

#[command]
fn validator_keygen_bls(
    app: tauri::AppHandle,
    args: ValidatorKeygenBlsArgs,
) -> Result<ValidatorBlsInfoResp, String> {
    let store_dir_abs = resolve_store_dir_path_for_app(&app, &args.store_dir)?;
    let (keystore_path, loc) = resolve_validator_keystore_path(&store_dir_abs);

    if keystore_path.exists() && !args.force {
        return Err(format!(
            "Keystore existiert bereits: {} (force aktivieren, um zu überschreiben)",
            keystore_path.display()
        ));
    }
    if let Some(parent) = keystore_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let passphrase = args.passphrase;
    if passphrase.trim().len() < 8 {
        return Err("Passphrase muss mindestens 8 Zeichen haben".to_string());
    }

    let signer_path = find_phantom_signer_binary()?;

    let out = with_temp_secret_file(
        "phantom_validator_passphrase",
        passphrase.trim(),
        |pass_path| {
            let mut cmd = Command::new(&signer_path);
            cmd.arg("keygen")
                .arg("--type")
                .arg("seat")
                .arg("--algo")
                .arg("bls")
                .arg("--out")
                .arg(keystore_path.to_string_lossy().to_string())
                .arg("--passphrase-file")
                .arg(pass_path);
            if args.force {
                cmd.arg("--force");
            }
            if args.use_passphrase_role {
                cmd.arg("--passphrase-role").arg("validator");
            }
            cmd.stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            cmd.output()
                .map_err(|e| format!("phantom-signer keygen failed: {e}"))
        },
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        let msg = stderr.trim();
        return Err(if msg.is_empty() {
            "phantom-signer keygen fehlgeschlagen".to_string()
        } else {
            format!("phantom-signer keygen fehlgeschlagen: {msg}")
        });
    }

    let (bls_pk, bls_pop) = validator_bls_info_inner(
        &signer_path,
        &keystore_path,
        &passphrase,
        args.use_passphrase_role,
    )?;

    Ok(ValidatorBlsInfoResp {
        ok: true,
        keystore_path: keystore_path.to_string_lossy().to_string(),
        keystore_location: match loc {
            ValidatorKeystoreLocation::StoreDir => "store_dir".to_string(),
            ValidatorKeystoreLocation::GlobalFallback => "global_fallback".to_string(),
            ValidatorKeystoreLocation::Missing => "missing".to_string(),
        },
        bls_pk,
        bls_pop,
    })
}

#[command]
fn validator_bls_info(
    app: tauri::AppHandle,
    args: ValidatorBlsInfoArgs,
) -> Result<ValidatorBlsInfoResp, String> {
    let store_dir_abs = resolve_store_dir_path_for_app(&app, &args.store_dir)?;
    let (keystore_path, loc) = resolve_validator_keystore_path(&store_dir_abs);
    if !keystore_path.exists() {
        return Err(format!(
            "Keystore nicht gefunden: {}",
            keystore_path.display()
        ));
    }
    let passphrase = args.passphrase;
    if passphrase.trim().len() < 8 {
        return Err("Passphrase muss mindestens 8 Zeichen haben".to_string());
    }
    let signer_path = find_phantom_signer_binary()?;
    let (bls_pk, bls_pop) = validator_bls_info_inner(
        &signer_path,
        &keystore_path,
        passphrase.trim(),
        args.use_passphrase_role,
    )?;
    Ok(ValidatorBlsInfoResp {
        ok: true,
        keystore_path: keystore_path.to_string_lossy().to_string(),
        keystore_location: match loc {
            ValidatorKeystoreLocation::StoreDir => "store_dir".to_string(),
            ValidatorKeystoreLocation::GlobalFallback => "global_fallback".to_string(),
            ValidatorKeystoreLocation::Missing => "missing".to_string(),
        },
        bls_pk,
        bls_pop,
    })
}

#[derive(Debug, Clone, Deserialize)]
struct ValidatorStakeArgs {
    addr: String,
    utxos: Vec<String>,
}

#[command]
fn validator_stake_bond(
    app: tauri::AppHandle,
    node_state: tauri::State<'_, NodeService>,
    wallet_state: tauri::State<'_, WalletService>,
    args: ValidatorStakeArgs,
) -> Result<SignerCmdResp, String> {
    let (wallet_name, wallet_kind, wallet_passphrase, selected_addr) = {
        let inner = match wallet_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let w = inner
            .as_ref()
            .ok_or_else(|| "Wallet ist nicht entsperrt".to_string())?;
        (
            w.wallet_name.clone(),
            w.wallet_kind,
            w.passphrase.clone(),
            w.selected_addr.clone(),
        )
    };
    if wallet_kind != WalletKind::Hot {
        return Err(
            "Stake-Bonding ist mit Watch-only-/BitBox-Wallet derzeit nicht verfügbar.".to_string(),
        );
    }

    if args.addr.trim() != selected_addr.trim() {
        return Err("Adresse stimmt nicht mit der ausgewählten Wallet-Adresse überein".to_string());
    }
    if args.utxos.is_empty() {
        return Err("Keine UTXOs ausgewählt".to_string());
    }

    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let seed_store_path = default_seedstore_path(&wallet_name)?;
    if !wallet_db_dir.exists() {
        return Err(format!("Wallet-DB fehlt: {}", wallet_db_dir.display()));
    }
    if !seed_store_path.exists() {
        return Err(format!("Seed-Store fehlt: {}", seed_store_path.display()));
    }

    let (status_http_addr, store_dir_abs) = {
        let inner = match node_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let h = inner
            .as_ref()
            .ok_or_else(|| "Node läuft nicht (Dashboard-managed)".to_string())?;
        let addr = h
            .cfg
            .status_http_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "StatusHTTP ist nicht aktiv".to_string())?;
        (addr.to_string(), h.store_dir_abs.clone())
    };

    let tls_ca_path = store_dir_abs.join("server.crt");
    if !tls_ca_path.exists() {
        return Err(format!(
            "TLS-CA fehlt (StatusHTTP): {}",
            tls_ca_path.display()
        ));
    }

    let auth_token_file = app_data_dir(&app)?.join("status_auth_token.txt");
    if !auth_token_file.exists() {
        return Err("Auth-Token-Datei fehlt (Node nicht via Dashboard gestartet?)".to_string());
    }

    let signer_path = find_phantom_signer_binary()?;
    let node_url = format!("https://{}", status_http_addr);
    let utxos_csv = args
        .utxos
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    if utxos_csv.is_empty() {
        return Err("Keine UTXOs ausgewählt".to_string());
    }

    with_temp_secret_file(
        "phantom_wallet_passphrase",
        wallet_passphrase.trim(),
        |pass_path| {
            let mut cmd = Command::new(&signer_path);
            cmd.arg("stake-bond")
                .arg("--addr")
                .arg(selected_addr.trim())
                .arg("--utxos")
                .arg(&utxos_csv)
                .arg("--wallet-db")
                .arg(wallet_db_dir.to_string_lossy().to_string())
                .arg("--seed-store")
                .arg(seed_store_path.to_string_lossy().to_string())
                .arg("--node")
                .arg(&node_url)
                .arg("--auth-token-file")
                .arg(auth_token_file.to_string_lossy().to_string())
                .arg("--tls-ca")
                .arg(tls_ca_path.to_string_lossy().to_string())
                .arg("--passphrase-file")
                .arg(pass_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            let out = cmd
                .output()
                .map_err(|e| format!("phantom-signer Aufruf fehlgeschlagen: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !out.status.success() {
                return Ok(SignerCmdResp {
                    ok: false,
                    stdout,
                    stderr,
                });
            }
            Ok(SignerCmdResp {
                ok: true,
                stdout,
                stderr,
            })
        },
    )
}

#[command]
fn validator_stake_unbond(
    app: tauri::AppHandle,
    node_state: tauri::State<'_, NodeService>,
    wallet_state: tauri::State<'_, WalletService>,
    args: ValidatorStakeArgs,
) -> Result<SignerCmdResp, String> {
    let (wallet_name, wallet_kind, wallet_passphrase, selected_addr) = {
        let inner = match wallet_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let w = inner
            .as_ref()
            .ok_or_else(|| "Wallet ist nicht entsperrt".to_string())?;
        (
            w.wallet_name.clone(),
            w.wallet_kind,
            w.passphrase.clone(),
            w.selected_addr.clone(),
        )
    };
    if wallet_kind != WalletKind::Hot {
        return Err(
            "Stake-Unbonding ist mit Watch-only-/BitBox-Wallet derzeit nicht verfügbar."
                .to_string(),
        );
    }

    if args.addr.trim() != selected_addr.trim() {
        return Err("Adresse stimmt nicht mit der ausgewählten Wallet-Adresse überein".to_string());
    }
    if args.utxos.is_empty() {
        return Err("Keine UTXOs ausgewählt".to_string());
    }

    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let seed_store_path = default_seedstore_path(&wallet_name)?;
    if !wallet_db_dir.exists() {
        return Err(format!("Wallet-DB fehlt: {}", wallet_db_dir.display()));
    }
    if !seed_store_path.exists() {
        return Err(format!("Seed-Store fehlt: {}", seed_store_path.display()));
    }

    let (status_http_addr, store_dir_abs) = {
        let inner = match node_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let h = inner
            .as_ref()
            .ok_or_else(|| "Node läuft nicht (Dashboard-managed)".to_string())?;
        let addr = h
            .cfg
            .status_http_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "StatusHTTP ist nicht aktiv".to_string())?;
        (addr.to_string(), h.store_dir_abs.clone())
    };

    let tls_ca_path = store_dir_abs.join("server.crt");
    if !tls_ca_path.exists() {
        return Err(format!(
            "TLS-CA fehlt (StatusHTTP): {}",
            tls_ca_path.display()
        ));
    }

    let auth_token_file = app_data_dir(&app)?.join("status_auth_token.txt");
    if !auth_token_file.exists() {
        return Err("Auth-Token-Datei fehlt (Node nicht via Dashboard gestartet?)".to_string());
    }

    let signer_path = find_phantom_signer_binary()?;
    let node_url = format!("https://{}", status_http_addr);
    let utxos_csv = args
        .utxos
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    if utxos_csv.is_empty() {
        return Err("Keine UTXOs ausgewählt".to_string());
    }

    with_temp_secret_file(
        "phantom_wallet_passphrase",
        wallet_passphrase.trim(),
        |pass_path| {
            let mut cmd = Command::new(&signer_path);
            cmd.arg("stake-unbond")
                .arg("--addr")
                .arg(selected_addr.trim())
                .arg("--utxos")
                .arg(&utxos_csv)
                .arg("--wallet-db")
                .arg(wallet_db_dir.to_string_lossy().to_string())
                .arg("--seed-store")
                .arg(seed_store_path.to_string_lossy().to_string())
                .arg("--node")
                .arg(&node_url)
                .arg("--auth-token-file")
                .arg(auth_token_file.to_string_lossy().to_string())
                .arg("--tls-ca")
                .arg(tls_ca_path.to_string_lossy().to_string())
                .arg("--passphrase-file")
                .arg(pass_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            let out = cmd
                .output()
                .map_err(|e| format!("phantom-signer Aufruf fehlgeschlagen: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !out.status.success() {
                return Ok(SignerCmdResp {
                    ok: false,
                    stdout,
                    stderr,
                });
            }
            Ok(SignerCmdResp {
                ok: true,
                stdout,
                stderr,
            })
        },
    )
}

#[derive(Debug, Clone, Deserialize)]
struct ValidatorRegisterArgs {
    addr: String,
    anchor_utxo: String,
    #[serde(default)]
    operator_id: Option<String>,
    validator_passphrase: String,
    #[serde(default)]
    use_passphrase_role: bool,
}

#[command]
fn validator_register(
    app: tauri::AppHandle,
    node_state: tauri::State<'_, NodeService>,
    wallet_state: tauri::State<'_, WalletService>,
    args: ValidatorRegisterArgs,
) -> Result<SignerCmdResp, String> {
    let (wallet_name, wallet_kind, wallet_passphrase, selected_addr) = {
        let inner = match wallet_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let w = inner
            .as_ref()
            .ok_or_else(|| "Wallet ist nicht entsperrt".to_string())?;
        (
            w.wallet_name.clone(),
            w.wallet_kind,
            w.passphrase.clone(),
            w.selected_addr.clone(),
        )
    };
    if wallet_kind != WalletKind::Hot {
        return Err(
            "Validator-Registrierung ist mit Watch-only-/BitBox-Wallet derzeit nicht verfügbar."
                .to_string(),
        );
    }

    if args.addr.trim() != selected_addr.trim() {
        return Err("Adresse stimmt nicht mit der ausgewählten Wallet-Adresse überein".to_string());
    }
    let anchor_utxo = args.anchor_utxo.trim().to_string();
    if anchor_utxo.is_empty() {
        return Err("anchor_utxo ist leer".to_string());
    }

    let wallet_db_dir = default_walletdb_path(&wallet_name)?;
    let seed_store_path = default_seedstore_path(&wallet_name)?;
    if !wallet_db_dir.exists() {
        return Err(format!("Wallet-DB fehlt: {}", wallet_db_dir.display()));
    }
    if !seed_store_path.exists() {
        return Err(format!("Seed-Store fehlt: {}", seed_store_path.display()));
    }

    let (status_http_addr, store_dir_abs) = {
        let inner = match node_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let h = inner
            .as_ref()
            .ok_or_else(|| "Node läuft nicht (Dashboard-managed)".to_string())?;
        let addr = h
            .cfg
            .status_http_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "StatusHTTP ist nicht aktiv".to_string())?;
        (addr.to_string(), h.store_dir_abs.clone())
    };

    let tls_ca_path = store_dir_abs.join("server.crt");
    if !tls_ca_path.exists() {
        return Err(format!(
            "TLS-CA fehlt (StatusHTTP): {}",
            tls_ca_path.display()
        ));
    }

    let auth_token_file = app_data_dir(&app)?.join("status_auth_token.txt");
    if !auth_token_file.exists() {
        return Err("Auth-Token-Datei fehlt (Node nicht via Dashboard gestartet?)".to_string());
    }

    // Resolve validator keystore (store_dir first, then global fallback) based on the managed node store_dir.
    let (keystore_path, _loc) = resolve_validator_keystore_path(&store_dir_abs);
    if !keystore_path.exists() {
        return Err(format!(
            "Validator-BLS Keystore fehlt: {}",
            keystore_path.display()
        ));
    }

    let signer_path = find_phantom_signer_binary()?;
    let node_url = format!("https://{}", status_http_addr);

    let (bls_pk, bls_pop) = validator_bls_info_inner(
        &signer_path,
        &keystore_path,
        args.validator_passphrase.trim(),
        args.use_passphrase_role,
    )?;

    with_temp_secret_file(
        "phantom_wallet_passphrase",
        wallet_passphrase.trim(),
        |pass_path| {
            let mut cmd = Command::new(&signer_path);
            cmd.arg("validator-register")
                .arg("--addr")
                .arg(selected_addr.trim())
                .arg("--anchor-utxo")
                .arg(&anchor_utxo)
                .arg("--bls-pk")
                .arg(&bls_pk)
                .arg("--bls-pop")
                .arg(&bls_pop)
                .arg("--wallet-db")
                .arg(wallet_db_dir.to_string_lossy().to_string())
                .arg("--seed-store")
                .arg(seed_store_path.to_string_lossy().to_string())
                .arg("--node")
                .arg(&node_url)
                .arg("--auth-token-file")
                .arg(auth_token_file.to_string_lossy().to_string())
                .arg("--tls-ca")
                .arg(tls_ca_path.to_string_lossy().to_string())
                .arg("--passphrase-file")
                .arg(pass_path);
            if let Some(op) = args
                .operator_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                cmd.arg("--operator-id").arg(op);
            }
            cmd.stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            let out = cmd
                .output()
                .map_err(|e| format!("phantom-signer Aufruf fehlgeschlagen: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !out.status.success() {
                return Ok(SignerCmdResp {
                    ok: false,
                    stdout,
                    stderr,
                });
            }
            Ok(SignerCmdResp {
                ok: true,
                stdout,
                stderr,
            })
        },
    )
}

#[command]
async fn http_get(args: HttpGetArgs) -> Result<String, String> {
    let u = validate_loopback_http_url(&args.url)?;
    validate_http_get_endpoint(&u)?;

    let timeout_ms = args.timeout_ms.unwrap_or(3000).clamp(100, 10_000);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| e.to_string())?;

    let mut headers = HeaderMap::new();
    if let Some(tok) = args.bearer_token {
        let tok = tok.trim();
        if !tok.is_empty() {
            let v = format!("Bearer {tok}");
            let hv = HeaderValue::from_str(&v).map_err(|e| e.to_string())?;
            headers.insert(AUTHORIZATION, hv);
        }
    }

    let resp = client
        .get(u)
        .headers(headers)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    const MAX_HTTP_BODY_BYTES: usize = 2_097_152; // 2 MiB
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > MAX_HTTP_BODY_BYTES {
        return Err(format!(
            "HTTP Antwort ist zu groß: {} bytes (max {} bytes)",
            bytes.len(),
            MAX_HTTP_BODY_BYTES
        ));
    }
    let body = String::from_utf8(bytes.to_vec())
        .map_err(|_| "HTTP Antwort ist nicht UTF-8".to_string())?;

    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status.as_u16(), body));
    }

    Ok(body)
}

#[derive(Debug, Clone, Serialize)]
struct ListenPort {
    port: u16,
    process: Option<String>,
}

fn parse_port_from_addr(s: &str) -> Option<u16> {
    let s = s.trim();
    let idx = s.rfind(':').or_else(|| s.rfind('.'))?;
    let p = &s[idx + 1..];
    let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u16>().ok()
}

fn parse_listen_ports_from_lsof(out: &str) -> Vec<ListenPort> {
    let mut ports: HashSet<u16> = HashSet::new();
    let mut out_ports: Vec<ListenPort> = Vec::new();
    for line in out.lines() {
        if !line.contains("(LISTEN)") {
            continue;
        }

        let tcp_idx = match line.find(" TCP ") {
            Some(i) => i,
            None => continue,
        };

        let after = &line[tcp_idx + 5..];
        let addr = after.split_whitespace().next().unwrap_or("");
        if let Some(p) = parse_port_from_addr(addr) {
            if p != 0 && !ports.contains(&p) {
                let process = line.split_whitespace().next().map(|s| s.to_string());
                ports.insert(p);
                out_ports.push(ListenPort { port: p, process });
            }
        }
    }
    out_ports.sort_by_key(|p| p.port);
    out_ports
}

fn parse_listen_ports_from_netstat(out: &str) -> Vec<ListenPort> {
    let mut ports: HashSet<u16> = HashSet::new();
    let mut out_ports: Vec<ListenPort> = Vec::new();
    for line in out.lines() {
        if !line.contains("LISTEN") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let local = parts[3];
        if let Some(p) = parse_port_from_addr(local) {
            if p != 0 && !ports.contains(&p) {
                ports.insert(p);
                out_ports.push(ListenPort {
                    port: p,
                    process: None,
                });
            }
        }
    }
    out_ports.sort_by_key(|p| p.port);
    out_ports
}

#[command]
fn list_listen_ports() -> Result<Vec<ListenPort>, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if let Some(lsof_bin) = find_system_bin("lsof") {
            let lsof = Command::new(lsof_bin)
                .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
                .output();
            if let Ok(out) = lsof {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout);
                    return Ok(parse_listen_ports_from_lsof(&s));
                }
            }
        }

        if let Some(netstat_bin) = find_system_bin("netstat") {
            let netstat = Command::new(netstat_bin)
                .args(["-anv", "-p", "tcp"])
                .output();
            if let Ok(out) = netstat {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout);
                    return Ok(parse_listen_ports_from_netstat(&s));
                }
            }
        }

        Err("Konnte lokale Ports nicht ermitteln (weder lsof noch netstat verfügbar).".to_string())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Automatisches Port-Finden ist auf diesem Betriebssystem nicht verfügbar.".to_string())
    }
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn normalize_hex_bytes(s: &str, expected_len: usize, label: &str) -> Result<String, String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("{label} ungültig: {e}"))?;
    if bytes.len() != expected_len {
        return Err(format!("{label} muss {expected_len}-Byte Hex sein."));
    }
    Ok(hex::encode(bytes))
}

fn normalize_hex_32(s: &str, label: &str) -> Result<String, String> {
    normalize_hex_bytes(s, 32, label)
}

fn normalize_hex_48(s: &str, label: &str) -> Result<String, String> {
    normalize_hex_bytes(s, 48, label)
}

#[cfg(debug_assertions)]
fn ps_ppid(pid: u32) -> Option<u32> {
    let ps = find_system_bin("ps")?;
    let out = Command::new(ps)
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    s.parse::<u32>().ok()
}

#[cfg(debug_assertions)]
fn ps_command(pid: u32) -> Option<String> {
    ps_command_any(pid)
}

#[cfg(debug_assertions)]
fn kill_int(pid: u32) {
    let Some(kill) = find_system_bin("kill") else {
        return;
    };
    let _ = Command::new(kill).args(["-INT", &pid.to_string()]).status();
}

#[cfg(debug_assertions)]
fn try_stop_vite_dev_server() {
    let Some(lsof_bin) = find_system_bin("lsof") else {
        return;
    };
    let out = Command::new(lsof_bin)
        .args(["-nP", "-iTCP:5173", "-sTCP:LISTEN"])
        .output();
    let Ok(out) = out else {
        return;
    };
    if !out.status.success() {
        return;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    for (i, line) in s.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _cmd = parts.next().unwrap_or("");
        let pid_s = parts.next().unwrap_or("");
        let Ok(pid) = pid_s.parse::<u32>() else {
            continue;
        };
        let Some(cmdline) = ps_command(pid) else {
            continue;
        };
        let low = cmdline.to_lowercase();
        if low.contains("node_modules/.bin/vite") && low.contains("apps/phantom-dashboard") {
            kill_int(pid);
        }
    }
}

#[cfg(debug_assertions)]
fn try_stop_tauri_dev_parent() {
    let mut cur = std::process::id();
    for _ in 0..8 {
        let Some(ppid) = ps_ppid(cur) else {
            break;
        };
        if ppid <= 1 {
            break;
        }

        if let Some(cmd) = ps_command(ppid) {
            let low = cmd.to_lowercase();
            if low.contains("tauri") && low.contains("dev") {
                kill_int(ppid);
                break;
            }
        }

        cur = ppid;
    }

    try_stop_vite_dev_server();
}

#[cfg(not(debug_assertions))]
fn try_stop_tauri_dev_parent() {}

#[command]
async fn app_quit(
    app: tauri::AppHandle,
    node_state: tauri::State<'_, NodeService>,
) -> Result<(), String> {
    stop_node_service_sync(&node_state);
    try_stop_tauri_dev_parent();
    app.exit(0);
    Ok(())
}

#[command]
fn get_dashboard_texts(lang: String) -> serde_json::Value {
    let l = phantom_i18n::Lang::from_str(&lang);
    let texts = phantom_i18n::dashboard_texts(l);
    serde_json::to_value(texts).unwrap_or_default()
}

fn main() {
    let smoke_http_request = std::env::var("PHANTOM_DASHBOARD_SMOKE_HTTP_URL")
        .ok()
        .map(|url| DashboardSmokeHttpRequest {
            url,
            bearer_token: std::env::var("PHANTOM_DASHBOARD_SMOKE_BEARER_TOKEN").ok(),
            expect_body_includes: std::env::var("PHANTOM_DASHBOARD_SMOKE_EXPECT_BODY_INCLUDES")
                .ok(),
        });
    let smoke_result_file = std::env::var("PHANTOM_DASHBOARD_SMOKE_RESULT_FILE").ok();
    let smoke_timeout_secs = std::env::var("PHANTOM_DASHBOARD_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(20);
    let smoke_done = Arc::new(AtomicBool::new(false));

    let result = tauri::Builder::default()
        .setup({
            let smoke_http_request = smoke_http_request.clone();
            let smoke_result_file = smoke_result_file.clone();
            let smoke_done = Arc::clone(&smoke_done);
            move |app| {
                startup_cleanup_orphan_phantom_processes(&app.app_handle());
                if let Some(req) = smoke_http_request.clone() {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.hide();
                    }

                    let app_handle = app.app_handle();
                    let app_handle_for_ready = app_handle.clone();
                    let ready_sent = Arc::new(AtomicBool::new(false));
                    let ready_sent_listener = Arc::clone(&ready_sent);
                    let req_for_ready = req.clone();
                    app_handle.listen_global("phantom-dashboard-smoke-ready", move |_| {
                        if ready_sent_listener.swap(true, Ordering::SeqCst) {
                            return;
                        }
                        if let Some(window) = app_handle_for_ready.get_window("main") {
                            let _ = window
                                .emit("phantom-dashboard-smoke-http-get", req_for_ready.clone());
                        }
                    });

                    let app_handle = app.app_handle();
                    let app_handle_for_result = app_handle.clone();
                    let smoke_done_listener = Arc::clone(&smoke_done);
                    let smoke_result_file_listener = smoke_result_file.clone();
                    app_handle.listen_global(
                        "phantom-dashboard-smoke-http-get-result",
                        move |event| {
                            if smoke_done_listener.swap(true, Ordering::SeqCst) {
                                return;
                            }
                            let payload = event.payload().unwrap_or("{}");
                            let parsed = serde_json::from_str::<DashboardSmokeHttpResult>(payload)
                                .unwrap_or_else(|e| DashboardSmokeHttpResult {
                                    ok: false,
                                    error: Some(format!("invalid smoke payload: {e}")),
                                    body_preview: Some(payload.to_string()),
                                });
                            if let Some(path) = smoke_result_file_listener.as_deref() {
                                let _ = write_json_file_atomic(Path::new(path), &parsed);
                            }
                            app_handle_for_result.exit(if parsed.ok { 0 } else { 1 });
                        },
                    );

                    let app_handle = app.app_handle();
                    let smoke_done_timeout = Arc::clone(&smoke_done);
                    let smoke_result_file_timeout = smoke_result_file.clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(smoke_timeout_secs)).await;
                        if smoke_done_timeout.swap(true, Ordering::SeqCst) {
                            return;
                        }
                        let timeout_result = DashboardSmokeHttpResult {
                            ok: false,
                            error: Some(format!(
                                "dashboard smoke timed out after {}s",
                                smoke_timeout_secs
                            )),
                            body_preview: None,
                        };
                        if let Some(path) = smoke_result_file_timeout.as_deref() {
                            let _ = write_json_file_atomic(Path::new(path), &timeout_result);
                        }
                        app_handle.exit(1);
                    });
                }
                Ok(())
            }
        })
        .manage(NodeService::default())
        .manage(WalletService::default())
        .manage(CanonicalGenesisResetService::default())
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                api.prevent_close();
                // Best-effort cleanup: stop managed child processes to avoid orphaned phantom-node instances.
                let app = event.window().app_handle();
                let ns = app.state::<NodeService>();
                stop_node_service_sync(&ns);
                try_stop_tauri_dev_parent();
                event.window().app_handle().exit(0);
            }
        })
        .invoke_handler(tauri::generate_handler![
            http_get,
            list_listen_ports,
            app_quit,
            bootstrap_peers_load,
            bootstrap_peers_save,
            wallet_generate_mnemonic,
            wallet_create,
            wallet_create_watch_only,
            wallet_status,
            wallet_unlock,
            wallet_lock,
            wallet_select_addr,
            wallet_send,
            wallet_backup_to_dir,
            wallet_restore_from_dir,
            wallet_history_csv_append,
            wallet_history_csv_open_folder,
            wallet_history_csv_range,
            bitbox_bridge_status,
            bitbox_hwi_enumerate,
            bitbox_hwi_get_xpub,
            validator_keygen_bls,
            validator_bls_info,
            validator_stake_bond,
            validator_stake_unbond,
            validator_register,
            node_canonical_genesis_reset_prepare,
            node_canonical_genesis_reset_commit,
            node_start,
            node_stop,
            node_status,
            node_logs,
            node_backup_store,
            node_wallet_utxos_by_lock,
            node_wallet_history,
            node_consensus_validators,
            get_dashboard_texts
        ])
        .run(tauri::generate_context!());
    if let Err(err) = result {
        eprintln!("error while running tauri application: {err}");
        std::process::exit(1);
    }
}
