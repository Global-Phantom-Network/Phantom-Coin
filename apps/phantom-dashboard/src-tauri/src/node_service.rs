use super::*;

pub(crate) fn repo_root_from_cwd() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..10 {
        let cand = dir.join("Cargo.toml");
        if cand.is_file()
            && std::fs::read_to_string(&cand)
                .ok()
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

pub(crate) fn repo_root_from_exe() -> Option<PathBuf> {
    let mut dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    for _ in 0..12 {
        let cand = dir.join("Cargo.toml");
        if cand.is_file()
            && std::fs::read_to_string(&cand)
                .ok()
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

pub(crate) fn repo_root() -> Option<PathBuf> {
    repo_root_from_exe().or_else(repo_root_from_cwd)
}

pub(crate) fn find_phantom_node_binary() -> Result<PathBuf, String> {
    let use_release = !cfg!(debug_assertions);
    let exe = if cfg!(windows) {
        "phantom-node.exe"
    } else {
        "phantom-node"
    };

    if let Some(root) = repo_root() {
        let p = root
            .join("target")
            .join(if use_release { "release" } else { "debug" })
            .join(exe);
        if p.is_file() {
            return Ok(p);
        }
        if cfg!(debug_assertions) {
            let pr = root.join("target").join("release").join(exe);
            if pr.is_file() {
                return Ok(pr);
            }
            let pd = root.join("target").join("debug").join(exe);
            if pd.is_file() {
                return Ok(pd);
            }
        }
    }
    Err("phantom-node Binary nicht gefunden (erwartet in target/{debug,release}/)".to_string())
}

pub(crate) fn find_status_http_binary() -> Result<PathBuf, String> {
    let use_release = !cfg!(debug_assertions);
    let exe = if cfg!(windows) {
        "status_http.exe"
    } else {
        "status_http"
    };

    if let Some(root) = repo_root() {
        let p = root
            .join("target")
            .join(if use_release { "release" } else { "debug" })
            .join(exe);
        if p.is_file() {
            return Ok(p);
        }
        if cfg!(debug_assertions) {
            let pr = root.join("target").join("release").join(exe);
            if pr.is_file() {
                return Ok(pr);
            }
            let pd = root.join("target").join("debug").join(exe);
            if pd.is_file() {
                return Ok(pd);
            }
        }
    }
    Err("status_http Binary nicht gefunden (erwartet in target/{debug,release}/)".to_string())
}

pub(crate) fn find_mint_rpc_binary() -> Result<PathBuf, String> {
    let use_release = !cfg!(debug_assertions);
    let exe = if cfg!(windows) {
        "mint_rpc.exe"
    } else {
        "mint_rpc"
    };

    if let Some(root) = repo_root() {
        let p = root
            .join("target")
            .join(if use_release { "release" } else { "debug" })
            .join(exe);
        if p.is_file() {
            return Ok(p);
        }
        if cfg!(debug_assertions) {
            let pr = root.join("target").join("release").join(exe);
            if pr.is_file() {
                return Ok(pr);
            }
            let pd = root.join("target").join("debug").join(exe);
            if pd.is_file() {
                return Ok(pd);
            }
        }
    }
    Err("mint_rpc Binary nicht gefunden (erwartet in target/{debug,release}/)".to_string())
}

pub(crate) fn find_phantom_signer_binary() -> Result<PathBuf, String> {
    let use_release = !cfg!(debug_assertions);
    let exe = if cfg!(windows) {
        "phantom-signer.exe"
    } else {
        "phantom-signer"
    };

    if let Some(root) = repo_root() {
        let p = root
            .join("target")
            .join(if use_release { "release" } else { "debug" })
            .join(exe);
        if p.is_file() {
            return Ok(p);
        }
        if cfg!(debug_assertions) {
            let pr = root.join("target").join("release").join(exe);
            if pr.is_file() {
                return Ok(pr);
            }
            let pd = root.join("target").join("debug").join(exe);
            if pd.is_file() {
                return Ok(pd);
            }
        }
    }
    Err("phantom-signer Binary nicht gefunden (erwartet in target/{debug,release}/)".to_string())
}

pub(crate) fn write_auth_token_file(
    app: &tauri::AppHandle,
    token: &str,
) -> Result<PathBuf, String> {
    let dir = app_data_dir(app)?;
    let path = dir.join("status_auth_token.txt");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("Token-Datei nicht schreibbar: {e}"))?;
        f.write_all(token.trim().as_bytes())
            .map_err(|e| format!("Token-Datei nicht schreibbar: {e}"))?;
        f.write_all(b"\n")
            .map_err(|e| format!("Token-Datei nicht schreibbar: {e}"))?;
        let _ = f.sync_all();
        Ok(path)
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&path, format!("{}\n", token.trim()))
            .map_err(|e| format!("Token-Datei nicht schreibbar: {e}"))?;
        Ok(path)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ManagedNodeStartArgs {
    pub status_addr: String,
    #[serde(default)]
    pub status_http_addr: Option<String>,
    #[serde(default)]
    pub mint_rpc_addr: Option<String>,
    pub p2p_listen_addr: String,
    pub store_dir: String,
    #[serde(default)]
    pub metrics_addr: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub bootstrap_peers: Vec<BootstrapPeerEntryDisk>,
    #[serde(default)]
    pub unsafe_confirm_p2p_public: bool,
    #[serde(default)]
    pub tx_proposer: bool,
    #[serde(default)]
    pub pow_miner: bool,
    #[serde(default)]
    pub validator_id: Option<String>,
    #[serde(default)]
    pub bls_pk: Option<String>,
    #[serde(default)]
    pub mint_amount: Option<u64>,
    #[serde(default)]
    pub mint_lock: Option<String>,
    #[serde(default)]
    pub override_validator_control: bool,
    #[serde(default)]
    pub validator_passphrase: Option<String>,
    #[serde(default)]
    pub use_passphrase_role: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ManagedNodeStatus {
    pub running: bool,
    pub p2p_running: bool,
    pub status_running: bool,
    pub status_http_running: bool,
    pub mint_rpc_running: bool,
    pub tx_proposer_enabled: bool,
    pub pow_miner_enabled: bool,
    pub mint_lock_hex: Option<String>,
    pub started_at_ts: Option<u64>,
    pub p2p_listen_addr: Option<String>,
    pub status_addr: Option<String>,
    pub status_http_addr: Option<String>,
    pub mint_rpc_addr: Option<String>,
    pub store_dir: Option<String>,
    pub metrics_addr: Option<String>,
    pub last_error: Option<String>,
}

pub(crate) struct ManagedNodeHandle {
    pub logs: Arc<Mutex<Vec<String>>>,
    pub started_at_ts: u64,
    pub store_dir_abs: PathBuf,
    pub cfg: ManagedNodeStartArgs,
    pub p2p: std::process::Child,
    pub status: std::process::Child,
    pub status_http: Option<std::process::Child>,
    pub mint_rpc: Option<std::process::Child>,
    pub finalizer_stop: Option<Arc<AtomicBool>>,
}

#[derive(Default)]
pub(crate) struct NodeService {
    pub inner: std::sync::Mutex<Option<ManagedNodeHandle>>,
}

static NODE_LOG_MIRROR_FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);
static NODE_LOG_MIRROR_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn set_node_log_mirror(path: PathBuf) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let file = opts
        .open(&path)
        .map_err(|e| format!("Node-Log-Datei nicht schreibbar ({}): {e}", path.display()))?;

    {
        let mut guard = match NODE_LOG_MIRROR_FILE.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        *guard = Some(file);
    }
    {
        let mut guard = match NODE_LOG_MIRROR_PATH.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        *guard = Some(path);
    }
    Ok(())
}

fn clear_node_log_mirror() {
    let file_opt = {
        let mut guard = match NODE_LOG_MIRROR_FILE.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.take()
    };
    if let Some(mut f) = file_opt {
        let _ = f.flush();
    }
    let mut guard = match NODE_LOG_MIRROR_PATH.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    *guard = None;
}

fn mirror_node_log(line: &str) {
    let important = line.contains("-ERR]")
        || line.contains("stream error")
        || line.contains("INTERNAL_ERROR")
        || line.contains("Internal:")
        || line.contains("log_file:");
    if important {
        eprintln!("{}", line);
    }

    let mut guard = match NODE_LOG_MIRROR_FILE.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if let Some(f) = guard.as_mut() {
        if writeln!(f, "{}", line).is_ok() {
            let _ = f.flush();
        }
    }
}

pub(crate) fn push_node_log(logs: &Arc<Mutex<Vec<String>>>, line: String) {
    mirror_node_log(&line);
    let mut guard = match logs.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    guard.push(line);
    if guard.len() > 5000 {
        let drop_n = guard.len().saturating_sub(5000);
        guard.drain(0..drop_n);
    }
}

pub(crate) fn attach_child_logs(
    prefix: &'static str,
    mut child: std::process::Child,
    logs: Arc<Mutex<Vec<String>>>,
) -> std::process::Child {
    use std::io::{BufRead, BufReader};

    if let Some(stdout) = child.stdout.take() {
        let logs2 = Arc::clone(&logs);
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                push_node_log(&logs2, format!("[{prefix}] {line}"));
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let logs2 = Arc::clone(&logs);
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                push_node_log(&logs2, format!("[{prefix}-ERR] {line}"));
            }
        });
    }
    child
}

pub(crate) const CANONICAL_GENESIS_NOTE: &[u8] =
    include_bytes!("../../../../data/genesis_note.bin");
pub(crate) const VALIDATOR_CONTROL_FILENAME: &str = "validator_control.json";
pub(crate) const LEGACY_BOOTSTRAP_GENESIS_MARKER_FILENAME: &str = "genesis_bootstrap_override.json";
pub(crate) const CANONICAL_GENESIS_RESET_CONFIRM_TEXT: &str = "GENESIS RESET VERSTEHE ICH";
pub(crate) const CANONICAL_GENESIS_RESET_COUNTDOWN_MS: u64 = 5_000;
pub(crate) const CANONICAL_GENESIS_RESET_PREPARE_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone)]
pub(crate) struct CanonicalGenesisResetPending {
    pub token: String,
    pub store_dir_abs: PathBuf,
    pub note_bytes: Vec<u8>,
    pub network_id: String,
    pub ready_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Default)]
pub(crate) struct CanonicalGenesisResetService {
    pub pending: std::sync::Mutex<Option<CanonicalGenesisResetPending>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CanonicalGenesisResetPrepareArgs {
    pub store_dir: String,
    pub confirm_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CanonicalGenesisResetPrepareResp {
    pub ok: bool,
    pub token: String,
    pub ready_at_unix_ms: u64,
    pub network_id: String,
    pub already_active: bool,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CanonicalGenesisResetCommitArgs {
    pub store_dir: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CanonicalGenesisResetCommitResp {
    pub ok: bool,
    pub network_id: String,
    pub already_active: bool,
    pub genesis_note_path: String,
    pub backup_path: Option<String>,
    pub purged_items: Vec<String>,
    pub message: String,
}

pub(crate) fn legacy_bootstrap_genesis_marker_path(mempool_dir: &Path) -> PathBuf {
    mempool_dir.join(LEGACY_BOOTSTRAP_GENESIS_MARKER_FILENAME)
}

pub(crate) fn decode_hex_array<const N: usize>(s: &str, label: &str) -> Result<[u8; N], String> {
    let normalized = normalize_hex_bytes(s, N, label)?;
    let bytes = hex::decode(normalized).map_err(|e| format!("{label} ungültig: {e}"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn decode_canonical_genesis_note() -> Result<GenesisNote, String> {
    pc_codec::decode_exact::<GenesisNote>(CANONICAL_GENESIS_NOTE)
        .map_err(|e| format!("eingebaute canonical genesis_note ungültig: {e}"))
}

pub(crate) fn canonical_genesis_network_id_hex() -> Result<String, String> {
    let note = decode_canonical_genesis_note()?;
    Ok(hex::encode(digest_genesis_note(&note)))
}

pub(crate) fn write_genesis_note_with_backup(
    mempool_dir: &Path,
    note_bytes: &[u8],
) -> Result<Option<String>, String> {
    fs::create_dir_all(mempool_dir)
        .map_err(|e| format!("mempool/ Ordner nicht erstellbar: {e}"))?;
    let note_path = mempool_dir.join("genesis_note.bin");
    let backup_dir = mempool_dir.join("genesis-note-backups");

    let mut backup_path: Option<String> = None;
    if let Ok(existing) = fs::read(&note_path) {
        if existing != note_bytes {
            fs::create_dir_all(&backup_dir)
                .map_err(|e| format!("genesis backup Verzeichnis nicht schreibbar: {e}"))?;
            let backup = backup_dir.join(format!("genesis_note.bin.{}.bak", now_secs_u64()));
            fs::write(&backup, &existing)
                .map_err(|e| format!("genesis backup nicht schreibbar: {e}"))?;
            backup_path = Some(backup.to_string_lossy().to_string());
        }
    }

    fs::write(&note_path, note_bytes)
        .map_err(|e| format!("genesis_note.bin nicht schreibbar: {e}"))?;
    Ok(backup_path)
}

pub(crate) fn check_node_stopped(node_state: &tauri::State<'_, NodeService>) -> Result<(), String> {
    let node_running = {
        let guard = match node_state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.is_some()
    };
    if node_running {
        return Err("Node läuft noch. Bitte zuerst Node stoppen.".to_string());
    }
    Ok(())
}

pub(crate) fn purge_runtime_state(store_dir: &Path) -> Result<Vec<String>, String> {
    let mut purged: Vec<String> = Vec::new();

    let dirs_in_store = [
        "headers",
        "payloads",
        "payload_segments",
        "utxo",
        "utxo.secondary",
        "utxo_secondary",
        "utxo_secondary_status_stake",
    ];
    for name in &dirs_in_store {
        let p = store_dir.join(name);
        if p.exists() {
            fs::remove_dir_all(&p).map_err(|e| format!("Konnte {name}/ nicht löschen: {e}"))?;
            purged.push(format!("{name}/"));
        }
    }

    let mempool = store_dir.join("mempool");
    let mempool_dirs = [
        "evidences",
        "state.rocks",
        "mints",
        "genesis-note-backups",
        "mint_seeds",
    ];
    for name in &mempool_dirs {
        let p = mempool.join(name);
        if p.exists() {
            fs::remove_dir_all(&p)
                .map_err(|e| format!("Konnte mempool/{name}/ nicht löschen: {e}"))?;
            purged.push(format!("mempool/{name}/"));
        }
    }

    let files_in_store = [
        "anchor_index",
        "state_root",
        "last_final_payload_root",
        ".finalizer_state",
        "stake_registry.json",
        "validator_control.json",
    ];
    for name in &files_in_store {
        let p = store_dir.join(name);
        match fs::remove_file(&p) {
            Ok(_) => {
                purged.push(name.to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Konnte {name} nicht löschen: {e}")),
        }
    }

    let mempool_files = [
        "mempool.journal",
        "evidences.journal",
        "supply_state.json",
        "mint_round_state.json",
        "wallet_history.v1.jsonl",
    ];
    for name in &mempool_files {
        let p = mempool.join(name);
        match fs::remove_file(&p) {
            Ok(_) => {
                purged.push(format!("mempool/{name}"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Konnte mempool/{name} nicht löschen: {e}")),
        }
    }

    match fs::read_dir(&mempool) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|e| format!("Konnte mempool/ nicht lesen: {e}"))?;
                let path = entry.path();
                let file_type = entry
                    .file_type()
                    .map_err(|e| format!("Konnte Dateityp in mempool/ nicht lesen: {e}"))?;
                if !file_type.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                if name == "genesis_note.bin" {
                    continue;
                }
                if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                    continue;
                }
                fs::remove_file(&path)
                    .map_err(|e| format!("Konnte mempool/{name} nicht löschen: {e}"))?;
                purged.push(format!("mempool/{name}"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("Konnte mempool/ nicht lesen: {e}")),
    }

    Ok(purged)
}

pub(crate) fn ensure_genesis_note(mempool_dir: &Path) -> Result<(), String> {
    let path = mempool_dir.join("genesis_note.bin");
    let marker_path = legacy_bootstrap_genesis_marker_path(mempool_dir);
    match fs::read(&path) {
        Ok(existing) => {
            if existing == CANONICAL_GENESIS_NOTE {
                let _ = fs::remove_file(&marker_path);
                return Ok(());
            }
            let store_dir = mempool_dir
                .parent()
                .ok_or_else(|| "mempool/ Pfad ohne store_dir Elternpfad".to_string())?;
            let purged_items = purge_runtime_state(store_dir)?;
            let backup_path = write_genesis_note_with_backup(mempool_dir, CANONICAL_GENESIS_NOTE)?;
            let _ = fs::remove_file(&marker_path);

            if !purged_items.is_empty() {
                eprintln!(
                    "[NODE] Runtime-State nach Genesis-Wechsel verworfen: {}",
                    purged_items.join(", ")
                );
            }
            eprintln!(
                "[NODE] Vorhandene genesis_note.bin ersetzt; Backup: {}",
                backup_path.as_deref().unwrap_or("-")
            );
            eprintln!(
                "[NODE] Kanonische genesis_note.bin installiert ({} bytes)",
                CANONICAL_GENESIS_NOTE.len()
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(mempool_dir)
                .map_err(|e| format!("mempool/ Ordner nicht erstellbar: {e}"))?;
            fs::write(&path, CANONICAL_GENESIS_NOTE)
                .map_err(|e| format!("genesis_note.bin nicht schreibbar: {e}"))?;
            let _ = fs::remove_file(&marker_path);
            eprintln!(
                "[NODE] Kanonische genesis_note.bin installiert ({} bytes)",
                CANONICAL_GENESIS_NOTE.len()
            );
            Ok(())
        }
        Err(e) => Err(format!("genesis_note.bin nicht lesbar: {e}")),
    }
}

#[command]
pub(crate) fn node_canonical_genesis_reset_prepare(
    app: tauri::AppHandle,
    node_state: tauri::State<'_, NodeService>,
    genesis_reset_state: tauri::State<'_, CanonicalGenesisResetService>,
    args: CanonicalGenesisResetPrepareArgs,
) -> Result<CanonicalGenesisResetPrepareResp, String> {
    check_node_stopped(&node_state)?;
    if args.confirm_text.trim() != CANONICAL_GENESIS_RESET_CONFIRM_TEXT {
        return Err(format!(
            "Bestätigungstext muss exakt sein: {}",
            CANONICAL_GENESIS_RESET_CONFIRM_TEXT
        ));
    }
    let store_dir_abs = resolve_store_dir_path_for_app(&app, &args.store_dir)?;
    let mempool_dir_abs = store_dir_abs.join("mempool");
    fs::create_dir_all(&mempool_dir_abs)
        .map_err(|e| format!("mempool/ Ordner nicht erstellbar: {e}"))?;

    let note_bytes = CANONICAL_GENESIS_NOTE.to_vec();
    let network_id = canonical_genesis_network_id_hex()?;

    let genesis_note_path = mempool_dir_abs.join("genesis_note.bin");
    let existing = fs::read(&genesis_note_path).ok();
    let bytes_match = existing
        .as_ref()
        .map(|b| b.as_slice() == note_bytes.as_slice())
        .unwrap_or(false);
    let already_active = bytes_match;

    let mut token_raw = [0u8; 16];
    AeadOsRng.fill_bytes(&mut token_raw);
    let token = hex::encode(token_raw);
    let now_ms = now_millis_u64();
    let ready_at_unix_ms = now_ms.saturating_add(CANONICAL_GENESIS_RESET_COUNTDOWN_MS);
    let expires_at_unix_ms = now_ms.saturating_add(CANONICAL_GENESIS_RESET_PREPARE_TTL_MS);

    let mut pending = match genesis_reset_state.pending.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    *pending = Some(CanonicalGenesisResetPending {
        token: token.clone(),
        store_dir_abs,
        note_bytes,
        network_id: network_id.clone(),
        ready_at_unix_ms,
        expires_at_unix_ms,
    });

    Ok(CanonicalGenesisResetPrepareResp {
        ok: true,
        token,
        ready_at_unix_ms,
        network_id,
        already_active,
        message: if already_active {
            "Kanonische Genesis ist bereits aktiv (final bestätigen, um den Zustand zu bestätigen)."
                .to_string()
        } else {
            "Vorprüfung erfolgreich. Countdown abwarten und final bestätigen.".to_string()
        },
    })
}

#[command]
pub(crate) fn node_canonical_genesis_reset_commit(
    app: tauri::AppHandle,
    node_state: tauri::State<'_, NodeService>,
    genesis_reset_state: tauri::State<'_, CanonicalGenesisResetService>,
    args: CanonicalGenesisResetCommitArgs,
) -> Result<CanonicalGenesisResetCommitResp, String> {
    check_node_stopped(&node_state)?;
    let store_dir_abs = resolve_store_dir_path_for_app(&app, &args.store_dir)?;
    let now_ms = now_millis_u64();

    let pending = {
        let mut guard = match genesis_reset_state.pending.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let Some(p) = guard.as_ref() else {
            return Err("Keine aktive Reset-Session. Bitte zuerst vorbereiten.".to_string());
        };
        if p.store_dir_abs != store_dir_abs {
            return Err("Store-Verzeichnis passt nicht zur aktiven Reset-Session.".to_string());
        }
        if p.token != args.token.trim() {
            return Err("Ungültiges Reset-Token.".to_string());
        }
        if now_ms > p.expires_at_unix_ms {
            *guard = None;
            return Err("Reset-Session abgelaufen. Bitte neu vorbereiten.".to_string());
        }
        if now_ms < p.ready_at_unix_ms {
            return Err("Countdown läuft noch. Bitte warten und erneut bestätigen.".to_string());
        }
        let out = p.clone();
        *guard = None;
        out
    };

    let purged_items = purge_runtime_state(&store_dir_abs)?;

    let mempool_dir_abs = store_dir_abs.join("mempool");
    fs::create_dir_all(&mempool_dir_abs)
        .map_err(|e| format!("mempool/ Ordner nicht erstellbar: {e}"))?;
    let note_path = mempool_dir_abs.join("genesis_note.bin");
    let existing = fs::read(&note_path).ok();
    let bytes_match = existing
        .as_ref()
        .map(|b| b.as_slice() == pending.note_bytes.as_slice())
        .unwrap_or(false);

    let backup_path = if bytes_match {
        let _ = fs::remove_file(legacy_bootstrap_genesis_marker_path(&mempool_dir_abs));
        None
    } else {
        let backup_path = write_genesis_note_with_backup(&mempool_dir_abs, &pending.note_bytes)?;
        let _ = fs::remove_file(legacy_bootstrap_genesis_marker_path(&mempool_dir_abs));
        backup_path
    };

    let final_note = load_genesis_note_exact(&note_path)?;
    let final_network_id = hex::encode(digest_genesis_note(&final_note));
    if !final_network_id.eq_ignore_ascii_case(&pending.network_id) {
        return Err(format!(
            "network_id mismatch nach Commit (expected {}, got {})",
            pending.network_id, final_network_id
        ));
    }

    Ok(CanonicalGenesisResetCommitResp {
        ok: true,
        network_id: final_network_id,
        already_active: bytes_match,
        genesis_note_path: note_path.to_string_lossy().to_string(),
        backup_path,
        purged_items: purged_items.clone(),
        message: if bytes_match && purged_items.is_empty() {
            "Kanonische Genesis war bereits aktiv; kein Rewrite und kein Purge durchgeführt."
                .to_string()
        } else if bytes_match {
            format!(
                "Kanonische Genesis war bereits aktiv; Runtime-State bereinigt ({} Einträge).",
                purged_items.len()
            )
        } else {
            format!(
                "Kanonische Genesis installiert + Runtime-State bereinigt ({} Einträge).",
                purged_items.len()
            )
        },
    })
}

pub(crate) fn load_genesis_note_exact(path: &Path) -> Result<GenesisNote, String> {
    let buf = fs::read(path).map_err(|e| format!("genesis_note.bin nicht lesbar: {e}"))?;
    pc_codec::decode_exact::<GenesisNote>(&buf)
        .map_err(|e| format!("genesis_note.bin ungültig: {e}"))
}

pub(crate) fn stop_node_service_sync(svc: &NodeService) {
    let mut inner = match svc.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let Some(mut h) = inner.take() else {
        return;
    };
    if let Some(stop) = h.finalizer_stop.take() {
        stop.store(true, Ordering::Relaxed);
    }
    if let Some(mut mint) = h.mint_rpc.take() {
        let _ = mint.kill();
        let _ = mint.wait();
    }
    if let Some(mut sh) = h.status_http.take() {
        let _ = sh.kill();
        let _ = sh.wait();
    }
    let _ = h.status.kill();
    let _ = h.status.wait();
    let _ = h.p2p.kill();
    let _ = h.p2p.wait();

    clear_node_log_mirror();
}

fn wait_for_p2p_cert_ready(cert_file: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if cert_file
            .metadata()
            .ok()
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        {
            // Give the QUIC listener a short grace period after the cert write landed.
            std::thread::sleep(std::time::Duration::from_millis(400));
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "P2P-Zertifikatsdatei nicht rechtzeitig bereit ({})",
                cert_file.display()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn wait_for_status_serve_ready(
    status_addr: std::net::SocketAddr,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let request = format!(
        "GET /readyz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        status_addr
    );
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("status-serve poll fehlgeschlagen: {e}"))?
        {
            return Err(format!("status-serve exited early: {status}"));
        }
        if Instant::now() > deadline {
            return Err("status-serve not ready in time".to_string());
        }

        match std::net::TcpStream::connect_timeout(
            &status_addr,
            std::time::Duration::from_millis(250),
        ) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(500)));
                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut resp = String::new();
                    if std::io::Read::read_to_string(&mut stream, &mut resp).is_ok()
                        && (resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"))
                    {
                        return Ok(());
                    }
                }
            }
            Err(_) => {}
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub(crate) fn with_temp_binary_file<R, F>(prefix: &str, bytes: &[u8], f: F) -> Result<R, String>
where
    F: FnOnce(&Path) -> Result<R, String>,
{
    let mut path_opt: Option<PathBuf> = None;
    for _ in 0..16 {
        let mut rnd = [0u8; 16];
        AeadOsRng.fill_bytes(&mut rnd);
        let name = format!("{}_{}.bin", prefix, hex::encode(rnd));
        let path = std::env::temp_dir().join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut fh) => {
                fh.write_all(bytes)
                    .map_err(|e| format!("Temp-Datei nicht schreibbar: {e}"))?;
                let _ = fh.flush();
                drop(fh);
                path_opt = Some(path);
                break;
            }
            Err(_) => continue,
        }
    }
    let path = path_opt.ok_or_else(|| {
        format!(
            "Temp-Datei nicht erzeugbar: {}",
            std::env::temp_dir().display()
        )
    })?;
    let res = f(&path);
    let _ = std::fs::remove_file(&path);
    res
}

pub(crate) fn signer_bls_sign_message(
    signer_path: &Path,
    keystore_path: &Path,
    passphrase: &str,
    use_passphrase_role: bool,
    msg: &[u8],
) -> Result<[u8; 96], String> {
    let try_sign = |role_validator: bool| -> Result<[u8; 96], String> {
        with_temp_secret_file("phantom_validator_passphrase", passphrase, |pass_file| {
            with_temp_binary_file("phantom_vote_msg", msg, |msg_file| {
                let mut cmd = Command::new(signer_path);
                cmd.arg("sign")
                    .arg("--keystore")
                    .arg(keystore_path.to_string_lossy().to_string())
                    .arg("--msg")
                    .arg(msg_file.to_string_lossy().to_string())
                    .arg("--passphrase-file")
                    .arg(pass_file.to_string_lossy().to_string());
                if role_validator {
                    cmd.arg("--passphrase-role").arg("validator");
                }
                let out = cmd
                    .output()
                    .map_err(|e| format!("phantom-signer sign failed: {e}"))?;
                if !out.status.success() {
                    let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    return if msg.is_empty() {
                        Err("phantom-signer sign fehlgeschlagen".to_string())
                    } else {
                        Err(format!("phantom-signer sign fehlgeschlagen: {msg}"))
                    };
                }
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let sig_hex = last_nonempty_line(&stdout);
                decode_hex_array::<96>(&sig_hex, "bls_signature")
            })
        })
    };

    match try_sign(use_passphrase_role) {
        Ok(sig) => Ok(sig),
        Err(e) => {
            if e.to_lowercase().contains("decrypt failed") {
                try_sign(!use_passphrase_role)
            } else {
                Err(e)
            }
        }
    }
}

pub(crate) fn inject_header_announce_once(
    node_bin: &Path,
    p2p_addr: &str,
    cert_file: &Path,
    header: &AnchorHeaderV2,
) -> Result<(), String> {
    let mut buf = Vec::new();
    let v = vec![header.clone()];
    pc_codec::Encodable::encode(&v, &mut buf).map_err(|e| format!("Header encode failed: {e}"))?;
    with_temp_binary_file("phantom_hdr", &buf, |hdr_file| {
        let out = Command::new(node_bin)
            .arg("p2p-inject-headers")
            .arg("--addr")
            .arg(p2p_addr)
            .arg("--cert-file")
            .arg(cert_file.to_string_lossy().to_string())
            .arg("--headers-file")
            .arg(hdr_file.to_string_lossy().to_string())
            .output()
            .map_err(|e| format!("p2p-inject-headers spawn failed: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if stderr.is_empty() {
                return Err("p2p-inject-headers failed".to_string());
            }
            return Err(format!("p2p-inject-headers failed: {stderr}"));
        }
        Ok(())
    })
}

pub(crate) fn latest_header_parent_from_store(headers_dir: &Path) -> Option<AnchorId> {
    let rd = fs::read_dir(headers_dir).ok()?;
    // Phase 1: stat-only – finde die neueste .bin Datei per mtime (kein Datei-Inhalt lesen).
    let mut best: Option<(std::time::SystemTime, PathBuf, [u8; 32])> = None;
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".bin") else {
            continue;
        };
        let Some(expected_id) = parse_hex_32(stem) else {
            continue;
        };
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        let dominated = match best {
            Some((best_modified, _, best_id)) => {
                modified > best_modified || (modified == best_modified && expected_id > best_id)
            }
            None => true,
        };
        if dominated {
            best = Some((modified, path, expected_id));
        }
    }
    // Phase 2: nur die eine beste Datei lesen + dekodieren + digest prüfen.
    let (_, path, expected_id) = best?;
    let buf = fs::read(&path).ok()?;
    let hdr = pc_codec::decode_exact::<AnchorHeaderV2>(&buf).ok()?;
    if hdr.id_digest() != expected_id {
        return None;
    }
    Some(AnchorId(expected_id))
}

type FinalizerWorkKey = ([u8; 32], Option<[u8; 32]>);

fn finalizer_work_key(root: [u8; 32], parent_tip: Option<AnchorId>) -> FinalizerWorkKey {
    (root, parent_tip.map(|id| id.0))
}

pub(crate) fn maybe_start_local_single_seat_finalizer(
    logs: Arc<Mutex<Vec<String>>>,
    node_bin: PathBuf,
    signer_bin: PathBuf,
    store_dir_abs: PathBuf,
    status_addr: String,
    status_token: String,
    p2p_listen_addr: String,
    bls_pk_hex: String,
    validator_passphrase: String,
    use_passphrase_role: bool,
) -> Option<Arc<AtomicBool>> {
    let (keystore_path, loc) = resolve_validator_keystore_path(&store_dir_abs);
    if !keystore_path.exists() {
        push_node_log(
            &logs,
            format!(
                "[FINALIZER] deaktiviert: Validator-Keystore nicht gefunden ({})",
                keystore_path.display()
            ),
        );
        return None;
    }
    match validator_bls_pub_inner(&signer_bin, &keystore_path) {
        Ok(pk) if pk.eq_ignore_ascii_case(&bls_pk_hex) => {}
        Ok(pk) => {
            push_node_log(
                &logs,
                format!(
                    "[FINALIZER] deaktiviert: Keystore-BLS passt nicht zu role bls_pk (keystore={}, role={})",
                    pk, bls_pk_hex
                ),
            );
            return None;
        }
        Err(e) => {
            push_node_log(
                &logs,
                format!("[FINALIZER] deaktiviert: Keystore-PubKey nicht lesbar ({e})"),
            );
            return None;
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let logs_t = logs.clone();
    let cert_file = store_dir_abs.join("p2p_quic_cert.der");
    let payloads_dir = store_dir_abs.join("payloads");
    let headers_dir = store_dir_abs.join("headers");
    let thread_name = "phantom-local-finalizer".to_string();
    let passphrase = Zeroizing::new(validator_passphrase);
    let role_str = match loc {
        ValidatorKeystoreLocation::StoreDir => "primary",
        ValidatorKeystoreLocation::GlobalFallback => "global_fallback",
        ValidatorKeystoreLocation::Missing => "missing",
    };
    push_node_log(
        &logs,
        format!(
            "[FINALIZER] gestartet (single-seat) p2p={} keystore={} source={}",
            p2p_listen_addr,
            keystore_path.display(),
            role_str
        ),
    );
    let _ = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    push_node_log(&logs_t, format!("[FINALIZER] deaktiviert: tokio runtime build fehlgeschlagen ({e})"));
                    return;
                }
            };
            let status_client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(client) => client,
                Err(e) => {
                    push_node_log(&logs_t, format!("[FINALIZER] deaktiviert: HTTP client build fehlgeschlagen ({e})"));
                    return;
                }
            };
            // Identical payload roots can recur at later anchors. Dedupe must include the
            // current parent tip, otherwise heartbeat roots get finalized exactly once and the
            // solo chain stalls with one forever-pending payload.
            let mut seen: HashSet<FinalizerWorkKey> = HashSet::new();
            let mut next_retry_after: HashMap<FinalizerWorkKey, Instant> = HashMap::new();
            let finalizer_state_path = store_dir_abs.join(".finalizer_state");
            let (mut parent_tip, cache_source): (Option<AnchorId>, &str) = if let Ok(hex_str) = fs::read_to_string(&finalizer_state_path) {
                let trimmed = hex_str.trim();
                if let Some(id) = parse_hex_32(trimmed) {
                    (Some(AnchorId(id)), "cache")
                } else {
                    (latest_header_parent_from_store(&headers_dir), "headers-fallback")
                }
            } else {
                (latest_header_parent_from_store(&headers_dir), "headers-scan")
            };
            if let Some(parent) = parent_tip {
                push_node_log(
                    &logs_t,
                    format!(
                        "[FINALIZER] Startup-Parent: {} (source={})",
                        hex::encode(parent.0),
                        cache_source
                    ),
                );
            } else {
                push_node_log(
                    &logs_t,
                    "[FINALIZER] Startup-Parent: keiner gefunden; erster neuer Header startet ohne Parent"
                        .to_string(),
                );
            }
            loop {
                if stop_t.load(Ordering::Relaxed) {
                    break;
                }
                if !cert_file.exists() || !payloads_dir.exists() {
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    continue;
                }
                // Signaldatei .latest vom Node lesen – enthält den Payload-Root-Hash.
                // Payloads liegen im SegmentStore, nicht als .bin-Dateien.
                let signal_path = payloads_dir.join(".latest");
                let root = match fs::read_to_string(&signal_path) {
                    Ok(hex_str) => match parse_hex_32(hex_str.trim()) {
                        Some(r) => r,
                        None => {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                            continue;
                        }
                    },
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        continue;
                    }
                };
                {
                    if parent_tip.is_none() {
                        parent_tip = latest_header_parent_from_store(&headers_dir);
                    }
                    let work_key = finalizer_work_key(root, parent_tip);
                    if seen.contains(&work_key) {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        continue;
                    }
                    if let Some(retry_at) = next_retry_after.get(&work_key) {
                        if Instant::now() < *retry_at {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                            continue;
                        }
                    }
                    let mut parents = ParentList::default();
                    if let Some(parent) = parent_tip {
                        if let Err(e) = parents.push(parent) {
                            let msg = format!(
                                "[FINALIZER] parent setup fehlgeschlagen root={} err={}",
                                hex::encode(root),
                                e
                            );
                            push_node_log(&logs_t, msg);
                            next_retry_after
                                .insert(work_key, Instant::now() + Duration::from_secs(5));
                            continue;
                        }
                    }
                    let prevote = match rt.block_on(resolve_local_finalizer_prevote(
                        &status_addr,
                        &status_token,
                        &status_client,
                        root,
                        &bls_pk_hex,
                    )) {
                        Ok(v) => v,
                        Err(e) => {
                            push_node_log(
                                &logs_t,
                                format!(
                                    "[FINALIZER] prevote context resolve fehlgeschlagen root={} err={}",
                                    hex::encode(root),
                                    e
                                ),
                            );
                            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                            continue;
                        }
                    };
                    let mut prevote_header = AnchorHeaderV2 {
                        version: 5,
                        shard_id: 0,
                        parents: parents.clone(),
                        payload_hash: root,
                        creator_index: prevote.creator_index,
                        vote_mask: prevote.vote_mask,
                        ack_present: false,
                        ack_id: AnchorId([0u8; 32]),
                        network_id: prevote.network_id,
                        vote_epoch: prevote.vote_epoch,
                        vote_round: 0,
                        attest_sig: None,
                        state_root: None,
                    };
                    let prevote_msg = committee_vote_message(
                        &prevote.network_id,
                        prevote.vote_epoch,
                        &prevote_header.vote_target_hash(),
                    );
                    let prevote_sig = match signer_bls_sign_message(
                        &signer_bin,
                        &keystore_path,
                        passphrase.as_str(),
                        use_passphrase_role,
                        &prevote_msg,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            push_node_log(
                                &logs_t,
                                format!(
                                    "[FINALIZER] prevote sign fehlgeschlagen root={} err={}",
                                    hex::encode(root),
                                    e
                                ),
                            );
                            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                            continue;
                        }
                    };
                    prevote_header.attest_sig = Some(prevote_sig);
                    match inject_header_announce_once(
                        &node_bin,
                        &p2p_listen_addr,
                        &cert_file,
                        &prevote_header,
                    ) {
                        Ok(()) => {
                            push_node_log(
                                &logs_t,
                                format!(
                                    "[FINALIZER] prevote header injected root={} vote_epoch={} parent_count={}",
                                    hex::encode(root),
                                    prevote.vote_epoch,
                                    prevote_header.parents.len
                                ),
                            );
                        }
                        Err(e) => {
                            push_node_log(
                                &logs_t,
                                format!(
                                    "[FINALIZER] prevote inject fehlgeschlagen root={} err={}",
                                    hex::encode(root),
                                    e
                                ),
                            );
                            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                            continue;
                        }
                    }

                    let resolved = match rt.block_on(resolve_local_finalizer_precommit(
                        &status_addr,
                        &status_token,
                        &status_client,
                        root,
                        &bls_pk_hex,
                    )) {
                        Ok(v) => v,
                        Err(e) => {
                            push_node_log(
                                &logs_t,
                                format!(
                                    "[FINALIZER] precommit context resolve fehlgeschlagen root={} err={}",
                                    hex::encode(root),
                                    e
                                ),
                            );
                            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                            continue;
                        }
                    };
                    if resolved.network_id != prevote.network_id
                        || resolved.vote_epoch != prevote.vote_epoch
                        || resolved.creator_index != prevote.creator_index
                        || resolved.vote_mask != prevote.vote_mask
                    {
                        push_node_log(
                            &logs_t,
                            format!(
                                "[FINALIZER] prevote/precommit context mismatch root={} prevote_epoch={} precommit_epoch={}",
                                hex::encode(root),
                                prevote.vote_epoch,
                                resolved.vote_epoch
                            ),
                        );
                        next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                        continue;
                    }

                    let network_id = resolved.network_id;
                    let vote_epoch = resolved.vote_epoch;
                    let creator_index = resolved.creator_index;
                    let vote_mask = resolved.vote_mask;
                    let committed_state_root = resolved.committed_state_root;
                    let mut header = AnchorHeaderV2 {
                        version: 5,
                        shard_id: 0,
                        parents,
                        payload_hash: root,
                        creator_index,
                        vote_mask,
                        ack_present: false,
                        ack_id: AnchorId([0u8; 32]),
                        network_id,
                        vote_epoch,
                        vote_round: 0,
                        attest_sig: None,
                        state_root: Some(committed_state_root),
                    };
                    let vote_msg = committee_precommit_message(
                        &network_id,
                        vote_epoch,
                        &header.vote_target_hash(),
                        &committed_state_root,
                    );
                    let sig = match signer_bls_sign_message(
                        &signer_bin,
                        &keystore_path,
                        passphrase.as_str(),
                        use_passphrase_role,
                        &vote_msg,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            push_node_log(
                                &logs_t,
                                format!(
                                    "[FINALIZER] precommit sign fehlgeschlagen root={} err={}",
                                    hex::encode(root),
                                    e
                                ),
                            );
                            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                            continue;
                        }
                    };
                    header.attest_sig = Some(sig);
                    let next_parent_tip = AnchorId(header.id_digest());

                    match inject_header_announce_once(
                        &node_bin,
                        &p2p_listen_addr,
                        &cert_file,
                        &header,
                    ) {
                        Ok(()) => {
                            seen.insert(work_key);
                            parent_tip = Some(next_parent_tip);
                            next_retry_after.remove(&work_key);
                            let _ = fs::write(&finalizer_state_path, hex::encode(next_parent_tip.0));
                            let msg = format!(
                                    "[FINALIZER] precommit header injected root={} vote_epoch={} parent_count={}",
                                    hex::encode(root),
                                    vote_epoch,
                                    header.parents.len
                                );
                            push_node_log(&logs_t, msg);
                        }
                        Err(e) => {
                            let msg = format!(
                                    "[FINALIZER] precommit inject fehlgeschlagen root={} err={}",
                                    hex::encode(root),
                                    e
                                );
                            push_node_log(&logs_t, msg);
                            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(900));
            }
            push_node_log(&logs_t, "[FINALIZER] gestoppt".to_string());
            })); // end catch_unwind
            if let Err(panic_info) = result {
                let msg = format!("[FINALIZER] PANIC: {:?}", panic_info.downcast_ref::<String>().map(|s| s.as_str()).or_else(|| panic_info.downcast_ref::<&str>().copied()).unwrap_or("unknown"));
                eprintln!("{}", msg);
            }
        });

    Some(stop)
}

#[command]
pub(crate) fn node_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, NodeService>,
    args: ManagedNodeStartArgs,
) -> Result<ManagedNodeStatus, String> {
    let mut inner = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if inner.is_some() {
        drop(inner);
        stop_node_service_sync(&state);
        std::thread::sleep(std::time::Duration::from_millis(500));
        inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
    }

    let status_addr = validate_loopback_socket_addr(&args.status_addr)?;
    let status_http_addr: Option<std::net::SocketAddr> = match args.status_http_addr.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(validate_loopback_socket_addr(s)?),
        _ => None,
    };
    let mint_rpc_addr: Option<std::net::SocketAddr> = match args.mint_rpc_addr.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(validate_loopback_socket_addr(s)?),
        _ => None,
    };

    if let Some(sa) = status_http_addr.as_ref() {
        if *sa == status_addr {
            return Err(
                "StatusHTTP-Addr kollidiert mit StatusServe-Addr (gleicher host:port)".to_string(),
            );
        }
    }
    if let Some(ma) = mint_rpc_addr.as_ref() {
        if *ma == status_addr {
            return Err(
                "Mint-RPC-Addr kollidiert mit StatusServe-Addr (gleicher host:port)".to_string(),
            );
        }
        if let Some(sa) = status_http_addr.as_ref() {
            if *ma == *sa {
                return Err(
                    "Mint-RPC-Addr kollidiert mit StatusHTTP-Addr (gleicher host:port)".to_string(),
                );
            }
        }
    }

    let p2p_addr: std::net::SocketAddr = args
        .p2p_listen_addr
        .trim()
        .parse()
        .map_err(|_| "P2P-Listen-Adresse ist ungültig (erwartet host:port)".to_string())?;
    if !p2p_addr.ip().is_loopback() && !args.unsafe_confirm_p2p_public {
        return Err("P2P-Listen-Adresse ist nicht loopback. Bestätige das explizit (unsafe_confirm_p2p_public=true).".to_string());
    }

    let store_dir_abs = resolve_store_dir_path_for_app(&app, &args.store_dir)?;
    let mempool_dir_abs = store_dir_abs.join("mempool");
    fs::create_dir_all(&mempool_dir_abs)
        .map_err(|e| format!("mempool/ Ordner nicht erstellbar: {e}"))?;

    let mut validator_id_norm = match args.validator_id.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(normalize_hex_32(s, "validator_id")?),
        _ => None,
    };
    let mut bls_pk_norm = match args.bls_pk.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(normalize_hex_48(s, "bls_pk")?),
        _ => None,
    };
    if validator_id_norm.is_some() && bls_pk_norm.is_some() {
        return Err("Bitte nur validator_id oder bls_pk setzen (nicht beides).".to_string());
    }

    let mint_lock_norm = match args.mint_lock.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(normalize_hex_32(s, "mint_lock")?),
        _ => None,
    };
    if args.pow_miner {
        if let Some(amount) = args.mint_amount {
            if amount == 0 {
                return Err("mint_amount muss > 0 sein (oder leer/auto).".to_string());
            }
        }
        if mint_lock_norm.is_none() {
            return Err("pow_miner benötigt mint_lock.".to_string());
        }
    }

    // Persist bootstrap_peers.json (no implicit examples; empty is fine).
    let peers_path = store_dir_abs.join("bootstrap_peers.json");
    const MAX_PEERS: usize = 256;
    const MAX_ADDR_LEN: usize = 1024;
    const MAX_CERT_LEN: usize = 4096;
    let mut peers: Vec<BootstrapPeerEntryDisk> = Vec::new();
    for p in args.bootstrap_peers.iter().cloned() {
        let addr = p.addr.trim().to_string();
        let cert_file = p.cert_file.trim().to_string();
        if addr.is_empty() && cert_file.is_empty() {
            continue;
        }
        if addr.is_empty() || cert_file.is_empty() {
            return Err("Bootstrap-Peer muss Adresse und Zertifikat-Datei enthalten".to_string());
        }
        if addr.len() > MAX_ADDR_LEN {
            return Err(format!(
                "Bootstrap-Adresse ist zu lang (max {MAX_ADDR_LEN})"
            ));
        }
        if cert_file.len() > MAX_CERT_LEN {
            return Err(format!(
                "Bootstrap-Zertifikat-Pfad ist zu lang (max {MAX_CERT_LEN})"
            ));
        }
        peers.push(BootstrapPeerEntryDisk { addr, cert_file });
        if peers.len() > MAX_PEERS {
            return Err(format!("Zu viele Bootstrap-Peers (max {MAX_PEERS})"));
        }
    }
    write_json_file_atomic(&peers_path, &BootstrapPeersFileDisk { peers })?;

    ensure_genesis_note(&mempool_dir_abs)?;
    let genesis_note_path = mempool_dir_abs.join("genesis_note.bin");
    let genesis_note = load_genesis_note_exact(&genesis_note_path)?;
    let committee_k = genesis_note.params.committee_k;
    if committee_k == 0 || committee_k > 64 {
        return Err(format!(
            "genesis_note committee_k ungültig: {} (erwartet 1..=64)",
            committee_k
        ));
    }
    let genesis_network_id = hex::encode(digest_genesis_note(&genesis_note));
    let genesis_validators_enabled =
        (genesis_note.params.features & GENESIS_FEATURE_GENESIS_VALIDATORS_V1) != 0;
    let genesis_validators_count = if genesis_validators_enabled && genesis_note.version >= 1 {
        genesis_note.genesis_validators.len()
    } else {
        0usize
    };
    let mut genesis_identity_source: Option<String> = None;
    let mut genesis_identity_validator: Option<String> = None;
    let mut genesis_identity_bls: Option<String> = None;
    let validator_passphrase = args
        .validator_passphrase
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    if args.tx_proposer && committee_k == 1 && validator_passphrase.is_empty() {
        return Err(
            "committee_k=1 + tx_proposer benötigt validator_passphrase, damit lokale Finalisierung aktiv ist und Mining-Auszahlungen on-chain finalisiert werden. Bitte im Node-Tab das Feld 'Validator-Passphrase' ausfüllen."
                .to_string(),
        );
    }
    if args.override_validator_control && !args.tx_proposer && genesis_validators_count > 0 {
        let genesis_validator_pairs: Vec<(String, String)> = genesis_note
            .genesis_validators
            .iter()
            .map(|v| (hex::encode(v.operator_id), hex::encode(v.bls_pk)))
            .collect();

        let mut selected: Option<(String, String, String)> = None;
        if let Some(pk) = bls_pk_norm.as_deref() {
            if let Some((vid, bpk)) = genesis_validator_pairs
                .iter()
                .find(|(_, bpk)| bpk.eq_ignore_ascii_case(pk))
            {
                selected = Some((vid.clone(), bpk.clone(), "cfg.bls_pk".to_string()));
            }
        }
        if selected.is_none() {
            if let Some(vid) = validator_id_norm.as_deref() {
                if let Some((m_vid, bpk)) = genesis_validator_pairs
                    .iter()
                    .find(|(m_vid, _)| m_vid.eq_ignore_ascii_case(vid))
                {
                    selected = Some((m_vid.clone(), bpk.clone(), "cfg.validator_id".to_string()));
                }
            }
        }
        if selected.is_none() {
            let (keystore_path, loc) = resolve_validator_keystore_path(&store_dir_abs);
            if keystore_path.exists() {
                if let Ok(signer_path) = find_phantom_signer_binary() {
                    if let Ok(keystore_pk) = validator_bls_pub_inner(&signer_path, &keystore_path) {
                        if let Some((m_vid, bpk)) = genesis_validator_pairs
                            .iter()
                            .find(|(_, bpk)| bpk.eq_ignore_ascii_case(&keystore_pk))
                        {
                            let src = match loc {
                                ValidatorKeystoreLocation::StoreDir => "keystore.store_dir",
                                ValidatorKeystoreLocation::GlobalFallback => {
                                    "keystore.global_fallback"
                                }
                                ValidatorKeystoreLocation::Missing => "keystore.missing",
                            };
                            selected = Some((m_vid.clone(), bpk.clone(), src.to_string()));
                        }
                    }
                }
            }
        }
        if selected.is_none() && genesis_validator_pairs.len() == 1 {
            if let Some((vid, bpk)) = genesis_validator_pairs.first() {
                selected = Some((
                    vid.clone(),
                    bpk.clone(),
                    "genesis.sole_genesis_validator".to_string(),
                ));
            }
        }
        if let Some((m_vid, bpk, src)) = selected {
            validator_id_norm = None;
            bls_pk_norm = Some(bpk.clone());
            genesis_identity_source = Some(src);
            genesis_identity_validator = Some(m_vid);
            genesis_identity_bls = Some(bpk);
        } else {
            let expected_ids: Vec<String> = genesis_validator_pairs
                .iter()
                .map(|(vid, _)| vid.clone())
                .collect();
            let expected_bls: Vec<String> = genesis_validator_pairs
                .iter()
                .map(|(_, bpk)| bpk.clone())
                .collect();
            return Err(format!(
                "Genesis-Validator konnte nicht automatisch aufgelöst werden. Erwartete validator_id(s): {} | bls_pk(s): {}",
                expected_ids.join(", "),
                expected_bls.join(", ")
            ));
        }
    }
    if args.tx_proposer && validator_id_norm.is_none() && bls_pk_norm.is_none() {
        return Err("tx_proposer benötigt validator_id oder bls_pk.".to_string());
    }
    if args.tx_proposer && committee_k == 1 {
        let role_bls_pk = bls_pk_norm.as_deref().ok_or_else(|| {
            "committee_k=1 + tx_proposer benötigt bls_pk (für lokale Finalisierung).".to_string()
        })?;
        let signer_bin = find_phantom_signer_binary()?;
        let (keystore_path, _loc) = resolve_validator_keystore_path(&store_dir_abs);
        if !keystore_path.exists() {
            return Err(format!(
                "committee_k=1 + tx_proposer: Validator-Keystore nicht gefunden ({})",
                keystore_path.display()
            ));
        }
        let keystore_pk = validator_bls_pub_inner(&signer_bin, &keystore_path)
            .map_err(|e| format!("Validator-Keystore PubKey nicht lesbar: {e}"))?;
        if !keystore_pk.eq_ignore_ascii_case(role_bls_pk) {
            return Err(format!(
                "committee_k=1 + tx_proposer: Keystore-BLS passt nicht zu role bls_pk (keystore={}, role={})",
                keystore_pk, role_bls_pk
            ));
        }
        let preflight_msg = [0u8; 32];
        signer_bls_sign_message(
            &signer_bin,
            &keystore_path,
            validator_passphrase.as_str(),
            args.use_passphrase_role,
            &preflight_msg,
        )
        .map_err(|e| format!("Validator-Passphrase/BLS-Preflight fehlgeschlagen: {e}"))?;
    }

    if args.override_validator_control {
        let vc_path = store_dir_abs.join(VALIDATOR_CONTROL_FILENAME);
        write_validator_control_override(&vc_path)?;
    }

    let phantom_node = find_phantom_node_binary()?;
    let status_http_bin: Option<PathBuf> = if status_http_addr.is_some() {
        Some(find_status_http_binary()?)
    } else {
        None
    };
    let mint_rpc_bin: Option<PathBuf> = if mint_rpc_addr.is_some() {
        Some(find_mint_rpc_binary()?)
    } else {
        None
    };

    let token = args
        .bearer_token
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(
            "Bearer-Token ist leer (StatusServe require_auth=true benötigt ein Token).".to_string(),
        );
    }
    let token_file = write_auth_token_file(&app, &token)?;

    let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let log_path = store_dir_abs.join("dashboard-node.log");
    match set_node_log_mirror(log_path.clone()) {
        Ok(()) => {
            push_node_log(&logs, format!("[NODE] log_file: {}", log_path.display()));
        }
        Err(e) => {
            push_node_log(
                &logs,
                format!("[NODE-ERR] log_file init fehlgeschlagen: {e}"),
            );
        }
    }

    let mut cleanup_ports = vec![p2p_addr.port(), status_addr.port()];
    if let Some(sa) = status_http_addr.as_ref() {
        cleanup_ports.push(sa.port());
    }
    if let Some(ma) = mint_rpc_addr.as_ref() {
        cleanup_ports.push(ma.port());
    }
    if let Some(ma) = args.metrics_addr.as_deref() {
        if let Some(p) = parse_port_from_addr(ma) {
            cleanup_ports.push(p);
        }
    }
    cleanup_orphan_phantom_processes(&cleanup_ports, &store_dir_abs, &logs);
    push_node_log(
        &logs,
        format!("[NODE] phantom-node: {}", phantom_node.display()),
    );
    push_node_log(
        &logs,
        format!("[NODE] store_dir: {}", store_dir_abs.display()),
    );
    push_node_log(
        &logs,
        format!(
            "[NODE] genesis network_id={} version={} committee_k={} features=0x{:x} genesis_validators={}",
            genesis_network_id,
            genesis_note.version,
            committee_k,
            genesis_note.params.features,
            genesis_validators_count
        ),
    );
    if let Some(source) = genesis_identity_source.as_deref() {
        push_node_log(
            &logs,
            format!(
                "[NODE] genesis_identity source={} validator_id={} bls_pk={}",
                source,
                genesis_identity_validator.as_deref().unwrap_or("-"),
                genesis_identity_bls.as_deref().unwrap_or("-")
            ),
        );
    }
    let role_validator_id = validator_id_norm
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let role_bls_pk = bls_pk_norm
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    push_node_log(
        &logs,
        format!(
            "[NODE] role_args tx_proposer={} pow_miner={} validator_id={} bls_pk={}",
            args.tx_proposer, args.pow_miner, role_validator_id, role_bls_pk
        ),
    );
    push_node_log(&logs, format!("[NODE] p2p_listen: {}", p2p_addr));
    push_node_log(&logs, format!("[NODE] status_addr: {}", status_addr));
    if let Some(sa) = status_http_addr.as_ref() {
        push_node_log(&logs, format!("[NODE] status_http_addr: {}", sa));
    }
    if let Some(ma) = mint_rpc_addr.as_ref() {
        push_node_log(&logs, format!("[NODE] mint_rpc_addr: {}", ma));
    }

    // Start P2P runtime first.
    let mut cmd_p2p = Command::new(&phantom_node);
    cmd_p2p
        .env("RUST_LOG", "info")
        .arg("p2p-quic-listen")
        .arg("--addr")
        .arg(p2p_addr.to_string())
        .arg("--store-dir")
        .arg(store_dir_abs.to_string_lossy().to_string())
        .arg("--k")
        .arg(committee_k.to_string())
        .arg("--cert-out")
        .arg(
            store_dir_abs
                .join("p2p_quic_cert.der")
                .to_string_lossy()
                .to_string(),
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if args.tx_proposer {
        cmd_p2p.arg("--tx-proposer");
    }
    if args.pow_miner {
        cmd_p2p.arg("--pow-miner");
    }
    if let Some(amount) = args.mint_amount {
        cmd_p2p.arg("--mint-amount").arg(amount.to_string());
    }
    if let Some(lock) = mint_lock_norm.as_ref() {
        cmd_p2p.arg("--mint-lock").arg(lock);
    }
    if let Some(vid) = validator_id_norm.as_ref() {
        cmd_p2p.arg("--validator-id").arg(vid);
    }
    if let Some(pk) = bls_pk_norm.as_ref() {
        cmd_p2p.arg("--bls-pk").arg(pk);
    }
    if !p2p_addr.ip().is_loopback() {
        cmd_p2p.arg("--unsafe-confirm");
    }
    if let Some(ma) = args.metrics_addr.as_deref() {
        let ma = ma.trim();
        if !ma.is_empty() {
            cmd_p2p.arg("--metrics-addr").arg(ma);
        }
    }

    let mut p2p_child = cmd_p2p
        .spawn()
        .map_err(|e| format!("P2P Start fehlgeschlagen: {e}"))?;
    p2p_child = attach_child_logs("P2P", p2p_child, Arc::clone(&logs));

    std::thread::sleep(std::time::Duration::from_millis(1200));

    // Start status-serve (HTTP endpoints for UI).
    let mut cmd_status = Command::new(&phantom_node);
    cmd_status
        .arg("status-serve")
        .arg("--addr")
        .arg(status_addr.to_string())
        .arg("--mempool-dir")
        .arg(mempool_dir_abs.to_string_lossy().to_string())
        .arg("--store-dir")
        .arg(store_dir_abs.to_string_lossy().to_string())
        .arg("--auth-token-file")
        .arg(token_file.to_string_lossy().to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let status_child = match cmd_status.spawn() {
        Ok(c) => c,
        Err(e) => {
            // Avoid leaving behind a running child when the second process fails to start.
            let _ = p2p_child.kill();
            let _ = p2p_child.wait();
            return Err(format!("StatusServe Start fehlgeschlagen: {e}"));
        }
    };
    let mut status_child = attach_child_logs("STATUS", status_child, Arc::clone(&logs));
    if let Err(e) = wait_for_p2p_cert_ready(
        &store_dir_abs.join("p2p_quic_cert.der"),
        Duration::from_secs(10),
    )
    .and_then(|_| {
        wait_for_status_serve_ready(status_addr, &mut status_child, Duration::from_secs(20))
    }) {
        let _ = status_child.kill();
        let _ = status_child.wait();
        let _ = p2p_child.kill();
        let _ = p2p_child.wait();
        return Err(e);
    }

    let mut status_http_child: Option<std::process::Child> = None;
    if let (Some(bin), Some(addr)) = (status_http_bin.as_ref(), status_http_addr.as_ref()) {
        let mut cmd = Command::new(bin);
        cmd.arg("--addr")
            .arg(addr.to_string())
            .arg("--store-dir")
            .arg(store_dir_abs.to_string_lossy().to_string())
            .arg("--auth-token-file")
            .arg(token_file.to_string_lossy().to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = status_child.kill();
                let _ = status_child.wait();
                let _ = p2p_child.kill();
                let _ = p2p_child.wait();
                return Err(format!("status_http Start fehlgeschlagen: {e}"));
            }
        };
        status_http_child = Some(attach_child_logs("STATUSHTTP", child, Arc::clone(&logs)));
    }

    let mut mint_rpc_child: Option<std::process::Child> = None;
    if let (Some(bin), Some(addr)) = (mint_rpc_bin.as_ref(), mint_rpc_addr.as_ref()) {
        let mut cmd = Command::new(bin);
        cmd.arg("--addr")
            .arg(addr.to_string())
            .arg("--store-dir")
            .arg(store_dir_abs.to_string_lossy().to_string())
            .arg("--mempool-dir")
            .arg(mempool_dir_abs.to_string_lossy().to_string())
            .arg("--genesis-note")
            .arg(
                mempool_dir_abs
                    .join("genesis_note.bin")
                    .to_string_lossy()
                    .to_string(),
            )
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                if let Some(mut sh) = status_http_child.take() {
                    let _ = sh.kill();
                    let _ = sh.wait();
                }
                let _ = status_child.kill();
                let _ = status_child.wait();
                let _ = p2p_child.kill();
                let _ = p2p_child.wait();
                return Err(format!("mint_rpc Start fehlgeschlagen: {e}"));
            }
        };
        mint_rpc_child = Some(attach_child_logs("MINT", child, Arc::clone(&logs)));
    }

    let started_at_ts = now_secs_u64();
    let mut finalizer_stop: Option<Arc<AtomicBool>> = None;

    if args.tx_proposer && committee_k > 1 {
        push_node_log(
            &logs,
            format!(
                "[FINALIZER] deaktiviert: committee_k={} > 1, lokaler Single-Seat-Finalizer kann nicht allein finalisieren",
                committee_k
            ),
        );
    }
    if args.tx_proposer && committee_k == 1 {
        let msg = if genesis_validators_enabled {
            "[FINALIZER] committee_k=1: lokale Seat-Auswahl erfolgt statebasiert mit Genesis-Validator-Fallback"
                .to_string()
        } else {
            "[FINALIZER] committee_k=1: lokale Seat-Auswahl erfolgt rein statebasiert".to_string()
        };
        push_node_log(&logs, msg);
    }
    if args.tx_proposer && committee_k == 1 {
        if validator_passphrase.is_empty() {
            push_node_log(
                &logs,
                "[FINALIZER] deaktiviert: validator_passphrase leer (keine lokale Finalisierung)"
                    .to_string(),
            );
        } else if let Some(pk) = bls_pk_norm.as_ref() {
            match (find_phantom_signer_binary(), find_phantom_node_binary()) {
                (Ok(signer_bin), Ok(node_bin)) => {
                    finalizer_stop = maybe_start_local_single_seat_finalizer(
                        Arc::clone(&logs),
                        node_bin,
                        signer_bin,
                        store_dir_abs.clone(),
                        status_addr.to_string(),
                        token.clone(),
                        args.p2p_listen_addr.clone(),
                        pk.clone(),
                        validator_passphrase.clone(),
                        args.use_passphrase_role,
                    );
                }
                (Err(e), _) => {
                    push_node_log(
                        &logs,
                        format!("[FINALIZER] deaktiviert: phantom-signer nicht gefunden ({e})"),
                    );
                }
                (_, Err(e)) => {
                    push_node_log(
                        &logs,
                        format!(
                            "[FINALIZER] deaktiviert: phantom-node binary nicht gefunden ({e})"
                        ),
                    );
                }
            }
        } else {
            push_node_log(
                &logs,
                "[FINALIZER] deaktiviert: bls_pk nicht gesetzt".to_string(),
            );
        }
    }

    let mut cfg_sanitized = args.clone();
    cfg_sanitized.validator_passphrase = None;

    *inner = Some(ManagedNodeHandle {
        logs,
        started_at_ts,
        store_dir_abs,
        cfg: cfg_sanitized,
        p2p: p2p_child,
        status: status_child,
        status_http: status_http_child,
        mint_rpc: mint_rpc_child,
        finalizer_stop,
    });

    Ok(ManagedNodeStatus {
        running: true,
        p2p_running: true,
        status_running: true,
        status_http_running: status_http_addr.is_some(),
        mint_rpc_running: mint_rpc_addr.is_some(),
        tx_proposer_enabled: args.tx_proposer,
        pow_miner_enabled: args.pow_miner,
        mint_lock_hex: mint_lock_norm,
        started_at_ts: Some(started_at_ts),
        p2p_listen_addr: Some(args.p2p_listen_addr),
        status_addr: Some(args.status_addr),
        status_http_addr: args.status_http_addr.clone(),
        mint_rpc_addr: args.mint_rpc_addr.clone(),
        store_dir: Some(args.store_dir),
        metrics_addr: args.metrics_addr,
        last_error: None,
    })
}

#[command]
pub(crate) fn node_stop(state: tauri::State<'_, NodeService>) -> Result<(), String> {
    stop_node_service_sync(&state);
    Ok(())
}

#[command]
pub(crate) fn node_status(
    state: tauri::State<'_, NodeService>,
) -> Result<ManagedNodeStatus, String> {
    let mut inner = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let Some(h) = inner.as_mut() else {
        return Ok(ManagedNodeStatus {
            running: false,
            p2p_running: false,
            status_running: false,
            status_http_running: false,
            mint_rpc_running: false,
            tx_proposer_enabled: false,
            pow_miner_enabled: false,
            mint_lock_hex: None,
            started_at_ts: None,
            p2p_listen_addr: None,
            status_addr: None,
            status_http_addr: None,
            mint_rpc_addr: None,
            store_dir: None,
            metrics_addr: None,
            last_error: None,
        });
    };

    let mut last_error: Option<String> = None;
    let (p2p_running, p2p_exit) = match h.p2p.try_wait() {
        Ok(Some(es)) => (false, Some(es)),
        Ok(None) => (true, None),
        Err(e) => {
            last_error = Some(format!("p2p try_wait failed: {e}"));
            (true, None)
        }
    };
    if let Some(es) = p2p_exit {
        last_error = Some(format!(
            "p2p exited ({})",
            es.code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string())
        ));
    }

    let (status_running, status_exit) = match h.status.try_wait() {
        Ok(Some(es)) => (false, Some(es)),
        Ok(None) => (true, None),
        Err(e) => {
            if last_error.is_none() {
                last_error = Some(format!("status try_wait failed: {e}"));
            }
            (true, None)
        }
    };
    if let Some(es) = status_exit {
        if last_error.is_none() {
            last_error = Some(format!(
                "status-serve exited ({})",
                es.code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string())
            ));
        }
    }

    let mut status_http_running = false;
    if let Some(sh) = h.status_http.as_mut() {
        match sh.try_wait() {
            Ok(Some(es)) => {
                status_http_running = false;
                if last_error.is_none() {
                    last_error = Some(format!(
                        "status_http exited ({})",
                        es.code()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "signal".to_string())
                    ));
                }
                h.status_http = None;
            }
            Ok(None) => {
                status_http_running = true;
            }
            Err(e) => {
                status_http_running = true;
                if last_error.is_none() {
                    last_error = Some(format!("status_http try_wait failed: {e}"));
                }
            }
        }
    }

    let mut mint_rpc_running = false;
    if let Some(mint) = h.mint_rpc.as_mut() {
        match mint.try_wait() {
            Ok(Some(es)) => {
                mint_rpc_running = false;
                if last_error.is_none() {
                    last_error = Some(format!(
                        "mint_rpc exited ({})",
                        es.code()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "signal".to_string())
                    ));
                }
                h.mint_rpc = None;
            }
            Ok(None) => {
                mint_rpc_running = true;
            }
            Err(e) => {
                mint_rpc_running = true;
                if last_error.is_none() {
                    last_error = Some(format!("mint_rpc try_wait failed: {e}"));
                }
            }
        }
    }

    let cfg_has_status_http = h.cfg.status_http_addr.as_deref().unwrap_or("").trim() != "";
    let cfg_has_mint_rpc = h.cfg.mint_rpc_addr.as_deref().unwrap_or("").trim() != "";

    Ok(ManagedNodeStatus {
        running: p2p_running
            && status_running
            && (!cfg_has_status_http || status_http_running)
            && (!cfg_has_mint_rpc || mint_rpc_running),
        p2p_running,
        status_running,
        status_http_running,
        mint_rpc_running,
        tx_proposer_enabled: h.cfg.tx_proposer,
        pow_miner_enabled: h.cfg.pow_miner,
        mint_lock_hex: h.cfg.mint_lock.clone(),
        started_at_ts: Some(h.started_at_ts),
        p2p_listen_addr: Some(h.cfg.p2p_listen_addr.clone()),
        status_addr: Some(h.cfg.status_addr.clone()),
        status_http_addr: h.cfg.status_http_addr.clone(),
        mint_rpc_addr: h.cfg.mint_rpc_addr.clone(),
        store_dir: Some(h.cfg.store_dir.clone()),
        metrics_addr: h.cfg.metrics_addr.clone(),
        last_error,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct NodeLogsArgs {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[command]
pub(crate) fn node_logs(
    state: tauri::State<'_, NodeService>,
    args: NodeLogsArgs,
) -> Result<Vec<String>, String> {
    let limit = args.limit.unwrap_or(1000).clamp(1, 5000);
    let inner = match state.inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let Some(h) = inner.as_ref() else {
        return Ok(Vec::new());
    };
    let logs = match h.logs.lock() {
        Ok(l) => l,
        Err(e) => e.into_inner(),
    };
    let start = logs.len().saturating_sub(limit);
    Ok(logs[start..].to_vec())
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct NodeBackupArgs {
    pub store_dir: String,
    pub backup_target: String,
    #[serde(default)]
    pub local_node_addr: Option<String>,
    #[serde(default)]
    pub mint_rpc_addr: Option<String>,
    #[serde(default)]
    pub p2p_listen_addr: Option<String>,
    #[serde(default)]
    pub metrics_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NodeBackupResp {
    pub ok: bool,
    pub dst: String,
    pub config_path: Option<String>,
}

#[command]
pub(crate) fn node_backup_store(
    app: tauri::AppHandle,
    state: tauri::State<'_, NodeService>,
    args: NodeBackupArgs,
) -> Result<NodeBackupResp, String> {
    {
        let inner = match state.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if inner.is_some() {
            return Err("Backup kann nur erstellt werden, wenn der Node gestoppt ist.".to_string());
        }
    }

    let src = resolve_existing_store_dir_path_for_app(&app, &args.store_dir)?;

    let backup_str = args.backup_target.trim();
    if backup_str.is_empty() {
        return Err("Backup-Ziel ist leer.".to_string());
    }
    if backup_str.len() > 4096 || backup_str.contains('\0') {
        return Err("Backup-Ziel ist ungültig.".to_string());
    }
    let dst = PathBuf::from(backup_str);
    if !dst.is_absolute() {
        return Err("Backup-Ziel muss ein absoluter Pfad sein.".to_string());
    }

    let device_path = dst.parent().unwrap_or(&dst);
    if !device_path.exists() {
        return Err(format!(
            "Backup-Ziel-Laufwerk oder Ordner existiert nicht: {}",
            device_path.display()
        ));
    }
    match same_device(&src, device_path) {
        Ok(true) => {
            return Err(
                "Backup abgelehnt: Store-Verzeichnis und Backup-Ziel liegen auf derselben Festplatte.".to_string(),
            );
        }
        Ok(false) => {}
        Err(e) => {
            return Err(format!("Dateisystem konnte nicht geprüft werden: {e}"));
        }
    }

    copy_dir_recursive(&src, &dst)?;

    let cfg_path = dst.join("phantom-node-config.txt");
    let mut cfg = String::new();
    cfg.push_str("Lokale Node-Adresse: ");
    cfg.push_str(args.local_node_addr.as_deref().unwrap_or("").trim());
    cfg.push('\n');
    cfg.push_str("Store-Verzeichnis: ");
    cfg.push_str(args.store_dir.trim());
    cfg.push('\n');
    cfg.push_str("Mint-RPC-Adresse: ");
    cfg.push_str(args.mint_rpc_addr.as_deref().unwrap_or("").trim());
    cfg.push('\n');
    cfg.push_str("P2P-Listen-Adresse: ");
    cfg.push_str(args.p2p_listen_addr.as_deref().unwrap_or("").trim());
    cfg.push('\n');
    cfg.push_str("Bootstrap-Datei: ");
    cfg.push_str(&src.join("bootstrap_peers.json").to_string_lossy());
    cfg.push('\n');
    cfg.push_str("Metrics-URL: ");
    cfg.push_str(args.metrics_url.as_deref().unwrap_or("").trim());
    cfg.push('\n');

    let config_path = match fs::write(&cfg_path, cfg) {
        Ok(()) => Some(cfg_path.to_string_lossy().to_string()),
        Err(_) => None,
    };

    Ok(NodeBackupResp {
        ok: true,
        dst: dst.to_string_lossy().to_string(),
        config_path,
    })
}

pub(crate) fn build_status_http_pinned_client(
    store_dir_abs: &Path,
) -> Result<reqwest::Client, String> {
    let ca_path = store_dir_abs.join("server.crt");
    let data = fs::read(&ca_path)
        .map_err(|e| format!("tls_ca lesen fehlgeschlagen ({}): {e}", ca_path.display()))?;
    let cert = reqwest::Certificate::from_pem(&data).map_err(|e| {
        format!(
            "tls_ca ist ungültig ({}): {e} (erwartet PEM)",
            ca_path.display()
        )
    })?;
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .build()
        .map_err(|e| format!("HTTP client build fehlgeschlagen: {e}"))
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct NodeWalletByLockArgs {
    pub lock_hex: String,
}

pub(crate) async fn status_http_get(
    status_http_addr: &str,
    token: &str,
    client: &reqwest::Client,
    path: &str,
) -> Result<String, String> {
    let url = format!("https://{}{}", status_http_addr.trim(), path);
    let mut req = client.get(url);
    if !token.trim().is_empty() {
        req = req.bearer_auth(token.trim());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("StatusHTTP Request fehlgeschlagen: {e}"))?;

    let status = resp.status();
    const MAX_HTTP_BODY_BYTES: usize = 8 * 1024 * 1024;
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("StatusHTTP Antwort nicht lesbar: {e}"))?;
    if bytes.len() > MAX_HTTP_BODY_BYTES {
        return Err(format!(
            "StatusHTTP Antwort ist zu groß: {} bytes (max {} bytes)",
            bytes.len(),
            MAX_HTTP_BODY_BYTES
        ));
    }
    let body = String::from_utf8(bytes.to_vec())
        .map_err(|_| "StatusHTTP Antwort ist nicht UTF-8".to_string())?;
    if !status.is_success() {
        return Err(format!("StatusHTTP {}: {}", status.as_u16(), body));
    }
    Ok(body)
}

pub(crate) async fn status_serve_get(
    status_addr: &str,
    token: &str,
    client: &reqwest::Client,
    path: &str,
) -> Result<String, String> {
    let base = validate_loopback_base_url(&format!("http://{}", status_addr.trim()))?;
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let mut req = client.get(url);
    if !token.trim().is_empty() {
        req = req.bearer_auth(token.trim());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("StatusServe Request fehlgeschlagen: {e}"))?;

    let status = resp.status();
    const MAX_HTTP_BODY_BYTES: usize = 8 * 1024 * 1024;
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("StatusServe Antwort nicht lesbar: {e}"))?;
    if bytes.len() > MAX_HTTP_BODY_BYTES {
        return Err(format!(
            "StatusServe Antwort ist zu groß: {} bytes (max {} bytes)",
            bytes.len(),
            MAX_HTTP_BODY_BYTES
        ));
    }
    let body = String::from_utf8(bytes.to_vec())
        .map_err(|_| "StatusServe Antwort ist nicht UTF-8".to_string())?;
    if !status.is_success() {
        return Err(format!("StatusServe {}: {}", status.as_u16(), body));
    }
    Ok(body)
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StatusServeLocalPrevoteContextResp {
    ok: bool,
    network_id: String,
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalFinalizerPrevote {
    network_id: [u8; 32],
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StatusServeLocalPrecommitContextResp {
    ok: bool,
    network_id: String,
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
    post_state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalFinalizerPrecommit {
    network_id: [u8; 32],
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
    committed_state_root: [u8; 32],
}

async fn status_serve_local_prevote_context(
    status_addr: &str,
    token: &str,
    client: &reqwest::Client,
    payload_root: [u8; 32],
    bls_pk_hex: &str,
) -> Result<LocalFinalizerPrevote, String> {
    let path = format!(
        "/consensus/local_prevote_context?payload_root={}&bls_pk={}",
        hex::encode(payload_root),
        bls_pk_hex
    );
    let body = status_serve_get(status_addr, token, client, &path).await?;
    let value: StatusServeLocalPrevoteContextResp = serde_json::from_str(&body)
        .map_err(|e| format!("StatusServe LocalPrevoteContext-JSON ungültig: {e}"))?;
    if !value.ok {
        return Err(format!(
            "StatusServe LocalPrevoteContext-Antwort nicht ok: {}",
            body
        ));
    }
    let network_id = parse_hex_32(&value.network_id)
        .ok_or_else(|| format!("StatusServe Antwort ohne gültige network_id: {}", body))?;
    Ok(LocalFinalizerPrevote {
        network_id,
        vote_epoch: value.vote_epoch,
        creator_index: value.creator_index,
        vote_mask: value.vote_mask,
    })
}

async fn status_serve_local_precommit_context(
    status_addr: &str,
    token: &str,
    client: &reqwest::Client,
    payload_root: [u8; 32],
    bls_pk_hex: &str,
) -> Result<LocalFinalizerPrecommit, String> {
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(payload_root),
        bls_pk_hex
    );
    let body = status_serve_get(status_addr, token, client, &path).await?;
    let value: StatusServeLocalPrecommitContextResp = serde_json::from_str(&body)
        .map_err(|e| format!("StatusServe LocalPrecommitContext-JSON ungültig: {e}"))?;
    if !value.ok {
        return Err(format!(
            "StatusServe LocalPrecommitContext-Antwort nicht ok: {}",
            body
        ));
    }
    let network_id = parse_hex_32(&value.network_id)
        .ok_or_else(|| format!("StatusServe Antwort ohne gültige network_id: {}", body))?;
    let committed_state_root = parse_hex_32(&value.post_state_root).ok_or_else(|| {
        format!(
            "StatusServe Antwort ohne gültigen post_state_root: {}",
            body
        )
    })?;
    Ok(LocalFinalizerPrecommit {
        network_id,
        vote_epoch: value.vote_epoch,
        creator_index: value.creator_index,
        vote_mask: value.vote_mask,
        committed_state_root,
    })
}

async fn resolve_local_finalizer_precommit(
    status_addr: &str,
    token: &str,
    client: &reqwest::Client,
    payload_root: [u8; 32],
    bls_pk_hex: &str,
) -> Result<LocalFinalizerPrecommit, String> {
    status_serve_local_precommit_context(status_addr, token, client, payload_root, bls_pk_hex).await
}

async fn resolve_local_finalizer_prevote(
    status_addr: &str,
    token: &str,
    client: &reqwest::Client,
    payload_root: [u8; 32],
    bls_pk_hex: &str,
) -> Result<LocalFinalizerPrevote, String> {
    status_serve_local_prevote_context(status_addr, token, client, payload_root, bls_pk_hex).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_codec::Encodable;
    use pc_consensus::{compute_total_payout_root, FeeSplitParams};
    use pc_crypto::{attestor_recipient_id_from_bls, bls_keygen_from_ikm, bls_pop_prove};
    use pc_types::{
        digest_genesis_note, genesis_payload_root, AnchorPayloadV3, GenesisNote, GenesisParams,
        GenesisValidatorV1, GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
    };
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration as StdDuration, Instant};

    struct LiveStatusServe {
        temp_dir: PathBuf,
        child: Child,
        addr: String,
        token: String,
        payload_root: [u8; 32],
        bls_pk_hex: String,
        network_id: [u8; 32],
    }

    impl Drop for LiveStatusServe {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }

    fn unique_test_dir(prefix: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "{}_{}_{}",
            prefix,
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        dir
    }

    fn free_port() -> Result<u16, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("bind free port failed: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("read local addr failed: {e}"))?
            .port();
        drop(listener);
        Ok(port)
    }

    fn write_test_genesis(
        mempool_dir: &Path,
        kp: &pc_crypto::BlsKeypair,
    ) -> Result<GenesisNote, String> {
        let note = GenesisNote {
            version: 3,
            network_name: b"dashboard-live-precommit".to_vec(),
            seed: [0x44; 32],
            params: GenesisParams {
                shards_initial: 1,
                committee_k: 1,
                txs_per_payload: 16,
                features: GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
            },
            genesis_validators: vec![GenesisValidatorV1 {
                operator_id: [0x55; 32],
                bls_pk: kp.pk.to_bytes(),
                bls_pop: bls_pop_prove(&kp.sk),
            }],
            genesis_message: vec![],
            emission_bootstrap_bucket: 1_773_964_800,
        };
        let mut note_buf = Vec::new();
        note.encode(&mut note_buf)
            .map_err(|e| format!("encode genesis note failed: {e}"))?;
        std::fs::create_dir_all(mempool_dir)
            .map_err(|e| format!("create mempool dir failed: {e}"))?;
        std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)
            .map_err(|e| format!("write genesis note failed: {e}"))?;
        let store_dir = mempool_dir
            .parent()
            .ok_or_else(|| "mempool_dir must have parent".to_string())?;
        std::fs::write(
            store_dir.join("last_final_payload_root"),
            hex::encode(genesis_payload_root(&note)),
        )
        .map_err(|e| format!("write last_final_payload_root failed: {e}"))?;
        Ok(note)
    }

    fn expected_test_payout_root(kp: &pc_crypto::BlsKeypair) -> Result<[u8; 32], String> {
        let params = FeeSplitParams::recommended();
        let recipients = [attestor_recipient_id_from_bls(&kp.pk)];
        let ack_distances = [None];
        compute_total_payout_root(0, &params, &recipients, 0, &ack_distances, &[])
            .map_err(|e| format!("compute payout root failed: {e:?}"))
    }

    fn write_legacy_payload_v3(
        store_dir: &Path,
        payload: &AnchorPayloadV3,
    ) -> Result<[u8; 32], String> {
        let payload_root = pc_types::payload_merkle_root_v3(payload);
        let payloads_dir = store_dir.join("payloads");
        std::fs::create_dir_all(&payloads_dir)
            .map_err(|e| format!("create payload dir failed: {e}"))?;
        let mut buf = Vec::new();
        payload
            .encode(&mut buf)
            .map_err(|e| format!("encode payload failed: {e}"))?;
        std::fs::write(
            payloads_dir.join(format!("{}.bin", hex::encode(payload_root))),
            buf,
        )
        .map_err(|e| format!("write payload failed: {e}"))?;
        Ok(payload_root)
    }

    async fn wait_ready(
        client: &reqwest::Client,
        addr: &str,
        child: &mut Child,
    ) -> Result<(), String> {
        let deadline = Instant::now() + StdDuration::from_secs(20);
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| format!("poll child failed: {e}"))?
            {
                return Err(format!("status-serve exited early: {status}"));
            }
            if Instant::now() > deadline {
                return Err("status-serve not ready in time".to_string());
            }
            match client.get(format!("http://{addr}/readyz")).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(StdDuration::from_millis(100)).await,
            }
        }
    }

    async fn spawn_live_status_serve() -> Result<LiveStatusServe, String> {
        let store_dir = unique_test_dir("dashboard-live-precommit");
        let mempool_dir = store_dir.join("mempool");
        std::fs::create_dir_all(&mempool_dir)
            .map_err(|e| format!("create mempool dir failed: {e}"))?;
        std::fs::write(store_dir.join("anchor_index"), b"0")
            .map_err(|e| format!("write anchor_index failed: {e}"))?;

        let ikm = [0x91u8; 32];
        let kp = bls_keygen_from_ikm(&ikm).ok_or_else(|| "bls keygen failed".to_string())?;
        let note = write_test_genesis(&mempool_dir, &kp)?;
        let network_id = digest_genesis_note(&note);
        let payload = AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: expected_test_payout_root(&kp)?,
            genesis_note: Some(note),
            null_mint: false,
        };
        let payload_root = write_legacy_payload_v3(&store_dir, &payload)?;
        let token = "dashboard-precommit-secret".to_string();
        let token_file = store_dir.join("status.token");
        std::fs::write(&token_file, format!("{token}\n"))
            .map_err(|e| format!("write token file failed: {e}"))?;

        let addr = format!("127.0.0.1:{}", free_port()?);
        let phantom_node = find_phantom_node_binary()?;
        let mut child = Command::new(&phantom_node)
            .arg("status-serve")
            .arg("--addr")
            .arg(&addr)
            .arg("--mempool-dir")
            .arg(mempool_dir.to_string_lossy().to_string())
            .arg("--store-dir")
            .arg(store_dir.to_string_lossy().to_string())
            .arg("--auth-token-file")
            .arg(token_file.to_string_lossy().to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn status-serve failed: {e}"))?;

        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| format!("reqwest client build failed: {e}"))?;
        wait_ready(&client, &addr, &mut child).await?;

        Ok(LiveStatusServe {
            temp_dir: store_dir,
            child,
            addr,
            token,
            payload_root,
            bls_pk_hex: hex::encode(kp.pk.to_bytes()),
            network_id,
        })
    }

    #[test]
    fn ensure_genesis_note_replaces_legacy_note_and_purges_runtime_state() {
        let store_dir = unique_test_dir("canonical_genesis_auto_purge");
        let result = (|| -> Result<(), String> {
            let mempool_dir = store_dir.join("mempool");
            let kp =
                bls_keygen_from_ikm(&[0x77; 32]).ok_or_else(|| "bls keygen failed".to_string())?;

            write_test_genesis(&mempool_dir, &kp)?;
            std::fs::create_dir_all(store_dir.join("utxo"))
                .map_err(|e| format!("create utxo dir failed: {e}"))?;
            std::fs::create_dir_all(store_dir.join("payload_segments"))
                .map_err(|e| format!("create payload segments dir failed: {e}"))?;
            std::fs::create_dir_all(mempool_dir.join("mints"))
                .map_err(|e| format!("create mints dir failed: {e}"))?;
            std::fs::create_dir_all(mempool_dir.join("mint_seeds"))
                .map_err(|e| format!("create mint seeds dir failed: {e}"))?;
            std::fs::write(store_dir.join("anchor_index"), "1112")
                .map_err(|e| format!("write anchor_index failed: {e}"))?;
            std::fs::write(mempool_dir.join("supply_state.json"), b"{}")
                .map_err(|e| format!("write supply state failed: {e}"))?;
            std::fs::write(mempool_dir.join("stale.bin"), [0x42])
                .map_err(|e| format!("write stale mint failed: {e}"))?;
            std::fs::write(mempool_dir.join("mint_seeds").join("deadbeef"), b"1")
                .map_err(|e| format!("write seed marker failed: {e}"))?;

            ensure_genesis_note(&mempool_dir)?;

            let installed = std::fs::read(mempool_dir.join("genesis_note.bin"))
                .map_err(|e| format!("read canonical genesis failed: {e}"))?;
            assert_eq!(installed.as_slice(), CANONICAL_GENESIS_NOTE);
            assert!(!store_dir.join("utxo").exists());
            assert!(!store_dir.join("payload_segments").exists());
            assert!(!store_dir.join("anchor_index").exists());
            assert!(!store_dir.join("last_final_payload_root").exists());
            assert!(!mempool_dir.join("mints").exists());
            assert!(!mempool_dir.join("mint_seeds").exists());
            assert!(!mempool_dir.join("supply_state.json").exists());
            assert!(!mempool_dir.join("stale.bin").exists());

            let backup_dir = mempool_dir.join("genesis-note-backups");
            assert!(backup_dir.exists());
            let backup_count = std::fs::read_dir(&backup_dir)
                .map_err(|e| format!("read backup dir failed: {e}"))?
                .count();
            assert_eq!(backup_count, 1);
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&store_dir);
        result.expect(
            "ensure_genesis_note should purge stale runtime state on canonical replacement",
        );
    }

    #[test]
    fn canonical_genesis_note_matches_reset_baseline() {
        let note = decode_canonical_genesis_note().expect("decode canonical genesis note");
        let mut encoded = Vec::new();
        note.encode(&mut encoded)
            .expect("re-encode canonical genesis note");
        assert_eq!(encoded.as_slice(), CANONICAL_GENESIS_NOTE);
        assert_eq!(note.version, 1);
        assert_eq!(note.network_name, b"phantom-mainnet".to_vec());
        assert_eq!(
            hex::encode(digest_genesis_note(&note)),
            "d4d309537274b9f8e0c8e5a067d6f8b9ba898773bcd203e8e106db08ed9023f6"
        );
        assert_eq!(
            canonical_genesis_network_id_hex().expect("canonical network id"),
            "d4d309537274b9f8e0c8e5a067d6f8b9ba898773bcd203e8e106db08ed9023f6"
        );
    }

    #[test]
    fn finalizer_work_key_distinguishes_same_root_across_parent_tips() {
        let root = [0x11; 32];
        let parent_a = Some(AnchorId([0x22; 32]));
        let parent_b = Some(AnchorId([0x33; 32]));

        assert_eq!(
            finalizer_work_key(root, parent_a),
            finalizer_work_key(root, parent_a)
        );
        assert_ne!(
            finalizer_work_key(root, parent_a),
            finalizer_work_key(root, parent_b)
        );
        assert_ne!(
            finalizer_work_key(root, None),
            finalizer_work_key(root, parent_a)
        );
    }

    #[tokio::test]
    async fn resolve_local_finalizer_prevote_uses_authoritative_node_context() {
        let server = spawn_live_status_serve()
            .await
            .expect("spawn live status-serve");
        let client = reqwest::Client::builder()
            .build()
            .expect("reqwest client build");

        let resolved = resolve_local_finalizer_prevote(
            &server.addr,
            &server.token,
            &client,
            server.payload_root,
            &server.bls_pk_hex,
        )
        .await
        .expect("resolve local finalizer prevote");

        let body = status_serve_get(
            &server.addr,
            &server.token,
            &client,
            &format!(
                "/consensus/local_prevote_context?payload_root={}&bls_pk={}",
                hex::encode(server.payload_root),
                server.bls_pk_hex
            ),
        )
        .await
        .expect("fetch local prevote context");
        let raw: StatusServeLocalPrevoteContextResp =
            serde_json::from_str(&body).expect("decode local prevote context response");

        assert!(raw.ok);
        assert_eq!(raw.network_id, hex::encode(server.network_id));
        assert_eq!(raw.vote_epoch, 0);
        assert_eq!(raw.creator_index, 0);
        assert_eq!(raw.vote_mask, 1);
        assert_eq!(
            resolved.network_id,
            parse_hex_32(&raw.network_id).expect("network_id hex")
        );
        assert_eq!(resolved.vote_epoch, raw.vote_epoch);
        assert_eq!(resolved.creator_index, raw.creator_index);
        assert_eq!(resolved.vote_mask, raw.vote_mask);
    }

    #[tokio::test]
    async fn resolve_local_finalizer_precommit_uses_authoritative_node_context() {
        let server = spawn_live_status_serve()
            .await
            .expect("spawn live status-serve");
        let client = reqwest::Client::builder()
            .build()
            .expect("reqwest client build");

        let resolved = resolve_local_finalizer_precommit(
            &server.addr,
            &server.token,
            &client,
            server.payload_root,
            &server.bls_pk_hex,
        )
        .await
        .expect("resolve local finalizer precommit");

        let body = status_serve_get(
            &server.addr,
            &server.token,
            &client,
            &format!(
                "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
                hex::encode(server.payload_root),
                server.bls_pk_hex
            ),
        )
        .await
        .expect("fetch local precommit context");
        let raw: StatusServeLocalPrecommitContextResp =
            serde_json::from_str(&body).expect("decode local precommit context response");

        assert!(raw.ok);
        assert_eq!(raw.network_id, hex::encode(server.network_id));
        assert_eq!(raw.vote_epoch, 0);
        assert_eq!(raw.creator_index, 0);
        assert_eq!(raw.vote_mask, 1);
        assert_eq!(
            resolved.network_id,
            parse_hex_32(&raw.network_id).expect("network_id hex")
        );
        assert_eq!(resolved.vote_epoch, raw.vote_epoch);
        assert_eq!(resolved.creator_index, raw.creator_index);
        assert_eq!(resolved.vote_mask, raw.vote_mask);
        assert_eq!(
            resolved.committed_state_root,
            parse_hex_32(&raw.post_state_root).expect("post_state_root hex")
        );
    }

    #[tokio::test]
    async fn resolve_local_finalizer_precommit_surfaces_unauthorized_from_live_node() {
        let server = spawn_live_status_serve()
            .await
            .expect("spawn live status-serve");
        let client = reqwest::Client::builder()
            .build()
            .expect("reqwest client build");

        let err = resolve_local_finalizer_precommit(
            &server.addr,
            "",
            &client,
            server.payload_root,
            &server.bls_pk_hex,
        )
        .await
        .expect_err("missing bearer token must fail");

        assert!(err.contains("401"), "unexpected error: {err}");
        assert!(err.contains("unauthorized"), "unexpected error: {err}");
    }
}

#[command]
pub(crate) async fn node_wallet_utxos_by_lock(
    state: tauri::State<'_, NodeService>,
    args: NodeWalletByLockArgs,
) -> Result<String, String> {
    let (status_http_addr, token, store_dir_abs) = {
        let inner = match state.inner.lock() {
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
            .unwrap_or("")
            .trim()
            .to_string();
        if addr.is_empty() {
            return Err("StatusHTTP ist nicht konfiguriert (status_http_addr fehlt)".to_string());
        }
        let token = h
            .cfg
            .bearer_token
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_string();
        if token.is_empty() {
            return Err("Bearer-Token fehlt".to_string());
        }
        (addr, token, h.store_dir_abs.clone())
    };

    let lock = parse_hex_32(&args.lock_hex)
        .ok_or_else(|| "lock_hex ist ungültig (erwartet 32-Byte Hex)".to_string())?;
    let lock_hex = hex::encode(lock);
    let client = build_status_http_pinned_client(&store_dir_abs)?;
    status_http_get(
        &status_http_addr,
        &token,
        &client,
        &format!("/wallet/utxos_by_lock/{}", lock_hex),
    )
    .await
}

#[command]
pub(crate) async fn node_wallet_history(
    state: tauri::State<'_, NodeService>,
    args: NodeWalletByLockArgs,
) -> Result<String, String> {
    let (status_http_addr, token, store_dir_abs) = {
        let inner = match state.inner.lock() {
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
            .unwrap_or("")
            .trim()
            .to_string();
        if addr.is_empty() {
            return Err("StatusHTTP ist nicht konfiguriert (status_http_addr fehlt)".to_string());
        }
        let token = h
            .cfg
            .bearer_token
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_string();
        if token.is_empty() {
            return Err("Bearer-Token fehlt".to_string());
        }
        (addr, token, h.store_dir_abs.clone())
    };

    let lock = parse_hex_32(&args.lock_hex)
        .ok_or_else(|| "lock_hex ist ungültig (erwartet 32-Byte Hex)".to_string())?;
    let lock_hex = hex::encode(lock);
    let client = build_status_http_pinned_client(&store_dir_abs)?;
    status_http_get(
        &status_http_addr,
        &token,
        &client,
        &format!("/wallet/history/{}", lock_hex),
    )
    .await
}

#[command]
pub(crate) async fn node_consensus_validators(
    state: tauri::State<'_, NodeService>,
) -> Result<String, String> {
    let (status_http_addr, token, store_dir_abs) = {
        let inner = match state.inner.lock() {
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
            .unwrap_or("")
            .trim()
            .to_string();
        if addr.is_empty() {
            return Err("StatusHTTP ist nicht konfiguriert (status_http_addr fehlt)".to_string());
        }
        let token = h
            .cfg
            .bearer_token
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_string();
        if token.is_empty() {
            return Err("Bearer-Token fehlt".to_string());
        }
        (addr, token, h.store_dir_abs.clone())
    };

    let client = build_status_http_pinned_client(&store_dir_abs)?;
    status_http_get(&status_http_addr, &token, &client, "/consensus/validators").await
}
