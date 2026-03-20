use super::*;

pub(crate) fn is_loopback_host_str(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub(crate) fn find_system_bin(name: &str) -> Option<PathBuf> {
    // Avoid PATH hijacking: only execute from standard system directories.
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let p = Path::new(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn ps_command_any(pid: u32) -> Option<String> {
    let ps = find_system_bin("ps")?;
    let out = Command::new(ps)
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn ps_command_any(_pid: u32) -> Option<String> {
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn pid_is_alive(pid: u32) -> bool {
    let Some(ps) = find_system_bin("ps") else {
        return false;
    };
    let out = Command::new(ps)
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output();
    let Ok(out) = out else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    !String::from_utf8_lossy(&out.stdout).trim().is_empty()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn pid_is_alive(_pid: u32) -> bool {
    false
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn kill_pid(pid: u32, signal: &str) -> bool {
    let Some(kill) = find_system_bin("kill") else {
        return false;
    };
    Command::new(kill)
        .args([signal, &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn kill_pid(_pid: u32, _signal: &str) -> bool {
    false
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn pids_listening_on_port(port: u16) -> Vec<u32> {
    let Some(lsof_bin) = find_system_bin("lsof") else {
        return Vec::new();
    };
    let out = Command::new(lsof_bin)
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .output();
    let Ok(out) = out else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut pids = HashSet::new();
    for (idx, line) in s.lines().enumerate() {
        if idx == 0 {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _cmd = parts.next().unwrap_or("");
        let pid_s = parts.next().unwrap_or("");
        if let Ok(pid) = pid_s.parse::<u32>() {
            pids.insert(pid);
        }
    }
    pids.into_iter().collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn pids_listening_on_port(_port: u16) -> Vec<u32> {
    Vec::new()
}

pub(crate) fn is_phantom_cmdline(cmdline: &str) -> bool {
    let low = cmdline.to_lowercase();
    low.contains("phantom-node")
        || low.contains("status-serve")
        || low.contains("status_http")
        || low.contains("mint_rpc")
        || low.contains("phantom-dashboard")
}

pub(crate) fn cmdline_mentions_store_dir(cmdline: &str, store_dir_abs: &Path) -> bool {
    let needle = store_dir_abs.to_string_lossy();
    !needle.is_empty() && cmdline.contains(needle.as_ref())
}

pub(crate) fn cleanup_orphan_phantom_processes(
    ports: &[u16],
    store_dir_abs: &Path,
    logs: &Arc<Mutex<Vec<String>>>,
) {
    if ports.is_empty() {
        return;
    }
    if find_system_bin("lsof").is_none() {
        push_node_log(
            logs,
            "[CLEANUP] lsof fehlt; Ports können nicht geprüft werden.".to_string(),
        );
        return;
    }
    if find_system_bin("ps").is_none() || find_system_bin("kill").is_none() {
        push_node_log(
            logs,
            "[CLEANUP] ps/kill fehlt; Prozesse können nicht beendet werden.".to_string(),
        );
        return;
    }

    let mut unique_ports = HashSet::new();
    let mut pids = HashSet::new();
    for port in ports.iter().copied() {
        if port == 0 || !unique_ports.insert(port) {
            continue;
        }
        for pid in pids_listening_on_port(port) {
            pids.insert(pid);
        }
    }

    if pids.is_empty() {
        return;
    }

    for pid in pids {
        if pid == std::process::id() {
            continue;
        }
        let Some(cmdline) = ps_command_any(pid) else {
            continue;
        };
        if !is_phantom_cmdline(&cmdline) {
            continue;
        }
        if !cmdline_mentions_store_dir(&cmdline, store_dir_abs) {
            push_node_log(
                logs,
                format!("[CLEANUP] Überspringe Prozess {pid} (anderes store_dir): {cmdline}"),
            );
            continue;
        }
        push_node_log(logs, format!("[CLEANUP] Beende Prozess {pid}: {cmdline}"));
        let _ = kill_pid(pid, "-TERM");
        std::thread::sleep(Duration::from_millis(250));
        if pid_is_alive(pid) {
            let _ = kill_pid(pid, "-KILL");
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn list_processes_with_cmdline() -> Vec<(u32, String)> {
    let Some(ps) = find_system_bin("ps") else {
        return Vec::new();
    };
    let out = Command::new(ps).args(["-Ao", "pid=,command="]).output();
    let Ok(out) = out else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let pid_s = fields.next().unwrap_or("");
        let Ok(pid) = pid_s.parse::<u32>() else {
            continue;
        };
        let cmdline = trimmed
            .get(pid_s.len()..)
            .map(|s| s.trim_start().to_string())
            .unwrap_or_default();
        if cmdline.is_empty() {
            continue;
        }
        rows.push((pid, cmdline));
    }
    rows
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn list_processes_with_cmdline() -> Vec<(u32, String)> {
    Vec::new()
}

pub(crate) fn startup_cleanup_orphan_phantom_processes(app: &tauri::AppHandle) {
    if find_system_bin("ps").is_none() || find_system_bin("kill").is_none() {
        return;
    }
    let app_data = match app_data_dir(app) {
        Ok(p) => p,
        Err(_) => return,
    };
    let app_data_raw = app_data.to_string_lossy().to_string();
    let app_data_canon = fs::canonicalize(&app_data)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let current_pid = std::process::id();
    let mut killed = 0usize;
    for (pid, cmdline) in list_processes_with_cmdline() {
        if pid == current_pid {
            continue;
        }
        if !is_phantom_cmdline(&cmdline) {
            continue;
        }
        let in_app_data = cmdline.contains(&app_data_raw)
            || app_data_canon
                .as_ref()
                .map(|canon| cmdline.contains(canon))
                .unwrap_or(false);
        if !in_app_data {
            continue;
        }
        eprintln!("[STARTUP-CLEANUP] Beende verwaisten Prozess {pid}: {cmdline}");
        let _ = kill_pid(pid, "-TERM");
        std::thread::sleep(Duration::from_millis(250));
        if pid_is_alive(pid) {
            let _ = kill_pid(pid, "-KILL");
        }
        killed = killed.saturating_add(1);
    }
    if killed > 0 {
        eprintln!("[STARTUP-CLEANUP] {killed} verwaiste Phantom-Prozesse beendet");
    }
}

pub(crate) fn validate_loopback_http_url(url: &str) -> Result<reqwest::Url, String> {
    if url.len() > 4096 {
        return Err("URL ist zu lang".to_string());
    }
    if url.chars().any(|c| c.is_control()) {
        return Err("URL enthält ungültige Zeichen".to_string());
    }

    let parsed = reqwest::Url::parse(url).map_err(|e| format!("URL ungültig: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("Nur http/https URLs sind erlaubt".to_string()),
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err("URL darf keine Username/Password-Komponente enthalten".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL hat keinen Host".to_string())?;
    if !is_loopback_host_str(host) {
        return Err("Nur Loopback-Hosts sind erlaubt (localhost/127.0.0.1/::1)".to_string());
    }
    Ok(parsed)
}

pub(crate) fn validate_http_get_endpoint(url: &reqwest::Url) -> Result<(), String> {
    if url.fragment().is_some() {
        return Err("URL darf kein Fragment enthalten".to_string());
    }
    if url.query().is_some() {
        return Err("URL darf keine Query enthalten".to_string());
    }
    let p = url.path().trim_end_matches('/');
    match p {
        "/status" | "/metrics" | "/consensus/validators" | "/mint/status" => Ok(()),
        _ => Err(
            "Nur /status, /metrics, /consensus/validators oder /mint/status sind erlaubt"
                .to_string(),
        ),
    }
}

pub(crate) fn validate_loopback_base_url(url: &str) -> Result<String, String> {
    let parsed = validate_loopback_http_url(url)?;
    if parsed.fragment().is_some() {
        return Err("URL darf kein Fragment enthalten".to_string());
    }
    if parsed.query().is_some() {
        return Err("URL darf keine Query enthalten".to_string());
    }
    let p = parsed.path();
    if !p.is_empty() && p != "/" {
        return Err("Base-URL darf keinen Path enthalten (nur Schema://Host:Port)".to_string());
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub(crate) fn validate_loopback_socket_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    if addr.len() > 128 {
        return Err("Adresse ist zu lang".to_string());
    }
    if addr.chars().any(|c| c.is_control()) {
        return Err("Adresse enthält ungültige Zeichen".to_string());
    }
    let sa: std::net::SocketAddr = addr
        .trim()
        .parse()
        .map_err(|_| "Adresse ist ungültig (erwartet host:port)".to_string())?;
    if !sa.ip().is_loopback() {
        return Err("Nur Loopback-Adressen sind erlaubt (127.0.0.1/::1)".to_string());
    }
    Ok(sa)
}

pub(crate) fn now_secs_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn now_millis_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(target_family = "unix")]
pub(crate) fn same_device(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let ma = std::fs::metadata(a)?;
    let mb = std::fs::metadata(b)?;
    Ok(ma.dev() == mb.dev())
}

#[cfg(not(target_family = "unix"))]
pub(crate) fn same_device(_a: &Path, _b: &Path) -> std::io::Result<bool> {
    // On non-Unix systems we can't reliably check. Treat as "different" to avoid false positives.
    Ok(false)
}

#[cfg(target_family = "unix")]
pub(crate) fn set_path_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = fs::metadata(path)
        .map_err(|e| format!("Dateirechte nicht lesbar ({}): {e}", path.display()))?
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
        .map_err(|e| format!("Dateirechte nicht setzbar ({}): {e}", path.display()))
}

#[cfg(not(target_family = "unix"))]
pub(crate) fn set_path_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

pub(crate) fn harden_private_file(path: &Path) -> Result<(), String> {
    set_path_mode(path, 0o600)
}

pub(crate) fn harden_private_tree(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("Datei nicht lesbar ({}): {e}", path.display()))?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Ok(());
    }
    if ft.is_file() {
        harden_private_file(path)?;
        return Ok(());
    }
    if ft.is_dir() {
        set_path_mode(path, 0o700)?;
        for entry in fs::read_dir(path)
            .map_err(|e| format!("Verzeichnis nicht lesbar ({}): {e}", path.display()))?
        {
            let entry = entry.map_err(|e| {
                format!("Verzeichniseintrag nicht lesbar ({}): {e}", path.display())
            })?;
            harden_private_tree(&entry.path())?;
        }
    }
    Ok(())
}

pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    let meta =
        fs::symlink_metadata(src).map_err(|e| format!("Quellverzeichnis nicht lesbar: {e}"))?;
    if !meta.is_dir() {
        return Err(format!(
            "Quellverzeichnis existiert nicht oder ist kein Verzeichnis: {}",
            src.display()
        ));
    }

    fs::create_dir_all(dst).map_err(|e| {
        format!(
            "Zielverzeichnis {} konnte nicht erstellt werden: {e}",
            dst.display()
        )
    })?;

    for entry in fs::read_dir(src).map_err(|e| {
        format!(
            "Inhalt von {} konnte nicht gelesen werden: {e}",
            src.display()
        )
    })? {
        let entry = entry
            .map_err(|e| format!("Verzeichniseintrag von {} nicht lesbar: {e}", src.display()))?;
        let file_type = entry.file_type().map_err(|e| {
            format!(
                "Dateityp von {} nicht bestimmbar: {e}",
                entry.path().display()
            )
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path).map_err(|e| {
                format!(
                    "Datei {} konnte nicht nach {} kopiert werden: {e}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
        } else {
            // Symlinks / sockets / etc. are not expected in Phantom data dirs.
            // Skip them to avoid following attacker-controlled links.
            continue;
        }
    }

    Ok(())
}

#[derive(Debug, Serialize)]
pub(crate) struct ValidatorControlOverride {
    pub version: u8,
    pub kill_switch: bool,
    pub maintenance: bool,
    pub manual_disable: bool,
    pub auto_reenable: bool,
    pub reason: String,
    pub updated_at: u64,
    pub cooldown_until: u64,
    pub last_changed_by: String,
}

pub(crate) fn write_validator_control_override(path: &Path) -> Result<(), String> {
    let now = now_secs_u64();
    let ctrl = ValidatorControlOverride {
        version: 1,
        kill_switch: false,
        maintenance: false,
        manual_disable: false,
        auto_reenable: true,
        reason: "genesis override: dashboard".to_string(),
        updated_at: now,
        cooldown_until: 0,
        last_changed_by: "dashboard".to_string(),
    };
    write_json_file_atomic(path, &ctrl)
}

pub(crate) fn copy_file_atomic(src: &Path, dst: &Path) -> Result<(), String> {
    let data =
        fs::read(src).map_err(|e| format!("Quelldatei nicht lesbar: {}: {e}", src.display()))?;

    let dir = dst
        .parent()
        .ok_or_else(|| "Zieldateipfad ist ungültig".to_string())?;
    fs::create_dir_all(dir)
        .map_err(|e| format!("Zielordner nicht erstellbar: {}: {e}", dir.display()))?;

    let file_name = dst
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "data".to_string());

    let mut last_err: Option<String> = None;
    for _ in 0..16 {
        let mut nonce = [0u8; 8];
        AeadOsRng.fill_bytes(&mut nonce);
        let tmp_name = format!(".{file_name}.{}.tmp", hex::encode(nonce));
        let tmp_path = dir.join(tmp_name);

        let opened = {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(target_family = "unix")]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            opts.open(&tmp_path)
        };
        let mut f = match opened {
            Ok(h) => h,
            Err(e) => {
                last_err = Some(format!("Temp-Datei nicht anlegbar: {e}"));
                continue;
            }
        };

        f.write_all(&data)
            .map_err(|e| format!("Temp-Datei nicht schreibbar: {e}"))?;
        let _ = f.sync_all();
        drop(f);

        if let Err(e) = fs::rename(&tmp_path, dst) {
            #[cfg(windows)]
            {
                if dst.exists() {
                    let _ = fs::remove_file(dst);
                }
                if let Err(e2) = fs::rename(&tmp_path, dst) {
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

        let _ = harden_private_file(dst);
        return Ok(());
    }

    Err(last_err.unwrap_or_else(|| "Temp-Datei konnte nicht angelegt werden".to_string()))
}
