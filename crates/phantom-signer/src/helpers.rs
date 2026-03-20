use super::*;

pub(crate) enum BitboxTransport {
    Usb,
    Bridge,
}

pub(crate) fn bitbox_transport_mode() -> String {
    env::var("PHANTOM_BITBOX_TRANSPORT")
        .unwrap_or_else(|_| "auto".to_string())
        .to_lowercase()
}

pub(crate) fn bitbox_bridge_url() -> String {
    env::var("PHANTOM_BITBOX_BRIDGE_URL").unwrap_or_else(|_| "http://127.0.0.1:8178".to_string())
}

pub(crate) fn bitbox_bridge_opt_in_enabled() -> bool {
    matches!(
        env::var("PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE"),
        Ok(v) if matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    )
}

pub(crate) fn ensure_bitbox_bridge_opt_in() -> Result<()> {
    if bitbox_bridge_opt_in_enabled() {
        return Ok(());
    }
    Err(anyhow!(
        "BitBox bridge is disabled by default; set PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE=1 to opt in explicitly"
    ))
}

pub(crate) fn bitbox_noise_config() -> Result<Box<dyn NoiseConfig>> {
    let home = env::var("HOME").context("HOME not set for BitBox noise config")?;
    let config_dir = PathBuf::from(home).join(".phantom").join("bitbox");
    fs::create_dir_all(&config_dir)
        .with_context(|| format!("create BitBox noise config dir '{}'", config_dir.display()))?;
    Ok(Box::new(PersistedNoiseConfig::new(
        &config_dir.to_string_lossy(),
    )))
}

pub(crate) fn bitbox_connect_usb() -> Result<bitbox_api::BitBox<DefaultRuntime>> {
    let device = usb::get_any_bitbox02().map_err(|e| anyhow!("bitbox usb: {e}"))?;
    let noise_cfg = bitbox_noise_config()?;
    let bitbox = block_on(bitbox_api::BitBox::<DefaultRuntime>::from_hid_device(
        device, noise_cfg,
    ))
    .map_err(|e| anyhow!("bitbox connect (usb): {e:?}"))?;
    Ok(bitbox)
}

pub(crate) fn bitbox_connect_bridge() -> Result<bitbox_api::BitBox<DefaultRuntime>> {
    ensure_bitbox_bridge_opt_in()?;
    let bridge_url = bitbox_bridge_url();
    let noise_cfg = bitbox_noise_config()?;
    let bitbox = block_on(bitbox_api::bridge::connect_any_bitbox02::<DefaultRuntime>(
        &bridge_url,
        noise_cfg,
    ))
    .map_err(|e| anyhow!("bitbox connect (bridge): {e}"))?;
    Ok(bitbox)
}

pub(crate) fn bitbox_pair(
    bitbox: bitbox_api::BitBox<DefaultRuntime>,
) -> Result<bitbox_api::PairedBitBox<DefaultRuntime>> {
    let pairing_bitbox =
        block_on(bitbox.unlock_and_pair()).map_err(|e| anyhow!("bitbox unlock/pair: {e:?}"))?;

    if let Some(code) = pairing_bitbox.get_pairing_code().as_ref() {
        eprintln!("BitBox pairing code:\n{}", code);
    }

    let paired = block_on(pairing_bitbox.wait_confirm())
        .map_err(|e| anyhow!("bitbox wait_confirm: {e:?}"))?;

    Ok(paired)
}

pub(crate) fn bitbox_connect_paired(
) -> Result<(bitbox_api::PairedBitBox<DefaultRuntime>, BitboxTransport)> {
    let mode = bitbox_transport_mode();
    let want_usb = mode != "bridge";
    let want_bridge = mode != "usb";

    let mut usb_err: Option<anyhow::Error> = None;
    let mut bridge_err: Option<anyhow::Error> = None;

    if want_usb {
        match bitbox_connect_usb() {
            Ok(bitbox) => return Ok((bitbox_pair(bitbox)?, BitboxTransport::Usb)),
            Err(e) => usb_err = Some(e),
        }
    }

    if want_bridge {
        match bitbox_connect_bridge() {
            Ok(bitbox) => return Ok((bitbox_pair(bitbox)?, BitboxTransport::Bridge)),
            Err(e) => bridge_err = Some(e),
        }
    }

    let mut msg = String::from("BitBox02 Verbindung fehlgeschlagen.");
    if let Some(e) = usb_err {
        msg.push_str(&format!(" USB: {}", e));
    }
    if let Some(e) = bridge_err {
        msg.push_str(&format!(" Bridge: {}", e));
    }
    Err(anyhow!(msg))
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SignerConfig {
    pub node_url: Option<String>,
    pub auth_token: Option<String>,
    pub auth_token_file: Option<String>,
    pub tls_ca: Option<String>,
    pub tls_client_pem: Option<String>,
}

pub(crate) fn load_signer_config(p: &Path) -> Result<SignerConfig> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Best-effort: warn if the config file is readable by group/others and contains secrets.
        if let Ok(meta) = std::fs::metadata(p) {
            let mode = meta.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                eprintln!(
                    "WARNUNG: Signer-Config ist für Gruppe/Andere lesbar (mode {:o}). Wenn sie auth_token enthält, ist das ein Secret-Leak-Risiko. Empfehlung: chmod 600 {}",
                    mode,
                    p.display()
                );
            }
        }
    }
    let raw = fs::read_to_string(p)?;
    let cfg: SignerConfig = toml::from_str(&raw)?;
    if cfg.auth_token.is_some() {
        eprintln!(
            "WARNUNG: auth_token in TOML-Config ist Klartext. Empfehlung: --auth-token-file oder auth_token_file nutzen (und Config-Datei 0o600)."
        );
    }
    Ok(cfg)
}

pub(crate) fn read_secret_file_trimmed(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(raw.trim().to_string())
}

#[cfg(unix)]
pub(crate) fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub(crate) fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

pub(crate) fn resolve_hwi_binary() -> Result<PathBuf> {
    if let Ok(p) = env::var("PHANTOM_HWI_PATH") {
        let s = p.trim();
        if s.is_empty() {
            return Err(anyhow!("PHANTOM_HWI_PATH ist leer"));
        }
        let pb = PathBuf::from(s);
        if !cfg!(debug_assertions) && !pb.is_absolute() {
            return Err(anyhow!(
                "PHANTOM_HWI_PATH muss ein absoluter Pfad sein (Release-Härtung)"
            ));
        }
        if !is_executable_file(&pb) {
            return Err(anyhow!(
                "PHANTOM_HWI_PATH zeigt nicht auf eine ausführbare Datei: {}",
                pb.display()
            ));
        }
        return Ok(pb);
    }

    // Prefer a bundled sibling binary if present.
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("hwi");
            if is_executable_file(&cand) {
                return Ok(cand);
            }
            #[cfg(windows)]
            {
                for ext in ["exe", "cmd", "bat", "com"] {
                    let c2 = cand.with_extension(ext);
                    if is_executable_file(&c2) {
                        return Ok(c2);
                    }
                }
            }
        }
    }

    // Common install locations (avoid PATH in release by default).
    // macOS (brew): /opt/homebrew/bin/hwi or /usr/local/bin/hwi
    // Linux: /usr/bin/hwi or /usr/local/bin/hwi
    let common = [
        "/opt/homebrew/bin/hwi",
        "/usr/local/bin/hwi",
        "/usr/bin/hwi",
    ];
    for p in common {
        let pb = PathBuf::from(p);
        if is_executable_file(&pb) {
            return Ok(pb);
        }
    }

    if cfg!(debug_assertions) {
        // Debug convenience: allow PATH-resolved tools.
        return Ok(PathBuf::from("hwi"));
    }

    Err(anyhow!(
        "hwi ist nicht konfiguriert. Setze PHANTOM_HWI_PATH auf den absoluten Pfad zu hwi"
    ))
}

pub(crate) fn resolve_bitbox2_signer_binary(external_cmd: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = external_cmd {
        return Ok(p);
    }
    if let Ok(p) = env::var("PHANTOM_BITBOX2_SIGNER") {
        let s = p.trim();
        if s.is_empty() {
            return Err(anyhow!("PHANTOM_BITBOX2_SIGNER ist leer"));
        }
        let pb = PathBuf::from(s);
        if !cfg!(debug_assertions) && !pb.is_absolute() {
            return Err(anyhow!(
                "PHANTOM_BITBOX2_SIGNER muss ein absoluter Pfad sein (Release-Härtung)"
            ));
        }
        if pb.is_absolute() && !is_executable_file(&pb) {
            return Err(anyhow!(
                "PHANTOM_BITBOX2_SIGNER zeigt nicht auf eine ausführbare Datei: {}",
                pb.display()
            ));
        }
        return Ok(pb);
    }
    Ok(PathBuf::from("bitbox02-signer"))
}

pub(crate) fn resolve_auth_token(
    cli_token: Option<String>,
    cli_token_file: Option<PathBuf>,
    cfg: Option<&SignerConfig>,
) -> Result<Option<String>> {
    if let Some(p) = cli_token_file {
        let t = read_secret_file_trimmed(&p)?;
        return Ok(if t.is_empty() { None } else { Some(t) });
    }
    if let Some(t) = cli_token {
        if !cfg!(debug_assertions) {
            return Err(anyhow!(
                "--auth-token ist in Release-Builds deaktiviert (Token-Leak via Prozessliste). Nutze --auth-token-file."
            ));
        }
        let tt = t.trim().to_string();
        return Ok(if tt.is_empty() { None } else { Some(tt) });
    }
    if let Some(c) = cfg {
        if let Some(ref p) = c.auth_token_file {
            let t = read_secret_file_trimmed(Path::new(p))?;
            if !t.is_empty() {
                return Ok(Some(t));
            }
        }
        if let Some(ref t) = c.auth_token {
            let tt = t.trim().to_string();
            if !tt.is_empty() {
                return Ok(Some(tt));
            }
        }
    }
    if let Ok(env_t) = std::env::var("PHANTOM_STATUS_AUTH_TOKEN") {
        let tt = env_t.trim().to_string();
        if !tt.is_empty() {
            return Ok(Some(tt));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedNodeConfig {
    pub node_url: String,
    pub auth_token: Option<String>,
    pub tls_ca: Option<PathBuf>,
    pub tls_client_pem: Option<PathBuf>,
}

pub(crate) fn resolve_node_config(
    node: String,
    default_node_url: &str,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    tls_ca: Option<PathBuf>,
    tls_client_pem: Option<PathBuf>,
    cfg: Option<&SignerConfig>,
) -> Result<ResolvedNodeConfig> {
    let node_url = if node == default_node_url {
        if let Some(c) = cfg {
            c.node_url.clone().unwrap_or(node)
        } else {
            node
        }
    } else {
        node
    };

    let auth_token = resolve_auth_token(auth_token, auth_token_file, cfg)?;

    let tls_ca: Option<PathBuf> = match tls_ca {
        Some(p) => Some(p),
        None => cfg.and_then(|c| c.tls_ca.clone()).map(PathBuf::from),
    };
    let tls_client_pem: Option<PathBuf> = match tls_client_pem {
        Some(p) => Some(p),
        None => cfg
            .and_then(|c| c.tls_client_pem.clone())
            .map(PathBuf::from),
    };

    Ok(ResolvedNodeConfig {
        node_url,
        auth_token,
        tls_ca,
        tls_client_pem,
    })
}

pub(crate) fn resolve_import_secret_hex(
    secret_hex: Option<String>,
    secret_file: Option<PathBuf>,
    secret_env: Option<String>,
) -> Result<String> {
    let mut sources = 0usize;
    if secret_hex.is_some() {
        sources = sources.saturating_add(1);
    }
    if secret_file.is_some() {
        sources = sources.saturating_add(1);
    }
    if secret_env.is_some() {
        sources = sources.saturating_add(1);
    }
    if sources != 1 {
        return Err(anyhow!(
            "genau eine Secret-Quelle angeben: --secret-hex ODER --secret-file ODER --secret-env"
        ));
    }

    if let Some(h) = secret_hex {
        if !cfg!(debug_assertions) {
            return Err(anyhow!(
                "--secret-hex ist in Release-Builds deaktiviert (Secret-Leak via Prozessliste). Nutze --secret-file oder --secret-env."
            ));
        }
        let trimmed = h.trim().to_string();
        if trimmed.is_empty() {
            return Err(anyhow!("secret_hex leer"));
        }
        return Ok(trimmed);
    }
    if let Some(path) = secret_file {
        return read_secret_file_trimmed(&path);
    }
    if let Some(name) = secret_env {
        let mut v = env::var(&name).with_context(|| format!("read secret env {}", name))?;
        let trimmed = v.trim().to_string();
        v.zeroize();
        if trimmed.is_empty() {
            return Err(anyhow!("secret env ist leer"));
        }
        return Ok(trimmed);
    }

    Err(anyhow!("keine Secret-Quelle angegeben"))
}

pub(crate) fn parse_network_id_hex(s: &str) -> Result<NetworkId> {
    let raw = hex::decode(s).map_err(|e| anyhow!("network-id ist kein hex: {e}"))?;
    if raw.len() != 32 {
        return Err(anyhow!(
            "network-id muss 32 bytes sein (64 hex Zeichen), ist aber {} bytes",
            raw.len()
        ));
    }
    let mut nid = [0u8; 32];
    nid.copy_from_slice(&raw);
    Ok(nid)
}

pub(crate) const DEFAULT_RPC_TIMEOUT_SECS: u64 = 10;
pub(crate) const DEFAULT_RPC_CONNECT_TIMEOUT_SECS: u64 = 5;
pub(crate) const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub(crate) fn parse_http_url(url: &str) -> Result<reqwest::Url> {
    let parsed = reqwest::Url::parse(url).map_err(|e| anyhow!("invalid URL '{url}': {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => {
            return Err(anyhow!(
                "unsupported URL scheme '{s}' (only http/https are allowed)"
            ))
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(anyhow!("URL must not contain username/password"));
    }
    if parsed.host_str().is_none() {
        return Err(anyhow!("URL missing host"));
    }
    Ok(parsed)
}

pub(crate) fn ensure_bearer_transport_safe(url: &reqwest::Url, auth: Option<&str>) -> Result<()> {
    let Some(_) = auth.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let host = url.host_str().ok_or_else(|| anyhow!("URL missing host"))?;
    if !is_loopback_host(host) && url.scheme() != "https" {
        return Err(anyhow!(
            "refusing to send bearer token to non-loopback host over non-HTTPS: {}",
            url
        ));
    }
    Ok(())
}
