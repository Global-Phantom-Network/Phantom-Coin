use super::*;

pub(crate) fn read_response_text_limited(
    resp: reqwest::blocking::Response,
    max_bytes: usize,
) -> Result<String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(anyhow!(
                "HTTP response too large (content-length {} > limit {})",
                len,
                max_bytes
            ));
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut r = resp.take((max_bytes + 1) as u64);
    r.read_to_end(&mut buf).context("read HTTP response body")?;
    if buf.len() > max_bytes {
        return Err(anyhow!(
            "HTTP response too large (read {} > limit {})",
            buf.len(),
            max_bytes
        ));
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub(crate) fn send_request_text(
    client: &reqwest::blocking::Client,
    method: reqwest::Method,
    url: &str,
    auth: Option<&str>,
    content_type: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<(reqwest::StatusCode, String)> {
    let url = parse_http_url(url)?;
    ensure_bearer_transport_safe(&url, auth)?;
    let mut req = client.request(method, url);
    if let Some(tok) = auth.map(str::trim).filter(|s| !s.is_empty()) {
        req = req.bearer_auth(tok);
    }
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    if let Some(b) = body {
        req = req.body(b);
    }
    let resp = req.send().context("send HTTP request")?;
    let status = resp.status();
    let text = read_response_text_limited(resp, MAX_HTTP_RESPONSE_BYTES)?;
    Ok((status, text))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BroadcastStateErrorKind {
    MissingInput,
    DoubleSpend,
    Other,
}

pub(crate) fn classify_broadcast_state_error(text: &str) -> Option<BroadcastStateErrorKind> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let code = v.get("state_error").and_then(|x| x.as_str())?;
    Some(match code {
        "missing_input" => BroadcastStateErrorKind::MissingInput,
        "double_spend" => BroadcastStateErrorKind::DoubleSpend,
        _ => BroadcastStateErrorKind::Other,
    })
}

pub(crate) fn fetch_network_id_from_node(
    node_url: &str,
    auth: Option<&str>,
    tls_ca: Option<&Path>,
    tls_client_pem: Option<&Path>,
) -> Result<NetworkId> {
    let url = format!("{}/status", node_url.trim_end_matches('/'));

    let client = build_rpc_client(tls_ca, tls_client_pem)?;
    let (status, text) = send_request_text(&client, reqwest::Method::GET, &url, auth, None, None)?;
    if !status.is_success() {
        return Err(anyhow!("node status fehlgeschlagen: {} {}", status, text));
    }

    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| anyhow!("/status antwort ist kein gültiges JSON: {e}"))?;
    let nid_hex = v
        .get("genesis")
        .and_then(|g| g.get("network_id"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            anyhow!("node liefert keine network-id in /status (genesis_note.bin fehlt?)")
        })?;
    parse_network_id_hex(nid_hex)
}

pub(crate) fn build_rpc_client(
    tls_ca: Option<&Path>,
    tls_client_pem: Option<&Path>,
) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(DEFAULT_RPC_TIMEOUT_SECS))
        .connect_timeout(std::time::Duration::from_secs(
            DEFAULT_RPC_CONNECT_TIMEOUT_SECS,
        ))
        // Redirects can be abused (public URL -> attacker-controlled redirect). Keep it simple and safe by default.
        .redirect(reqwest::redirect::Policy::none());
    if let Some(ca_path) = tls_ca {
        let data =
            fs::read(ca_path).with_context(|| format!("read tls_ca {}", ca_path.display()))?;
        let cert = reqwest::Certificate::from_pem(&data).context("parse tls_ca pem")?;
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert);
    }
    if let Some(pem_path) = tls_client_pem {
        let data = fs::read(pem_path)
            .with_context(|| format!("read tls_client_pem {}", pem_path.display()))?;
        let id = reqwest::Identity::from_pem(&data).context("parse client pem")?;
        builder = builder.identity(id);
    }
    builder.build().context("build http client")
}

pub(crate) fn resolve_network_id_from_cfg_or_arg(
    cfg: Option<&SignerConfig>,
    network_id: Option<String>,
) -> Result<NetworkId> {
    if let Some(s) = network_id {
        return parse_network_id_hex(&s);
    }
    let Some(cfg) = cfg else {
        return Err(anyhow!(
            "network-id fehlt. Bitte gib --network-id <64 hex Zeichen> an oder nutze --config mit node_url"
        ));
    };
    let Some(node_url) = cfg.node_url.as_deref() else {
        return Err(anyhow!(
            "network-id fehlt. Bitte setze node_url in der config oder gib --network-id an"
        ));
    };
    let auth_owned = resolve_auth_token(None, None, Some(cfg))?;
    let auth = auth_owned.as_deref();
    let tls_ca = cfg.tls_ca.as_deref().map(Path::new);
    let tls_client_pem = cfg.tls_client_pem.as_deref().map(Path::new);
    fetch_network_id_from_node(node_url, auth, tls_ca, tls_client_pem)
}

pub(crate) fn default_xpubstore_path(fingerprint: &Option<String>, hrp: &str) -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME not set for default xpubstore path")?;
    let base_dir = PathBuf::from(home).join(".phantom").join("xpubs");
    fs::create_dir_all(&base_dir)
        .with_context(|| format!("create default xpubstore dir '{}'", base_dir.display()))?;

    let mut base = String::from("xpub_");
    base.push_str(hrp);
    if let Some(fp) = fingerprint.as_ref() {
        if !fp.is_empty() {
            base.push('_');
            base.push_str(fp);
        }
    }

    let mut candidate = base_dir.join(format!("{}.toml", base));
    if candidate.exists() {
        let mut idx: u32 = 1;
        loop {
            let cand = base_dir.join(format!("{}_{}.toml", base, idx));
            if !cand.exists() {
                candidate = cand;
                break;
            }
            idx = idx
                .checked_add(1)
                .ok_or_else(|| anyhow!("xpubstore default name overflow"))?;
        }
    }

    Ok(candidate)
}

pub(crate) fn default_walletdb_path(wallet_name: &str) -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME not set for default walletdb path")?;
    let base_dir = PathBuf::from(home).join(".phantom").join("wallets");
    fs::create_dir_all(&base_dir)
        .with_context(|| format!("create default wallets dir '{}'", base_dir.display()))?;
    Ok(base_dir.join(wallet_name))
}

pub(crate) fn default_seedstore_path(wallet_name: &str) -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME not set for default seedstore path")?;
    let base_dir = PathBuf::from(home).join(".phantom").join("seeds");
    fs::create_dir_all(&base_dir)
        .with_context(|| format!("create default seeds dir '{}'", base_dir.display()))?;
    Ok(base_dir.join(format!("{}.toml", wallet_name)))
}

#[cfg(unix)]
pub(crate) fn set_owner_only_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)
        .with_context(|| format!("set permissions {:o} on '{}'", mode, path.display()))?;
    Ok(())
}

pub(crate) fn write_file_atomic_secure(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir '{}'", parent.display()))?;
    }

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("atomic write requires parent directory"))?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid target filename"))?;

    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    let tmp = parent.join(format!(".{}.{}.tmp", file_name, hex::encode(rnd)));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).write(true).mode(0o600);
        let mut f = opts.open(&tmp)?;
        std::io::Write::write_all(&mut f, data)?;
        std::io::Write::flush(&mut f)?;
        let _ = f.sync_data();
    }
    #[cfg(not(unix))]
    {
        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).write(true);
        let mut f = opts.open(&tmp)?;
        std::io::Write::write_all(&mut f, data)?;
        std::io::Write::flush(&mut f)?;
    }

    fs::rename(&tmp, path)
        .with_context(|| format!("atomic rename '{}' -> '{}'", tmp.display(), path.display()))?;
    #[cfg(unix)]
    set_owner_only_mode(path, 0o600)?;
    Ok(())
}

/// Encrypted seed store document. Uses #[serde(default)] for backward compatibility.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct SeedStoreEncDoc {
    pub version: u32,
    pub kind: String,
    pub kdf: KdfSection,
    pub enc: EncSection,
}

impl Default for SeedStoreEncDoc {
    fn default() -> Self {
        Self {
            version: 1,
            kind: "seed_enc".to_string(),
            kdf: KdfSection::default(),
            enc: EncSection::default(),
        }
    }
}

pub(crate) fn save_seed_store_encrypted(
    mnemonic: &Mnemonic,
    path: &Path,
    passphrase: &str,
    force: bool,
) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "SeedStore existiert bereits: {} (--force zum Überschreiben)",
            path.display()
        ));
    }
    let kdf_params = default_kdf_params();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt, &kdf_params)?;

    let plain = mnemonic.to_string().into_bytes();
    let (ct, nonce) = encrypt_secret(&key, &plain)?;

    let doc = SeedStoreEncDoc {
        version: 1,
        kind: "seed_enc".to_string(),
        kdf: KdfSection {
            name: "argon2id".to_string(),
            salt_b64: general_purpose::STANDARD.encode(salt),
            params: kdf_params,
        },
        enc: EncSection {
            cipher: "xchacha20poly1305".to_string(),
            nonce_b64: general_purpose::STANDARD.encode(nonce),
            ct_b64: general_purpose::STANDARD.encode(&ct),
        },
    };

    let data = toml::to_string_pretty(&doc)?;
    write_file_atomic_secure(path, data.as_bytes())?;
    Ok(())
}

pub(crate) fn derive_xpub_from_mnemonic(
    mnemonic: &Mnemonic,
    derivation: &str,
) -> Result<(ExtendedPublicKey<B32SecpPk>, Option<String>)> {
    // Design note (BIP39): the optional BIP39 passphrase is always the empty string ("").
    // The mnemonic is protected at-rest via the encrypted SeedStore passphrase.
    let seed = mnemonic.to_seed("");
    let master: ExtendedPrivateKey<bip32::secp256k1::SecretKey> =
        ExtendedPrivateKey::new(seed).map_err(|e| anyhow!("create master key: {e}"))?;

    let fingerprint = {
        let master_pk = master.public_key();
        let pk_bytes = master_pk.to_bytes();
        let hash = pc_crypto::blake3_32(&pk_bytes);
        hex::encode(hash.get(..4).ok_or_else(|| anyhow!("fingerprint slice"))?)
    };

    let path = DerivationPath::from_str(derivation)
        .map_err(|e| anyhow!("parse derivation path '{}': {e}", derivation))?;

    let mut derived = master;
    for child in path.iter() {
        derived = derived
            .derive_child(child)
            .map_err(|e| anyhow!("derive child: {e}"))?;
    }
    let xpub = derived.public_key();
    Ok((xpub, Some(fingerprint)))
}

pub(crate) fn save_xpub_store_with_passphrase(
    xs: &XpubStore,
    path: &Path,
    passphrase: &str,
    force: bool,
) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "XpubStore existiert bereits: {} (--force zum Überschreiben)",
            path.display()
        ));
    }
    let kdf_params = default_kdf_params();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt, &kdf_params)?;

    let plain = serde_json::to_vec(xs)?;
    let (ct, nonce) = encrypt_secret(&key, &plain)?;

    let doc = XpubStoreEncDoc {
        version: xs.version,
        kind: "xpub_enc".to_string(),
        algo: xs.algo.clone(),
        kdf: KdfSection {
            name: "argon2id".to_string(),
            salt_b64: general_purpose::STANDARD.encode(salt),
            params: kdf_params,
        },
        enc: EncSection {
            cipher: "xchacha20poly1305".to_string(),
            nonce_b64: general_purpose::STANDARD.encode(nonce),
            ct_b64: general_purpose::STANDARD.encode(&ct),
        },
    };

    let data = toml::to_string_pretty(&doc)?;
    write_file_atomic_secure(path, data.as_bytes())?;
    Ok(())
}

pub(crate) fn load_seed_store_mnemonic(path: &Path, passphrase: &str) -> Result<Mnemonic> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("read seedstore '{}'", path.display()))?;
    let doc: SeedStoreEncDoc =
        toml::from_str(&raw).map_err(|e| anyhow!("parse seedstore toml: {e}"))?;
    if doc.kind.as_str() != "seed_enc" {
        return Err(anyhow!(
            "seedstore kind nicht unterstützt: {} (erwartet seed_enc)",
            doc.kind
        ));
    }

    let salt = general_purpose::STANDARD
        .decode(&doc.kdf.salt_b64)
        .map_err(|e| anyhow!("seedstore salt decode: {e}"))?;
    if salt.len() != 16 {
        return Err(anyhow!("seedstore salt len != 16"));
    }
    let mut salt16 = [0u8; 16];
    salt16.copy_from_slice(&salt);

    let nonce = general_purpose::STANDARD
        .decode(&doc.enc.nonce_b64)
        .map_err(|e| anyhow!("seedstore nonce decode: {e}"))?;
    if nonce.len() != 24 {
        return Err(anyhow!("seedstore nonce len != 24"));
    }
    let mut nonce24 = [0u8; 24];
    nonce24.copy_from_slice(&nonce);

    let ct = general_purpose::STANDARD
        .decode(&doc.enc.ct_b64)
        .map_err(|e| anyhow!("seedstore ct decode: {e}"))?;

    let key = derive_key(passphrase, &salt16, &doc.kdf.params)?;
    let plain = decrypt_secret(&key, &nonce24, &ct)?;
    let words = String::from_utf8(plain).map_err(|e| anyhow!("seedstore plaintext utf8: {e}"))?;
    let mnemonic = Mnemonic::parse_in(Language::English, words.trim())
        .map_err(|e| anyhow!("seedstore mnemonic parse: {e}"))?;
    Ok(mnemonic)
}

pub(crate) fn init_wallet_from_mnemonic(
    mnemonic: &Mnemonic,
    hrp: &str,
    wallet_name: &str,
    passphrase: &str,
    force: bool,
) -> Result<String> {
    let derivation = "m/86'/12345'/0'".to_string();

    let (xpub, fingerprint) = derive_xpub_from_mnemonic(mnemonic, &derivation)?;

    let xpub_path = default_xpubstore_path(&fingerprint, hrp)?;
    let walletdb_path = default_walletdb_path(wallet_name)?;
    let seedstore_path = default_seedstore_path(wallet_name)?;

    if walletdb_path.exists() && !force {
        return Err(anyhow!(
            "WalletDb existiert bereits: {} (--force zum Überschreiben)",
            walletdb_path.display()
        ));
    }

    save_seed_store_encrypted(mnemonic, &seedstore_path, passphrase, force)?;
    info!(path = %seedstore_path.display(), "seed gespeichert (verschlüsselt)");

    let xs = XpubStore {
        version: 1,
        kind: "xpub".to_string(),
        algo: "schnorr".to_string(),
        xpub: xpub.to_string(bip32::Prefix::XPUB),
        derivation: derivation.clone(),
        fingerprint: fingerprint.clone(),
        hrp: hrp.to_string(),
    };
    save_xpub_store_with_passphrase(&xs, &xpub_path, passphrase, force)?;
    info!(path = %xpub_path.display(), "xpubstore erstellt");

    if force && walletdb_path.exists() {
        fs::remove_dir_all(&walletdb_path)
            .with_context(|| format!("remove existing walletdb '{}'", walletdb_path.display()))?;
    }
    walletdb::WalletDb::init(&walletdb_path)?;
    let wdb = walletdb::WalletDb::open_locked(&walletdb_path, passphrase)?;

    let xonly = derive_child_xonly(&xpub, 0, 0)?;
    let first_addr = bech32m_address_from_xonly(hrp, &xonly)?;

    let meta = walletdb::WalletAddrMeta {
        version: 1,
        addr: first_addr.clone(),
        hrp: hrp.to_string(),
        change: 0,
        index: 0,
        xpub_derivation: derivation,
        fingerprint,
        xpubstore_path: xpub_path.to_string_lossy().to_string(),
        label: Some("primary".to_string()),
    };
    wdb.put_address(&meta)?;
    info!(path = %walletdb_path.display(), addr = %first_addr, "walletdb initialisiert");

    Ok(first_addr)
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum KeyType {
    Seat,
    Bond,
    Payout,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct XpubStore {
    pub version: u32,
    pub kind: String,       // "xpub"
    pub algo: String,       // "schnorr"
    pub xpub: String,       // base58
    pub derivation: String, // e.g., m/86'/12345'/0'
    pub fingerprint: Option<String>,
    pub hrp: String, // hrp for addresses, e.g., "pc"
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct XpubStoreEncDoc {
    pub version: u32,
    pub kind: String,
    pub algo: String,
    pub kdf: KdfSection,
    pub enc: EncSection,
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum Algo {
    Schnorr,
    Bls,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum PassphraseRole {
    Validator,
    Miner,
}
