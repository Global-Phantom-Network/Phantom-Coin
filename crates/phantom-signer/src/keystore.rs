use super::*;

/// KDF parameters. Uses #[serde(default)] for backward compatibility.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_lanes: 1,
        }
    }
}

/// Keystore document. Uses #[serde(default)] for backward compatibility.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Keystore {
    pub version: u32,
    pub key_type: String,
    pub algo: String,
    pub kdf: KdfSection,
    pub enc: EncSection,
    pub pub_hex: String,
}

impl Default for Keystore {
    fn default() -> Self {
        Self {
            version: 1,
            key_type: String::new(),
            algo: String::new(),
            kdf: KdfSection::default(),
            enc: EncSection::default(),
            pub_hex: String::new(),
        }
    }
}

/// KDF parameters section. Uses #[serde(default)] for backward compatibility.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct KdfSection {
    pub name: String,
    pub salt_b64: String,
    pub params: KdfParams,
}

impl Default for KdfSection {
    fn default() -> Self {
        Self {
            name: "argon2id".to_string(),
            salt_b64: String::new(),
            params: KdfParams::default(),
        }
    }
}

/// Encryption section. Uses #[serde(default)] for backward compatibility.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct EncSection {
    pub cipher: String,
    pub nonce_b64: String,
    pub ct_b64: String,
}

impl Default for EncSection {
    fn default() -> Self {
        Self {
            cipher: "xchacha20poly1305".to_string(),
            nonce_b64: String::new(),
            ct_b64: String::new(),
        }
    }
}

pub(crate) fn derive_key(pass: &str, salt: &[u8], kdf: &KdfParams) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_lanes, Some(32))
        .map_err(|_| anyhow!("invalid Argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| anyhow!("argon2 hash into"))?;
    Ok(out)
}

pub(crate) fn encrypt_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24])> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga: XNonce = nonce.into();
    let ct = cipher
        .encrypt(&nonce_ga, plaintext)
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok((ct, nonce))
}

pub(crate) fn decrypt_secret(key: &[u8; 32], nonce: &[u8; 24], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_ga: XNonce = (*nonce).into();
    let pt = cipher
        .decrypt(&nonce_ga, ct)
        .map_err(|_| anyhow!("decrypt failed"))?;
    Ok(pt)
}

pub(crate) fn validate_passphrase(pass: &str) -> Result<()> {
    if pass.chars().count() < 8 {
        return Err(anyhow!(
            "Passphrase muss mindestens 8 Zeichen lang sein (Groß-/Kleinschreibung, Ziffern und Sonderzeichen werden unterschieden)"
        ));
    }
    // Optional hardening (warning-only): help users avoid trivially weak passphrases.
    // Optionale Härtung (nur Warnung): hilft Usern triviale Passphrases zu vermeiden.
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_other = false;
    for c in pass.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_other = true;
        }
    }
    let classes =
        u8::from(has_lower) + u8::from(has_upper) + u8::from(has_digit) + u8::from(has_other);
    if has_digit && !has_lower && !has_upper && !has_other {
        eprintln!("WARNUNG: Passphrase besteht nur aus Ziffern; das ist leicht zu erraten. (Warnung, kein Fehler)");
    } else if classes <= 1 {
        eprintln!("WARNUNG: Passphrase wirkt sehr einfach (nur eine Zeichenklasse). (Warnung, kein Fehler)");
    }
    Ok(())
}

pub(crate) fn read_pass_twice() -> Result<String> {
    let p1 = read_password_from_tty("Passphrase (mind. 8 Zeichen, Groß-/Kleinschreibung, Ziffern und Sonderzeichen werden unterschieden): ")?;
    validate_passphrase(&p1)?;
    let p2 = read_password_from_tty("Passphrase (wiederholen): ")?;
    if p1 != p2 {
        return Err(anyhow!("Passphrasen stimmen nicht überein"));
    }
    Ok(p1)
}

pub(crate) fn read_password_from_tty(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    let s = read_password()?;
    validate_passphrase(&s)?;
    Ok(s)
}

pub(crate) fn read_string_from_file_strip(p: &Path) -> Result<String> {
    let s = fs::read_to_string(p)?;
    let t = s.trim_end_matches(['\n', '\r']).to_string();
    Ok(t)
}

pub(crate) fn get_passphrase(
    pass_env: &Option<String>,
    pass_file: &Option<PathBuf>,
    prompt: &str,
) -> Result<String> {
    if let Some(var) = pass_env.as_ref() {
        let v = env::var(var).with_context(|| format!("read env {}", var))?;
        validate_passphrase(&v)?;
        Ok(v)
    } else if let Some(p) = pass_file.as_ref() {
        let v = read_string_from_file_strip(p)?;
        validate_passphrase(&v)?;
        Ok(v)
    } else {
        read_password_from_tty(prompt)
    }
}

pub(crate) fn passphrase_role_salt(role: PassphraseRole) -> &'static [u8] {
    match role {
        PassphraseRole::Validator => b"pc:role:validator:passphrase:v1",
        PassphraseRole::Miner => b"pc:role:miner:passphrase:v1",
    }
}

pub(crate) fn derive_role_passphrase(master: &str, role: PassphraseRole) -> Result<String> {
    let kdf_params = role_kdf_params();
    let salt = passphrase_role_salt(role);
    let key = derive_key(master, salt, &kdf_params)?;
    Ok(hex::encode(key))
}

pub(crate) fn get_passphrase_with_role(
    pass_env: &Option<String>,
    pass_file: &Option<PathBuf>,
    pass_role: &Option<PassphraseRole>,
    prompt: &str,
    confirm: bool,
) -> Result<String> {
    let mut pass = if pass_env.is_some() || pass_file.is_some() {
        get_passphrase(pass_env, pass_file, prompt)?
    } else if confirm {
        read_pass_twice()?
    } else {
        read_password_from_tty(prompt)?
    };
    if let Some(role) = pass_role {
        let derived = derive_role_passphrase(&pass, *role)?;
        pass.zeroize();
        Ok(derived)
    } else {
        Ok(pass)
    }
}

pub(crate) fn role_kdf_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 64 * 1024, // 64 MiB
        t_cost: 3,
        p_lanes: 1,
    }
}

pub(crate) fn default_kdf_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 64 * 1024, // 64 MiB
        t_cost: 3,
        p_lanes: 1,
    }
}

pub(crate) fn ks_path_check(out: &Path, force: bool) -> Result<()> {
    if out.exists() && !force {
        return Err(anyhow!("Keystore existiert bereits; --force verwenden"));
    }
    Ok(())
}

pub(crate) fn save_keystore(ks: &Keystore, path: &Path) -> Result<()> {
    let data = toml::to_string_pretty(ks)?;
    write_file_atomic_secure(path, data.as_bytes())
}

pub(crate) fn load_keystore(path: &Path) -> Result<Keystore> {
    let raw = fs::read_to_string(path)?;
    let ks: Keystore = toml::from_str(&raw)?;
    Ok(ks)
}

pub(crate) fn schnorr_keypair_from_keystore(
    keystore_path: &Path,
    passphrase: &str,
) -> Result<schnorr::SchnorrKeypair> {
    let ks = load_keystore(keystore_path)?;
    if ks.algo.as_str() != "schnorr" {
        return Err(anyhow!("keystore algo muss schnorr sein"));
    }
    let salt = general_purpose::STANDARD
        .decode(&ks.kdf.salt_b64)
        .map_err(|e| anyhow!("keystore salt decode: {e}"))?;
    if salt.len() != 16 {
        return Err(anyhow!("keystore salt len != 16"));
    }
    let mut salt16 = [0u8; 16];
    salt16.copy_from_slice(&salt);
    let key = derive_key(passphrase, &salt16, &ks.kdf.params)?;

    let nonce = general_purpose::STANDARD
        .decode(&ks.enc.nonce_b64)
        .map_err(|e| anyhow!("keystore nonce decode: {e}"))?;
    if nonce.len() != 24 {
        return Err(anyhow!("keystore nonce len != 24"));
    }
    let mut nonce24 = [0u8; 24];
    nonce24.copy_from_slice(&nonce);

    let ct = general_purpose::STANDARD
        .decode(&ks.enc.ct_b64)
        .map_err(|e| anyhow!("keystore ct decode: {e}"))?;

    let secret = decrypt_secret(&key, &nonce24, &ct)?;
    if secret.len() != 32 {
        return Err(anyhow!("invalid secret length"));
    }
    let mut sec32 = [0u8; 32];
    sec32.copy_from_slice(&secret);
    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
    sec32.zeroize();
    Ok(kp)
}

pub(crate) fn save_xpub_store(xs: &XpubStore, path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!("XpubStore existiert bereits; --force verwenden"));
    }
    let pass = read_pass_twice()?;
    let mut pass_owned = pass;
    let kdf_params = default_kdf_params();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(&pass_owned, &salt, &kdf_params)?;
    pass_owned.zeroize();

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
    write_file_atomic_secure(path, data.as_bytes())
}

fn load_xpub_store_with_optional_passphrase(
    path: &Path,
    passphrase: Option<&str>,
) -> Result<XpubStore> {
    let raw = fs::read_to_string(path)?;
    // Versuche zuerst verschlüsseltes Format (XpubStoreEncDoc)
    if let Ok(doc) = toml::from_str::<XpubStoreEncDoc>(&raw) {
        if doc.kind.as_str() != "xpub_enc" {
            return Err(anyhow!("xpubstore: unerwartetes kind: {}", doc.kind));
        }
        let pass = if let Some(passphrase) = passphrase {
            validate_passphrase(passphrase)?;
            passphrase.to_string()
        } else {
            read_password_from_tty("XpubStore Passphrase: ")?
        };
        let mut pass_owned = pass;
        let salt_bytes = general_purpose::STANDARD
            .decode(&doc.kdf.salt_b64)
            .map_err(|e| anyhow!("xpubstore salt decode: {e}"))?;
        if salt_bytes.len() != 16 {
            return Err(anyhow!("xpubstore salt len != 16"));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);
        let key = derive_key(&pass_owned, &salt, &doc.kdf.params)?;
        pass_owned.zeroize();

        let nonce_bytes = general_purpose::STANDARD
            .decode(&doc.enc.nonce_b64)
            .map_err(|e| anyhow!("xpubstore nonce decode: {e}"))?;
        if nonce_bytes.len() != 24 {
            return Err(anyhow!("xpubstore nonce len != 24"));
        }
        let mut nonce24 = [0u8; 24];
        nonce24.copy_from_slice(&nonce_bytes);
        let ct_bytes = general_purpose::STANDARD
            .decode(&doc.enc.ct_b64)
            .map_err(|e| anyhow!("xpubstore ct decode: {e}"))?;

        let plain = decrypt_secret(&key, &nonce24, &ct_bytes)?;
        let xs: XpubStore = serde_json::from_slice(&plain)
            .map_err(|e| anyhow!("xpubstore plaintext decode: {e}"))?;
        return Ok(xs);
    }

    // Legacy: unverschlüsselter XpubStore im TOML-Format
    let xs: XpubStore = toml::from_str(&raw)?;
    if xs.kind.as_str() != "xpub" {
        return Ok(xs);
    }

    // Migration: beim ersten Laden in verschlüsseltes Format umwandeln
    let pass = if let Some(passphrase) = passphrase {
        validate_passphrase(passphrase)?;
        passphrase.to_string()
    } else {
        read_pass_twice()?
    };
    let mut pass_owned = pass;
    let kdf_params = default_kdf_params();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(&pass_owned, &salt, &kdf_params)?;
    pass_owned.zeroize();
    let plain = serde_json::to_vec(&xs)?;
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

    let backup_path = path.with_extension("bak");
    fs::copy(path, &backup_path).with_context(|| {
        format!(
            "create xpubstore migration backup '{}' -> '{}'",
            path.display(),
            backup_path.display()
        )
    })?;
    #[cfg(unix)]
    set_owner_only_mode(&backup_path, 0o600)?;

    write_file_atomic_secure(path, data.as_bytes())?;
    Ok(xs)
}

pub(crate) fn load_xpub_store(path: &Path) -> Result<XpubStore> {
    load_xpub_store_with_optional_passphrase(path, None)
}

pub(crate) fn load_xpub_store_with_passphrase(path: &Path, passphrase: &str) -> Result<XpubStore> {
    load_xpub_store_with_optional_passphrase(path, Some(passphrase))
}

/// Mindestgebühr für normale Wallet-Sends (Subcoin).
/// Muss mit `MIN_FEE_ABS` im phantom-node konsistent gehalten werden (siehe docs/SPEC_FEES.md).
pub(crate) const WALLET_MIN_FEE_ABS: u64 = 1_000;

pub(crate) fn bech32m_address_from_xonly(hrp: &str, xonly: &[u8; 32]) -> Result<String> {
    // SegWit v1 address: version=1, program=32 bytes xonly
    let mut data = vec![bech32::u5::try_from_u8(1).map_err(|_| anyhow!("u5 version"))?];
    data.extend_from_slice(&xonly.to_base32());
    bech32::encode(hrp, data, bech32::Variant::Bech32m).map_err(|e| anyhow!("bech32 encode: {e}"))
}

pub(crate) fn lock_from_pc_address(addr: &str) -> Result<pc_types::LockCommitment> {
    let (_hrp, data, variant) = bech32::decode(addr).map_err(|e| anyhow!("bech32 decode: {e}"))?;
    if variant != bech32::Variant::Bech32m {
        return Err(anyhow!("expected Bech32m variant"));
    }
    let (ver_u5, prog_u5) = data
        .split_first()
        .ok_or_else(|| anyhow!("bech32 data empty"))?;
    if ver_u5.to_u8() != 1 {
        return Err(anyhow!("unsupported witness version: {}", ver_u5.to_u8()));
    }
    let prog: Vec<u8> =
        Vec::<u8>::from_base32(prog_u5).map_err(|e| anyhow!("bech32 program decode: {e}"))?;
    if prog.len() != 32 {
        return Err(anyhow!(
            "program length must be 32 bytes, got {}",
            prog.len()
        ));
    }
    let mut lock = [0u8; 32];
    lock.copy_from_slice(&prog);
    Ok(pc_types::LockCommitment(lock))
}

pub(crate) fn parse_hex_32(s: &str) -> Result<Hash32> {
    let t = s.trim().trim_start_matches("0x");
    let raw = hex::decode(t).map_err(|e| anyhow!("hex decode: {e}"))?;
    if raw.len() != 32 {
        return Err(anyhow!("hex length != 32 bytes (got {})", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub(crate) fn parse_outpoint_str(s: &str) -> Result<pc_types::OutPoint> {
    let parts: Vec<&str> = s.split(':').collect();
    let [txid_s, vout_s] = parts.as_slice() else {
        return Err(anyhow!(
            "OutPoint muss Format txid:vout haben, bekommen: '{s}'"
        ));
    };
    let txid = parse_hex_32(txid_s)?;
    let vout: u32 = vout_s
        .parse()
        .map_err(|e| anyhow!("ungültiger vout: {e}"))?;
    Ok(pc_types::OutPoint { txid, vout })
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct WalletUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub minted_at: u64,
    pub staked: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct WalletUtxoResp {
    pub ok: bool,
    pub lock: String,
    pub utxos: Vec<WalletUtxo>,
}

pub(crate) fn derive_child_xonly(
    xpub: &ExtendedPublicKey<B32SecpPk>,
    change: u32,
    index: u32,
) -> Result<[u8; 32]> {
    let change_cn =
        ChildNumber::new(change, false).map_err(|e| anyhow!("derive change child: {e}"))?;
    let index_cn =
        ChildNumber::new(index, false).map_err(|e| anyhow!("derive index child: {e}"))?;
    let c1 = xpub
        .derive_child(change_cn)
        .map_err(|e| anyhow!("derive change: {e}"))?;
    let c2 = c1
        .derive_child(index_cn)
        .map_err(|e| anyhow!("derive index: {e}"))?;
    let pk_bytes = c2.public_key().to_bytes();
    let secp_pk = SecpPub::from_slice(&pk_bytes).map_err(|_| anyhow!("secp256k1 pubkey parse"))?;
    let (xonly, _parity) = secp_pk.x_only_public_key();
    Ok(xonly.serialize())
}

pub(crate) fn schnorr_keypair_from_wallet_seedstore(
    wallet_db: &Path,
    seed_store: &Path,
    passphrase: &str,
    addr: &str,
) -> Result<schnorr::SchnorrKeypair> {
    let wdb = walletdb::WalletDb::open_locked(wallet_db, passphrase)?;
    let meta = wdb
        .get_address(addr)?
        .ok_or_else(|| anyhow!("addr nicht in wallet-db gefunden: {}", addr))?;

    let mnemonic = load_seed_store_mnemonic(seed_store, passphrase)?;
    let seed = mnemonic.to_seed("");
    let master: ExtendedPrivateKey<bip32::secp256k1::SecretKey> =
        ExtendedPrivateKey::new(seed).map_err(|e| anyhow!("create master key: {e}"))?;

    let base_path = DerivationPath::from_str(&meta.xpub_derivation)
        .map_err(|e| anyhow!("parse derivation path '{}': {e}", meta.xpub_derivation))?;

    let mut derived = master;
    for child in base_path.iter() {
        derived = derived
            .derive_child(child)
            .map_err(|e| anyhow!("derive child: {e}"))?;
    }
    let change_cn =
        ChildNumber::new(meta.change, false).map_err(|e| anyhow!("derive change child: {e}"))?;
    let index_cn =
        ChildNumber::new(meta.index, false).map_err(|e| anyhow!("derive index child: {e}"))?;
    derived = derived
        .derive_child(change_cn)
        .map_err(|e| anyhow!("derive change: {e}"))?;
    derived = derived
        .derive_child(index_cn)
        .map_err(|e| anyhow!("derive index: {e}"))?;

    let mut sk =
        <bip32::secp256k1::SecretKey as bip32::PrivateKey>::to_bytes(derived.private_key());
    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sk)
        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
    sk.zeroize();

    // Safety check: derived xonly must match the requested address.
    // Safety-Check: abgeleiteter xonly muss zur gewünschten Adresse passen.
    let derived_addr = bech32m_address_from_xonly(&meta.hrp, &kp.public_xonly_bytes())?;
    if derived_addr != addr {
        return Err(anyhow!(
            "abgeleiteter Key passt nicht zur Adresse (derived={}, wanted={})",
            derived_addr,
            addr
        ));
    }

    Ok(kp)
}
