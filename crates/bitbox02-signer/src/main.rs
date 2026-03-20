// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use bip32::{DerivationPath, ExtendedPrivateKey};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use clap::{Parser, Subcommand};
use pc_crypto::{blake3_32, schnorr_sign, Hash32, SchnorrKeypair};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use zeroize::Zeroize;

const KIND_SEEDSTORE: &str = "seedstore";
const DEFAULT_STORE_DIR: &str = ".phantom/bitbox02-signer";
const DEFAULT_STORE_FILE: &str = "seedstore.toml";

#[derive(Parser, Debug)]
#[command(name = "bitbox02-signer", version, about = "Externer Signer für Phantom (Schnorr, Digest)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialisiert einen verschlüsselten Seed-Store aus einer BIP39-Mnemonic.
    Init {
        /// Pfad zum Seed-Store (TOML). Default: ~/.phantom/bitbox02-signer/seedstore.toml
        #[arg(long)]
        seedstore: Option<PathBuf>,
        /// Überschreibt einen existierenden Seed-Store.
        #[arg(long)]
        force: bool,
        /// Mnemonic aus ENV lesen (24 Wörter).
        #[arg(long)]
        mnemonic_env: Option<String>,
        /// Mnemonic aus Datei lesen.
        #[arg(long)]
        mnemonic_file: Option<PathBuf>,
        /// Optional: BIP39-Passphrase aus ENV.
        #[arg(long)]
        mnemonic_passphrase_env: Option<String>,
        /// Optional: BIP39-Passphrase aus Datei.
        #[arg(long)]
        mnemonic_passphrase_file: Option<PathBuf>,
        /// Store-Passphrase aus ENV.
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Store-Passphrase aus Datei.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Signiert einen 32-Byte Digest (hex) mit dem abgeleiteten Schnorr-Key.
    Sign {
        /// 32-Byte Digest (Hex, 64 Zeichen).
        #[arg(long)]
        digest: String,
        /// Derivation Path, z. B. m/86'/12345'/0'/0/0
        #[arg(long)]
        path: String,
        /// Optional: Fingerprint-Prüfung (Hex, 8 Zeichen).
        #[arg(long)]
        fingerprint: Option<String>,
        /// Pfad zum Seed-Store (TOML). Default: ~/.phantom/bitbox02-signer/seedstore.toml
        #[arg(long)]
        seedstore: Option<PathBuf>,
        /// Store-Passphrase aus ENV.
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Store-Passphrase aus Datei.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_lanes: u32,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct KdfSection {
    name: String,
    salt_b64: String,
    params: KdfParams,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct EncSection {
    cipher: String,
    nonce_b64: String,
    ct_b64: String,
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

#[derive(Debug, Serialize, Deserialize)]
struct SeedStoreEncDoc {
    version: u32,
    kind: String,
    algo: String,
    fingerprint: String,
    kdf: KdfSection,
    enc: EncSection,
}

#[derive(Debug, Serialize, Deserialize)]
struct SeedPlain {
    seed_b64: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Init {
            seedstore,
            force,
            mnemonic_env,
            mnemonic_file,
            mnemonic_passphrase_env,
            mnemonic_passphrase_file,
            passphrase_env,
            passphrase_file,
        } => {
            let path = seedstore.unwrap_or(default_seedstore_path()?);
            init_seedstore(
                &path,
                InitSeedstoreArgs {
                    force,
                    mnemonic_env,
                    mnemonic_file,
                    mnemonic_passphrase_env,
                    mnemonic_passphrase_file,
                    passphrase_env,
                    passphrase_file,
                },
            )?;
        }
        Commands::Sign {
            digest,
            path,
            fingerprint,
            seedstore,
            passphrase_env,
            passphrase_file,
        } => {
            let store_path = seedstore.unwrap_or(default_seedstore_path()?);
            let out = sign_digest(
                &store_path,
                &digest,
                &path,
                fingerprint.as_deref(),
                passphrase_env,
                passphrase_file,
            )?;
            println!("{}", out);
        }
    }
    Ok(())
}

fn default_seedstore_path() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME nicht gesetzt")?;
    let dir = PathBuf::from(home).join(DEFAULT_STORE_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("create dir {}", dir.display()))?;
    Ok(dir.join(DEFAULT_STORE_FILE))
}

struct InitSeedstoreArgs {
    force: bool,
    mnemonic_env: Option<String>,
    mnemonic_file: Option<PathBuf>,
    mnemonic_passphrase_env: Option<String>,
    mnemonic_passphrase_file: Option<PathBuf>,
    passphrase_env: Option<String>,
    passphrase_file: Option<PathBuf>,
}

fn init_seedstore(path: &Path, args: InitSeedstoreArgs) -> Result<()> {
    let InitSeedstoreArgs {
        force,
        mnemonic_env,
        mnemonic_file,
        mnemonic_passphrase_env,
        mnemonic_passphrase_file,
        passphrase_env,
        passphrase_file,
    } = args;
    if path.exists() && !force {
        return Err(anyhow!(
            "Seed-Store existiert bereits: {} (--force zum Überschreiben)",
            path.display()
        ));
    }
    if path.exists() && force {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(anyhow!("Refuse to overwrite symlink: {}", path.display()));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }

    let mut mnemonic_str = read_mnemonic(mnemonic_env, mnemonic_file)?;
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str.trim())
        .map_err(|e| anyhow!("ungültige Mnemonic: {e}"))?;
    mnemonic_str.zeroize();

    let mut mnemonic_passphrase =
        get_optional_passphrase(mnemonic_passphrase_env, mnemonic_passphrase_file)?;

    let mut seed = mnemonic.to_seed(&mnemonic_passphrase);
    let master: ExtendedPrivateKey<bip32::secp256k1::SecretKey> =
        ExtendedPrivateKey::new(seed).map_err(|e| anyhow!("master key: {e}"))?;
    let fingerprint = compute_fingerprint(&master)?;

    let mut store_pass = get_passphrase_for_init(passphrase_env, passphrase_file)?;

    let kdf_params = KdfParams::default();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(&store_pass, &salt, &kdf_params)?;

    let plain = SeedPlain {
        seed_b64: general_purpose::STANDARD.encode(seed),
    };
    let plain_bytes = serde_json::to_vec(&plain)?;
    let (ct, nonce) = encrypt_secret(&key, &plain_bytes)?;

    let doc = SeedStoreEncDoc {
        version: 1,
        kind: KIND_SEEDSTORE.to_string(),
        algo: "schnorr".to_string(),
        fingerprint: fingerprint.clone(),
        kdf: KdfSection {
            name: "argon2id".to_string(),
            salt_b64: general_purpose::STANDARD.encode(salt),
            params: kdf_params,
        },
        enc: EncSection {
            cipher: "xchacha20poly1305".to_string(),
            nonce_b64: general_purpose::STANDARD.encode(nonce),
            ct_b64: general_purpose::STANDARD.encode(ct),
        },
    };

    write_seedstore(path, &doc, force)?;
    eprintln!("Seed-Store erstellt: {}", path.display());
    eprintln!("Fingerprint: {}", fingerprint);

    seed.zeroize();
    mnemonic_passphrase.zeroize();
    store_pass.zeroize();
    Ok(())
}

fn sign_digest(
    store_path: &Path,
    digest_hex: &str,
    derivation: &str,
    fingerprint_opt: Option<&str>,
    passphrase_env: Option<String>,
    passphrase_file: Option<PathBuf>,
) -> Result<String> {
    let mut digest = parse_hex_32(digest_hex)?;
    let path = DerivationPath::from_str(derivation)
        .map_err(|e| anyhow!("Derivation Path ungültig '{}': {e}", derivation))?;

    let mut pass = get_passphrase_for_sign(passphrase_env, passphrase_file)?;
    let (mut seed, doc_fp) = load_seedstore(store_path, &pass)?;
    pass.zeroize();

    if let Some(fp) = fingerprint_opt {
        let fp_norm = normalize_hex(fp)?;
        if fp_norm != doc_fp {
            return Err(anyhow!(
                "Fingerprint passt nicht (erwartet {}, gefunden {})",
                fp_norm,
                doc_fp
            ));
        }
    }

    let master: ExtendedPrivateKey<bip32::secp256k1::SecretKey> =
        ExtendedPrivateKey::new(&seed).map_err(|e| anyhow!("master key: {e}"))?;
    seed.zeroize();

    let mut derived = master;
    for child in path.iter() {
        derived = derived
            .derive_child(child)
            .map_err(|e| anyhow!("derive child: {e}"))?;
    }
    let mut sk =
        <bip32::secp256k1::SecretKey as bip32::PrivateKey>::to_bytes(derived.private_key());
    let kp = SchnorrKeypair::from_secret_key_bytes(&sk)
        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
    let sig = schnorr_sign(&digest, &kp);
    let pub_xonly = kp.public_xonly_bytes();

    let out = serde_json::json!({
        "pub_xonly_hex": hex::encode(pub_xonly),
        "sig_hex": hex::encode(sig),
    });

    sk.zeroize();
    digest.zeroize();

    Ok(out.to_string())
}

fn read_mnemonic(mnemonic_env: Option<String>, mnemonic_file: Option<PathBuf>) -> Result<String> {
    if let Some(env_name) = mnemonic_env {
        let v = env::var(&env_name).with_context(|| format!("read mnemonic env {}", env_name))?;
        return Ok(v);
    }
    if let Some(p) = mnemonic_file {
        let s = fs::read_to_string(&p)
            .with_context(|| format!("read mnemonic file {}", p.display()))?;
        return Ok(s);
    }
    eprintln!("Mnemonic eingeben (Wörter durch Leerzeichen getrennt):");
    let s = read_secret_line("Mnemonic: ")?;
    Ok(s)
}

fn read_secret_line(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    let s = read_password().context("read secret from tty")?;
    Ok(s)
}

fn get_optional_passphrase(env_name: Option<String>, file: Option<PathBuf>) -> Result<String> {
    if let Some(var) = env_name {
        return env::var(&var).with_context(|| format!("read env {}", var));
    }
    if let Some(p) = file {
        return read_string_from_file_strip(&p);
    }
    let s = read_secret_line("BIP39 Passphrase (optional, Enter für leer): ")?;
    Ok(s)
}

fn get_passphrase_for_init(env_name: Option<String>, file: Option<PathBuf>) -> Result<String> {
    if let Some(var) = env_name {
        let v = env::var(&var).with_context(|| format!("read env {}", var))?;
        validate_passphrase(&v)?;
        return Ok(v);
    }
    if let Some(p) = file {
        let v = read_string_from_file_strip(&p)?;
        validate_passphrase(&v)?;
        return Ok(v);
    }
    read_pass_twice()
}

fn get_passphrase_for_sign(env_name: Option<String>, file: Option<PathBuf>) -> Result<String> {
    if let Some(var) = env_name {
        let v = env::var(&var).with_context(|| format!("read env {}", var))?;
        validate_passphrase(&v)?;
        return Ok(v);
    }
    if let Some(p) = file {
        let v = read_string_from_file_strip(&p)?;
        validate_passphrase(&v)?;
        return Ok(v);
    }
    read_password_from_tty("Passphrase: ")
}

fn validate_passphrase(pass: &str) -> Result<()> {
    if pass.chars().count() < 8 {
        return Err(anyhow!("Passphrase muss mindestens 8 Zeichen lang sein"));
    }
    Ok(())
}

fn read_pass_twice() -> Result<String> {
    let p1 = read_password_from_tty("Passphrase (mind. 8 Zeichen): ")?;
    let p2 = read_password_from_tty("Passphrase (wiederholen): ")?;
    if p1 != p2 {
        return Err(anyhow!("Passphrasen stimmen nicht überein"));
    }
    Ok(p1)
}

fn read_password_from_tty(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    let s = read_password().context("read passphrase from tty")?;
    validate_passphrase(&s)?;
    Ok(s)
}

fn read_string_from_file_strip(p: &Path) -> Result<String> {
    let s = fs::read_to_string(p)?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

fn derive_key(pass: &str, salt: &[u8; 16], kdf: &KdfParams) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_lanes, Some(32))
        .map_err(|_| anyhow!("invalid Argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| anyhow!("argon2 hash failed"))?;
    Ok(out)
}

fn encrypt_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24])> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga: XNonce = nonce.into();
    let ct = cipher
        .encrypt(&nonce_ga, plaintext)
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok((ct, nonce))
}

fn decrypt_secret(key: &[u8; 32], nonce: &[u8; 24], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_ga: XNonce = (*nonce).into();
    let pt = cipher
        .decrypt(&nonce_ga, ct)
        .map_err(|_| anyhow!("decrypt failed"))?;
    Ok(pt)
}

fn write_seedstore(path: &Path, doc: &SeedStoreEncDoc, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "Seed-Store existiert bereits: {} (--force)",
            path.display()
        ));
    }
    let data = toml::to_string_pretty(doc)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.create(true).truncate(true).write(true).mode(0o600);
        let mut f = opts.open(path)?;
        use std::io::Write;
        f.write_all(data.as_bytes())?;
        f.flush()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

fn load_seedstore(path: &Path, passphrase: &str) -> Result<(Vec<u8>, String)> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("read seedstore {}", path.display()))?;
    let doc: SeedStoreEncDoc = toml::from_str(&raw).map_err(|e| anyhow!("parse seedstore: {e}"))?;
    if doc.kind != KIND_SEEDSTORE {
        return Err(anyhow!("seedstore: unerwartetes kind: {}", doc.kind));
    }
    if doc.kdf.name != "argon2id" {
        return Err(anyhow!(
            "seedstore: kdf nicht unterstützt: {}",
            doc.kdf.name
        ));
    }
    if doc.enc.cipher != "xchacha20poly1305" {
        return Err(anyhow!(
            "seedstore: cipher nicht unterstützt: {}",
            doc.enc.cipher
        ));
    }

    let salt = general_purpose::STANDARD
        .decode(&doc.kdf.salt_b64)
        .map_err(|e| anyhow!("salt decode: {e}"))?;
    if salt.len() != 16 {
        return Err(anyhow!("salt len != 16"));
    }
    let mut salt16 = [0u8; 16];
    salt16.copy_from_slice(&salt);

    let nonce = general_purpose::STANDARD
        .decode(&doc.enc.nonce_b64)
        .map_err(|e| anyhow!("nonce decode: {e}"))?;
    if nonce.len() != 24 {
        return Err(anyhow!("nonce len != 24"));
    }
    let mut nonce24 = [0u8; 24];
    nonce24.copy_from_slice(&nonce);

    let ct = general_purpose::STANDARD
        .decode(&doc.enc.ct_b64)
        .map_err(|e| anyhow!("ct decode: {e}"))?;

    let key = derive_key(passphrase, &salt16, &doc.kdf.params)?;
    let plain = decrypt_secret(&key, &nonce24, &ct)?;
    let seed_plain: SeedPlain =
        serde_json::from_slice(&plain).map_err(|e| anyhow!("seedstore plaintext: {e}"))?;
    let seed = general_purpose::STANDARD
        .decode(seed_plain.seed_b64)
        .map_err(|e| anyhow!("seed decode: {e}"))?;
    if seed.len() != 64 {
        return Err(anyhow!("seed len != 64"));
    }
    Ok((seed, doc.fingerprint))
}

fn compute_fingerprint(master: &ExtendedPrivateKey<bip32::secp256k1::SecretKey>) -> Result<String> {
    let master_pk = master.public_key();
    let pk_bytes = master_pk.to_bytes();
    let hash = blake3_32(&pk_bytes);
    // 8-byte fingerprint for ~2^64 collision resistance (still human-friendly).
    let fp = hash.get(..8).ok_or_else(|| anyhow!("fingerprint slice"))?;
    Ok(hex::encode(fp))
}

fn normalize_hex(s: &str) -> Result<String> {
    let t = s.trim().trim_start_matches("0x");
    if !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("hex ungültig"));
    }
    Ok(t.to_lowercase())
}

fn parse_hex_32(hex_str: &str) -> Result<Hash32> {
    let norm = normalize_hex(hex_str)?;
    if norm.len() != 64 {
        return Err(anyhow!("digest muss 64 hex Zeichen sein"));
    }
    let bytes = hex::decode(norm)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f56_fingerprint_is_8_bytes_hex_encoded() {
        let seed = [1u8; 64];
        let master: ExtendedPrivateKey<bip32::secp256k1::SecretKey> =
            ExtendedPrivateKey::new(seed).expect("master key");
        let fp = compute_fingerprint(&master).expect("fingerprint");
        assert_eq!(fp.len(), 16);
    }
}
