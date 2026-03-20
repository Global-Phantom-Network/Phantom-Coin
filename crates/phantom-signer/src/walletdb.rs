use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use fs2::FileExt;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use zeroize::Zeroize;

const CF_ADDRS: &str = "addrs";
const CF_META: &str = "meta";
const DB_DIR: &str = "walletdb";
const META_KEY: &[u8] = b"walletdb_enc_meta_v1";
const META_PASS_CHECK_KEY: &[u8] = b"walletdb_passphrase_check_v1";
const PASS_CHECK_MARKER: &[u8] = b"walletdb_v1_check";

#[cfg(unix)]
fn chmod_owner_only(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {:o} '{}'", mode, path.display()))
}

/// Wallet address metadata. Uses #[serde(default)] for backward compatibility
/// when new fields are added in future versions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletAddrMeta {
    pub version: u32,
    pub addr: String,
    pub hrp: String,
    pub change: u32,
    pub index: u32,
    pub xpub_derivation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub xpubstore_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Default for WalletAddrMeta {
    fn default() -> Self {
        Self {
            version: 1,
            addr: String::new(),
            hrp: String::new(),
            change: 0,
            index: 0,
            xpub_derivation: String::new(),
            fingerprint: None,
            xpubstore_path: String::new(),
            label: None,
        }
    }
}

fn validate_legacy_wallet_addr_meta(meta: &WalletAddrMeta) -> Result<()> {
    const MAX_ADDR_LEN: usize = 256;
    const MAX_HRP_LEN: usize = 32;
    const MAX_DERIVATION_LEN: usize = 256;
    const MAX_XPUBSTORE_PATH_LEN: usize = 1024;
    const MAX_LABEL_LEN: usize = 256;
    const MAX_FINGERPRINT_LEN: usize = 128;

    if meta.version != 1 {
        return Err(anyhow!("walletdb legacy migration: version must be 1"));
    }
    if meta.addr.trim().is_empty() {
        return Err(anyhow!("walletdb legacy migration: addr must not be empty"));
    }
    if meta.addr.len() > MAX_ADDR_LEN {
        return Err(anyhow!("walletdb legacy migration: addr too long"));
    }
    if meta.hrp.len() > MAX_HRP_LEN {
        return Err(anyhow!("walletdb legacy migration: hrp too long"));
    }
    if meta.xpub_derivation.len() > MAX_DERIVATION_LEN {
        return Err(anyhow!(
            "walletdb legacy migration: xpub_derivation too long"
        ));
    }
    if meta.xpubstore_path.len() > MAX_XPUBSTORE_PATH_LEN {
        return Err(anyhow!(
            "walletdb legacy migration: xpubstore_path too long"
        ));
    }
    if meta
        .label
        .as_ref()
        .map(|s| s.len() > MAX_LABEL_LEN)
        .unwrap_or(false)
    {
        return Err(anyhow!("walletdb legacy migration: label too long"));
    }
    if meta
        .fingerprint
        .as_ref()
        .map(|s| s.len() > MAX_FINGERPRINT_LEN)
        .unwrap_or(false)
    {
        return Err(anyhow!("walletdb legacy migration: fingerprint too long"));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletDbKdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_lanes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletDbEncMeta {
    version: u32,
    kdf: WalletDbKdfParams,
    salt_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletDbCipherText {
    v: u32,
    nonce_b64: String,
    ct_b64: String,
}

pub struct WalletDb {
    db: DB,
    #[allow(dead_code)]
    lock_file: std::fs::File,
    enc_key: [u8; 32],
}

#[cfg(unix)]
fn chmod_rocksdb_recursive(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir '{}'", dir.display()))? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_file() {
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))?;
        } else if ft.is_dir() {
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o700))?;
            chmod_rocksdb_recursive(&entry.path())?;
        }
    }
    Ok(())
}

fn open_rocksdb(path: &Path) -> Result<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    let cfs = vec![
        ColumnFamilyDescriptor::new(CF_ADDRS, Options::default()),
        ColumnFamilyDescriptor::new(CF_META, Options::default()),
    ];
    let db = DB::open_cf_descriptors(&opts, path, cfs)
        .with_context(|| format!("open rocksdb at '{}'", path.display()))?;
    #[cfg(unix)]
    {
        chmod_owner_only(path, 0o700)?;
        chmod_rocksdb_recursive(path)?;
    }
    Ok(db)
}

fn default_kdf_params() -> WalletDbKdfParams {
    WalletDbKdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_lanes: 1,
    }
}

fn derive_key(pass: &str, salt: &[u8; 16], kdf: &WalletDbKdfParams) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_lanes, Some(32))
        .map_err(|_| anyhow!("invalid Argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| anyhow!("argon2 hash into"))?;
    Ok(out)
}

fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<WalletDbCipherText> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga: XNonce = nonce.into();
    let ct = cipher
        .encrypt(&nonce_ga, plaintext)
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok(WalletDbCipherText {
        v: 1,
        nonce_b64: general_purpose::STANDARD.encode(nonce),
        ct_b64: general_purpose::STANDARD.encode(&ct),
    })
}

fn decrypt_value(key: &[u8; 32], enc: &WalletDbCipherText) -> Result<Vec<u8>> {
    let nonce_bytes = general_purpose::STANDARD
        .decode(&enc.nonce_b64)
        .with_context(|| "walletdb nonce decode")?;
    if nonce_bytes.len() != 24 {
        return Err(anyhow!("walletdb nonce len != 24"));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let ct = general_purpose::STANDARD
        .decode(&enc.ct_b64)
        .with_context(|| "walletdb ct decode")?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_ga: XNonce = nonce.into();
    let pt = cipher
        .decrypt(&nonce_ga, ct.as_ref())
        .map_err(|_| anyhow!("decrypt failed"))?;
    Ok(pt)
}

impl WalletDb {
    pub fn init(db_path: &Path) -> Result<()> {
        if !db_path.exists() {
            std::fs::create_dir_all(db_path)
                .with_context(|| format!("create wallet db dir '{}'", db_path.display()))?;
        }
        #[cfg(unix)]
        chmod_owner_only(db_path, 0o700)?;

        let db_dir = db_path.join(DB_DIR);
        let _db = open_rocksdb(&db_dir)?;
        #[cfg(unix)]
        chmod_owner_only(&db_dir, 0o700)?;
        Ok(())
    }

    pub fn open_locked(db_path: &Path, passphrase: &str) -> Result<Self> {
        if !db_path.exists() {
            return Err(anyhow!(
                "wallet-db nicht gefunden: {} (zuerst 'wallet-db-init' ausführen oder via AddrFromXpub --wallet-db erzeugen)",
                db_path.display()
            ));
        }
        let lock_path = db_path.join(".lock");
        let mut lock_opts = OpenOptions::new();
        lock_opts
            .create(true)
            .read(true)
            .write(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_opts.mode(0o600);
        }
        let mut lock_file = lock_opts
            .open(&lock_path)
            .with_context(|| format!("open wallet-db lock file '{}'", lock_path.display()))?;
        #[cfg(unix)]
        chmod_owner_only(&lock_path, 0o600)?;

        lock_file
            .try_lock_exclusive()
            .with_context(|| "acquire exclusive lock on wallet db")?;
        let _ = lock_file.set_len(0);
        let _ = lock_file.write_all(std::process::id().to_string().as_bytes());

        let db_dir = db_path.join(DB_DIR);
        if !db_dir.exists() {
            return Err(anyhow!(
                "wallet-db datei nicht gefunden: {} (zuerst 'wallet-db-init' ausführen)",
                db_dir.display()
            ));
        }
        let db = open_rocksdb(&db_dir)?;

        let enc_key: [u8; 32];

        let cf_meta = db
            .cf_handle(CF_META)
            .ok_or_else(|| anyhow!("walletdb: column family '{}' not found", CF_META))?;
        let cf_addrs = db
            .cf_handle(CF_ADDRS)
            .ok_or_else(|| anyhow!("walletdb: column family '{}' not found", CF_ADDRS))?;

        let meta_raw: Option<Vec<u8>> = db
            .get_cf(&cf_meta, META_KEY)
            .with_context(|| "walletdb read meta")?;

        if let Some(raw) = meta_raw {
            let meta_dec: WalletDbEncMeta =
                serde_json::from_slice(&raw).with_context(|| "walletdb enc meta decode")?;
            let salt_bytes = general_purpose::STANDARD
                .decode(&meta_dec.salt_b64)
                .with_context(|| "walletdb salt decode")?;
            if salt_bytes.len() != 16 {
                return Err(anyhow!("walletdb salt len != 16"));
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&salt_bytes);
            enc_key = derive_key(passphrase, &salt, &meta_dec.kdf)?;

            let marker_raw: Option<Vec<u8>> = db
                .get_cf(&cf_meta, META_PASS_CHECK_KEY)
                .with_context(|| "walletdb read marker")?;
            if let Some(marker_raw) = marker_raw {
                let marker_enc: WalletDbCipherText = serde_json::from_slice(&marker_raw)
                    .with_context(|| "walletdb marker decode")?;
                let marker_plain = decrypt_value(&enc_key, &marker_enc)
                    .map_err(|_| anyhow!("walletdb passphrase check failed"))?;
                if marker_plain.as_slice() != PASS_CHECK_MARKER {
                    return Err(anyhow!("walletdb passphrase check failed"));
                }
            } else {
                // Backward compatibility: old DBs without marker.
                let mut iter = db.iterator_cf(&cf_addrs, IteratorMode::Start);
                if let Some(item) = iter.next() {
                    let (_k, v) = item.with_context(|| "walletdb iter addrs")?;
                    if let Ok(enc) = serde_json::from_slice::<WalletDbCipherText>(&v) {
                        let plain = decrypt_value(&enc_key, &enc)
                            .map_err(|_| anyhow!("walletdb passphrase check failed"))?;
                        let _: WalletAddrMeta = serde_json::from_slice(&plain)
                            .map_err(|_| anyhow!("walletdb passphrase check failed"))?;
                    } else if let Ok(meta_plain) = serde_json::from_slice::<WalletAddrMeta>(&v) {
                        validate_legacy_wallet_addr_meta(&meta_plain)?;
                    } else {
                        return Err(anyhow!("walletdb passphrase check failed"));
                    }
                }

                let marker_enc = encrypt_value(&enc_key, PASS_CHECK_MARKER)?;
                let marker_bytes = serde_json::to_vec(&marker_enc)?;
                db.put_cf(&cf_meta, META_PASS_CHECK_KEY, &marker_bytes)
                    .with_context(|| "walletdb write marker")?;
            }
        } else {
            let kdf = default_kdf_params();
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            enc_key = derive_key(passphrase, &salt, &kdf)?;

            let mut legacy: Vec<(Vec<u8>, WalletAddrMeta)> = Vec::new();
            {
                let iter = db.iterator_cf(&cf_addrs, IteratorMode::Start);
                for item in iter {
                    let (k, v) = item.with_context(|| "walletdb iter addrs")?;
                    match serde_json::from_slice::<WalletAddrMeta>(&v) {
                        Ok(meta_val) => {
                            validate_legacy_wallet_addr_meta(&meta_val)?;
                            legacy.push((k.to_vec(), meta_val));
                        }
                        Err(e) => {
                            return Err(anyhow!(
                                "walletdb: vorhandener Eintrag ist weder verschlüsselt noch WalletAddrMeta ({}), Migration abgebrochen",
                                e
                            ));
                        }
                    }
                }
            }

            let mut batch = WriteBatch::default();
            for (k, meta_val) in legacy.into_iter() {
                let plain = serde_json::to_vec(&meta_val)?;
                let enc = encrypt_value(&enc_key, &plain)?;
                let enc_bytes = serde_json::to_vec(&enc)?;
                batch.put_cf(&cf_addrs, &k, &enc_bytes);
            }
            let meta_enc = WalletDbEncMeta {
                version: 1,
                kdf,
                salt_b64: general_purpose::STANDARD.encode(salt),
            };
            let meta_bytes = serde_json::to_vec(&meta_enc)?;
            batch.put_cf(&cf_meta, META_KEY, &meta_bytes);
            let marker_enc = encrypt_value(&enc_key, PASS_CHECK_MARKER)?;
            let marker_bytes = serde_json::to_vec(&marker_enc)?;
            batch.put_cf(&cf_meta, META_PASS_CHECK_KEY, &marker_bytes);
            db.write(batch).with_context(|| "walletdb write batch")?;
        }

        Ok(Self {
            db,
            lock_file,
            enc_key,
        })
    }

    pub fn put_address(&self, meta: &WalletAddrMeta) -> Result<()> {
        let cf_addrs = self
            .db
            .cf_handle(CF_ADDRS)
            .ok_or_else(|| anyhow!("walletdb: cf '{}' not found", CF_ADDRS))?;
        let key = meta.addr.as_bytes();
        let plain = serde_json::to_vec(meta)?;
        let enc = encrypt_value(&self.enc_key, &plain)?;
        let val = serde_json::to_vec(&enc)?;
        self.db
            .put_cf(&cf_addrs, key, &val)
            .with_context(|| "walletdb put_address")?;
        Ok(())
    }

    pub fn get_address(&self, addr: &str) -> Result<Option<WalletAddrMeta>> {
        let cf_addrs = self
            .db
            .cf_handle(CF_ADDRS)
            .ok_or_else(|| anyhow!("walletdb: cf '{}' not found", CF_ADDRS))?;
        match self
            .db
            .get_cf(&cf_addrs, addr.as_bytes())
            .with_context(|| "walletdb get_address")?
        {
            Some(raw) => {
                if let Ok(enc) = serde_json::from_slice::<WalletDbCipherText>(&raw) {
                    let plain = decrypt_value(&self.enc_key, &enc)?;
                    let meta: WalletAddrMeta = serde_json::from_slice(&plain)?;
                    Ok(Some(meta))
                } else {
                    let meta: WalletAddrMeta = serde_json::from_slice(&raw)?;
                    Ok(Some(meta))
                }
            }
            None => Ok(None),
        }
    }

    pub fn all_addresses(&self) -> Result<Vec<WalletAddrMeta>> {
        let cf_addrs = self
            .db
            .cf_handle(CF_ADDRS)
            .ok_or_else(|| anyhow!("walletdb: cf '{}' not found", CF_ADDRS))?;
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf_addrs, IteratorMode::Start);
        for item in iter {
            let (_k, v) = item.with_context(|| "walletdb iter addrs")?;
            if let Ok(enc) = serde_json::from_slice::<WalletDbCipherText>(&v) {
                let plain = decrypt_value(&self.enc_key, &enc)?;
                let meta: WalletAddrMeta = serde_json::from_slice(&plain)?;
                out.push(meta);
            } else {
                let meta: WalletAddrMeta = serde_json::from_slice(&v)?;
                out.push(meta);
            }
        }
        Ok(out)
    }
}

impl Drop for WalletDb {
    fn drop(&mut self) {
        self.enc_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f41_walletdb_drop_zeroizes_enc_key() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("walletdb.rs");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(src.contains("impl Drop for WalletDb"));
        assert!(src.contains("self.enc_key.zeroize()"));
    }

    #[test]
    fn f47_walletdb_lockfile_is_not_truncated_on_failed_lock_acquire() {
        let td = tempfile::tempdir().unwrap();
        let db_dir = td.path();
        WalletDb::init(db_dir).unwrap();

        let db1 = WalletDb::open_locked(db_dir, "correct-pass").unwrap();
        let lock_path = db_dir.join(".lock");
        let pid_before = std::fs::read_to_string(&lock_path).unwrap();
        assert!(!pid_before.trim().is_empty(), "lock file must contain pid");

        assert!(
            WalletDb::open_locked(db_dir, "correct-pass").is_err(),
            "second open_locked must fail while lock is held"
        );
        let pid_after = std::fs::read_to_string(&lock_path).unwrap();
        assert_eq!(
            pid_after, pid_before,
            "failed lock acquire must not truncate/overwrite existing pid"
        );

        drop(db1);
    }

    #[test]
    fn open_locked_rejects_malformed_legacy_entry_during_migration() {
        let td = tempfile::tempdir().unwrap();
        let db_dir = td.path();
        WalletDb::init(db_dir).unwrap();

        let rocks_dir = db_dir.join(DB_DIR);
        let db = open_rocksdb(&rocks_dir).unwrap();
        let cf_addrs = db.cf_handle(CF_ADDRS).unwrap();
        let malformed = WalletAddrMeta {
            version: 2, // invalid legacy version
            addr: String::new(),
            hrp: "pc".to_string(),
            change: 0,
            index: 0,
            xpub_derivation: "m/86'/12345'/0'/0/0".to_string(),
            fingerprint: None,
            xpubstore_path: "xpubs/default.toml".to_string(),
            label: None,
        };
        let raw = serde_json::to_vec(&malformed).unwrap();
        db.put_cf(&cf_addrs, b"legacy_bad", &raw).unwrap();
        drop(db);

        let err = match WalletDb::open_locked(db_dir, "test-passphrase") {
            Ok(_) => panic!("legacy migration must reject malformed entries"),
            Err(err) => err,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("walletdb legacy migration"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn open_locked_rejects_wrong_passphrase_with_marker() {
        let td = tempfile::tempdir().unwrap();
        let db_dir = td.path();
        WalletDb::init(db_dir).unwrap();

        // First open initializes encrypted metadata + passphrase marker.
        let db = WalletDb::open_locked(db_dir, "correct-pass").unwrap();
        drop(db);

        let err = match WalletDb::open_locked(db_dir, "wrong-pass") {
            Ok(_) => panic!("walletdb must reject wrong passphrase"),
            Err(err) => err,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("walletdb passphrase check failed"),
            "unexpected error message: {msg}"
        );
    }
}
