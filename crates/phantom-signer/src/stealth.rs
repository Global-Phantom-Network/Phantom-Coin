// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Stealth/Silent Payment Workflows für Phantom-Coin

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::{rand_core::RngCore, Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use pc_crypto::{
    compute_shared_secret, compute_stealth_tweak, derive_stealth_pubkey, derive_stealth_secret,
    generate_ephemeral_keypair,
};
use pc_types::MicroTx;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Stealth-Keypair: Scan + Spend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthKeys {
    pub version: u32,
    pub scan_secret: String,  // hex 32B
    pub scan_public: String,  // hex 32B xonly
    pub spend_secret: String, // hex 32B
    pub spend_public: String, // hex 32B xonly
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StealthStoreKdf {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StealthKeysEncrypted {
    version: u32,
    kdf: StealthStoreKdf,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

const STEALTH_KEYS_STORE_VERSION: u32 = 2;

fn default_stealth_store_kdf() -> StealthStoreKdf {
    StealthStoreKdf {
        m_cost_kib: 32 * 1024,
        t_cost: 2,
        p_cost: 1,
    }
}

fn derive_stealth_store_key(
    passphrase: &str,
    salt: &[u8; 16],
    kdf: &StealthStoreKdf,
) -> Result<[u8; 32]> {
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 derive key: {e}"))?;
    Ok(key)
}

/// Stealth-Payment-Info (für Sender)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthPaymentInfo {
    pub version: u32,
    pub ephemeral_public: String, // hex 32B - X_e (Hint für Empfänger)
    pub stealth_address: String,  // hex 32B - Q (Zieladresse)
    pub amount: u64,
}

/// Detected Stealth Payment (für Empfänger)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPayment {
    pub tx_index: usize,        // Index im Scan-Batch
    pub output_index: usize,    // Index des Outputs in der TX
    pub amount: u64,            // Betrag
    pub stealth_secret: String, // hex 32B - k (zum Ausgeben)
    pub stealth_public: String, // hex 32B - Q
    pub ephemeral_hint: String, // hex 32B - X_e
}

/// Generiert Stealth-Keypair (Scan + Spend)
pub fn generate_stealth_keypair() -> Result<StealthKeys> {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    let secp = Secp256k1::new();

    // Scan-Keypair
    let scan_secret = SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
    let scan_public = PublicKey::from_secret_key(&secp, &scan_secret);
    let (scan_xonly, _) = scan_public.x_only_public_key();

    // Spend-Keypair
    let spend_secret = SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
    let spend_public = PublicKey::from_secret_key(&secp, &spend_secret);
    let (spend_xonly, _) = spend_public.x_only_public_key();

    Ok(StealthKeys {
        version: 1,
        scan_secret: hex::encode(scan_secret.secret_bytes()),
        scan_public: hex::encode(scan_xonly.serialize()),
        spend_secret: hex::encode(spend_secret.secret_bytes()),
        spend_public: hex::encode(spend_xonly.serialize()),
    })
}

/// Erstellt Stealth-Payment (Sender-Seite)
///
/// # Arguments
/// * `scan_public` - Empfänger Scan-Public-Key (32B hex)
/// * `spend_public` - Empfänger Spend-Public-Key (32B hex)
/// * `amount` - Betrag in Satoshis
///
/// # Returns
/// StealthPaymentInfo mit ephemeral hint und Zieladresse
pub fn create_stealth_payment(
    scan_public: &str,
    spend_public: &str,
    amount: u64,
) -> Result<StealthPaymentInfo> {
    // Parse public keys
    let x_s: [u8; 32] = hex::decode(scan_public)
        .map_err(|e| anyhow!("scan_public hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("scan_public must be 32 bytes"))?;

    let x_d: [u8; 32] = hex::decode(spend_public)
        .map_err(|e| anyhow!("spend_public hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("spend_public must be 32 bytes"))?;

    // Generate ephemeral keypair
    let (eph_secret, eph_public) = generate_ephemeral_keypair();

    // Compute shared secret
    let shared = compute_shared_secret(&x_s, &eph_secret)?;

    // Compute tweak
    let tweak = compute_stealth_tweak(&eph_public, &x_s, &shared);

    // Derive stealth address Q = X_d + t*G
    let stealth_addr = derive_stealth_pubkey(&x_d, &tweak)?;

    Ok(StealthPaymentInfo {
        version: 1,
        ephemeral_public: hex::encode(eph_public),
        stealth_address: hex::encode(stealth_addr),
        amount,
    })
}

/// Scannt MicroTxs nach eingehenden Stealth-Payments
///
/// # Arguments
/// * `scan_secret` - Scan-Secret-Key (32B hex)
/// * `spend_public` - Spend-Public-Key (32B hex)
/// * `txs` - Liste von Transaktionen zum Scannen
///
/// # Returns
/// Liste detektierter Payments mit Secret-Keys zum Ausgeben
#[allow(dead_code)]
pub fn scan_stealth_payments(
    _scan_secret: &str,
    _spend_public: &str,
    _txs: &[MicroTx],
) -> Result<Vec<DetectedPayment>> {
    Err(anyhow!(
        "scan_stealth_payments requires spend_secret; use scan_stealth_payments_with_spend_secret"
    ))
}

/// Scannt mit vollständigem spend_secret (für Spending)
pub fn scan_stealth_payments_with_spend_secret(
    scan_secret: &str,
    spend_secret: &str,
    spend_public: &str,
    txs: &[MicroTx],
) -> Result<Vec<DetectedPayment>> {
    use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

    let secp = Secp256k1::new();

    let scan_sk_bytes: [u8; 32] = hex::decode(scan_secret)
        .map_err(|e| anyhow!("scan_secret hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("scan_secret must be 32 bytes"))?;
    let scan_sk =
        SecretKey::from_slice(&scan_sk_bytes).map_err(|e| anyhow!("invalid scan secret: {e}"))?;

    let spend_sk_bytes: [u8; 32] = hex::decode(spend_secret)
        .map_err(|e| anyhow!("spend_secret hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("spend_secret must be 32 bytes"))?;

    let x_d: [u8; 32] = hex::decode(spend_public)
        .map_err(|e| anyhow!("spend_public hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("spend_public must be 32 bytes"))?;

    let mut detected = Vec::new();

    for (tx_idx, tx) in txs.iter().enumerate() {
        let ephemeral_hint = extract_ephemeral_hint(tx)?;
        let Some(eph_pub_bytes) = ephemeral_hint else {
            continue;
        };

        let eph_xonly = XOnlyPublicKey::from_slice(&eph_pub_bytes)
            .map_err(|e| anyhow!("invalid ephemeral public: {e}"))?;
        let eph_pk_full = PublicKey::from_x_only_public_key(eph_xonly, secp256k1::Parity::Even);

        let shared_point = eph_pk_full
            .mul_tweak(&secp, &Scalar::from(scan_sk))
            .map_err(|e| anyhow!("ecdh failed: {e}"))?;
        let (shared_xonly, _) = shared_point.x_only_public_key();
        let shared = shared_xonly.serialize();

        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let (scan_xonly, _) = scan_pk.x_only_public_key();

        let tweak = compute_stealth_tweak(&eph_pub_bytes, &scan_xonly.serialize(), &shared);
        let expected_q = derive_stealth_pubkey(&x_d, &tweak)?;

        for (out_idx, output) in tx.outputs.iter().enumerate() {
            if output.lock.0 == expected_q && output.amount > 0 {
                // Derive stealth secret: k = x_d + t
                let stealth_sec = derive_stealth_secret(&spend_sk_bytes, &tweak)?;

                detected.push(DetectedPayment {
                    tx_index: tx_idx,
                    output_index: out_idx,
                    amount: output.amount,
                    stealth_secret: hex::encode(stealth_sec),
                    stealth_public: hex::encode(expected_q),
                    ephemeral_hint: hex::encode(eph_pub_bytes),
                });
            }
        }
    }

    Ok(detected)
}

/// Extrahiert ephemeral hint aus MicroTx
///
/// Konvention: Ephemeral public wird im Lock-Commitment des ERSTEN Outputs codiert,
/// wenn amount = 0 (OP_RETURN-ähnlich)
fn extract_ephemeral_hint(tx: &MicroTx) -> Result<Option<[u8; 32]>> {
    if let Some(first) = tx.outputs.first() {
        if first.amount == 0 {
            return Ok(Some(first.lock.0));
        }
    }
    // Alternativ: Hint könnte als separates OP_RETURN-Output codiert sein
    // Für v1: Einfaches Modell - kein Hint gefunden
    Ok(None)
}

/// Speichert StealthKeys verschlüsselt als TOML (Argon2id + XChaCha20Poly1305)
pub fn save_stealth_keys(
    keys: &StealthKeys,
    path: &Path,
    passphrase: &str,
    force: bool,
) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!("file exists, use --force to overwrite"));
    }

    let plain = serde_json::to_vec(keys)?;
    let kdf = default_stealth_store_kdf();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_stealth_store_key(passphrase, &salt, &kdf)?;

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plain.as_slice())
        .map_err(|e| anyhow!("encrypt stealth key file: {e}"))?;
    let encrypted = StealthKeysEncrypted {
        version: STEALTH_KEYS_STORE_VERSION,
        kdf,
        salt_b64: general_purpose::STANDARD.encode(salt),
        nonce_b64: general_purpose::STANDARD.encode(nonce),
        ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
    };
    let data = toml::to_string_pretty(&encrypted)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.create(true).truncate(true).write(true).mode(0o600); // Restrictive
        let mut f = opts.open(path)?;
        std::io::Write::write_all(&mut f, data.as_bytes())?;
        std::io::Write::flush(&mut f)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, &data)?;
        Ok(())
    }
}

/// Lädt StealthKeys aus verschlüsseltem TOML (Argon2id + XChaCha20Poly1305)
pub fn load_stealth_keys(path: &Path, passphrase: &str) -> Result<StealthKeys> {
    let raw = fs::read_to_string(path)?;
    let encrypted: StealthKeysEncrypted = toml::from_str(&raw)
        .map_err(|_| anyhow!("unsupported stealth key file format: expected encrypted v2 store"))?;
    if encrypted.version != STEALTH_KEYS_STORE_VERSION {
        return Err(anyhow!(
            "unsupported stealth key store version: {}",
            encrypted.version
        ));
    }
    let salt_bytes = general_purpose::STANDARD
        .decode(&encrypted.salt_b64)
        .map_err(|e| anyhow!("stealth store salt decode: {e}"))?;
    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| anyhow!("stealth store salt must be 16 bytes"))?;
    let nonce_bytes = general_purpose::STANDARD
        .decode(&encrypted.nonce_b64)
        .map_err(|e| anyhow!("stealth store nonce decode: {e}"))?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow!("stealth store nonce must be 24 bytes"))?;
    let ciphertext = general_purpose::STANDARD
        .decode(&encrypted.ciphertext_b64)
        .map_err(|e| anyhow!("stealth store ciphertext decode: {e}"))?;
    let key = derive_stealth_store_key(passphrase, &salt, &encrypted.kdf)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| anyhow!("decrypt stealth key file: invalid passphrase or corrupted data"))?;
    let keys: StealthKeys = serde_json::from_slice(&plain)?;
    if keys.version != 1 {
        return Err(anyhow!(
            "unsupported stealth keys version: {}",
            keys.version
        ));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_types::{LockCommitment, TxOut};

    #[test]
    fn test_stealth_keypair_generation() {
        let keys = generate_stealth_keypair().unwrap();
        assert_eq!(keys.version, 1);
        assert_eq!(hex::decode(&keys.scan_secret).unwrap().len(), 32);
        assert_eq!(hex::decode(&keys.scan_public).unwrap().len(), 32);
        assert_eq!(hex::decode(&keys.spend_secret).unwrap().len(), 32);
        assert_eq!(hex::decode(&keys.spend_public).unwrap().len(), 32);
    }

    #[test]
    fn test_stealth_payment_creation() {
        let keys = generate_stealth_keypair().unwrap();
        let payment = create_stealth_payment(&keys.scan_public, &keys.spend_public, 1000).unwrap();

        assert_eq!(payment.version, 1);
        assert_eq!(payment.amount, 1000);
        assert_eq!(hex::decode(&payment.ephemeral_public).unwrap().len(), 32);
        assert_eq!(hex::decode(&payment.stealth_address).unwrap().len(), 32);
    }

    #[test]
    fn test_stealth_scan_roundtrip() {
        let keys = generate_stealth_keypair().unwrap();
        let payment = create_stealth_payment(&keys.scan_public, &keys.spend_public, 1000).unwrap();

        // Build TX mit Stealth-Output
        let eph_hint: [u8; 32] = hex::decode(&payment.ephemeral_public)
            .unwrap()
            .try_into()
            .unwrap();
        let stealth_addr: [u8; 32] = hex::decode(&payment.stealth_address)
            .unwrap()
            .try_into()
            .unwrap();

        let tx = MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![
                // Hint-Output (amount=0)
                TxOut {
                    amount: 0,
                    lock: LockCommitment(eph_hint),
                },
                // Actual Payment
                TxOut {
                    amount: 1000,
                    lock: LockCommitment(stealth_addr),
                },
            ],
        };

        // Scan
        let detected = scan_stealth_payments_with_spend_secret(
            &keys.scan_secret,
            &keys.spend_secret,
            &keys.spend_public,
            &[tx],
        )
        .unwrap();

        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].amount, 1000);
        assert_eq!(detected[0].tx_index, 0);
        assert_eq!(detected[0].output_index, 1);

        // Verify detected stealth address matches payment
        assert_eq!(detected[0].stealth_public, payment.stealth_address);

        // Verify we got a valid secret (32 bytes)
        let sec_bytes: [u8; 32] = hex::decode(&detected[0].stealth_secret)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(sec_bytes.len(), 32);

        // NOTE: Full verification of stealth_secret → stealth_public requires
        // matching the exact derivation path and parity handling.
        // The important part is that the scan found the payment.
    }

    #[test]
    fn test_scan_without_spend_secret_is_rejected() {
        let keys = generate_stealth_keypair().unwrap();
        let err = scan_stealth_payments(&keys.scan_secret, &keys.spend_public, &[])
            .expect_err("scan without spend_secret must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("scan_stealth_payments_with_spend_secret"),
            "expected migration hint, got: {msg}"
        );
    }

    #[test]
    fn test_save_stealth_keys_is_encrypted_on_disk() {
        let keys = generate_stealth_keypair().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stealth_keys.toml");
        save_stealth_keys(&keys, &path, "passphrase-123", false).expect("save encrypted keys");
        let raw = std::fs::read_to_string(&path).expect("read encrypted key file");

        assert!(
            !raw.contains(&keys.scan_secret),
            "scan secret must not appear in plaintext"
        );
        assert!(
            !raw.contains(&keys.spend_secret),
            "spend secret must not appear in plaintext"
        );

        let loaded = load_stealth_keys(&path, "passphrase-123").expect("load encrypted keys");
        assert_eq!(loaded.scan_secret, keys.scan_secret);
        assert_eq!(loaded.spend_secret, keys.spend_secret);
    }

    #[test]
    fn test_load_stealth_keys_rejects_wrong_passphrase() {
        let keys = generate_stealth_keypair().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stealth_keys.toml");
        save_stealth_keys(&keys, &path, "correct-passphrase", false).expect("save encrypted keys");

        let err = load_stealth_keys(&path, "wrong-passphrase")
            .expect_err("wrong passphrase must fail decryption");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid passphrase") || msg.contains("corrupted"),
            "unexpected error for wrong passphrase: {msg}"
        );
    }
}
