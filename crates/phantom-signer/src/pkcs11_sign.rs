// SPDX-License-Identifier: AGPL-3.0-only
//! PKCS#11 / HSM signing support via cryptoki

use anyhow::{anyhow, Context, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::env;
use std::fs;
use std::path::Path;

struct LogoutOnDrop<'a>(&'a cryptoki::session::Session);

impl<'a> Drop for LogoutOnDrop<'a> {
    fn drop(&mut self) {
        self.0.logout().ok();
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct SeatVoteHsmParams<'a> {
    pub module_path: &'a Path,
    pub pin_env: &'a str,
    pub key_id: &'a str,
    pub slash_db_path: &'a Path,
    pub epoch: u64,
    pub shard: u16,
    pub round: u64,
    pub header_id: &'a [u8],
}

/// Signiert eine Nachricht mit PKCS#11 HSM
pub fn sign_with_hsm(
    module_path: &Path,
    pin_env: &str,
    key_id: &str,
    msg: &[u8],
    mechanism: &str,
) -> Result<Vec<u8>> {
    // 1. PKCS#11 Context initialisieren
    let pkcs11 = Pkcs11::new(module_path)
        .context(format!("Failed to load PKCS#11 module: {:?}", module_path))?;

    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11")?;

    // 2. Slot mit Token finden
    let slots = pkcs11
        .get_slots_with_token()
        .context("Failed to get slots")?;
    let slot = slots
        .into_iter()
        .next()
        .context("No slots with token found")?;

    // 3. Session öffnen
    let session = pkcs11
        .open_rw_session(slot)
        .context("Failed to open session")?;

    // 4. Login mit PIN aus Environment
    let pin = env::var(pin_env).context(format!("Environment variable {} not set", pin_env))?;
    session
        .login(UserType::User, Some(&AuthPin::new(pin)))
        .context("Failed to login to HSM")?;
    let _logout = LogoutOnDrop(&session);

    // 5. Private Key finden
    let key_id_bytes = hex::decode(key_id).context("Invalid key ID hex")?;
    let template = vec![
        Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
        Attribute::Id(key_id_bytes),
    ];

    let objects = session
        .find_objects(&template)
        .context("Failed to find objects")?;
    let key_handle = objects
        .first()
        .context(format!("Key with ID {} not found", key_id))?;

    // 6. Mechanism auswählen
    let mech = match mechanism {
        "ECDSA" => Mechanism::Ecdsa,
        "ECDSA_SHA256" => Mechanism::EcdsaSha256,
        _ => return Err(anyhow!("Unsupported mechanism: {}", mechanism)),
    };

    // 7. Signieren
    let signature = session
        .sign(&mech, *key_handle, msg)
        .context("Signing failed")?;

    Ok(signature)
}

/// Signiert einen Seat-Vote mit PKCS#11 HSM (mit Slashing-DB Enforcement)
pub fn seat_vote_sign_with_hsm(params: SeatVoteHsmParams<'_>) -> Result<Vec<u8>> {
    let _ = params;
    Err(anyhow!(
        "seat-vote pkcs11 disabled: ECDSA mechanism cannot produce protocol-required Schnorr signatures"
    ))
}

/// Liest Nachricht aus Datei und signiert mit HSM
pub fn sign_file_with_hsm(
    module_path: &Path,
    pin_env: &str,
    key_id: &str,
    msg_path: &Path,
    mechanism: &str,
) -> Result<Vec<u8>> {
    let msg = fs::read(msg_path).context(format!("Failed to read message file: {:?}", msg_path))?;
    sign_with_hsm(module_path, pin_env, key_id, &msg, mechanism)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f80_seat_vote_sign_with_hsm_is_fail_closed_without_schnorr_mechanism() {
        let header = [0u8; 32];
        let params = SeatVoteHsmParams {
            module_path: Path::new("/tmp/nonexistent-pkcs11.so"),
            pin_env: "PKCS11_PIN",
            key_id: "00",
            slash_db_path: Path::new("/tmp/nonexistent-slashdb"),
            epoch: 1,
            shard: 0,
            round: 1,
            header_id: &header,
        };
        let err = seat_vote_sign_with_hsm(params).expect_err("must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("protocol-required Schnorr signatures"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn f38_seat_vote_sign_with_hsm_is_fail_closed_and_returns_no_signature() {
        let header = [0u8; 32];
        let params = SeatVoteHsmParams {
            module_path: Path::new("/tmp/nonexistent-pkcs11.so"),
            pin_env: "PKCS11_PIN",
            key_id: "00",
            slash_db_path: Path::new("/tmp/nonexistent-slashdb"),
            epoch: 1,
            shard: 0,
            round: 1,
            header_id: &header,
        };
        let err = seat_vote_sign_with_hsm(params).expect_err("must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("disabled") || msg.contains("Schnorr"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn f45_sign_with_hsm_installs_logout_guard_after_login() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("pkcs11_sign.rs");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            src.contains("let _logout = LogoutOnDrop(&session);"),
            "expected LogoutOnDrop guard to be installed after login"
        );
    }
}
