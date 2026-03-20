// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use pc_codec::{Decodable, Encodable};
use pc_crypto::Hash32;
use pc_types::{sighash_microtx_v1, MicroTx, NetworkId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Derivation {
    pub path: String, // z. B. m/86'/12345'/0'/0/0
}

// Hinweis: Nur in Tests benötigt -> in Testmodul verschoben, um dead_code-Warnung zu vermeiden

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministische Output-Sortierung: aufsteigend nach amount, dann lexikografisch nach lock
    fn sort_outputs_deterministic(tx: &mut MicroTx) {
        tx.outputs.sort_by(|a, b| match a.amount.cmp(&b.amount) {
            core::cmp::Ordering::Equal => a.lock.0.cmp(&b.lock.0),
            o => o,
        });
    }

    #[test]
    fn sighash_len_is_32_and_stable_on_empty_tx() {
        let nid: NetworkId = [0u8; 32];
        let tx = MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
        };
        let h = sighash_of_tx(&nid, &tx);
        assert_eq!(h.len(), 32);
        // Roundtrip encode does not change sighash
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let tx2 = MicroTx::decode(&mut &buf[..]).unwrap();
        assert_eq!(sighash_of_tx(&nid, &tx), sighash_of_tx(&nid, &tx2));
    }

    #[test]
    fn witness_layout_is_96_bytes_xonly_plus_sig() {
        let pub_xonly = [1u8; 32];
        let sig64 = [2u8; 64];
        let w = build_witness(&pub_xonly, &sig64);
        assert_eq!(w.len(), 96);
        assert_eq!(&w[0..32], &pub_xonly);
        assert_eq!(&w[32..96], &sig64);
    }

    #[test]
    fn outputs_are_sorted_by_amount_then_lock() {
        let o1 = pc_types::TxOut {
            amount: 10,
            lock: pc_types::LockCommitment([2u8; 32]),
        };
        let o2 = pc_types::TxOut {
            amount: 5,
            lock: pc_types::LockCommitment([9u8; 32]),
        };
        let o3 = pc_types::TxOut {
            amount: 10,
            lock: pc_types::LockCommitment([1u8; 32]),
        };
        let mut tx = MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![o1, o2, o3],
        };
        sort_outputs_deterministic(&mut tx);
        assert_eq!(tx.outputs[0].amount, 5);
        assert_eq!(tx.outputs[1].amount, 10);
        assert_eq!(tx.outputs[2].amount, 10);
        assert!(tx.outputs[1].lock.0 < tx.outputs[2].lock.0);
    }

    #[cfg(unix)]
    #[test]
    fn to_toml_file_sets_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tx = MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
        };
        let out = std::env::temp_dir().join(format!(
            "phantom_psbt_perm_test_{}_{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        to_toml_file(&tx, &[], &out).expect("to_toml_file");
        let md = std::fs::metadata(&out).expect("metadata");
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "group/other bits must be unset: {:o}",
            mode
        );
        let _ = std::fs::remove_file(&out);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomPsbtToml {
    pub version: u32,
    pub algo: String, // "schnorr"
    pub tx_b64: String,
    pub derivations: Vec<Derivation>, // pro Input
}

#[allow(dead_code)]
pub fn tx_without_witness(mut tx: MicroTx) -> MicroTx {
    for tin in &mut tx.inputs {
        tin.witness.clear();
    }
    tx
}

pub fn encode_tx(tx: &MicroTx) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(tx.encoded_len());
    tx.encode(&mut buf).map_err(|e| anyhow!("encode tx: {e}"))?;
    Ok(buf)
}

pub fn decode_tx(bytes: &[u8]) -> Result<MicroTx> {
    let mut s = bytes;
    let tx = MicroTx::decode(&mut s).map_err(|e| anyhow!("decode tx: {e}"))?;
    Ok(tx)
}

pub fn to_toml_file(tx: &MicroTx, derivations: &[Derivation], out: &Path) -> Result<()> {
    if derivations.len() != tx.inputs.len() {
        return Err(anyhow!(
            "derivations len ({}) != inputs len ({})",
            derivations.len(),
            tx.inputs.len()
        ));
    }
    let enc = encode_tx(tx)?;
    let psbt = PhantomPsbtToml {
        version: 1,
        algo: "schnorr".to_string(),
        tx_b64: general_purpose::STANDARD.encode(enc),
        derivations: derivations.to_vec(),
    };
    let data = toml::to_string_pretty(&psbt)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.create(true).truncate(true).write(true).mode(0o600);
        let mut f = opts.open(out)?;
        std::io::Write::write_all(&mut f, data.as_bytes())?;
        std::io::Write::flush(&mut f)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(out, &data)?;
        Ok(())
    }
}

pub fn from_toml_file(path: &Path) -> Result<(MicroTx, Vec<Derivation>)> {
    let raw = fs::read_to_string(path).map_err(|e| anyhow!("read psbt: {e}"))?;
    let psbt: PhantomPsbtToml = toml::from_str(&raw).map_err(|e| anyhow!("parse toml: {e}"))?;
    let tx_bytes = general_purpose::STANDARD
        .decode(&psbt.tx_b64)
        .map_err(|e| anyhow!("decode tx_b64: {e}"))?;
    let tx = decode_tx(&tx_bytes)?;
    Ok((tx, psbt.derivations))
}

pub fn sighash_of_tx(network_id: &NetworkId, tx: &MicroTx) -> Hash32 {
    sighash_microtx_v1(network_id, tx)
}

pub fn build_witness(pub_xonly: &[u8; 32], sig64: &[u8; 64]) -> Vec<u8> {
    // Zeugnis-Layout: xonly(32) || sig(64)
    let mut w = Vec::with_capacity(96);
    w.extend_from_slice(pub_xonly);
    w.extend_from_slice(sig64);
    w
}

pub fn attach_witnesses(mut tx: MicroTx, witnesses: &[Vec<u8>]) -> Result<MicroTx> {
    if witnesses.len() != tx.inputs.len() {
        return Err(anyhow!(
            "witnesses len ({}) != inputs len ({})",
            witnesses.len(),
            tx.inputs.len()
        ));
    }
    for (tin, w) in tx.inputs.iter_mut().zip(witnesses.iter()) {
        tin.witness = w.clone();
    }
    Ok(tx)
}
