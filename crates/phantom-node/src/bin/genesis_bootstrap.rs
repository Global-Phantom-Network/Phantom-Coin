// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use pc_codec::Encodable;
use pc_crypto::blake3_32;
use pc_types::{
    digest_genesis_note, GenesisNote, GenesisParams, GENESIS_FEATURE_ROLE_POLICY_V1,
    MAX_GENESIS_MESSAGE_BYTES,
};
use phantom_config as pcfg;
#[path = "../store_path.rs"]
mod store_path;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "genesis_bootstrap",
    version,
    about = "Erzeuge genesis_note.bin im Runtime-Mempool-Verzeichnis (network_id)"
)]
struct Args {
    /// Mempool directory, e.g. /var/lib/phantom-coin/data/mempool.
    /// Mempool-Verzeichnis, z. B. /var/lib/phantom-coin/data/mempool
    #[arg(long, alias = "mempool_dir", default_value_t = store_path::default_runtime_mempool_dir_string())]
    mempool_dir: String,
    /// Logical network name (feeds deterministically into the seed).
    /// Logischer Name des Netzwerks (fließt deterministisch in den Seed ein)
    #[arg(long, alias = "network_name", default_value = "ci-bench")]
    network_name: String,
    /// Number of initial shards.
    /// Anzahl initialer Shards
    #[arg(long, alias = "shards_initial", default_value_t = 64u16)]
    shards_initial: u16,
    /// Committee-K (Seats)
    #[arg(long, alias = "committee_k", default_value_t = 21u8)]
    committee_k: u8,
    /// Number of TX per payload (documentation only for GenesisNote params).
    /// Anzahl TX pro Payload (nur Dokumentationszweck für GenesisNote-Params)
    #[arg(long, alias = "txs_per_payload", default_value_t = 256u16)]
    txs_per_payload: u16,
    /// Feature bitmask.
    /// Feature-Bitmaske
    #[arg(long, default_value_t = 0u64)]
    features: u64,
    /// Optional: role policy JSON file (binds seed to policy commitment).
    /// Optional: Role-Policy JSON (bindet seed an Policy-Commitment).
    #[arg(long, alias = "role_policy")]
    role_policy: Option<String>,
    /// Optional: genesis inscription/message (stored in GenesisNote v2 field).
    /// Optional: Genesis-Nachricht (wird in GenesisNote v2 gespeichert).
    #[arg(long, alias = "genesis_message")]
    genesis_message: Option<String>,
    /// Optional: committed emission bootstrap bucket for first-round ASERT difficulty.
    /// Optional: konsensgebundener Emissions-Bootstrap-Bucket für ASERT vor dem ersten Mint.
    #[arg(long, default_value_t = 0u64)]
    emission_bootstrap_bucket: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let store_dir = store_path::default_runtime_store_dir()?;
    let mempool_dir = store_path::resolve_mempool_dir_value(&args.mempool_dir, &store_dir, false)?;

    let mut features = args.features;
    let seed = if let Some(ref policy_path) = args.role_policy {
        let policy = pcfg::load_role_policy_from_file(std::path::Path::new(policy_path))
            .map_err(|e| anyhow!("role_policy load failed: {e}"))?;
        features |= GENESIS_FEATURE_ROLE_POLICY_V1;
        policy.commitment()
    } else {
        if (features & GENESIS_FEATURE_ROLE_POLICY_V1) != 0 {
            return Err(anyhow!(
                "GENESIS_FEATURE_ROLE_POLICY_V1 set but no --role-policy provided"
            ));
        }
        // Derive deterministic seed from network_name (stable for CI).
        // Seed deterministisch aus network_name ableiten (stabil für CI)
        let mut seed_in = b"pc:genesis:seed:v1".to_vec();
        seed_in.extend_from_slice(args.network_name.as_bytes());
        blake3_32(&seed_in)
    };

    let params = GenesisParams {
        shards_initial: args.shards_initial,
        committee_k: args.committee_k,
        txs_per_payload: args.txs_per_payload,
        features,
    };

    let genesis_message = args
        .genesis_message
        .as_deref()
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    if genesis_message.len() > MAX_GENESIS_MESSAGE_BYTES {
        return Err(anyhow!(
            "genesis_message zu lang: {} > {} bytes",
            genesis_message.len(),
            MAX_GENESIS_MESSAGE_BYTES
        ));
    }

    // Versioning:
    // - v0: no validators, no message
    // - v2: supports genesis message (and validators if used by other tooling)
    // - v3: adds committed emission bootstrap bucket
    let mut version = if genesis_message.is_empty() { 0 } else { 2 };
    if args.emission_bootstrap_bucket != 0 {
        version = 3;
    }

    let note = GenesisNote {
        version,
        network_name: args.network_name.as_bytes().to_vec(),
        seed,
        params,
        genesis_validators: vec![],
        genesis_message,
        emission_bootstrap_bucket: args.emission_bootstrap_bucket,
    };

    let nid = digest_genesis_note(&note);

    let mut out_dir = PathBuf::from(&mempool_dir);
    create_dir_all(&out_dir).with_context(|| format!("mkdir -p {}", out_dir.display()))?;
    out_dir.push("genesis_note.bin");

    let mut buf: Vec<u8> = Vec::with_capacity(note.encoded_len());
    note.encode(&mut buf)
        .map_err(|e| anyhow!("encode genesis_note: {e}"))?;

    let mut f = File::create(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    f.write_all(&buf)
        .with_context(|| format!("write {}", out_dir.display()))?;
    f.flush().ok();

    println!(
        "{{\"type\":\"genesis_note_written\",\"file\":\"{}\",\"network_name\":\"{}\",\"network_id\":\"{}\",\"version\":{},\"genesis_message_bytes\":{},\"emission_bootstrap_bucket\":{}}}",
        out_dir.display(),
        String::from_utf8_lossy(&note.network_name),
        hex::encode(nid),
        note.version,
        note.genesis_message.len(),
        note.emission_bootstrap_bucket
    );

    Ok(())
}
