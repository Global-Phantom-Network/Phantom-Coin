// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use pc_consensus::{consts, pow_hash, pow_meets};
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "mine_mint",
    version,
    about = "Finde einen Nonce für ein gegebenes pow_seed (Mint-PoW), basierend auf 'bits' (führende Nullbits)"
)]
struct Args {
    /// 32-Byte Hex (pow_seed)
    #[arg(long)]
    pow_seed: String,
    /// Optional: Bits (führende Nullbits). Falls nicht gesetzt, wird aus Genesis gelesen, sonst Default.
    #[arg(long)]
    bits: Option<u8>,
    /// Optional: Pfad zur genesis.toml. Wird verwendet, wenn --bits nicht angegeben.
    #[arg(long)]
    genesis: Option<String>,
    /// Start-Nonce (Default: 0)
    #[arg(long, default_value_t = 0u64)]
    start_nonce: u64,
    /// Anzahl Threads (Default: Anzahl CPU-Kerne)
    #[arg(long)]
    threads: Option<usize>,
    /// Optional: Status-Intervall in Sekunden (0=aus)
    #[arg(long, default_value_t = 5u64)]
    progress_secs: u64,
}

#[derive(Debug, Deserialize)]
struct GenesisConsensusPowOnly {
    pow_bits: Option<u8>,
}
#[derive(Debug, Deserialize)]
struct GenesisPowOnly {
    consensus: GenesisConsensusPowOnly,
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("invalid hex length for 32-byte id: {}", s.len());
    }
    let b = hex::decode(s).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if b.len() != 32 {
        bail!("invalid decoded length (got {}): must be 32 bytes", b.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn resolve_bits(args: &Args) -> Result<u8> {
    if let Some(b) = args.bits {
        return Ok(b);
    }
    if let Some(ref gpath) = args.genesis {
        let s = std::fs::read_to_string(gpath)
            .map_err(|e| anyhow!("read genesis '{}': {}", gpath, e))?;
        let g: GenesisPowOnly =
            toml::from_str(&s).map_err(|e| anyhow!("parse toml '{}': {}", gpath, e))?;
        if let Some(b) = g.consensus.pow_bits {
            return Ok(b);
        }
    }
    Ok(consts::POW_DEFAULT_BITS)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let seed = parse_hex32(&args.pow_seed)?;
    let bits = resolve_bits(&args)?;
    if (bits as u16) > 256 {
        bail!("bits {} out of range (must be 0..=256)", bits);
    }

    let n_threads = args.threads.unwrap_or_else(num_cpus::get);
    let n_threads = std::cmp::max(1, n_threads);

    let found = Arc::new(AtomicBool::new(false));
    let winner = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let total_hashes = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(n_threads);
    for tid in 0..n_threads {
        let seed_t = seed;
        let found_t = found.clone();
        let winner_t = winner.clone();
        let total_hashes_t = total_hashes.clone();
        let start_nonce = args.start_nonce;
        let step = n_threads as u64;
        let bits_t = bits;
        let h = thread::spawn(move || {
            let mut nonce = start_nonce.wrapping_add(tid as u64);
            while !found_t.load(Ordering::Relaxed) {
                let h = pow_hash(&seed_t, nonce);
                total_hashes_t.fetch_add(1, Ordering::Relaxed);
                if pow_meets(bits_t, &h) {
                    if !found_t.swap(true, Ordering::Relaxed) {
                        winner_t.store(nonce, Ordering::Relaxed);
                    }
                    break;
                }
                nonce = nonce.wrapping_add(step);
            }
        });
        handles.push(h);
    }

    // Optionaler Fortschritts-Logger
    let mut progress_handle = None;
    if args.progress_secs > 0 {
        let found_p = found.clone();
        let th = total_hashes.clone();
        let secs = args.progress_secs;
        progress_handle = Some(thread::spawn(move || {
            while !found_p.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(secs));
                let elapsed = start.elapsed().as_secs_f64();
                let hashes = th.load(Ordering::Relaxed) as f64;
                let hps = if elapsed > 0.0 { hashes / elapsed } else { 0.0 };
                eprintln!(
                    "{{\"type\":\"progress\",\"elapsed_s\":{:.2},\"hashes\":{},\"hashes_per_s\":{:.2}}}",
                    elapsed, hashes as u64, hps
                );
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }
    if let Some(h) = progress_handle {
        let _ = h.join();
    }

    let nonce = winner.load(Ordering::Relaxed);
    let hh = pow_hash(&seed, nonce);
    println!(
        "{{\"seed\":\"{}\",\"bits\":{},\"nonce\":{},\"hash\":\"{}\"}}",
        hex::encode(seed),
        bits,
        nonce,
        hex::encode(hh)
    );
    Ok(())
}
