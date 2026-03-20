/// Phantom-Coin Tx-Pipeline Benchmark v2
///
/// Misst den maximalen Durchsatz der echten Transaktionspipeline:
///   Keypair → MicroTx erstellen → Signieren → Batch-Signaturprüfung (parallel)
///   → Sanity-Check → State-Validierung → Payload → Merkle-Root → State-Apply
///
/// Optimierungen gegenüber v1:
///   - Batch-Größe: 4096 (MAX_PAYLOAD_MICROTX)
///   - Parallele Signaturprüfung via rayon (Multi-Core)
///   - Parallele Tx-Erstellung + Signierung
///   - Auto-CPU-Erkennung: alle Kerne - 1 (1 Backup-Kern frei)
///
/// Läuft 3 Durchgänge: 10s, 20s, 30s
///
/// Aufruf:  cargo run --release --example bench_throughput -p pc-state
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use pc_crypto::blake3_32;
use pc_crypto::schnorr::{schnorr_sign, SchnorrKeypair};
use pc_state::{InMemoryBackend, UtxoState};
use pc_types::{
    digest_microtx, digest_mint, lock_commitment_schnorr_xonly_v1, payload_merkle_root_v3,
    sighash_microtx_v1, validate_microtx_sanity, validate_payload_sanity_v3, AnchorPayloadV3,
    MicroTx, MintEvent, OutPoint, TxIn, TxOut, TX_VERSION_TRANSFER_V1,
};

const NETWORK_ID: [u8; 32] = [0xBEu8; 32];
const MATURITY_THRESHOLD: u64 = 0;
const BATCH_SIZE: usize = 4096;

fn detect_worker_threads() -> usize {
    let total = num_cpus::get();
    let workers = if total > 2 { total - 1 } else { 1 };
    workers
}

struct Wallet {
    keypair: SchnorrKeypair,
    lock: pc_types::LockCommitment,
    pk_bytes: [u8; 32],
    utxos: VecDeque<(OutPoint, u64)>,
}

fn make_wallet(seed: &[u8]) -> Wallet {
    let sk = blake3_32(seed);
    let kp = SchnorrKeypair::from_secret_key_bytes(&sk).expect("valid seckey");
    let pk_bytes = kp.public_xonly_bytes();
    let lock = lock_commitment_schnorr_xonly_v1(&pk_bytes);
    Wallet {
        keypair: kp,
        lock,
        pk_bytes,
        utxos: VecDeque::new(),
    }
}

fn seed_utxos(state: &mut UtxoState<InMemoryBackend>, wallet: &mut Wallet, count: usize) {
    let mut prev_mint_id = [0u8; 32];
    for i in 0..count {
        let mint = MintEvent {
            version: 1,
            prev_mint_id,
            outputs: vec![TxOut {
                amount: 1_000_000,
                lock: wallet.lock,
            }],
            pow_seed: [0u8; 32],
            pow_nonce: i as u64,
            minted_at: 0,
        };
        let txid = digest_mint(&mint);
        state.apply_mint_with_index(&mint, 0);
        wallet
            .utxos
            .push_back((OutPoint { txid, vout: 0 }, 1_000_000));
        prev_mint_id = txid;
    }
}

fn build_unsigned_tx(lock: &pc_types::LockCommitment, op: OutPoint, amount: u64) -> MicroTx {
    MicroTx {
        version: TX_VERSION_TRANSFER_V1,
        inputs: vec![TxIn {
            prev_out: op,
            witness: vec![0u8; 96],
        }],
        outputs: vec![TxOut {
            amount,
            lock: *lock,
        }],
    }
}

fn sign_tx(tx: &mut MicroTx, kp: &SchnorrKeypair, pk_bytes: &[u8; 32]) {
    let digest = sighash_microtx_v1(&NETWORK_ID, tx);
    let sig = schnorr_sign(&digest, kp);
    let mut witness = Vec::with_capacity(96);
    witness.extend_from_slice(pk_bytes);
    witness.extend_from_slice(&sig);
    tx.inputs[0].witness = witness;
}

struct BatchSigData {
    msgs: Vec<[u8; 32]>,
    sigs: Vec<[u8; 64]>,
    pks: Vec<[u8; 32]>,
}

fn extract_sig_data(txs: &[MicroTx]) -> BatchSigData {
    let n = txs.len();
    let mut msgs = Vec::with_capacity(n);
    let mut sigs = Vec::with_capacity(n);
    let mut pks = Vec::with_capacity(n);
    for tx in txs {
        msgs.push(sighash_microtx_v1(&NETWORK_ID, tx));
        let w = &tx.inputs[0].witness;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&w[0..32]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&w[32..96]);
        pks.push(pk);
        sigs.push(sig);
    }
    BatchSigData { msgs, sigs, pks }
}

fn batch_verify_parallel(data: &BatchSigData) -> bool {
    data.msgs
        .par_iter()
        .zip(data.sigs.par_iter())
        .zip(data.pks.par_iter())
        .all(|((msg, sig), pk)| pc_crypto::schnorr::schnorr_verify_xonly_bytes(msg, sig, pk))
}

struct BenchResult {
    duration_secs: u64,
    elapsed: f64,
    total_txs: u64,
    total_payloads: u64,
    peak_batch_tps: f64,
    workers: usize,
    time_create_sign: f64,
    time_batch_verify: f64,
    time_sanity: f64,
    time_payload_merkle: f64,
    time_state_apply: f64,
    time_utxo_register: f64,
}

fn run_benchmark(duration_secs: u64, workers: usize) -> BenchResult {
    let backend = InMemoryBackend::new();
    let mut state = UtxoState::new(backend);

    let mut wallet = make_wallet(b"bench:wallet:seed:v2:optimized");
    let initial_utxos = 200_000;
    seed_utxos(&mut state, &mut wallet, initial_utxos);

    let deadline = Duration::from_secs(duration_secs);
    let start = Instant::now();
    let mut total_txs: u64 = 0;
    let mut total_payloads: u64 = 0;
    let mut anchor_index: u64 = 100;
    let mut peak_batch_tps: f64 = 0.0;

    let mut acc_create_sign: f64 = 0.0;
    let mut acc_batch_verify: f64 = 0.0;
    let mut acc_sanity: f64 = 0.0;
    let mut acc_payload_merkle: f64 = 0.0;
    let mut acc_state_apply: f64 = 0.0;
    let mut acc_utxo_register: f64 = 0.0;

    while start.elapsed() < deadline {
        let batch_start = Instant::now();
        let available = wallet.utxos.len().min(BATCH_SIZE);
        if available == 0 {
            break;
        }

        // 1) UTXOs entnehmen
        let utxo_batch: Vec<(OutPoint, u64)> = wallet.utxos.drain(..available).collect();

        // 2) Transaktionen erstellen + signieren (parallel)
        let t = Instant::now();
        let kp = &wallet.keypair;
        let pk = &wallet.pk_bytes;
        let lock = &wallet.lock;
        let txs: Vec<MicroTx> = utxo_batch
            .par_iter()
            .map(|(op, amount)| {
                let mut tx = build_unsigned_tx(lock, *op, *amount);
                sign_tx(&mut tx, kp, pk);
                tx
            })
            .collect();
        acc_create_sign += t.elapsed().as_secs_f64();

        // 3) Batch-Signaturprüfung (parallel über alle Kerne)
        let t = Instant::now();
        let sig_data = extract_sig_data(&txs);
        if !batch_verify_parallel(&sig_data) {
            eprintln!("FEHLER: Batch-Signaturprüfung fehlgeschlagen");
            break;
        }
        acc_batch_verify += t.elapsed().as_secs_f64();

        // 4) Sanity-Check (parallel, stateless)
        let t = Instant::now();
        let sanity_ok = txs.par_iter().all(|tx| validate_microtx_sanity(tx).is_ok());
        if !sanity_ok {
            eprintln!("FEHLER: Sanity-Check fehlgeschlagen");
            break;
        }
        acc_sanity += t.elapsed().as_secs_f64();

        // 5) Payload bauen + Merkle-Root
        let t = Instant::now();
        let payload = AnchorPayloadV3 {
            version: 3,
            micro_txs: txs.clone(),
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        };
        if let Err(e) = validate_payload_sanity_v3(&payload) {
            eprintln!("FEHLER payload-sanity: {e}");
            break;
        }
        let _root = payload_merkle_root_v3(&payload);
        acc_payload_merkle += t.elapsed().as_secs_f64();

        // 6) State anwenden / Finalisierung (sequentiell – konsens-kritisch)
        let t = Instant::now();
        match state.apply_payload_v2_tolerant(
            &[],
            &txs,
            &[],
            anchor_index,
            MATURITY_THRESHOLD,
            &NETWORK_ID,
        ) {
            Ok(skipped) => {
                if !skipped.is_empty() {
                    eprintln!("WARNUNG: {} Txs übersprungen", skipped.len());
                }
            }
            Err(e) => {
                eprintln!("FEHLER apply: {e:?}");
                break;
            }
        }
        acc_state_apply += t.elapsed().as_secs_f64();

        // 7) Neue UTXOs registrieren
        let t = Instant::now();
        for tx in &txs {
            let txid = digest_microtx(tx);
            for (i, out) in tx.outputs.iter().enumerate() {
                wallet.utxos.push_back((
                    OutPoint {
                        txid,
                        vout: i as u32,
                    },
                    out.amount,
                ));
            }
        }
        acc_utxo_register += t.elapsed().as_secs_f64();

        let batch_elapsed = batch_start.elapsed().as_secs_f64();
        let batch_tps = available as f64 / batch_elapsed;
        if batch_tps > peak_batch_tps {
            peak_batch_tps = batch_tps;
        }

        total_txs += available as u64;
        total_payloads += 1;
        anchor_index += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();

    BenchResult {
        duration_secs,
        elapsed,
        total_txs,
        total_payloads,
        peak_batch_tps,
        workers,
        time_create_sign: acc_create_sign,
        time_batch_verify: acc_batch_verify,
        time_sanity: acc_sanity,
        time_payload_merkle: acc_payload_merkle,
        time_state_apply: acc_state_apply,
        time_utxo_register: acc_utxo_register,
    }
}

fn print_result(r: &BenchResult) {
    let avg_tps = r.total_txs as f64 / r.elapsed;
    let avg_txs_per_payload = if r.total_payloads > 0 {
        r.total_txs as f64 / r.total_payloads as f64
    } else {
        0.0
    };
    let total_pipeline = r.time_create_sign
        + r.time_batch_verify
        + r.time_sanity
        + r.time_payload_merkle
        + r.time_state_apply
        + r.time_utxo_register;

    let pct = |t: f64| -> f64 { (t / total_pipeline) * 100.0 };

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!(
        "║  Benchmark: {}s Lauf  ({} Kerne)                          ║",
        r.duration_secs, r.workers
    );
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!(
        "║  Laufzeit            : {:>10.2}s                        ║",
        r.elapsed
    );
    println!(
        "║  Transaktionen       : {:>10}                         ║",
        r.total_txs
    );
    println!(
        "║  Payloads            : {:>10}                         ║",
        r.total_payloads
    );
    println!(
        "║  Txs/Payload (avg)   : {:>10.0}                         ║",
        avg_txs_per_payload
    );
    println!("║  ───────────────────────────────────────────────────     ║");
    println!(
        "║  Durchsatz (avg)     : {:>10.0} TPS                     ║",
        avg_tps
    );
    println!(
        "║  Durchsatz (peak)    : {:>10.0} TPS                     ║",
        r.peak_batch_tps
    );
    println!("║  ───────────────────────────────────────────────────     ║");
    println!("║  Pipeline-Aufschlüsselung:                              ║");
    println!(
        "║    Tx erstellen+sign : {:>7.2}s  ({:>5.1}%)                  ║",
        r.time_create_sign,
        pct(r.time_create_sign)
    );
    println!(
        "║    Batch-Sig-Verify  : {:>7.2}s  ({:>5.1}%)                  ║",
        r.time_batch_verify,
        pct(r.time_batch_verify)
    );
    println!(
        "║    Sanity-Check      : {:>7.2}s  ({:>5.1}%)                  ║",
        r.time_sanity,
        pct(r.time_sanity)
    );
    println!(
        "║    Payload+Merkle    : {:>7.2}s  ({:>5.1}%)                  ║",
        r.time_payload_merkle,
        pct(r.time_payload_merkle)
    );
    println!(
        "║    State-Apply       : {:>7.2}s  ({:>5.1}%)                  ║",
        r.time_state_apply,
        pct(r.time_state_apply)
    );
    println!(
        "║    UTXO-Register     : {:>7.2}s  ({:>5.1}%)                  ║",
        r.time_utxo_register,
        pct(r.time_utxo_register)
    );
    println!("║  ───────────────────────────────────────────────────     ║");
    let shards_for_1m = (1_000_000.0 / avg_tps).ceil() as u64;
    println!(
        "║  Für 1 Mio TPS       : ~{} Shards nötig                  ║",
        shards_for_1m
    );
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
}

fn main() {
    let workers = detect_worker_threads();
    let total_cpus = num_cpus::get();

    rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build_global()
        .expect("rayon thread pool");

    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("   Phantom-Coin Tx-Pipeline Benchmark v2");
    println!("   ─────────────────────────────────────────────────────");
    println!("   CPU-Kerne erkannt  : {total_cpus}");
    println!("   Worker-Threads     : {workers} (1 Kern als Backup frei)");
    println!("   Batch-Größe        : {BATCH_SIZE} Txs/Payload");
    println!("   ─────────────────────────────────────────────────────");
    println!("   Pipeline: Erstellen → Signieren → Batch-Sig-Verify");
    println!("   → Sanity → Payload+Merkle → State-Apply (finalisieren)");
    println!("   ─────────────────────────────────────────────────────");
    println!("   Parallelisiert: Erstellen, Signieren, Sig-Verify, Sanity");
    println!("   Sequentiell:    State-Apply (konsens-kritisch)");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    // Warmup
    let t0 = Instant::now();
    {
        let backend = InMemoryBackend::new();
        let mut state = UtxoState::new(backend);
        let mut w = make_wallet(b"warmup:v2");
        seed_utxos(&mut state, &mut w, 2000);
        let utxos: Vec<_> = w.utxos.drain(..100).collect();
        let txs: Vec<MicroTx> = utxos
            .par_iter()
            .map(|(op, amount)| {
                let mut tx = build_unsigned_tx(&w.lock, *op, *amount);
                sign_tx(&mut tx, &w.keypair, &w.pk_bytes);
                tx
            })
            .collect();
        let sig_data = extract_sig_data(&txs);
        let _ = batch_verify_parallel(&sig_data);
        let _ = state.apply_payload_v2_tolerant(&[], &txs, &[], 100, 0, &NETWORK_ID);
    }
    println!("Warmup fertig ({:.2}s)\n", t0.elapsed().as_secs_f64());

    for &secs in &[10, 20, 30] {
        let result = run_benchmark(secs, workers);
        print_result(&result);
    }

    println!("═══════════════════════════════════════════════════════════");
    println!("   Benchmark abgeschlossen.");
    println!("═══════════════════════════════════════════════════════════");
}
