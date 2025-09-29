// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Write;
use clap::Parser;
use pc_codec::Encodable;
use pc_types::{AnchorPayload, MicroTx, TxIn, TxOut, OutPoint, LockCommitment, PayoutSet, PayoutEntry};

#[derive(Debug, Clone, Parser)]
#[command(name = "gen_payloads", version, about = "Generate Vec<AnchorPayload> in pc-codec format")]
struct Args {
    #[arg(long, default_value = "./test_payloads.bin")]
    out: String,
    #[arg(long, default_value_t = 3)]
    count: usize,
}

fn make_payload(i: usize) -> AnchorPayload {
    // Einfache MicroTx mit einem Input/Output
    let op = OutPoint { txid: [i as u8; 32], vout: 0 };
    let txin = TxIn { prev_out: op, witness: vec![1, 2, 3, (i % 255) as u8] };
    let txout = TxOut { amount: 100 + i as u64, lock: LockCommitment([((7 + (i % 200)) as u8); 32]) };
    let micro = MicroTx { version: 1, inputs: vec![txin], outputs: vec![txout] };

    // Payout-Root aus einfachem PayoutSet bestimmen
    let ps = PayoutSet { entries: vec![
        PayoutEntry { recipient_id: [i as u8; 32], amount: 10 + i as u64 },
        PayoutEntry { recipient_id: [(i as u8).wrapping_add(1); 32], amount: 20 + i as u64 },
    ]};
    let payout_root = ps.payout_root();

    AnchorPayload {
        version: 1,
        micro_txs: vec![micro],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root,
    }
}

fn main() {
    let args = Args::parse();
    let mut v: Vec<AnchorPayload> = Vec::with_capacity(args.count);
    for i in 0..args.count { v.push(make_payload(i)); }
    let mut buf: Vec<u8> = Vec::new();
    if let Err(e) = v.encode(&mut buf) {
        eprintln!("encode failed: {e}");
        std::process::exit(1);
    }
    if let Err(e) = File::create(&args.out).and_then(|mut f| f.write_all(&buf)) {
        eprintln!("write {} failed: {e}", &args.out);
        std::process::exit(1);
    }
    println!("written {} payloads to {}", args.count, args.out);
}
