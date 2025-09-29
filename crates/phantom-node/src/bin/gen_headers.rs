// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Write;
use clap::Parser;
use pc_codec::Encodable;
use pc_types::{AnchorHeader, ParentList, AnchorId};

#[derive(Debug, Clone, Parser)]
#[command(name = "gen_headers", version, about = "Generate Vec<AnchorHeader> in pc-codec format")]
struct Args {
    #[arg(long, default_value = "./test_headers.bin")]
    out: String,
    #[arg(long, default_value_t = 5)]
    count: usize,
}

fn main() {
    let args = Args::parse();
    let mut v: Vec<AnchorHeader> = Vec::with_capacity(args.count);
    for i in 0..args.count {
        let mut parents = ParentList::default();
        let _ = parents.push(AnchorId([i as u8; 32]));
        let mut h = AnchorHeader::default();
        h.version = 1;
        h.shard_id = (i % 7) as u16;
        h.parents = parents;
        h.payload_hash = [i as u8; 32];
        h.creator_index = (i % 8) as u8;
        h.vote_mask = 1u64 << (i % 16);
        h.ack_present = false;
        v.push(h);
    }
    let mut buf: Vec<u8> = Vec::new();
    if let Err(e) = v.encode(&mut buf) {
        eprintln!("encode failed: {e}");
        std::process::exit(1);
    }
    if let Err(e) = File::create(&args.out).and_then(|mut f| f.write_all(&buf)) {
        eprintln!("write {} failed: {e}", &args.out);
        std::process::exit(1);
    }
    println!("written {} headers to {}", args.count, args.out);
}
