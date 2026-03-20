#![forbid(unsafe_code)]

use pc_types::{LockCommitment, MintEvent, TxOut};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Vectors {
    network_id: String,
    bits: u8,
    golden: Golden,
    negative: Vec<Negative>,
}

#[derive(Debug, Deserialize)]
struct Golden {
    template: Template,
    pow_seed: String,
    pow_nonce: u64,
    pow_hash: String,
}

#[derive(Debug, Deserialize)]
struct Negative {
    name: String,
    template: Template,
    pow_seed: String,
    pow_nonce: u64,
}

#[derive(Debug, Deserialize)]
struct Template {
    version: u8,
    prev_mint_id: String,
    outputs: Vec<OutJson>,
}

#[derive(Debug, Deserialize)]
struct OutJson {
    amount: u64,
    lock: String,
}

fn parse_hex32(s: &str) -> [u8; 32] {
    let raw = hex::decode(s).expect("hex decode (32 bytes)");
    assert_eq!(raw.len(), 32, "expected 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

fn mk_template_mint(t: &Template) -> MintEvent {
    let prev_mint_id = parse_hex32(&t.prev_mint_id);
    let mut outs: Vec<TxOut> = Vec::with_capacity(t.outputs.len());
    for o in t.outputs.iter() {
        let lock = LockCommitment(parse_hex32(&o.lock));
        outs.push(TxOut {
            amount: o.amount,
            lock,
        });
    }
    MintEvent {
        version: t.version,
        prev_mint_id,
        outputs: outs,
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    }
}

fn mk_mint_with_solution(template: &Template, pow_seed: [u8; 32], pow_nonce: u64) -> MintEvent {
    let mut m = mk_template_mint(template);
    m.pow_seed = pow_seed;
    m.pow_nonce = pow_nonce;
    m
}

#[test]
fn mint_pow_v1_vectors_json() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_vectors/mint_pow_v1.json");
    let raw = std::fs::read_to_string(&path).expect("read mint_pow_v1.json");
    let v: Vectors = serde_json::from_str(&raw).expect("parse mint_pow_v1.json");

    let network_id = parse_hex32(&v.network_id);
    let bits = v.bits;

    // Golden
    let tmpl = mk_template_mint(&v.golden.template);
    let expected_seed = pc_consensus::mint_pow_seed_v1(&network_id, &tmpl);
    assert_eq!(hex::encode(expected_seed), v.golden.pow_seed);

    let mint = mk_mint_with_solution(&v.golden.template, expected_seed, v.golden.pow_nonce);
    let got_pow_hash = pc_consensus::pow_hash(&mint.pow_seed, mint.pow_nonce);
    assert_eq!(hex::encode(got_pow_hash), v.golden.pow_hash);
    assert!(pc_consensus::pow_meets(bits, &got_pow_hash));
    assert!(pc_consensus::validate_mint_pow_bound_v1(&network_id, &mint, bits).is_ok());

    // Negative
    for n in v.negative.iter() {
        let tmpl_n = mk_template_mint(&n.template);
        let expected_seed_n = pc_consensus::mint_pow_seed_v1(&network_id, &tmpl_n);
        let claimed_seed = parse_hex32(&n.pow_seed);
        let mint_n = mk_mint_with_solution(&n.template, claimed_seed, n.pow_nonce);

        let invalid = if expected_seed_n != mint_n.pow_seed {
            true
        } else {
            pc_consensus::validate_mint_pow_bound_v1(&network_id, &mint_n, bits).is_err()
        };

        assert!(invalid, "negative vector must be invalid: {}", n.name);
    }
}
