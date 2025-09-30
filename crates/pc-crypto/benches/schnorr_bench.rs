use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pc_crypto::{blake3_32, schnorr_sign, schnorr_verify, SchnorrKeypair};
use secp256k1::XOnlyPublicKey;

fn bench_schnorr_sign(c: &mut Criterion) {
    let seed = blake3_32(b"bench:schnorr:seed");
    let kp = SchnorrKeypair::from_secret_key_bytes(&seed).expect("valid seckey");
    let msg = blake3_32(b"bench message");

    let mut group = c.benchmark_group("schnorr_sign");
    group.bench_function(BenchmarkId::from_parameter("1-msg"), |b| {
        b.iter(|| {
            let sig = schnorr_sign(black_box(&msg), &kp);
            black_box(sig)
        })
    });
    group.finish();
}

fn bench_schnorr_verify(c: &mut Criterion) {
    let seed = blake3_32(b"bench:schnorr:seed:verify");
    let kp = SchnorrKeypair::from_secret_key_bytes(&seed).expect("valid seckey");
    let msg = blake3_32(b"bench message verify");
    let sig = schnorr_sign(&msg, &kp);
    let pk: XOnlyPublicKey = kp.xonly;

    let mut group = c.benchmark_group("schnorr_verify");
    group.bench_function(BenchmarkId::from_parameter("1-sig"), |b| {
        b.iter(|| {
            let ok = schnorr_verify(black_box(&msg), black_box(&sig), &pk);
            black_box(ok)
        })
    });
    group.finish();
}

criterion_group!(benches, bench_schnorr_sign, bench_schnorr_verify);
criterion_main!(benches);
