use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pc_crypto::{bls_aggregate_signatures, bls_fast_aggregate_verify, bls_keygen_from_ikm, bls_sign};

fn bench_bls_sign(c: &mut Criterion) {
    let ikm = pc_crypto::blake3_32(b"bench:bls:ikm");
    let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
    let msg = b"bench bls message";

    let mut group = c.benchmark_group("bls_sign");
    group.bench_function(BenchmarkId::from_parameter("1-msg"), |b| {
        b.iter(|| {
            let sig = bls_sign(black_box(msg), &kp.sk);
            black_box(sig)
        })
    });
    group.finish();
}

fn bench_bls_fast_aggregate_verify(c: &mut Criterion) {
    let ikm1 = pc_crypto::blake3_32(b"bench:bls:ikm1");
    let ikm2 = pc_crypto::blake3_32(b"bench:bls:ikm2");
    let kp1 = bls_keygen_from_ikm(&ikm1).unwrap();
    let kp2 = bls_keygen_from_ikm(&ikm2).unwrap();
    let msg = b"same-message";
    let s1 = bls_sign(msg, &kp1.sk);
    let s2 = bls_sign(msg, &kp2.sk);
    let agg = bls_aggregate_signatures(&[s1, s2]).unwrap();

    let mut group = c.benchmark_group("bls_fast_agg_verify");
    group.bench_function(BenchmarkId::from_parameter("2-of-N"), |b| {
        b.iter(|| {
            let ok = bls_fast_aggregate_verify(black_box(msg), black_box(&agg), &[kp1.pk.clone(), kp2.pk.clone()]);
            black_box(ok)
        })
    });
    group.finish();
}

criterion_group!(benches, bench_bls_sign, bench_bls_fast_aggregate_verify);
criterion_main!(benches);
