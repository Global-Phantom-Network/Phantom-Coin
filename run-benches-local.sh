#!/bin/bash
set -e

echo "===== Local Benches Run ====="
echo "Started: $(date)"
echo ""

# Env vars (wie in benches-agg.yml)
export BENCH_MEASUREMENT_TIME=15
export BENCH_SAMPLE_SIZE=10
export BENCH_WARMUP_TIME=2
export RUST_LOG=warn

echo "Step 1: Cargo check"
cargo check --locked

echo ""
echo "Step 2: Bench libp2p RPC"
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_rpc -- \
  --measurement-time ${BENCH_MEASUREMENT_TIME} \
  --sample-size ${BENCH_SAMPLE_SIZE} \
  --warm-up-time ${BENCH_WARMUP_TIME}

echo ""
echo "Step 3: Bench libp2p E2E"
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_e2e -- \
  --measurement-time ${BENCH_MEASUREMENT_TIME} \
  --sample-size ${BENCH_SAMPLE_SIZE} \
  --warm-up-time ${BENCH_WARMUP_TIME}

echo ""
echo "Step 4: Bench QUIC"
cargo bench -p pc-p2p --features "async quic" --bench p2p_quic_bench -- \
  --measurement-time ${BENCH_MEASUREMENT_TIME} \
  --sample-size ${BENCH_SAMPLE_SIZE} \
  --warm-up-time ${BENCH_WARMUP_TIME}

echo ""
echo "Step 5: Bench libp2p EXTRA"
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_libp2p_extra -- \
  --measurement-time ${BENCH_MEASUREMENT_TIME} \
  --sample-size ${BENCH_SAMPLE_SIZE} \
  --warm-up-time ${BENCH_WARMUP_TIME}

echo ""
echo "Step 6: Bench Throughput headers"
cargo bench -p pc-p2p --features "async libp2p" --bench p2p_throughput_bench

echo ""
echo "Step 7: Aggregate results"
cargo run -p pc-p2p --bin bench_agg

echo ""
echo "Step 8: Budget Gate (absolute)"
cargo run -p pc-p2p --bin bench_ci_gate --release || echo "Budget Gate FAILED"

echo ""
echo "Step 9: Regression Gate vs Baseline"
cargo run -p pc-p2p --bin bench_gate -- --agg target/criterion_agg.csv || echo "Regression Gate FAILED"

echo ""
echo "===== Results ====="
if [ -f target/criterion_agg.md ]; then
  cat target/criterion_agg.md
else
  echo "No criterion_agg.md found"
fi

echo ""
echo "Finished: $(date)"
