# phantom-miner

## English version

Simple miner client (status polling). Serves as a placeholder for future PoW/proposer workflows.

### Mint mining (`mine`)

Mine against a `mint_rpc` server:

```bash
cargo run -p phantom-miner -- \
  mine \
  --rpc-url http://127.0.0.1:19090 \
  --lock <32-byte-hex-lock> \
  --threads 4 \
  --progress-secs 5 \
  --metrics-addr 127.0.0.1:9200
```

### Start via CLI

```bash
cargo run -p phantom-miner -- \
  run \
  --node-url https://127.0.0.1:8443 \
  --status-path /status \
  --tls-ca /etc/phantom-coin/certs/ca.crt \
  --interval-ms 1000
```

### Metrics summary (`metrics`)

```bash
cargo run -p phantom-miner -- \
  metrics \
  --metrics-url http://127.0.0.1:9200/metrics
```

JSON output:

```bash
cargo run -p phantom-miner -- \
  metrics \
  --metrics-url http://127.0.0.1:9200/metrics \
  --json
```

### Start via config (TOML)

Example: `miner.toml`

```toml
node_url = "https://127.0.0.1:8443"
status_path = "/status"
interval_ms = 1000
tls_ca = "/etc/phantom-coin/certs/ca.crt"
```

Start:

```bash
cargo run -p phantom-miner -- run --config miner.toml
```

## Deutsche Version

Einfacher Miner-Client (Status-Polling). Dient als Platz für künftige PoW-/Proposer-Workflows.

### Mint Mining (`mine`)

Mine gegen einen `mint_rpc` Server:

```bash
cargo run -p phantom-miner -- \
  mine \
  --rpc-url http://127.0.0.1:19090 \
  --lock <32-byte-hex-lock> \
  --threads 4 \
  --progress-secs 5 \
  --metrics-addr 127.0.0.1:9200
```

### Start per CLI

```bash
cargo run -p phantom-miner -- \
  run \
  --node-url https://127.0.0.1:8443 \
  --status-path /status \
  --tls-ca /etc/phantom-coin/certs/ca.crt \
  --interval-ms 1000
```

### Metrics Summary (`metrics`)

```bash
cargo run -p phantom-miner -- \
  metrics \
  --metrics-url http://127.0.0.1:9200/metrics
```

JSON:

```bash
cargo run -p phantom-miner -- \
  metrics \
  --metrics-url http://127.0.0.1:9200/metrics \
  --json
```

### Start per Config (TOML)

Beispiel: `miner.toml`

```toml
node_url = "https://127.0.0.1:8443"
status_path = "/status"
interval_ms = 1000
tls_ca = "/etc/phantom-coin/certs/ca.crt"
```

Start:

```bash
cargo run -p phantom-miner -- run --config miner.toml
```
