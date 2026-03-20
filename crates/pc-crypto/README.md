# pc-crypto

## English version

Cryptographic primitives for Phantom-Coin: Schnorr (secp256k1), BLS12-381, BLAKE3 and Merkle trees.

## Features

### Schnorr (secp256k1)

- **BIP340 compatible**: x-only public keys (32B), signatures (64B)
- **Signing**: `schnorr_sign(msg32, keypair)` → 64B signature
- **Verification**: `schnorr_verify(msg32, sig64, xonly_pk)` → bool
- **Batch verify**: `schnorr_verify_many(msgs, sigs, pks)` → bool

**Usage:**

```rust
use pc_crypto::{SchnorrKeypair, schnorr_sign, schnorr_verify, blake3_32};

let seed = blake3_32(b"my-secret-seed");
let kp = SchnorrKeypair::from_secret_key_bytes(&seed)?;
let msg = blake3_32(b"hello world");
let sig = schnorr_sign(&msg, &kp);
assert!(schnorr_verify(&msg, &sig, &kp.xonly));
```

### BLS12-381 (min_pk)

- **IETF ciphersuite**: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
- **Signature aggregation**: non-interactive, PoP-protected
- **PoP** (Proof of Possession): rogue-key resistance
- **VRF** (Verifiable Random Function): built on BLS signatures

**Core API:**

```rust
use pc_crypto::{bls_keygen_from_ikm, bls_sign, bls_verify, bls_pop_prove, bls_pop_verify};

let ikm = blake3_32(b"my-ikm");
let kp = bls_keygen_from_ikm(&ikm)?;

// PoP
let pop = bls_pop_prove(&kp.sk);
assert!(bls_pop_verify(&kp.pk, &pop));

// Signature
let msg = b"hello bls";
let sig = bls_sign(msg, &kp.sk);
assert!(bls_verify(msg, &sig, &kp.pk));
```

**Aggregation:**

```rust
use pc_crypto::{bls_aggregate_signatures, bls_fast_aggregate_verify};

let sig1 = bls_sign(msg, &kp1.sk);
let sig2 = bls_sign(msg, &kp2.sk);
let agg_sig = bls_aggregate_signatures(&[sig1, sig2])?;

// Fast aggregate verify (same message)
assert!(bls_fast_aggregate_verify(msg, &agg_sig, &[kp1.pk, kp2.pk]));
```

**VRF:**

```rust
use pc_crypto::{bls_vrf_prove, bls_vrf_verify};

let (proof, output) = bls_vrf_prove(b"input", &sk);
let verified_output = bls_vrf_verify(b"input", &proof, &pk);
assert_eq!(Some(output), verified_output);
```

### BLAKE3

- **Hash**: `blake3_32(data)` → [u8; 32]
- **Domain separation**: used in all digest functions

### Merkle trees

- **Root**: `merkle_root_hashes(&[Hash32])` → `Hash32`
- **Proof**: `merkle_build_proof(leaves, index)` → `Vec<MerkleStep>`
- **Verify**: `merkle_verify_with_proof(leaf, proof, root)` → bool
- **Domain-separated**: pair hashing with `pc:mrkl:pair:v1`

## Attestor ID derivation

```rust
use pc_crypto::{attestor_recipient_id_from_bls, bls_keygen_from_ikm};

let kp = bls_keygen_from_ikm(&ikm)?;
let recipient_id = attestor_recipient_id_from_bls(&kp.pk);
// → 32-byte ID, domain separated
```

## Tests

```bash
cargo test -p pc-crypto
```

**Test coverage:**

- ✅ Schnorr: sign/verify roundtrip, batch verify, golden vectors
- ✅ BLS: sign/verify, PoP, aggregation (fast & distinct), golden vectors
- ✅ VRF: prove/verify roundtrip, wrong PK, tampered proof, determinism
- ✅ Merkle: basic, proof build, verify
- ✅ Attestor ID: stability, uniqueness

**Total: 13 tests (2 ignored golden dumps)**

## Benchmarks

```bash
cargo bench -p pc-crypto
```

**Targets:**

- `schnorr_bench`: sign/verify performance
- `bls_bench`: sign, fast aggregate verify

**Typical reference measurements:**

- Schnorr sign: ~52 µs
- Schnorr verify: ~63 µs
- BLS sign: ~349 µs
- BLS fast aggregate verify (2-of-N): ~890 µs

## Security

- **Domain separation**: all hashes use explicit domain tags
- **Rogue-key resistance**: BLS PoP verification is mandatory
- **No unsafe code**: `#![forbid(unsafe_code)]`
- **Determinism**: all operations are deterministically reproducible

## Dependencies

- `blake3`: BLAKE3 hash function
- `secp256k1`: Bitcoin-compatible Schnorr signatures
- `blst`: high-performance BLS12-381 implementation

## Documentation

See:

- `docs/CRYPTO_CHOICE.md` – architecture decisions
- `docs/SPEC_CRYPTO.md` – technical specification

## Deutsche Version

Kryptographische Primitiven für Phantom-Coin: Schnorr (secp256k1), BLS12-381, BLAKE3 und Merkle-Trees.

## Features

### Schnorr (secp256k1)

- **BIP340-kompatibel**: x-only Public Keys (32B), Signaturen (64B)
- **Signatur**: `schnorr_sign(msg32, keypair)` → 64B Signatur
- **Verifikation**: `schnorr_verify(msg32, sig64, xonly_pk)` → bool
- **Batch-Verify**: `schnorr_verify_many(msgs, sigs, pks)` → bool

**Verwendung:**

```rust
use pc_crypto::{SchnorrKeypair, schnorr_sign, schnorr_verify, blake3_32};

let seed = blake3_32(b"my-secret-seed");
let kp = SchnorrKeypair::from_secret_key_bytes(&seed)?;
let msg = blake3_32(b"hello world");
let sig = schnorr_sign(&msg, &kp);
assert!(schnorr_verify(&msg, &sig, &kp.xonly));
```

### BLS12-381 (min_pk)

- **IETF Ciphersuite**: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
- **Signatur-Aggregation**: nicht-interaktiv, PoP-gesichert
- **PoP** (Proof of Possession): Rogue-Key-Resistenz
- **VRF** (Verifiable Random Function): basierend auf BLS-Signaturen

**Kern-API:**

```rust
use pc_crypto::{bls_keygen_from_ikm, bls_sign, bls_verify, bls_pop_prove, bls_pop_verify};

let ikm = blake3_32(b"my-ikm");
let kp = bls_keygen_from_ikm(&ikm)?;

// PoP
let pop = bls_pop_prove(&kp.sk);
assert!(bls_pop_verify(&kp.pk, &pop));

// Signatur
let msg = b"hello bls";
let sig = bls_sign(msg, &kp.sk);
assert!(bls_verify(msg, &sig, &kp.pk));
```

**Aggregation:**

```rust
use pc_crypto::{bls_aggregate_signatures, bls_fast_aggregate_verify};

let sig1 = bls_sign(msg, &kp1.sk);
let sig2 = bls_sign(msg, &kp2.sk);
let agg_sig = bls_aggregate_signatures(&[sig1, sig2])?;

// Fast Aggregate Verify (gleiche Message)
assert!(bls_fast_aggregate_verify(msg, &agg_sig, &[kp1.pk, kp2.pk]));
```

**VRF:**

```rust
use pc_crypto::{bls_vrf_prove, bls_vrf_verify};

let (proof, output) = bls_vrf_prove(b"input", &sk);
let verified_output = bls_vrf_verify(b"input", &proof, &pk);
assert_eq!(Some(output), verified_output);
```

### BLAKE3

- **Hash**: `blake3_32(data)` → [u8; 32]
- **Domain-Separation**: in allen Digest-Funktionen verwendet

### Merkle-Trees

- **Root**: `merkle_root_hashes(&[Hash32])` → `Hash32`
- **Proof**: `merkle_build_proof(leaves, index)` → `Vec<MerkleStep>`
- **Verify**: `merkle_verify_with_proof(leaf, proof, root)` → bool
- **Domain-separated**: Paar-Hashing mit `pc:mrkl:pair:v1`

## Attestor-ID Ableitung

```rust
use pc_crypto::{attestor_recipient_id_from_bls, bls_keygen_from_ikm};

let kp = bls_keygen_from_ikm(&ikm)?;
let recipient_id = attestor_recipient_id_from_bls(&kp.pk);
// → 32-Byte ID, domain-separiert
```

## Tests

```bash
cargo test -p pc-crypto
```

**Test-Coverage:**

- ✅ Schnorr: Sign/Verify roundtrip, Batch-Verify, Golden-Vektoren
- ✅ BLS: Sign/Verify, PoP, Aggregation (fast & distinct), Golden-Vektoren
- ✅ VRF: Prove/Verify roundtrip, Wrong PK, Tampered Proof, Determinismus
- ✅ Merkle: Basic, Proof-Build, Verify
- ✅ Attestor-ID: Stabilität, Eindeutigkeit

**Gesamt: 13 Tests (2 ignored Golden-Dumps)**

## Benchmarks

```bash
cargo bench -p pc-crypto
```

**Targets:**

- `schnorr_bench`: Sign/Verify Performance
- `bls_bench`: Sign, Fast-Aggregate-Verify

**Typische Messwerte (Referenz):**

- Schnorr Sign: ~52 µs
- Schnorr Verify: ~63 µs
- BLS Sign: ~349 µs
- BLS Fast Aggregate Verify (2-of-N): ~890 µs

## Sicherheit

- **Domain-Separation**: alle Hashes mit expliziten Domain-Tags
- **Rogue-Key-Resistenz**: BLS PoP-Verifikation obligatorisch
- **No Unsafe Code**: `#![forbid(unsafe_code)]`
- **Determinismus**: alle Operationen deterministisch reproduzierbar

## Abhängigkeiten

- `blake3`: BLAKE3 Hash-Funktion
- `secp256k1`: Bitcoin-kompatible Schnorr-Signaturen
- `blst`: hochperformante BLS12-381 Implementierung

## Dokumentation

Siehe:

- `docs/CRYPTO_CHOICE.md` – Architekturentscheidungen
- `docs/SPEC_CRYPTO.md` – Technische Spezifikation
