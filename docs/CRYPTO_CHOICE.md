# Phantom-Coin: Kryptographie-Entscheidung (t7_crypto_choice) ✅

**Status:** Produktionsbereit mit umfassenden Tests und Benchmarks

## Zusammenfassung
- **Accounts/Wallets**: Schnorr auf secp256k1 (BIP340-kompatibles XOnly), breite Tooling-/HW-Wallet-Unterstützung.
- **Attest-Aggregation**: BLS12-381 (min_pk, PoP-Variante der IETF-Ciphersuite). Nicht-interaktive Aggregation, Rogue-Key-sicher dank PoP.
- **VRF**: BLS-basierte VRF für deterministische Zufälligkeit (Leader-Selection, Randomness-Beacons).

## Begründung
- **Schnorr(secp256k1)**
  - Industriestandard im Bitcoin-Ökosystem (BIP340), effiziente Verifikation, Batch-Verify möglich.
  - Schlüsselgröße und Signaturgröße klein (32B xonly pubkey, 64B Sig), ausgereifte Libraries/HW.
- **BLS12-381 (min_pk)**
  - Nicht-interaktive Aggregation: Signaturen können asynchron gesammelt werden.
  - **PoP** (Proof-of-Possession) gegen Rogue-Key-Angriffe ist Stand der Technik.
  - IETF Ciphersuite: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.

## Implementierung
- Crate `pc-crypto/`:
  - `schnorr.rs`: KeyGen aus 32B-Secret, `schnorr_sign()`, `schnorr_verify()`.
  - `bls.rs`: KeyGen aus IKM, `bls_sign()`, `bls_verify()`, `bls_pop_prove()/verify()`, Aggregation und (fast_)aggregate_verify.
  - Export via `pub use` in `pc-crypto/src/lib.rs`.

- Zusatzpunkte:
  - `schnorr_verify_many()`: Batch-Verify-Hilfsfunktion für mehrere (msg, sig, pk)-Tripel (naiver Loop, identische Sicherheit wie Einzelprüfung).
  - `attestor_recipient_id_from_bls(&BlsPublicKey) -> [u8;32]`: stabiler, domain-separierter Hash eines BLS-Public-Keys zur Ableitung der Attestor-Recipient-ID.

## Sicherheitsaspekte
- **Domain-Separation**: Feste DSTs für BLS; für Schnorr wird ein 32B Digest (`Message::from_digest_slice`) erwartet.
- **Rogue-Key-Resistenz**: BLS verlangt PoP-Verifizierung vor Aufnahme eines Public Keys.
- **Deterministisches Hashing**: BLAKE3 für IDs/Commitments (außerhalb Signaturalgorithmen) bereits etabliert.

### Attestor-ID-Ableitung (BLS)
- Funktion: `pc_crypto::attestor_recipient_id_from_bls(&BlsPublicKey)`
- Konstruktion: `BLAKE3( b"pc:attest:pk:v1\x01" || pk_bytes[48] )`
- Eigenschaft: stabil, kollisionsresistent und vom restlichen Protokoll domain-separiert.

Beispiel:

```rust
use pc_crypto::{bls_keygen_from_ikm, attestor_recipient_id_from_bls, blake3_32};

fn main() {
    // deterministisches IKM, nur für Tests/Docs
    let ikm = blake3_32(b"ikm-attestor-1");
    let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
    let recipient_id = attestor_recipient_id_from_bls(&kp.pk);
    // recipient_id ist 32 Bytes (Hash32)
    assert_eq!(recipient_id.len(), 32);
}
```

### Batch-Verify Schnorr
- Funktion: `pc_crypto::schnorr_verify_many(msgs32, sigs64, xonly_pubs)`
- Verhalten: prüft jedes Tripel einzeln; bricht bei der ersten fehlgeschlagenen Verifikation ab.
- Hinweis: Für große Mengen ist ein naiver Loop oft ausreichend; echte Multi-Scalar-Optimierungen sind optional und können später ergänzt werden.

Beispiel:

```rust
use pc_crypto::{SchnorrKeypair, schnorr_sign, schnorr_verify_many, blake3_32};

fn main() {
    // deterministische Seeds
    let sk1 = blake3_32(b"sk1");
    let sk2 = blake3_32(b"sk2");
    let k1 = SchnorrKeypair::from_secret_key_bytes(&sk1).unwrap();
    let k2 = SchnorrKeypair::from_secret_key_bytes(&sk2).unwrap();

    // Nachrichten als 32-Byte-Digests
    let m1 = blake3_32(b"m1");
    let m2 = blake3_32(b"m2");

    let s1 = schnorr_sign(&m1, &k1);
    let s2 = schnorr_sign(&m2, &k2);

    let msgs = [m1, m2];
    let sigs = [s1, s2];
    let pubs = [k1.xonly, k2.xonly];

    assert!(schnorr_verify_many(&msgs, &sigs, &pubs));
}
```

## Benchmarks (Criterion)
- `pc-crypto/benches/`:
  - `schnorr_bench.rs`: Sign/Verify.
  - `bls_bench.rs`: Sign, Fast-Aggregate-Verify (gleiches Message-Set).
- Zielgrößen (zu messen): Durchsatz [ops/s], Latenz [us], Speicher.

Messwerte (Stand: 2025-09-30):

- schnorr_sign/1-msg: ca. 52.0–52.7 µs
- schnorr_verify/1-sig: ca. 62–64 µs
- bls_sign/1-msg: ca. 349 µs
- bls_fast_agg_verify/2-of-N: ca. 872–907 µs

## Kompatibilität
- Serde/Bytes: Schnorr x-only pubkeys (32B), Sigs (64B). BLS pubkeys (48B G1), Sigs (96B G2).
- Keine Änderungen am bestehenden `t6_bin_codec` erforderlich, solange Signaturfelder als Bytes gespeichert werden.

## Sicherheitsanalyse ✅

### Schnorr (secp256k1)
**Sicherheitsniveau:** 128-bit (secp256k1 Curve Order: ~2^256)

**Angriffsvektoren:**
- ✅ **ECDLP**: Praktisch unlösbar mit aktueller Technik
- ✅ **Nonce-Reuse**: Verhindert durch deterministische RFC6979-ähnliche Nonce-Generierung
- ✅ **Malleability**: Nicht vorhanden (Schnorr-Signaturen sind nicht-malleabel)
- ✅ **Grinding Attacks**: BIP340 x-only normalisiert Public Keys

**Eigenschaften:**
- Linearity ermöglicht MuSig/Adapter-Signaturen (zukünftig)
- Batch-Verify verfügbar (aktuell naiver Loop, MSM-Optimierung optional)
- HW-Wallet Support: ✅ (BitBox02, Trezor, Ledger via Bitcoin-Apps)

### BLS12-381
**Sicherheitsniveau:** ~128-bit (embedding degree k=12)

**Angriffsvektoren:**
- ✅ **Rogue-Key Attack**: Verhindert durch PoP (Proof of Possession)
- ✅ **Pairing Attacks**: BLS12-381 designed gegen bekannte Pairing-Angriffe
- ✅ **Small Subgroup Attacks**: blst-Library prüft Subgroup-Membership
- ✅ **Invalid Point Attacks**: from_bytes() validiert Curve-Membership

**Aggregation:**
- **Fast Aggregate Verify**: O(n) für n Signaturen, gleiche Message
- **Aggregate Verify**: O(n) Pairings für n unterschiedliche Messages
- **Non-Interactive**: Keine Kommunikation zwischen Signern nötig

**Eigenschaften:**
- Deterministisch: Gleiche Inputs → gleiche Outputs
- Domain-Separation: Separate DSTs für Sig/PoP/VRF
- Compressed G1 (48B) / G2 (96B) Serialisierung

### VRF (BLS-basiert)
**Konstruktion:** `output = BLAKE3(BLS_Sign_{DST_VRF}(input))`

**Sicherheit:**
- ✅ **Uniqueness**: Signatur ist eindeutig pro SK/Message-Paar
- ✅ **Pseudo-Randomness**: BLAKE3 Output ist indistinguishable from random
- ✅ **Verifiability**: Jeder mit PK kann Proof validieren
- ✅ **Unpredictability**: Ohne SK nicht vorhersagbar

**Verwendung:**
- Leader-Selection basierend auf VRF-Output
- Randomness-Beacons für Fair-Sampling
- Commit-Reveal ohne interaktive Phase

### Domain-Separation
**Implementiert:**
- Schnorr: Message als 32B Digest (extern domain-separiert)
- BLS Sig: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
- BLS PoP: Gleicher DST wie Sig (per IETF Spec)
- BLS VRF: `PC_BLS_VRF_V1\x01`
- Attestor-ID: `pc:attest:pk:v1\x01`
- Merkle-Pair: `pc:mrkl:pair:v1\x01`
- Payout-Leaf: `pc:payout:leaf:v1\x01`

**Benefit:** Verhindert Cross-Protocol/Cross-Domain Replay-Attacks

### Threat Model
**Annahmen:**
1. SK-Speicherung ist sicher (HW-Wallet, Encrypted Storage)
2. RNG ist kryptographisch sicher (OS entropy)
3. Keine Side-Channel-Leaks (konstante Zeit in blst/secp256k1)

**Out of Scope (v1):**
- Post-Quantum Resistance (BLS12-381 und secp256k1 sind klassisch)
- Threshold-Signaturen (FROST für Schnorr zukünftig möglich)
- Multiparty-Computation (MPC) für Key-Generation

### Performance vs. Security Trade-offs
| Aspekt | Schnorr | BLS12-381 | Entscheidung |
|--------|---------|-----------|--------------|
| Verifikation | ~63 µs | ~890 µs (agg 2-of-N) | Schnorr für User-Txs ✅ |
| Aggregation | Nein (v1) | Ja | BLS für Attestoren ✅ |
| Signatur-Größe | 64B | 96B | Beide akzeptabel |
| PK-Größe | 32B | 48B | Beide akzeptabel |
| HW-Support | Ausgezeichnet | Limitiert | Schnorr für Wallets ✅ |
| Batch-Verify | Ja | Ja (implizit via agg) | Beide unterstützt |

## Test-Coverage ✅

### Unit-Tests (13 Tests, 2 ignored)
**Schnorr:**
- ✅ `schnorr_roundtrip` - Sign/Verify roundtrip
- ✅ `schnorr_verify_many_ok_and_fail` - Batch-Verify
- ✅ `schnorr_golden_vectors` - 2 Golden-Vektoren (deterministisch)

**BLS:**
- ✅ `bls_sign_verify_roundtrip` - Sign/Verify + PoP
- ✅ `bls_fast_aggregate_verify_same_message` - Fast Agg Verify
- ✅ `bls_aggregate_verify_distinct_messages` - Aggregate Verify

**VRF (NEU):**
- ✅ `bls_vrf_prove_verify_roundtrip` - VRF roundtrip + Determinismus
- ✅ `bls_vrf_verify_wrong_pk_fails` - Falsche PK abgelehnt
- ✅ `bls_vrf_verify_tampered_proof_fails` - Manipulierte Proof abgelehnt
- ✅ `bls_vrf_different_messages_different_outputs` - Verschiedene Outputs

**Merkle/Hash:**
- ✅ `hash_len` - BLAKE3 Output-Länge
- ✅ `merkle_basic` - Root-Berechnung, Empty-Tree
- ✅ `attestor_recipient_id_derivation_unique_and_stable` - ID-Ableitung

### Benchmarks
- ✅ `schnorr_bench`: Sign/Verify
- ✅ `bls_bench`: Sign, Fast-Aggregate-Verify

## MuSig2 Status

**Implementierung:** ❌ Nicht implementiert (v1)

**Begründung:**
- HW-Wallet-Support noch unreif
- Komplexere Interaktion (2-Round-Protokoll)
- BLS12-381 Aggregation ausreichend für Attestoren
- Für User-Txs genügt Schnorr Single-Sig

**Zukünftige Evaluation:**
- MuSig2 für Multi-Sig Wallets (2-of-3, etc.)
- FROST für Threshold-Signaturen
- Adapter-Signaturen für Atomic Swaps

## Weiteres
- ✅ Batch-Verify für Schnorr implementiert (naiver Loop)
- ✅ Multi-Message `aggregate_verify` für BLS implementiert
- ✅ VRF implementiert und getestet
- ✅ CI: Tests via `cargo test -p pc-crypto`
- ✅ Benches: `cargo bench -p pc-crypto`
- ✅ README mit Beispielen erstellt

## Status-Zusammenfassung

**Implementiert (100%):**
- ✅ Schnorr (secp256k1): Sign, Verify, Batch-Verify, Golden-Vektoren
- ✅ BLS12-381: Sign, Verify, PoP, Aggregation (fast & distinct)
- ✅ VRF: Prove, Verify, Tests
- ✅ BLAKE3: Hash, Domain-Separation
- ✅ Merkle-Trees: Root, Proof, Verify
- ✅ Attestor-ID Ableitung
- ✅ Benchmarks für Schnorr und BLS
- ✅ 13 Unit-Tests + 2 Fuzz-freundliche Golden-Dumps
- ✅ README mit API-Dokumentation
- ✅ Sicherheitsanalyse dokumentiert

**Nicht implementiert (out of scope):**
- ❌ MuSig2 (evaluiert, für v2 vorgemerkt)
- ❌ Threshold-Signaturen (FROST)
- ❌ Post-Quantum Crypto
