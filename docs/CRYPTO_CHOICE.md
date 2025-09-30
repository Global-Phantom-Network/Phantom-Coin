# Phantom-Coin: Kryptographie-Entscheidung (t7_crypto_choice)

## Zusammenfassung
- **Accounts/Wallets**: Schnorr auf secp256k1 (BIP340-kompatibles XOnly), breite Tooling-/HW-Wallet-Unterstützung.
- **Attest-Aggregation**: BLS12-381 (min_pk, PoP-Variante der IETF-Ciphersuite). Nicht-interaktive Aggregation, Rogue-Key-sicher dank PoP.

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

## Weiteres
- Optional: Batch-Verify für Schnorr, Multi-Message `aggregate_verify`-Pfade für BLS im Protokoll verankern.
- CI: Benches optional mit `cargo bench -p pc-crypto`.
