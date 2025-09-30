# Phantom-Coin: Binary Codec & Commitments v0

Ziel: Kanonisches, deterministisches Binärformat für alle PC-Datentypen, inklusive Domain-separierter Digests und Payload-Merkle-Root. Dieses Dokument ist normativ zur Wire-Kompatibilität.

## Geltungsbereich
- Codec-Grundlagen: Varints, feste Längen, `Vec<T>`.
- Layouts: `AnchorHeader`, `AnchorPayload`, `MicroTx`, `MintEvent`, `ClaimEvent`, `EvidenceEvent`/`EvidenceKind`, `ParentList`, `Tx*`.
- Commitments: Domain-separierte Leaf-Digests, Payload-Merkle-Root, Header-ID.
- Testvektoren (Golden) zur Kompatibilitäts-Prüfung.

Referenzimplementationen:
- `pc-codec`: `crates/pc-codec/src/lib.rs`
- `pc-types`: `crates/pc-types/src/lib.rs`
- PoW-Domain (nur Info): `crates/pc-consensus/src/consts.rs` (`POW_DOMAIN`) – in SPEC_POW dokumentiert.

## Codec-Grundlagen (pc-codec)
- Primitiven-Codierung
  - `u8`, `bool`: 1 Byte (`bool` als 0/1)
  - `u16`, `u32`: Little-Endian (LE)
  - `u64`: Varint (LEB128-ähnlich, base-128, max. 10 Bytes)
  - `[u8;32]`: 32 Bytes roh
- `Vec<T>`: `len: u64` als Varint, dann `len` Elemente in Reihenfolge.
- Fehlerbehandlung: `CodecError::{Truncated, InvalidTag(u8), InvalidLength(usize), Io(..)}`. Kein `panic!` im normalem Pfad.
- `encoded_len()` stimmt exakt mit der seriell geschriebenen Länge überein (Tests stellen dies sicher).

Varint (u64):
```text
while v >= 0x80 { write((v & 0x7f) | 0x80); v >>= 7 };
write(v)
```

## Strukturen (pc-types)
- `AnchorId([u8;32])` – Wrapper um 32-Byte-Hash.
- `OutPoint { txid: [u8;32], vout: u32 }`
- `TxIn { prev_out: OutPoint, witness: Vec<u8> }`
- `TxOut { amount: u64, lock: [u8;32] }` (als `LockCommitment`)
- `MicroTx { version: u8, inputs: Vec<TxIn>, outputs: Vec<TxOut> }`
- `MintEvent { version: u8, prev_mint_id: [u8;32], outputs: Vec<TxOut>, pow_seed: [u8;32], pow_nonce: u64 }`
- `ClaimEvent { version: u8, anchor_id: AnchorId, recipient_id: [u8;32], amount: u64, merkle_proof: Vec<[u8;32]>, payout_lock: [u8;32] }`
- `EvidenceKind` getaggt:
  - Tag=1 `Equivocation { seat_id: [u8;32], epoch_id: u64, a: AnchorHeader, b: AnchorHeader }`
  - Tag=2 `VoteInvalid { seat_id: [u8;32], anchor: AnchorHeader, reason_code: u16 }`
  - Tag=3 `ConflictingDAAttest { seat_id: [u8;32], anchor_id: AnchorId, attest_a: Vec<u8>, attest_b: Vec<u8> }`
- `EvidenceEvent { version: u8, evidence: EvidenceKind }`
- `ParentList { len: u8, ids: [AnchorId; 4], use: len Einträge }` – `len<=MAX_PARENTS` (sonst Decode-Fehler)
- `AnchorHeader { version: u8, shard_id: u16, parents: ParentList, payload_hash: [u8;32], creator_index: u8, vote_mask: u64, ack_present: bool, ack_id?: AnchorId }`
  - `ack_id` nur wenn `ack_present=true`.
- `AnchorPayload { version: u8, micro_txs: Vec<MicroTx>, mints: Vec<MintEvent>, claims: Vec<ClaimEvent>, evidences: Vec<EvidenceEvent>, payout_root: [u8;32] }`

Hinweise zu Limits (stateless sanity):
- In `pc-types` vorhanden, z. B. `MAX_TX_INPUTS`, `MAX_PAYLOAD_MICROTX` usw.
- Durchgesetzt durch `validate_*`-Funktionen (nicht durch Codec selbst).

## Domain-separierte Leaf-Digests (pc-types)
Konstanten (Bytestrings, Version sufﬁx `\x01`):
- `LEAF_MICROTX = b"pc:leaf:microtx:v1\x01"`
- `LEAF_MINT    = b"pc:leaf:mint:v1\x01"`
- `LEAF_CLAIM   = b"pc:leaf:claim:v1\x01"`
- `LEAF_EVID    = b"pc:leaf:evidence:v1\x01"`
- `LEAF_PAYOUT_ROOT = b"pc:leaf:payout_root:v1\x01"`

Definitionen:
- `digest_with_domain(domain, bytes) = blake3_32(domain || bytes)`
- `digest_microtx(tx) = digest_with_domain(LEAF_MICROTX, encode(tx))`
- `digest_mint(m)     = digest_with_domain(LEAF_MINT, encode(m))`
- `digest_claim(c)    = digest_with_domain(LEAF_CLAIM, encode(c))`
- `digest_evidence(e) = digest_with_domain(LEAF_EVID, encode(e))`
- `digest_payout_root(root32) = blake3_32(LEAF_PAYOUT_ROOT || root32)`

Header-ID (kein Domain-Tag):
- `AnchorHeader::id_digest() = blake3_32(encode(header))`

## Payload-Merkle-Root
1. Erzeuge Blätter:
   - Für alle `micro_txs`: `digest_microtx(tx)`
   - Für alle `mints`: `digest_mint(m)`
   - Für alle `claims`: `digest_claim(c)`
   - Für alle `evidences`: `digest_evidence(e)`
   - Plus ein Leaf für den `payout_root`: `digest_payout_root(&payload.payout_root)`
2. Sortiere alle Leaf-Hashes lexikographisch aufsteigend (`sort_unstable`).
3. `merkle_root_hashes(leaves)` liefert den 32-Byte-Root.

Eigenschaften:
- Ordnungsinvarianz: Reihenfolge innerhalb der Kategorien beeinflusst den Root nicht.
- Determinismus: vollständig deterministisch bei gleichen Eingaben.

## Kompatibilität & Versionierung
- Änderungen an Domaintags oder Layouts brechen Kompatibilität. Versionssprung (`v1` → `v2`) und neue Domaintags nötig.
- Golden-Tests (siehe unten) fungieren als Kompatibilitäts-Gate.

## Testvektoren (Golden)
Diese Vektoren werden in `pc-types` als Golden-Test geprüft. Änderungen erfordern bewussten Versionssprung.

- MICROTX_DIGEST:
  `1f701e879ce87e53d835dbf6ac42a51e2204135f664152749a51db4172872e73`
- MINT_DIGEST:
  `08d15620dc06558b18c7a175ed7613ebabe2b79329fc05ffa6860386137861f2`
- CLAIM_DIGEST:
  `ff1d41d529269c7aeea43b664ec7b674eae08ab97f7cc65976853d5b5aa3aea8`
- EVIDENCE_DIGEST:
  `78221b1ec5446d85ce9c7046d77033e4c9d9e6078cf8bd6fdf27c16b676db9e6`
- PAYLOAD_ROOT:
  `2b6cdafd1cba1ecf772c93135af43d5e6d8b0efde30be0a2504a9b85f769d0ba`
- HEADER_ID:
  `43e6762a4560e36c7528e6e85def46d5e1aa068eb44362b21e36691628cf7d91`

Quelle: `stable_hash_vectors_golden` in `crates/pc-types/src/lib.rs` (Tests). Ein zusätzlicher `#[ignore]`-Dump-Test kann Hashes sichtbar machen (nicht in CI aktiv).

## Beispiel-Encoding: AnchorHeader

Beispielobjekt (siehe `header_encode_example_bytes` in `pc-types` Tests):

- version = 1
- shard_id = 0x1234 (LE: 34 12)
- parents: len=2, ids=[AA..AA (32 B), BB..BB (32 B)]
- payload_hash = 11..11 (32 B)
- creator_index = 5
- vote_mask = 300 (Varint: AC 02)
- ack_present = true (01)
- ack_id = CC..CC (32 B)

Kanonisches Encoding (Hex):

```
01341202aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb111111111111111111111111111111111111111111111111111111111111111105ac0201cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
```

Feldaufbau in Reihenfolge:

- 01                         → version
- 34 12                      → shard_id (LE)
- 02                         → parents.len
- AA×32                      → parents[0]
- BB×32                      → parents[1]
- 11×32                      → payload_hash
- 05                         → creator_index
- AC 02                      → vote_mask (varint 300)
- 01                         → ack_present (true)
- CC×32                      → ack_id

### Diagramm: Byte-Layout AnchorHeader (v1)

```mermaid
flowchart TD
    A[version (1B)] --> B[shard_id (2B LE)] --> C[parents.len (1B)]
    C --> D1[parent[0] (32B)] --> D2[parent[1] (32B)] --> E[payload_hash (32B)]
    E --> F[creator_index (1B)] --> G[vote_mask (varuint)] --> H[ack_present (1B)]
    H --> I{ack_present?}
    I -- yes --> J[ack_id (32B)]
    I -- no  --> K[Ende]
```

## Beispiel-Encoding: AnchorPayload

Beispielobjekt (siehe `anchor_payload_encode_example_bytes` in `pc-types` Tests):

- version = 1
- `micro_txs`: 1 Eintrag (mit 1 Input/1 Output)
- `mints`: 1 Eintrag
- `claims`: 1 Eintrag (mit 2 Merkle-Proof-Hashes)
- `evidences`: 1 Eintrag (VoteInvalid)
- `payout_root`: aus `PayoutSet` mit 1 Entry

Kanonisches Encoding (Hex):

```
0101010110101010101010101010101010101010101010101010101010101010101010100100000002aabb01d2092020202020202020202020202020202020202020202020202020202020202020010130303030303030303030303030303030303030303030303030303030303030300137404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050508906010160606060606060606060606060606060606060606060606060606060606060606161616161616161616161616161616161616161616161616161616161616161de010262626262626262626262626262626262626262626262626262626262626262626363636363636363636363636363636363636363636363636363636363636363646464646464646464646464646464646464646464646464646464646464646401010270707070707070707070707070707070707070707070707070707070707070700100000000000000000000000000000000000000000000000000000000000000000000000000000003412b4cc5b78d49df718d9d7e615ead571bd76cb943144c196ed5893561280a30d95
```

### Diagramm: Byte-Layout AnchorPayload (v1)

```mermaid
flowchart TD
    A[version (1B)] --> B[Vec<MicroTx>] --> C[Vec<MintEvent>] --> D[Vec<ClaimEvent>] --> E[Vec<EvidenceEvent>] --> F[payout_root (32B)]
```

## Beispiel-Encoding: EvidenceKind-Varianten

Beispielobjekte (siehe `evidence_kinds_encode_example_bytes` in `pc-types` Tests):

- Tag=1: Equivocation `{ seat_id:[A0×32], epoch_id:42, a:Header::default(), b:Header::default() }`
  - Hex:
    ```
    0101a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a02a010000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000
    ```

- Tag=2: VoteInvalid `{ seat_id:[B0×32], anchor:Header::default(), reason_code:0xCAFE }`
  - Hex:
    ```
    0102b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0010000000000000000000000000000000000000000000000000000000000000000000000000000feca
    ```

- Tag=3: ConflictingDAAttest `{ seat_id:[C0×32], anchor_id:[C1×32], attest_a: [01,02,03], attest_b: [FF,EE] }`
  - Hex:
    ```
    0103c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c10301020302ffee
    ```

### Diagramm: EvidenceKind-Tagging (v1)

```mermaid
flowchart TD
    T[Tag (1B)] --> |1| EQ[Equivocation: seat_id(32B), epoch_id(varuint), a:AnchorHeader, b:AnchorHeader]
    T --> |2| VI[VoteInvalid: seat_id(32B), anchor:AnchorHeader, reason_code(u16 LE)]
    T --> |3| DA[ConflictingDAAttest: seat_id(32B), anchor_id(32B), attest_a(Vec<u8>), attest_b(Vec<u8>)]
```

## CI-Integration
- Bestehender Workflow `.github/workflows/ci.yml` führt `cargo test --workspace` aus; Golden-Tests laufen standardmäßig mit.
- Clippy- und Format-Checks sind aktiviert.

## Sicherheit & Performance
- Domain-Separation verhindert Cross-Protocol-Reuse/Collision-Angriffe über Datentypgrenzen.
- 32-Byte BLAKE3 für alle Commitments; Merkle-Sortierung reduziert Abhängigkeit von Eingabereihenfolgen.
- Kein Secret im Codec; konstante Zeitvergleiche nicht erforderlich.

## Hinweise zu PoW (nur Referenz)
- PoW-Domain: `POW_DOMAIN = b"pc:mint:pow:v1\x01"` (siehe SPEC_POW).
- Hash: `blake3_32(POW_DOMAIN || pow_seed || nonce_le)`; Vergleich per Leading-Zero-Bits.

### Diagramm: Payload-Merkle-Prozess

```mermaid
flowchart LR
    subgraph Inputs
        MT[micro_txs] --> MTd[digest_microtx]
        MN[mints] --> MNd[digest_mint]
        CL[claims] --> CLd[digest_claim]
        EV[evidences] --> EVd[digest_evidence]
        PR[payout_root] --> PRd[digest_payout_root]
    end

    MTd --> L[Leaves]
    MNd --> L
    CLd --> L
    EVd --> L
    PRd --> L

    L --> S[sort_unstable (lexicographisch)] --> MR[merkle_root_hashes] --> R[(Payload Root)]
```
