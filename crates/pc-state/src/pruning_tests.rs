use super::*;
use pc_types::{LockCommitment, MintEvent, TxOut};

#[test]
fn pruning_removes_old_utxos() {
    let mut st = UtxoState::new(InMemoryBackend::new());

    // Create mints at heights 0, 10, 20
    for i in 0..3 {
        let mint = MintEvent {
            version: 1,
            prev_mint_id: [0u8; 32],
            outputs: vec![TxOut {
                amount: 100,
                lock: LockCommitment([i as u8; 32]),
            }],
            pow_seed: [i as u8; 32],
            pow_nonce: i,
            minted_at: 0,
        };
        st.apply_mint_with_index(&mint, i * 10);
    }

    assert_eq!(st.backend.iter().count(), 3);
    let pruned = st.prune_old_utxos(30, 15);
    assert_eq!(pruned, 2);
    assert_eq!(st.backend.iter().count(), 1);
}

#[test]
fn pruning_removes_legacy_utxo_without_minted_at() {
    let mut st = UtxoState::new(InMemoryBackend::new());
    let op = OutPoint {
        txid: [0xabu8; 32],
        vout: 0,
    };
    st.backend_mut().put(op, (123, LockCommitment([0x44; 32])));
    assert_eq!(st.backend().get_minted_at(&op), None);

    // cutoff = 90; legacy entry defaults to minted_at=0 and must be pruned.
    let pruned = st.prune_old_utxos(100, 10);
    assert_eq!(pruned, 1);
    assert!(st.backend().get(&op).is_none());
}

#[test]
fn snapshot_roundtrip() {
    let mut st = UtxoState::new(InMemoryBackend::new());
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32],
        outputs: vec![TxOut {
            amount: 50,
            lock: LockCommitment([1u8; 32]),
        }],
        pow_seed: [3u8; 32],
        pow_nonce: 7,
        minted_at: 0,
    };
    st.apply_mint_with_index(&mint, 100);
    let root = st.root();

    let snap = st.create_snapshot(100);
    assert_eq!(snap.metadata.state_root, root);

    let mut st2 = UtxoState::new(InMemoryBackend::new());
    let res = st2.restore_snapshot(snap);
    assert!(res.is_ok(), "restore snapshot: {:?}", res.err());
    assert_eq!(st2.root(), root);
}
