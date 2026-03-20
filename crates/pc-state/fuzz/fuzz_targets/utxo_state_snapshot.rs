#![no_main]

use libfuzzer_sys::fuzz_target;
use pc_state::{InMemoryBackend, UtxoState};
use pc_types::{LockCommitment, MintEvent, TxOut};

fuzz_target!(|data: &[u8]| {
    if data.len() < 100 {
        return;
    }
    
    // Create state with multiple UTXOs
    let mut state = UtxoState::new(InMemoryBackend::new());
    
    let num_mints = (data[0] as usize % 10).max(1);
    let mut offset = 1;
    
    for i in 0..num_mints {
        if offset + 40 > data.len() {
            break;
        }
        
        // Parse amount
        let mut amt_bytes = [0u8; 8];
        amt_bytes.copy_from_slice(&data[offset..offset + 8]);
        let amount = u64::from_le_bytes(amt_bytes);
        offset += 8;
        
        // Parse lock
        let mut lock_bytes = [0u8; 32];
        lock_bytes.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        let mint = MintEvent {
            version: 1,
            prev_mint_id: [i as u8; 32],
            outputs: vec![TxOut {
                amount,
                lock: LockCommitment(lock_bytes),
            }],
            pow_seed: [i as u8; 32],
            pow_nonce: i as u64,
            minted_at: 0,
        };
        
        state.apply_mint_with_index(&mint, i as u64);
    }
    
    // Create snapshot
    let height = u64::from_le_bytes([
        data.get(offset).copied().unwrap_or(0),
        data.get(offset + 1).copied().unwrap_or(0),
        data.get(offset + 2).copied().unwrap_or(0),
        data.get(offset + 3).copied().unwrap_or(0),
        data.get(offset + 4).copied().unwrap_or(0),
        data.get(offset + 5).copied().unwrap_or(0),
        data.get(offset + 6).copied().unwrap_or(0),
        data.get(offset + 7).copied().unwrap_or(0),
    ]);
    
    let snapshot = state.create_snapshot(height);
    
    // Restore to new state
    let mut state2 = UtxoState::new(InMemoryBackend::new());
    let _ = state2.restore_snapshot(snapshot);
    
    // Verify roots match
    let root1 = state.root();
    let root2 = state2.root();
    assert_eq!(root1, root2, "Snapshot restore should preserve merkle root");
});
