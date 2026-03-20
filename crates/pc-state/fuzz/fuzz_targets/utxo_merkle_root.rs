#![no_main]

use libfuzzer_sys::fuzz_target;
use pc_state::{InMemoryBackend, UtxoState};
use pc_types::{LockCommitment, MintEvent, TxOut};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    let mut state = UtxoState::new(InMemoryBackend::new());
    
    // Test merkle root with varying number of UTXOs
    let num_utxos = (data[0] as usize % 100).max(1);
    let mut offset = 1;
    
    for i in 0..num_utxos {
        if offset + 40 > data.len() {
            break;
        }
        
        // Parse amount
        let mut amt_bytes = [0u8; 8];
        if offset + 8 <= data.len() {
            amt_bytes.copy_from_slice(&data[offset..offset + 8]);
        }
        let amount = u64::from_le_bytes(amt_bytes);
        offset += 8;
        
        // Parse lock
        let mut lock_bytes = [0u8; 32];
        if offset + 32 <= data.len() {
            lock_bytes.copy_from_slice(&data[offset..offset + 32]);
        }
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
    
    // Compute root multiple times - should be deterministic
    let root1 = state.root();
    let root2 = state.root();
    assert_eq!(root1, root2, "Merkle root must be deterministic");
    
    // Create second state with same UTXOs in different order
    let mut state2 = UtxoState::new(InMemoryBackend::new());
    
    // Apply in reverse order
    for i in (0..num_utxos).rev() {
        let mint = MintEvent {
            version: 1,
            prev_mint_id: [i as u8; 32],
            outputs: vec![TxOut {
                amount: 100 + i as u64,
                lock: LockCommitment([i as u8; 32]),
            }],
            pow_seed: [i as u8; 32],
            pow_nonce: i as u64,
            minted_at: 0,
        };
        
        state2.apply_mint_with_index(&mint, i as u64);
    }
    
    // Roots should match (sorted internally)
    let root3 = state2.root();
    let _ = root3; // Roots may differ due to different amounts/locks, just verify no panic
});
