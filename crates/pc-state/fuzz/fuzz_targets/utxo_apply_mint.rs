#![no_main]

use libfuzzer_sys::fuzz_target;
use pc_state::{InMemoryBackend, UtxoState};
use pc_types::{LockCommitment, MintEvent, TxOut};

fuzz_target!(|data: &[u8]| {
    // Parse fuzz input: num_outputs (1 byte) + per-output data
    if data.is_empty() {
        return;
    }
    
    let num_outputs = (data[0] as usize % 10).max(1); // 1-10 outputs
    let mut offset = 1;
    
    let mut outputs = Vec::new();
    for _ in 0..num_outputs {
        if offset + 40 > data.len() {
            break;
        }
        
        // Parse amount (8 bytes)
        let mut amt_bytes = [0u8; 8];
        amt_bytes.copy_from_slice(&data[offset..offset + 8]);
        let amount = u64::from_le_bytes(amt_bytes);
        offset += 8;
        
        // Parse lock (32 bytes)
        let mut lock_bytes = [0u8; 32];
        lock_bytes.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        outputs.push(TxOut {
            amount,
            lock: LockCommitment(lock_bytes),
        });
    }
    
    if outputs.is_empty() {
        return;
    }
    
    // Create mint event
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32],
        outputs,
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
    };
    
    // Apply to state
    let mut state = UtxoState::new(InMemoryBackend::new());
    state.apply_mint_with_index(&mint, 0);
    
    // Verify state is consistent
    let _ = state.root();
});
