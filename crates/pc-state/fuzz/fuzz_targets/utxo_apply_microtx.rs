#![no_main]

use libfuzzer_sys::fuzz_target;
use pc_state::{InMemoryBackend, UtxoState};
use pc_types::{digest_mint, sighash_microtx_v1, LockCommitment, MicroTx, MintEvent, NetworkId, OutPoint, TxIn, TxOut};

fuzz_target!(|data: &[u8]| {
    if data.len() < 50 {
        return;
    }

    let nid: NetworkId = [9u8; 32];
    let sk = [1u8; 32];
    let kp = match pc_crypto::SchnorrKeypair::from_secret_key_bytes(&sk) {
        Ok(k) => k,
        Err(_) => return,
    };
    let pk = kp.public_xonly_bytes();
    
    // Setup: Create initial UTXO via mint
    let initial_amount = 1_000_000u64;
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32],
        outputs: vec![TxOut {
            amount: initial_amount,
            lock: LockCommitment(pk),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
    };
    
    let mut state = UtxoState::new(InMemoryBackend::new());
    state.apply_mint_with_index(&mint, 0);
    
    let txid = digest_mint(&mint);
    
    // Parse fuzz input for MicroTx
    let num_inputs = (data[0] as usize % 5).max(1); // 1-5 inputs
    let num_outputs = (data[1] as usize % 5).max(1); // 1-5 outputs
    let mut offset = 2;
    
    // Create inputs (all pointing to same UTXO for simplicity)
    let mut inputs = Vec::new();
    for _ in 0..num_inputs {
        inputs.push(TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            witness: vec![],
        });
    }
    
    // Create outputs
    let mut outputs = Vec::new();
    let mut total_out = 0u64;
    
    for i in 0..num_outputs {
        if offset + 40 > data.len() {
            break;
        }
        
        // Parse amount (8 bytes)
        let mut amt_bytes = [0u8; 8];
        amt_bytes.copy_from_slice(&data[offset..offset + 8]);
        let amount = u64::from_le_bytes(amt_bytes) % (initial_amount / num_outputs as u64).max(1);
        offset += 8;
        
        total_out = total_out.saturating_add(amount);
        
        // Parse lock (32 bytes)
        let mut lock_bytes = [0u8; 32];
        lock_bytes.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        outputs.push(TxOut {
            amount,
            lock: LockCommitment(lock_bytes),
        });
        
        if i == num_outputs - 1 && total_out < initial_amount {
            // Adjust last output to match input amount
            if let Some(last) = outputs.last_mut() {
                last.amount = initial_amount.saturating_sub(total_out - last.amount);
            }
        }
    }
    
    if outputs.is_empty() {
        return;
    }
    
    let mut tx = MicroTx {
        version: 1,
        inputs,
        outputs,
    };

    let digest = sighash_microtx_v1(&nid, &tx);
    let sig = pc_crypto::schnorr_sign(&digest, &kp);
    for tin in tx.inputs.iter_mut() {
        let mut w = Vec::with_capacity(96);
        w.extend_from_slice(&pk);
        w.extend_from_slice(&sig);
        tin.witness = w;
    }
    
    // Try to apply (may fail, which is fine for fuzzing)
    let _ = state.apply_micro_tx_with_maturity_indexed(&tx, 100, 10, &nid);
    
    // Verify state consistency
    let _ = state.root();
});
