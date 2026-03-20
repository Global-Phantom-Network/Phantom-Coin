#![no_main]

use libfuzzer_sys::fuzz_target;
use pc_crypto::{blake3_32, Hash32};

// Simple merkle proof verification for fuzzing
fn verify_merkle_proof(leaf: Hash32, proof: &[Hash32], root: Hash32, index: usize) -> bool {
    let mut current = leaf;
    let mut idx = index;
    
    for sibling in proof {
        current = if idx % 2 == 0 {
            // Leaf is on left
            blake3_32(&[current.as_slice(), sibling.as_slice()].concat())
        } else {
            // Leaf is on right
            blake3_32(&[sibling.as_slice(), current.as_slice()].concat())
        };
        idx /= 2;
    }
    
    current == root
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 100 {
        return;
    }
    
    // Parse leaf
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&data[0..32]);
    
    // Parse root
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[32..64]);
    
    // Parse index (4 bytes)
    let index = u32::from_le_bytes([data[64], data[65], data[66], data[67]]) as usize;
    
    // Parse proof length
    let proof_len = (data[68] as usize % 10).min((data.len() - 69) / 32);
    let mut offset = 69;
    
    let mut proof = Vec::new();
    for _ in 0..proof_len {
        if offset + 32 > data.len() {
            break;
        }
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        proof.push(hash);
        offset += 32;
    }
    
    // Verify proof (may be valid or invalid)
    let is_valid = verify_merkle_proof(leaf, &proof, root, index);
    
    // Just ensure no panic
    let _ = is_valid;
});
