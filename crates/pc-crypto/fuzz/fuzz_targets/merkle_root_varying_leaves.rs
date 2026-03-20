#![no_main]

use libfuzzer_sys::fuzz_target;
use pc_crypto::{blake3_32, merkle_root_hashes, Hash32};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    // Parse number of leaves
    let num_leaves = (data[0] as usize % 100).max(1);
    let mut offset = 1;
    
    let mut leaves = Vec::new();
    for _ in 0..num_leaves {
        if offset + 32 > data.len() {
            // Generate hash from remaining data
            let hash = blake3_32(&data[offset..]);
            leaves.push(hash);
            break;
        }
        
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&data[offset..offset + 32]);
        leaves.push(leaf);
        offset += 32;
    }
    
    if leaves.is_empty() {
        return;
    }
    
    // Compute merkle root
    let root1 = merkle_root_hashes(&leaves);
    
    // Recompute - should be deterministic
    let root2 = merkle_root_hashes(&leaves);
    assert_eq!(root1, root2, "Merkle root must be deterministic");
    
    // Test with single leaf
    if !leaves.is_empty() {
        let single_root = merkle_root_hashes(&[leaves[0]]);
        let _ = single_root; // Should not panic
    }
    
    // Test with empty (edge case)
    let empty_root = merkle_root_hashes(&[]);
    let _ = empty_root;
});
