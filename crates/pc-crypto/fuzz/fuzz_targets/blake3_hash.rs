#![no_main]

use libfuzzer_sys::fuzz_target;
use pc_crypto::blake3_32;

fuzz_target!(|data: &[u8]| {
    // Test blake3 with arbitrary input
    let hash1 = blake3_32(data);
    
    // Recompute - should be deterministic
    let hash2 = blake3_32(data);
    assert_eq!(hash1, hash2, "Blake3 hash must be deterministic");
    
    // Test with empty input
    let empty_hash = blake3_32(&[]);
    let _ = empty_hash;
    
    // Test with doubled input (different result expected)
    let mut doubled = data.to_vec();
    doubled.extend_from_slice(data);
    let hash3 = blake3_32(&doubled);
    
    // Different inputs should (almost always) produce different hashes
    if !data.is_empty() && hash1 == hash3 {
        // Collision found (extremely unlikely but not a bug)
        let _ = hash1;
    }
});
