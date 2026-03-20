#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz-Decode für AnchorPayloadV2 (robust gegen beliebige Bytes)
    let mut cur = std::io::Cursor::new(data);
    let _ = <pc_types::AnchorPayloadV2 as pc_codec::Decodable>::decode(&mut cur);
});
