#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cur = std::io::Cursor::new(data);
    // Bring the trait into scope so that `decode` is available.
    // Trait in Scope bringen, damit decode verfügbar ist
    use pc_codec::Decodable;
    let _ = <pc_p2p::messages::P2pMessage as pc_codec::Decodable>::decode(&mut cur);
});
