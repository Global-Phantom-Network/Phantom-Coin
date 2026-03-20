#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cur = std::io::Cursor::new(data);
    use pc_codec::Decodable;
    let _ = <pc_p2p::messages::ReqMsg as pc_codec::Decodable>::decode(&mut cur);
});
