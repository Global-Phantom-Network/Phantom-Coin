#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use pc_codec::Decodable;
    let mut cur = std::io::Cursor::new(data);
    let _ = <Vec<pc_types::AnchorHeaderV2> as pc_codec::Decodable>::decode(&mut cur);
});
