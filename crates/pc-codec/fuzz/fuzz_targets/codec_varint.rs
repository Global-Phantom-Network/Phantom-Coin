#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Versuche eine Varint aus beliebigen Bytes zu lesen.
    // Erwartung: keine Panics, nur Ok/Err.
    let mut cur = std::io::Cursor::new(data);
    let _ = pc_codec::read_varu64(&mut cur);
});
