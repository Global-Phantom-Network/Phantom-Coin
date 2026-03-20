#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Versuche diverse Vec-Decodes aus beliebigen Bytes.
    let mut cur = std::io::Cursor::new(data);
    let _ = <Vec<u8> as pc_codec::Decodable>::decode(&mut cur);

    let mut cur2 = std::io::Cursor::new(data);
    let _ = <Vec<[u8;32]> as pc_codec::Decodable>::decode(&mut cur2);

    let mut cur3 = std::io::Cursor::new(data);
    let _ = <Vec<Vec<[u8;32]>> as pc_codec::Decodable>::decode(&mut cur3);
});
