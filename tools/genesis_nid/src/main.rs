use std::fs;
fn main() {
    let path = std::env::args().nth(1).expect("usage: genesis_nid <genesis_note.bin>");
    let data = fs::read(&path).expect("cannot read file");
    let domain = b"pc:genesis:note:v1\x01";
    let mut buf = Vec::with_capacity(domain.len() + data.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(&data);
    let hash = blake3::hash(&buf);
    println!("{}", hash.to_hex());
}
