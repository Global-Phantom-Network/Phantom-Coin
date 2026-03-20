// SPDX-License-Identifier: AGPL-3.0-only

#[test]
fn bech32m_addr_vector_pc_hrp_xonly32() {
    use bech32::{self, FromBase32, ToBase32};
    // Beispiel xonly (32B)
    let xonly = [0x11u8; 32];
    // Version 1
    let mut data = vec![bech32::u5::try_from_u8(1).expect("u5")];
    data.extend_from_slice(&xonly.to_base32());
    let addr = bech32::encode("pc", data.clone(), bech32::Variant::Bech32m).expect("encode");
    assert!(addr.starts_with("pc1"));

    // Decode und prüfen
    let (hrp, data_dec, var) = bech32::decode(&addr).expect("decode");
    assert_eq!(hrp, "pc");
    assert_eq!(var, bech32::Variant::Bech32m);
    // Erste u5 ist Version 1
    assert_eq!(data_dec.first().expect("empty bech32 payload").to_u8(), 1);
    // Rest zurück nach Bytes (32B)
    let rest = data_dec.get(1..).unwrap_or(&[]);
    let prog: Vec<u8> = Vec::<u8>::from_base32(rest).expect("from_base32");
    assert_eq!(prog.len(), 32);
    assert_eq!(&prog[..], &xonly);
}
