// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::result_large_err)]

use crate::Hash32;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrKeypair {
    pub keypair: Keypair,
    pub xonly: XOnlyPublicKey,
}

impl SchnorrKeypair {
    pub fn from_secret_key_bytes(sk_bytes: &[u8; 32]) -> Result<Self, secp256k1::Error> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(sk_bytes)?;
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&kp);
        Ok(Self { keypair: kp, xonly })
    }

    pub fn public_xonly_bytes(&self) -> [u8; 32] {
        self.xonly.serialize()
    }
}

pub fn schnorr_sign(msg32: &Hash32, kp: &SchnorrKeypair) -> [u8; 64] {
    let secp = Secp256k1::new();
    // msg32 is guaranteed to be 32 bytes long (type alias Hash32).
    // msg32 ist garantiert 32 Bytes lang (Typalias Hash32)
    let m = Message::from_digest(*msg32);
    let sig = secp.sign_schnorr(&m, &kp.keypair);
    let bytes_ref: &[u8; 64] = sig.as_ref();
    let mut out = [0u8; 64];
    out.copy_from_slice(bytes_ref);
    out
}

pub fn schnorr_sign_with_aux(msg32: &Hash32, kp: &SchnorrKeypair, aux32: &[u8; 32]) -> [u8; 64] {
    let secp = Secp256k1::new();
    // msg32 is guaranteed to be 32 bytes long (type alias Hash32).
    // msg32 ist garantiert 32 Bytes lang (Typalias Hash32)
    let m = Message::from_digest(*msg32);
    let sig = secp.sign_schnorr_with_aux_rand(&m, &kp.keypair, aux32);
    let bytes_ref: &[u8; 64] = sig.as_ref();
    let mut out = [0u8; 64];
    out.copy_from_slice(bytes_ref);
    out
}

pub fn schnorr_verify(msg32: &Hash32, sig64: &[u8; 64], pubkey_xonly: &XOnlyPublicKey) -> bool {
    let secp = Secp256k1::verification_only();
    let m = match Message::from_digest_slice(msg32) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let sig = match secp256k1::schnorr::Signature::from_slice(sig64) {
        Ok(s) => s,
        Err(_) => return false,
    };
    secp.verify_schnorr(&sig, &m, pubkey_xonly).is_ok()
}

pub fn schnorr_verify_xonly_bytes(
    msg32: &Hash32,
    sig64: &[u8; 64],
    pubkey_xonly_bytes: &[u8; 32],
) -> bool {
    let pk = match XOnlyPublicKey::from_slice(pubkey_xonly_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    schnorr_verify(msg32, sig64, &pk)
}

pub fn schnorr_verify_many(
    msgs32: &[[u8; 32]],
    sigs64: &[[u8; 64]],
    pubs: &[XOnlyPublicKey],
) -> bool {
    if msgs32.len() != sigs64.len() || sigs64.len() != pubs.len() {
        return false;
    }
    msgs32
        .iter()
        .zip(sigs64.iter())
        .zip(pubs.iter())
        .all(|((m, s), p)| schnorr_verify(m, s, p))
}

pub fn schnorr_verify_many_parallel(
    msgs32: &[[u8; 32]],
    sigs64: &[[u8; 64]],
    pubs: &[XOnlyPublicKey],
) -> bool {
    use rayon::prelude::*;
    if msgs32.len() != sigs64.len() || sigs64.len() != pubs.len() {
        return false;
    }
    msgs32
        .par_iter()
        .zip(sigs64.par_iter())
        .zip(pubs.par_iter())
        .all(|((m, s), p)| schnorr_verify(m, s, p))
}

pub fn schnorr_verify_many_parallel_xonly_bytes(
    msgs32: &[[u8; 32]],
    sigs64: &[[u8; 64]],
    pubkeys_xonly_bytes: &[[u8; 32]],
) -> bool {
    use rayon::prelude::*;
    if msgs32.len() != sigs64.len() || sigs64.len() != pubkeys_xonly_bytes.len() {
        return false;
    }
    msgs32
        .par_iter()
        .zip(sigs64.par_iter())
        .zip(pubkeys_xonly_bytes.par_iter())
        .all(|((m, s), pk)| schnorr_verify_xonly_bytes(m, s, pk))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::blake3_32;
    use hex::encode as hex_encode;

    #[test]
    fn schnorr_verify_many_ok_and_fail() {
        let m1 = blake3_32(b"m1");
        let m2 = blake3_32(b"m2");
        let m3 = blake3_32(b"m3");
        let s1 = blake3_32(b"sk1");
        let s2 = blake3_32(b"sk2");
        let s3 = blake3_32(b"sk3");
        let k1 = SchnorrKeypair::from_secret_key_bytes(&s1).expect("sk1");
        let k2 = SchnorrKeypair::from_secret_key_bytes(&s2).expect("sk2");
        let k3 = SchnorrKeypair::from_secret_key_bytes(&s3).expect("sk3");
        let sig1 = schnorr_sign(&m1, &k1);
        let sig2 = schnorr_sign(&m2, &k2);
        let sig3 = schnorr_sign(&m3, &k3);
        let pubs = vec![k1.xonly, k2.xonly, k3.xonly];
        assert!(schnorr_verify_many(
            &[m1, m2, m3],
            &[sig1, sig2, sig3],
            &pubs
        ));

        // fail when one signature is tampered
        let mut bad = sig2;
        bad[5] ^= 0x55;
        assert!(!schnorr_verify_many(
            &[m1, m2, m3],
            &[sig1, bad, sig3],
            &pubs
        ));
    }

    #[test]
    #[ignore]
    fn dump_schnorr_golden() {
        // Deterministic golden vector.
        // deterministischer Golden-Vektor
        let seed = blake3_32(b"golden:schnorr:sk1");
        let kp = SchnorrKeypair::from_secret_key_bytes(&seed).expect("valid seckey");
        let msg = blake3_32(b"phantomcoin schnorr golden v1");
        let sig = schnorr_sign_with_aux(&msg, &kp, &[0u8; 32]);
        println!(
            "SCHNORR_PUBKEY_XONLY_1={}",
            hex_encode(kp.public_xonly_bytes())
        );
        println!("SCHNORR_SIG_1={}", hex_encode(sig));

        // Second vector.
        // zweiter Vektor
        let seed2 = blake3_32(b"golden:schnorr:sk2");
        let kp2 = SchnorrKeypair::from_secret_key_bytes(&seed2).expect("valid seckey");
        let msg2 = blake3_32(b"phantomcoin schnorr golden v2");
        let sig2 = schnorr_sign_with_aux(&msg2, &kp2, &[0u8; 32]);
        println!(
            "SCHNORR_PUBKEY_XONLY_2={}",
            hex_encode(kp2.public_xonly_bytes())
        );
        println!("SCHNORR_SIG_2={}", hex_encode(sig2));
    }

    #[test]
    fn schnorr_golden_vectors() {
        // Vector 1.
        // Vektor 1
        let seed = blake3_32(b"golden:schnorr:sk1");
        let kp = SchnorrKeypair::from_secret_key_bytes(&seed).expect("valid seckey");
        let msg = blake3_32(b"phantomcoin schnorr golden v1");
        let sig = schnorr_sign_with_aux(&msg, &kp, &[0u8; 32]);
        assert_eq!(
            hex_encode(kp.public_xonly_bytes()),
            "25e54aa1bb6443e1f3e96f98cd0324040c8c844d3bd845130402d15449d6f4b8"
        );
        assert_eq!(hex_encode(sig), "1c4c9df177d728d1fb90a71ffb783e5fa47c42bf320d91bf24c960c9cf09c2b6d529cd5506dd0cf578816d0d8f6d44e75385830cc0654e78358fa201d2bdb114");
        assert!(schnorr_verify(&msg, &sig, &kp.xonly));

        // Vector 2.
        // Vektor 2
        let seed2 = blake3_32(b"golden:schnorr:sk2");
        let kp2 = SchnorrKeypair::from_secret_key_bytes(&seed2).expect("valid seckey");
        let msg2 = blake3_32(b"phantomcoin schnorr golden v2");
        let sig2 = schnorr_sign_with_aux(&msg2, &kp2, &[0u8; 32]);
        assert_eq!(
            hex_encode(kp2.public_xonly_bytes()),
            "85de37200a0e4736d9c0ba5cd3c73a71ffc1ae94b3ea57f3dbebd2dafaeff5c2"
        );
        assert_eq!(hex_encode(sig2), "ab22eaab984c1f25e5c994dd281b1e5105f7c2b679060cff8a71894f2ec738de5786385429ac5a081786ee59eba50ed64c7f285e8852d5717b635b0363a1cf63");
        assert!(schnorr_verify(&msg2, &sig2, &kp2.xonly));
    }

    #[test]
    fn schnorr_roundtrip() {
        // Deterministic secret key derived from hash.
        // deterministischer seckey aus Hash
        let seed = blake3_32(b"pc:schnorr:test:seed");
        // SecretKey::from_slice requires a valid scalar; the BLAKE3 output satisfies this with high probability.
        // SecretKey::from_slice verlangt ein valides Skalar; der BLAKE3-Ausgang erfüllt dies mit hoher Wahrscheinlichkeit
        // Otherwise tests would fail and would need a retry mechanism.
        // Falls nicht, würden Tests fehlschlagen und müssten mit Retry-Mechanismus ergänzt werden.
        let kp = SchnorrKeypair::from_secret_key_bytes(&seed).expect("valid seckey");
        let msg = blake3_32(b"message");
        let sig = schnorr_sign(&msg, &kp);
        assert!(schnorr_verify(&msg, &sig, &kp.xonly));

        // negative
        let mut tampered = sig;
        tampered[0] ^= 0x01;
        assert!(!schnorr_verify(&msg, &tampered, &kp.xonly));
    }
}
