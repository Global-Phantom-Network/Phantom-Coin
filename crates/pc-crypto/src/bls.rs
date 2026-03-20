// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::result_large_err)]

use blst::{min_pk as bls, BLST_ERROR};

// IETF ciphersuite with POP variant (min_pk: pubkeys in G1, signatures in G2)
const DST_SIG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
// Proof-of-possession MUST use its own domain separation tag (not the signature DST).
const DST_POP: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
// Domain separation for BLS-based VRF (signature acts as VRF proof; output = H(sig)).
// Domain-Separation für BLS-basierte VRF (Signatur dient als VRF-Proof; Output = H(sig))
const DST_VRF: &[u8] = b"PC_BLS_VRF_V1\x01";

#[derive(Clone)]
pub struct BlsSecretKey(pub bls::SecretKey);

#[derive(Clone)]
pub struct BlsPublicKey(pub bls::PublicKey);

impl BlsPublicKey {
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }
    pub fn from_bytes(b: &[u8; 48]) -> Option<Self> {
        bls::PublicKey::from_bytes(b).ok().map(Self)
    }
}

impl core::fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "BlsPublicKey(")?;
        for b in bytes.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}
/// VRF proof based on BLS: proof = Sign_{DST_VRF}(msg), output = blake3_32(proof).
/// VRF-Proof auf Basis von BLS: proof = Sign_{DST_VRF}(msg), output = blake3_32(proof)
pub fn bls_vrf_prove(msg: &[u8], sk: &BlsSecretKey) -> ([u8; 96], crate::Hash32) {
    let sig = sk.0.sign(msg, DST_VRF, &[]).to_bytes();
    let y = crate::blake3_32(&sig);
    (sig, y)
}

/// VRF verify: checks proof under DST_VRF; returns deterministic output if valid.
/// VRF-Verify: prüft Proof unter DST_VRF; gibt deterministischen Output zurück, falls gültig
pub fn bls_vrf_verify(msg: &[u8], proof: &[u8; 96], pk: &BlsPublicKey) -> Option<crate::Hash32> {
    let sig = match bls::Signature::from_bytes(proof) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let ok = sig.verify(true, msg, DST_VRF, &[], &pk.0, true) == BLST_ERROR::BLST_SUCCESS;
    if !ok {
        return None;
    }
    Some(crate::blake3_32(proof))
}

pub struct BlsKeypair {
    pub sk: BlsSecretKey,
    pub pk: BlsPublicKey,
}

pub fn bls_keygen_from_ikm(ikm: &[u8]) -> Option<BlsKeypair> {
    let sk = bls::SecretKey::key_gen(ikm, &[]).ok()?;
    let pk = sk.sk_to_pk();
    Some(BlsKeypair {
        sk: BlsSecretKey(sk),
        pk: BlsPublicKey(pk),
    })
}

pub fn bls_sign(msg: &[u8], sk: &BlsSecretKey) -> [u8; 96] {
    let sig = sk.0.sign(msg, DST_SIG, &[]);
    sig.to_bytes()
}

pub fn bls_verify(msg: &[u8], sig_bytes: &[u8; 96], pk: &BlsPublicKey) -> bool {
    let sig = match bls::Signature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.verify(true, msg, DST_SIG, &[], &pk.0, true) == BLST_ERROR::BLST_SUCCESS
}

pub fn bls_pop_prove(sk: &BlsSecretKey) -> [u8; 96] {
    // PoP = Sign(pk_bytes) under POP-DST
    let pk = sk.0.sk_to_pk();
    let pk_bytes = pk.to_bytes();
    let sig = sk.0.sign(&pk_bytes, DST_POP, &[]);
    sig.to_bytes()
}

pub fn bls_pop_verify(pk: &BlsPublicKey, pop_sig: &[u8; 96]) -> bool {
    let sig = match bls::Signature::from_bytes(pop_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk_bytes = pk.to_bytes();
    sig.verify(true, &pk_bytes, DST_POP, &[], &pk.0, true) == BLST_ERROR::BLST_SUCCESS
}

pub fn bls_aggregate_signatures(sigs: &[[u8; 96]]) -> Option<[u8; 96]> {
    let mut sig_refs: Vec<bls::Signature> = Vec::with_capacity(sigs.len());
    for s in sigs {
        sig_refs.push(bls::Signature::from_bytes(s).ok()?);
    }
    let refs: Vec<&bls::Signature> = sig_refs.iter().collect();
    let agg = bls::AggregateSignature::aggregate(&refs, true).ok()?;
    Some(agg.to_signature().to_bytes())
}

pub fn bls_fast_aggregate_verify(msg: &[u8], agg_sig: &[u8; 96], pks: &[BlsPublicKey]) -> bool {
    let sig = match bls::Signature::from_bytes(agg_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let refs: Vec<&bls::PublicKey> = pks.iter().map(|p| &p.0).collect();
    sig.fast_aggregate_verify(true, msg, DST_SIG, &refs) == BLST_ERROR::BLST_SUCCESS
}

pub fn bls_aggregate_verify(msgs: &[&[u8]], agg_sig: &[u8; 96], pks: &[BlsPublicKey]) -> bool {
    if msgs.len() != pks.len() {
        return false;
    }
    let sig = match bls::Signature::from_bytes(agg_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let refs: Vec<&bls::PublicKey> = pks.iter().map(|p| &p.0).collect();
    sig.aggregate_verify(true, msgs, DST_SIG, &refs, true) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::blake3_32;
    use hex::encode as hex_encode;

    #[test]
    fn f52_bls_sign_verify_roundtrip_and_pop_domain_separation() {
        let ikm = blake3_32(b"ikm-1");
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        // POP
        let pop = bls_pop_prove(&kp.sk);
        assert!(bls_pop_verify(&kp.pk, &pop));
        // Domain separation: a regular signature over pk_bytes MUST NOT verify as PoP.
        let pk_bytes = kp.pk.to_bytes();
        let sig_over_pk = bls_sign(&pk_bytes, &kp.sk);
        assert!(!bls_pop_verify(&kp.pk, &sig_over_pk));
        // message
        let msg = b"hello world";
        let sig = bls_sign(msg, &kp.sk);
        assert!(bls_verify(msg, &sig, &kp.pk));
        // negative
        let mut tampered = sig;
        tampered[0] ^= 1;
        assert!(!bls_verify(msg, &tampered, &kp.pk));
    }

    #[test]
    fn bls_fast_aggregate_verify_same_message() {
        let ikm1 = blake3_32(b"ikm-1");
        let ikm2 = blake3_32(b"ikm-2");
        let kp1 = bls_keygen_from_ikm(&ikm1).unwrap();
        let kp2 = bls_keygen_from_ikm(&ikm2).unwrap();
        let msg = b"agg-msg";
        let s1 = bls_sign(msg, &kp1.sk);
        let s2 = bls_sign(msg, &kp2.sk);
        let agg = bls_aggregate_signatures(&[s1, s2]).unwrap();
        assert!(bls_fast_aggregate_verify(
            msg,
            &agg,
            &[kp1.pk.clone(), kp2.pk.clone()]
        ));
    }

    #[test]
    fn bls_aggregate_verify_distinct_messages() {
        let ikm1 = blake3_32(b"ikm-1");
        let ikm2 = blake3_32(b"ikm-2");
        let kp1 = bls_keygen_from_ikm(&ikm1).unwrap();
        let kp2 = bls_keygen_from_ikm(&ikm2).unwrap();
        let m1 = b"m1" as &[u8];
        let m2 = b"m2" as &[u8];
        let s1 = bls_sign(m1, &kp1.sk);
        let s2 = bls_sign(m2, &kp2.sk);
        let agg = bls_aggregate_signatures(&[s1, s2]).unwrap();
        assert!(bls_aggregate_verify(
            &[m1, m2],
            &agg,
            &[kp1.pk.clone(), kp2.pk.clone()]
        ));
    }

    #[test]
    #[ignore]
    fn dump_bls_golden() {
        // Vector 1.
        // Vektor 1
        let ikm1 = blake3_32(b"golden:bls:ikm1");
        let kp1 = bls_keygen_from_ikm(&ikm1).expect("keygen");
        let msg1 = b"phantomcoin bls golden v1" as &[u8];
        let sig1 = bls_sign(msg1, &kp1.sk);
        let pop1 = bls_pop_prove(&kp1.sk);
        println!("BLS_PK_1={}", hex_encode(kp1.pk.to_bytes()));
        println!("BLS_SIG_1={}", hex_encode(sig1));
        println!("BLS_POP_1={}", hex_encode(pop1));

        // Vector 2.
        // Vektor 2
        let ikm2 = blake3_32(b"golden:bls:ikm2");
        let kp2 = bls_keygen_from_ikm(&ikm2).expect("keygen");
        let msg2 = b"phantomcoin bls golden v2" as &[u8];
        let sig2 = bls_sign(msg2, &kp2.sk);
        let pop2 = bls_pop_prove(&kp2.sk);
        println!("BLS_PK_2={}", hex_encode(kp2.pk.to_bytes()));
        println!("BLS_SIG_2={}", hex_encode(sig2));
        println!("BLS_POP_2={}", hex_encode(pop2));
    }

    #[test]
    fn bls_vrf_prove_verify_roundtrip() {
        let ikm = blake3_32(b"vrf-test-ikm");
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        let msg = b"vrf test message";

        let (proof, output) = bls_vrf_prove(msg, &kp.sk);

        // Verify returns the same output.
        // Verify liefert gleichen Output
        let verified_output = bls_vrf_verify(msg, &proof, &kp.pk);
        assert_eq!(Some(output), verified_output);

        // Determinism: same message → same output.
        // Determinismus: gleiche msg → gleicher Output
        let (proof2, output2) = bls_vrf_prove(msg, &kp.sk);
        assert_eq!(output, output2);
        assert_eq!(proof, proof2);
    }

    #[test]
    fn bls_vrf_verify_wrong_pk_fails() {
        let ikm1 = blake3_32(b"vrf-ikm1");
        let ikm2 = blake3_32(b"vrf-ikm2");
        let kp1 = bls_keygen_from_ikm(&ikm1).unwrap();
        let kp2 = bls_keygen_from_ikm(&ikm2).unwrap();

        let msg = b"vrf message";
        let (proof, _output) = bls_vrf_prove(msg, &kp1.sk);

        // Verify with the wrong public key must fail.
        // Verify mit falschem PK schlägt fehl
        let result = bls_vrf_verify(msg, &proof, &kp2.pk);
        assert_eq!(None, result);
    }

    #[test]
    fn bls_vrf_verify_tampered_proof_fails() {
        let ikm = blake3_32(b"vrf-ikm-tamper");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let msg = b"vrf tamper test";

        let (mut proof, _output) = bls_vrf_prove(msg, &kp.sk);

        // Tamper with the proof.
        // Manipuliere Proof
        proof[5] ^= 0x01;

        let result = bls_vrf_verify(msg, &proof, &kp.pk);
        assert_eq!(None, result);
    }

    #[test]
    fn bls_vrf_different_messages_different_outputs() {
        let ikm = blake3_32(b"vrf-ikm-distinct");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();

        let msg1 = b"message 1";
        let msg2 = b"message 2";

        let (_proof1, output1) = bls_vrf_prove(msg1, &kp.sk);
        let (_proof2, output2) = bls_vrf_prove(msg2, &kp.sk);

        assert_ne!(output1, output2);
    }
}
