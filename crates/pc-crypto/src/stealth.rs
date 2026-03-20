// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Stealth/Silent payments for Phantom Coin.
//! Stealth/Silent Payments für Phantom-Coin.
//!
//! Implements BIP340-compatible ECDH and stealth address derivation.
//! Implementiert BIP340-kompatibles ECDH und Stealth-Address-Ableitung.

use crate::{blake3_32, Hash32};
use anyhow::{anyhow, Result};
use secp256k1::{Keypair, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

const STEALTH_DOMAIN: &[u8] = b"PHANTOM_STEALTH_V1";

/// Computes shared secret via ECDH (x-only compatible).
/// Berechnet Shared Secret via ECDH (x-only kompatibel).
///
/// # Arguments / Argumente
/// * `x_s` - scan public key (32B x-only) / Scan-Public-Key (32B xonly)
/// * `x_e_secret` - ephemeral secret key (32B) / Ephemeral-Secret-Key (32B)
///
/// # Returns / Rückgabe
/// Shared secret (32B).
/// Shared Secret (32B)
pub fn compute_shared_secret(x_s: &[u8; 32], x_e_secret: &[u8; 32]) -> Result<[u8; 32]> {
    let secp = Secp256k1::new();

    // Parse keys.
    // Keys parsen.
    let scan_pk =
        XOnlyPublicKey::from_slice(x_s).map_err(|e| anyhow!("invalid scan public key: {e}"))?;
    let ephemeral_sk =
        SecretKey::from_slice(x_e_secret).map_err(|e| anyhow!("invalid ephemeral secret: {e}"))?;

    // Convert x-only public key to a full public key.
    //
    // BIP340 defines x-only public keys by their x-coordinate, with the implicit
    // convention to use the even-Y point. For this ECDH we ultimately extract
    // only the shared point's x-coordinate, which is invariant under point
    // negation, so the parity choice does not change the resulting shared
    // secret bytes. We still pick Even here to follow the BIP340 convention.
    //
    // Konvertiert x-only Public Key zu vollem Public Key.
    // BIP340 definiert x-only Keys via X-Koordinate (implizit Even-Y). Da wir
    // als Shared-Secret nur die X-Koordinate des Shared-Points verwenden (die
    // unter Negation invariant ist), beeinflusst die Parität das Ergebnis nicht.
    // Wir verwenden trotzdem Even gemäß BIP340-Konvention.
    let scan_pk_full = PublicKey::from_x_only_public_key(scan_pk, secp256k1::Parity::Even);

    // ECDH: S = x_e * X_s.
    // ECDH: S = x_e * X_s.
    let shared_point = scan_pk_full
        .mul_tweak(&secp, &Scalar::from(ephemeral_sk))
        .map_err(|e| anyhow!("ecdh mul_tweak failed: {e}"))?;

    // Extract x-coordinate as shared secret.
    // Extrahiere x-Koordinate als Shared Secret.
    let (shared_xonly, _parity) = shared_point.x_only_public_key();
    Ok(shared_xonly.serialize())
}

/// Computes stealth tweak from shared secret.
/// Berechnet Stealth-Tweak aus Shared Secret.
///
/// # Arguments / Argumente
/// * `x_e_pub` - ephemeral public key (32B x-only) / Ephemeral-Public-Key (32B xonly)
/// * `x_s` - scan public key (32B x-only) / Scan-Public-Key (32B xonly)
/// * `shared_secret` - ECDH shared secret (32B) / ECDH Shared Secret (32B)
///
/// # Returns / Rückgabe
/// Tweak t (32B) = blake3("PHANTOM_STEALTH_V1" || X_e || X_s || S)
pub fn compute_stealth_tweak(
    x_e_pub: &[u8; 32],
    x_s: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Hash32 {
    let mut buf = Vec::with_capacity(STEALTH_DOMAIN.len() + 96);
    buf.extend_from_slice(STEALTH_DOMAIN);
    buf.extend_from_slice(x_e_pub);
    buf.extend_from_slice(x_s);
    buf.extend_from_slice(shared_secret);
    blake3_32(&buf)
}

/// Derives stealth address: Q = X_d + t*G.
/// Leitet Stealth-Adresse ab: Q = X_d + t*G.
///
/// # Arguments / Argumente
/// * `x_d` - spend public key (32B x-only) / Spend-Public-Key (32B xonly)
/// * `tweak` - tweak t (32B) / Tweak t (32B)
///
/// # Returns / Rückgabe
/// Stealth public key Q (32B x-only).
/// Stealth-Public-Key Q (32B xonly)
pub fn derive_stealth_pubkey(x_d: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32]> {
    let secp = Secp256k1::new();

    // Parse spend x-only public key.
    // Spend-x-only-Public-Key parsen.
    let spend_xonly =
        XOnlyPublicKey::from_slice(x_d).map_err(|e| anyhow!("invalid spend pubkey: {e}"))?;

    // Parse tweak as scalar.
    // Parse Tweak als Scalar.
    let tweak_scalar =
        Scalar::from_be_bytes(*tweak).map_err(|_| anyhow!("invalid tweak scalar"))?;

    // Q = X_d + t*G (x-only tweak add, parity-consistent).
    // Q = X_d + t*G (x-only Tweak-Addition, Parität konsistent).
    let (tweaked_xonly, _parity) = spend_xonly
        .add_tweak(&secp, &tweak_scalar)
        .map_err(|e| anyhow!("xonly add_tweak failed: {e}"))?;

    Ok(tweaked_xonly.serialize())
}

/// Computes stealth secret key for spending: k = x_d + t.
/// Berechnet Stealth-Secret-Key für Spending: k = x_d + t.
///
/// # Arguments / Argumente
/// * `x_d_secret` - spend secret key (32B) / Spend-Secret-Key (32B)
/// * `tweak` - tweak t (32B) / Tweak t (32B)
///
/// # Returns / Rückgabe
/// Stealth secret key k (32B).
/// Stealth-Secret-Key k (32B)
pub fn derive_stealth_secret(x_d_secret: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32]> {
    let secp = Secp256k1::new();

    let kp = Keypair::from_seckey_slice(&secp, x_d_secret)
        .map_err(|e| anyhow!("invalid spend secret: {e}"))?;
    let tweak_scalar =
        Scalar::from_be_bytes(*tweak).map_err(|_| anyhow!("invalid tweak scalar"))?;

    // Parity-correct x-only tweak addition on the keypair.
    // Paritäts-korrekte x-only Tweak-Addition auf dem KeyPair.
    let tweaked = kp
        .add_xonly_tweak(&secp, &tweak_scalar)
        .map_err(|e| anyhow!("keypair add_xonly_tweak failed: {e}"))?;

    Ok(tweaked.secret_key().secret_bytes())
}

/// Generates ephemeral key pair.
/// Generiert Ephemeral-Key-Pair.
///
/// # Returns / Rückgabe
/// (secret, public) both 32B x-only.
/// (secret, public) beide 32B xonly.
pub fn generate_ephemeral_keypair() -> ([u8; 32], [u8; 32]) {
    use secp256k1::rand::rngs::OsRng;

    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    let (xonly_pub, _parity) = public_key.x_only_public_key();

    (secret_key.secret_bytes(), xonly_pub.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_generation() {
        let (secret, public) = generate_ephemeral_keypair();
        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 32);

        // Verify public key derivable from secret
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();
        assert_eq!(xonly.serialize(), public);
    }

    #[test]
    fn f53_ecdh_shared_secret_is_parity_invariant() {
        let secp = Secp256k1::new();

        // Generate scan keypair
        let scan_secret = SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
        let scan_public = PublicKey::from_secret_key(&secp, &scan_secret);
        let (scan_xonly, _) = scan_public.x_only_public_key();

        // Generate ephemeral keypair
        let (eph_secret, eph_public) = generate_ephemeral_keypair();

        // Sender computes shared secret
        let shared_sender = compute_shared_secret(&scan_xonly.serialize(), &eph_secret).unwrap();

        // Receiver computes shared secret (with ephemeral public).
        //
        // Important: parity selection for an x-only pubkey does not change the derived
        // x-only shared secret (x(P) == x(-P)), so both parities must match.
        let eph_xonly = XOnlyPublicKey::from_slice(&eph_public).unwrap();
        let eph_pk_even = PublicKey::from_x_only_public_key(eph_xonly, secp256k1::Parity::Even);
        let eph_pk_odd = PublicKey::from_x_only_public_key(eph_xonly, secp256k1::Parity::Odd);

        let shared_even = eph_pk_even
            .mul_tweak(&secp, &Scalar::from(scan_secret))
            .unwrap();
        let (shared_even_xonly, _) = shared_even.x_only_public_key();

        let shared_odd = eph_pk_odd
            .mul_tweak(&secp, &Scalar::from(scan_secret))
            .unwrap();
        let (shared_odd_xonly, _) = shared_odd.x_only_public_key();

        assert_eq!(shared_even_xonly.serialize(), shared_odd_xonly.serialize());
        assert_eq!(shared_sender, shared_even_xonly.serialize());
    }

    #[test]
    fn test_stealth_tweak_deterministic() {
        let x_e = [1u8; 32];
        let x_s = [2u8; 32];
        let s = [3u8; 32];

        let tweak1 = compute_stealth_tweak(&x_e, &x_s, &s);
        let tweak2 = compute_stealth_tweak(&x_e, &x_s, &s);

        assert_eq!(tweak1, tweak2);
        assert_eq!(tweak1.len(), 32);
    }

    #[test]
    fn test_stealth_pubkey_derivation() {
        let secp = Secp256k1::new();

        // Generate spend keypair
        let spend_secret = SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
        let spend_public = PublicKey::from_secret_key(&secp, &spend_secret);
        let (spend_xonly, _) = spend_public.x_only_public_key();

        // Tweak
        let tweak = [42u8; 32];

        // Derive stealth pubkey
        let stealth_pubkey = derive_stealth_pubkey(&spend_xonly.serialize(), &tweak).unwrap();

        // Derive stealth secret
        let stealth_secret = derive_stealth_secret(&spend_secret.secret_bytes(), &tweak).unwrap();

        // Verify: pubkey from stealth secret matches derived pubkey
        let sk = SecretKey::from_slice(&stealth_secret).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let (derived_xonly, _) = pk.x_only_public_key();

        assert_eq!(derived_xonly.serialize(), stealth_pubkey);
    }

    #[test]
    fn test_full_stealth_flow() {
        let secp = Secp256k1::new();

        // Receiver generates scan and spend keypairs
        let scan_secret = SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
        let scan_public = PublicKey::from_secret_key(&secp, &scan_secret);
        let (scan_xonly, _) = scan_public.x_only_public_key();

        let spend_secret = SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
        let spend_public = PublicKey::from_secret_key(&secp, &spend_secret);
        let (spend_xonly, _) = spend_public.x_only_public_key();

        // Sender generates ephemeral keypair
        let (eph_secret, eph_public) = generate_ephemeral_keypair();

        // Sender computes shared secret and tweak
        let shared = compute_shared_secret(&scan_xonly.serialize(), &eph_secret).unwrap();
        let tweak = compute_stealth_tweak(&eph_public, &scan_xonly.serialize(), &shared);

        // Sender derives stealth pubkey
        let stealth_pubkey = derive_stealth_pubkey(&spend_xonly.serialize(), &tweak).unwrap();

        // Receiver scans: computes shared secret from ephemeral public
        let eph_pk_xonly = XOnlyPublicKey::from_slice(&eph_public).unwrap();
        let eph_pk_full = PublicKey::from_x_only_public_key(eph_pk_xonly, secp256k1::Parity::Even);
        let shared_recv = eph_pk_full
            .mul_tweak(&secp, &Scalar::from(scan_secret))
            .unwrap();
        let (shared_recv_xonly, _) = shared_recv.x_only_public_key();

        // Receiver computes tweak
        let tweak_recv = compute_stealth_tweak(
            &eph_public,
            &scan_xonly.serialize(),
            &shared_recv_xonly.serialize(),
        );
        assert_eq!(tweak, tweak_recv);

        // Receiver derives stealth pubkey (should match)
        let stealth_pubkey_recv =
            derive_stealth_pubkey(&spend_xonly.serialize(), &tweak_recv).unwrap();
        assert_eq!(stealth_pubkey, stealth_pubkey_recv);

        // Receiver derives stealth secret for spending
        let stealth_secret =
            derive_stealth_secret(&spend_secret.secret_bytes(), &tweak_recv).unwrap();

        // Verify stealth secret matches stealth pubkey
        let sk = SecretKey::from_slice(&stealth_secret).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let (derived_xonly, _) = pk.x_only_public_key();
        assert_eq!(derived_xonly.serialize(), stealth_pubkey);
    }
}
