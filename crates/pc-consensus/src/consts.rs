// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

// Empfohlene Default-Konstanten für Konsens (v0)
// Beachte: k (Committee-Größe) ist netzabhängig; RECOMMENDED_K dient nur als Richtwert.

pub const RECOMMENDED_K: u8 = 21; // Richtwert; tatsächliches k kommt aus Genesis/Config

// Sharding (v0)
pub const SHARDS_INITIAL: u16 = 64; // Startkonfiguration S=64
pub const K_MAX: u8 = 64; // harte Obergrenze: k ≤ 64 (vote_mask passt in u64)

// Proposer-Limit
pub const MAX_PROPOSERS_PER_SHARD: u8 = 4; // P≤4: max. 4 gleichzeitige Proposer pro Shard

// Empfohlene Batch-/Payload-Defaults (nicht konsenserzwingend; CLI/Config kann überschreiben)
pub const DEFAULT_TXS_PER_PAYLOAD: usize = 4096; // B≈4096: maximaler Durchsatz pro Payload

// Maturity-Stufen (globaler Anchor-Index; uhrfrei)
pub const MATURITY_L1: u64 = 50_000;
pub const MATURITY_L2: u64 = 100_000;
pub const MATURITY_L3: u64 = 200_000;

// Fee-Split (Basispunkte; Summe = 10_000)
pub const P_BASE_BP: u16 = 6500; // Basis-Anteil (gleichmäßig auf k Seats)
pub const P_PROP_BP: u16 = 1000; // Proposer-Anteil
pub const P_PERF_BP: u16 = 1500; // Performance-Topf (nach Ack-Distanz-Gewichten)
pub const P_ATT_BP: u16 = 1000; // Attestor-Topf

// Performance-Gewichtungsparameter
pub const D_MAX: u8 = 8; // maximale Ack-Distanz, die gewertet wird
pub const PERF_ALPHA_NUM: u32 = 6; // α = 6/10 = 0.6 (ganzzahlig)
pub const PERF_ALPHA_DEN: u32 = 10;

// PoW: Domain-Tag und Default-Schwierigkeit (Bits)
pub const POW_DOMAIN: &[u8] = b"pc:mint:pow:v1\x01";
pub const POW_DEFAULT_BITS: u8 = 20; // Default-Schwierigkeit (Leitwert für Tools)
pub const EMISSION_BUCKET_MS: u64 = 1_000;
pub const EMISSION_COLLECT_BUCKETS: u64 = 5;
pub const EMISSION_FINALIZE_GRACE_BUCKETS: u64 = 15;
pub const EMISSION_MAX_FUTURE_SKEW_BUCKETS: u64 = 1;
pub const POW_TARGET_SPACING_BUCKETS: u64 = 600;
pub const POW_ASERT_HALFLIFE_BUCKETS: u64 = 3_600;

// Difficulty policy (Bitcoin-like retarget, but clock-free).
//
// We avoid Unix timestamps. Instead we use the global finalized anchor index as a
// monotonic "time surrogate" (see phantom-node: `anchor_index`).
//
// - Target: 1 mint per POW_TARGET_ANCHORS_PER_MINT finalized anchors.
// - Retarget: every POW_RETARGET_WINDOW_MINTS mints.
// - Clamp: actual timespan is clamped to [expected/4, expected*4] (Bitcoin-style).
pub const POW_TARGET_ANCHORS_PER_MINT: u64 = 60;
pub const POW_RETARGET_WINDOW_MINTS: u64 = 2016;
pub const POW_RETARGET_CLAMP_FACTOR: u64 = 4;

// Mint-censorship proof window defaults (v1).
// Anchor-index based, deterministic consensus parameters.
pub const MINT_CENSOR_WINDOWS_START_ANCHOR: u64 = 0;
pub const MINT_WINDOW_V2_ACTIVATION_ANCHOR: u64 = 0;
pub const MINT_CENSOR_WINDOW_W: u64 = 64;
pub const MINT_CENSOR_WINDOW_K: u64 = 8;
pub const MINT_CENSOR_TOP_N: usize = 256;
pub const MINT_CENSOR_EXPECTED_CANDIDATES_E: u64 = 8;
pub const MINT_CENSOR_RETARGET_REL_MIN_NUM: u64 = 1;
pub const MINT_CENSOR_RETARGET_REL_MIN_DEN: u64 = 2;
pub const MINT_CENSOR_RETARGET_REL_MAX_NUM: u64 = 2;
pub const MINT_CENSOR_RETARGET_REL_MAX_DEN: u64 = 1;

// Candidate target bounds represented as PoW bits converted to u256 targets.
// Harder => more leading zero bits.
pub const MINT_CENSOR_MIN_TARGET_BITS: u8 = 32;
pub const MINT_CENSOR_MAX_TARGET_BITS: u8 = 8;

#[inline]
pub fn pow_bits_for_mint_height(base_bits: u8, next_mint_height: u64) -> u8 {
    // Bitcoin does not increase difficulty deterministically with height.
    // Keep the "v0" helper stable for callers that set an initial pow_limit/baseline.
    let _ = next_mint_height; // kept for API stability
    base_bits
}

#[inline]
pub fn emission_bucket_from_unix_millis(unix_millis: u128) -> u64 {
    (unix_millis / (EMISSION_BUCKET_MS as u128)) as u64
}

#[inline]
pub fn emission_collect_deadline_bucket(hit_bucket: u64) -> u64 {
    hit_bucket.saturating_add(EMISSION_COLLECT_BUCKETS)
}

#[inline]
pub fn emission_finalize_deadline_bucket(hit_bucket: u64) -> u64 {
    emission_collect_deadline_bucket(hit_bucket).saturating_add(EMISSION_FINALIZE_GRACE_BUCKETS)
}

#[inline]
pub fn pow_asert_bits(
    reference_bits: u8,
    min_bits: u8,
    reference_bucket: u64,
    current_bucket: u64,
) -> u8 {
    if reference_bits == 0 {
        return 0;
    }
    if reference_bucket == 0 || current_bucket <= reference_bucket {
        return reference_bits.max(min_bits);
    }

    let actual = current_bucket.saturating_sub(reference_bucket) as i128;
    let target = POW_TARGET_SPACING_BUCKETS as i128;
    let halflife = POW_ASERT_HALFLIFE_BUCKETS.max(1) as i128;
    let error = target - actual;

    let delta = if error >= 0 {
        (error + (halflife / 2)) / halflife
    } else {
        (error - (halflife / 2)) / halflife
    };

    let next = (reference_bits as i128)
        .saturating_add(delta)
        .clamp(min_bits as i128, 255);
    next as u8
}

/// Computes the next PoW difficulty bits using a Bitcoin-like retarget scheme.
///
/// Input units:
/// - `expected_window_anchors`: target timespan in finalized anchors for the window.
/// - `actual_window_anchors`: observed timespan in finalized anchors for the window.
///
/// The result is deterministic and does not use floating point math.
#[inline]
pub fn pow_retarget_bits(
    old_bits: u8,
    min_bits: u8,
    expected_window_anchors: u64,
    actual_window_anchors: u64,
) -> u8 {
    // Explicit "PoW disabled" mode: keep it disabled deterministically.
    if old_bits == 0 {
        return 0;
    }

    // Defensive: avoid division by zero on malformed inputs.
    let expected = expected_window_anchors.max(1);
    let mut actual = actual_window_anchors.max(1);

    // Bitcoin-style clamp to prevent extreme swings.
    let min_actual = (expected / POW_RETARGET_CLAMP_FACTOR).max(1);
    let max_actual = expected
        .saturating_mul(POW_RETARGET_CLAMP_FACTOR)
        .max(min_actual);
    if actual < min_actual {
        actual = min_actual;
    } else if actual > max_actual {
        actual = max_actual;
    }

    // ratio = expected / actual in Q32 fixed point.
    let ratio_q32: u64 = (((expected as u128) << 32) / (actual as u128)) as u64;

    // Thresholds for rounding `log2(ratio)` to the nearest integer.
    // Boundaries are at 2^(k+0.5) == sqrt(2) * 2^k.
    const SQRT2_Q32: u64 = 6_074_001_000;
    const INV_SQRT2_Q32: u64 = 3_037_000_500;
    const TWO_SQRT2_Q32: u64 = 12_148_002_000;
    const INV_TWO_SQRT2_Q32: u64 = 1_518_500_250;

    // delta_bits = round(log2(expected/actual)), clamped to [-2, 2] due to POW_RETARGET_CLAMP_FACTOR=4.
    let delta_bits: i16 = if ratio_q32 >= TWO_SQRT2_Q32 {
        2
    } else if ratio_q32 >= SQRT2_Q32 {
        1
    } else if ratio_q32 >= INV_SQRT2_Q32 {
        0
    } else if ratio_q32 >= INV_TWO_SQRT2_Q32 {
        -1
    } else {
        -2
    };

    let mut next = (old_bits as i16).saturating_add(delta_bits);
    // Enforce powLimit (minimum difficulty / easiest allowed).
    if next < (min_bits as i16) {
        next = min_bits as i16;
    }
    // Keep within u8 range (0..=255).
    next.clamp(0, 255) as u8
}

// Monetäre Konstanten (Hardcap, Einheiten)
pub const COIN: u64 = 100_000_000; // 1 PC = 100_000_000 Einheiten
pub const HARD_CAP_PC: u64 = 50_000_000; // 50 Mio PC
pub const HARD_CAP_UNITS: u128 = (HARD_CAP_PC as u128) * (COIN as u128);

// Emissionskurve (Halving-basiert)
pub const INITIAL_MINT_REWARD: u64 = 50 * COIN; // 50 PC initial reward
pub const HALVING_INTERVAL: u64 = 210_000; // Halvings alle 210k Mints (~4 Jahre bei 1 Mint/10min)
pub const MAX_HALVINGS: u32 = 32; // Nach 32 Halvings: Reward ~= 0

// Emissionskurve-Funktion: Berechnet Mint-Reward basierend auf Mint-Höhe
// Bitcoin-style Halving: Reward halbiert sich alle HALVING_INTERVAL Mints
pub fn compute_mint_reward(mint_height: u64) -> u64 {
    if mint_height == 0 {
        return 0; // Genesis-Mint hat kein Reward
    }
    let halvings = mint_height / HALVING_INTERVAL;
    if halvings >= MAX_HALVINGS as u64 {
        return 0; // Nach MAX_HALVINGS: kein Reward mehr
    }
    // Reward = INITIAL_MINT_REWARD >> halvings
    INITIAL_MINT_REWARD >> halvings
}

// M3-Fix: Minimum Stake für Attestor-Teilnahme
// M3-Fix: Minimum stake required for attestor participation
pub const MIN_ATTESTOR_STAKE: u64 = 10_000 * COIN; // 10.000 PC Minimum

// Slashing (Basispunkte)
pub const SLASH_EQUIVOCATION_BP: u16 = 10_000; // 100%
pub const SLASH_VOTE_INVALID_MIN_BP: u16 = 5_000; // 50%
pub const SLASH_VOTE_INVALID_MAX_BP: u16 = 10_000; // 100%
pub const SLASH_DA_25_BP: u16 = 2_500; // 25%
pub const SLASH_DA_50_BP: u16 = 5_000; // 50%
pub const SLASH_DA_100_BP: u16 = 10_000; // 100%

// Reporter reward share for successful slashing evidence (basis points).
// Reporter-Reward Anteil bei erfolgreicher Slashing-Evidence (Basispunkte).
pub const SLASH_REPORTER_REWARD_BP: u16 = 1_000; // 10%

// Hilfsfunktion: generiert eine monoton fallende Gewichtsliste Länge D_MAX
pub fn perf_weights_recommended() -> Vec<u32> {
    let mut w = Vec::with_capacity(D_MAX as usize);
    let mut cur: u32 = 10_000; // Skala 10000
    for _ in 0..D_MAX {
        w.push(cur);
        let next = (cur as u64 * PERF_ALPHA_NUM as u64) / PERF_ALPHA_DEN as u64;
        let mut next_u32 = next as u32;
        if next_u32 == 0 {
            next_u32 = 1;
        }
        cur = next_u32;
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_bits_for_mint_height_is_constant_like_bitcoin() {
        assert_eq!(pow_bits_for_mint_height(0, 1), 0);
        assert_eq!(pow_bits_for_mint_height(0, u64::MAX), 0);
        assert_eq!(
            pow_bits_for_mint_height(POW_DEFAULT_BITS, 1),
            POW_DEFAULT_BITS
        );
        assert_eq!(
            pow_bits_for_mint_height(POW_DEFAULT_BITS, u64::MAX),
            POW_DEFAULT_BITS
        );
    }

    #[test]
    fn pow_retarget_bits_rounds_and_clamps_like_bitcoin() {
        let old = 20u8;
        let min = 20u8;
        let expected = POW_TARGET_ANCHORS_PER_MINT * POW_RETARGET_WINDOW_MINTS;

        // Exactly on target: unchanged.
        assert_eq!(pow_retarget_bits(old, min, expected, expected), old);

        // Fast: 4x faster -> +2 bits (harder).
        assert_eq!(pow_retarget_bits(old, min, expected, expected / 4), old + 2);

        // Fast: 2x faster -> +1 bit.
        assert_eq!(pow_retarget_bits(old, min, expected, expected / 2), old + 1);

        // Slow: 2x slower -> -1 bit, but not below powLimit.
        assert_eq!(pow_retarget_bits(old, min, expected, expected * 2), old);

        // Allow decreases when min_bits is lower.
        assert_eq!(pow_retarget_bits(old, 0, expected, expected * 2), old - 1);

        // Slow: 4x slower -> -2 bits.
        assert_eq!(pow_retarget_bits(old, 0, expected, expected * 4), old - 2);

        // Extreme fast is clamped (actual < expected/4): still +2.
        assert_eq!(pow_retarget_bits(old, min, expected, 1), old + 2);
    }

    #[test]
    fn pow_asert_bits_relaxes_when_finds_are_slow() {
        let ref_bits = 20u8;
        let min_bits = 16u8;
        let got = pow_asert_bits(
            ref_bits,
            min_bits,
            1_000,
            1_000 + POW_TARGET_SPACING_BUCKETS + POW_ASERT_HALFLIFE_BUCKETS,
        );
        assert!(got < ref_bits);
        assert!(got >= min_bits);
    }

    #[test]
    fn pow_asert_bits_hardens_when_finds_are_fast() {
        let ref_bits = 20u8;
        let min_bits = 16u8;
        let got = pow_asert_bits(ref_bits, min_bits, 1_000, 1_100);
        assert!(got >= ref_bits);
    }
}
