#![allow(dead_code)]

// Empfohlene Default-Konstanten für Konsens (v0)
// Beachte: k (Committee-Größe) ist netzabhängig; RECOMMENDED_K dient nur als Richtwert.

pub const RECOMMENDED_K: u8 = 21; // Richtwert; tatsächliches k kommt aus Genesis/Config

// Fee-Split (Basispunkte; Summe = 10_000)
pub const P_BASE_BP: u16 = 6500; // Basis-Anteil (gleichmäßig auf k Seats)
pub const P_PROP_BP: u16 = 1000; // Proposer-Anteil
pub const P_PERF_BP: u16 = 1500; // Performance-Topf (nach Ack-Distanz-Gewichten)
pub const P_ATT_BP: u16 = 1000; // Attestor-Topf

// Performance-Gewichtungsparameter
pub const D_MAX: u8 = 8;           // maximale Ack-Distanz, die gewertet wird
pub const PERF_ALPHA_NUM: u32 = 6; // α = 6/10 = 0.6 (ganzzahlig)
pub const PERF_ALPHA_DEN: u32 = 10;

// Hilfsfunktion: generiert eine monoton fallende Gewichtsliste Länge D_MAX
pub fn perf_weights_recommended() -> Vec<u32> {
    let mut w = Vec::with_capacity(D_MAX as usize);
    let mut cur: u32 = 10_000; // Skala 10000
    for _ in 0..D_MAX {
        w.push(cur);
        let next = (cur as u64 * PERF_ALPHA_NUM as u64) / PERF_ALPHA_DEN as u64;
        let mut next_u32 = next as u32;
        if next_u32 == 0 { next_u32 = 1; }
        cur = next_u32;
    }
    w
}
