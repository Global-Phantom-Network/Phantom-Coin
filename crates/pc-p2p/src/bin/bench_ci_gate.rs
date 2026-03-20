// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
struct BenchMetrics {
    p95: Option<f64>,
    p95_approx: Option<f64>,
    timeout_rate: Option<f64>,
    tp_ops: Option<f64>,
}

fn raw_p95_from_candidates(bench: &str) -> Option<(f64, String)> {
    // Use only our own raw data (nanoseconds per sample).
    // Nur unsere eigenen Rohdaten verwenden (Nanosekunden pro Sample)
    let p = PathBuf::from("target/criterion_raw").join(format!("{}.csv", bench));
    if p.exists() {
        if let Some(vals) = load_raw_values(&p) {
            if let Some(p95) = percentile_from_values(vals, 0.95) {
                return Some((p95, "criterion_raw".to_string()));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
struct Budget {
    // Time limits in nanoseconds (ns).
    // Zeitgrenzen in Nanosekunden (ns)
    p95_max_ns: Option<f64>,
    // Throughput: operations per second.
    // Durchsatz: Operationen pro Sekunde
    tp_min_ops: Option<f64>,
    // Maximum allowed timeout rate (0.0 .. 1.0).
    // Maximal zulässige Timeout-Rate (0.0 .. 1.0)
    timeout_rate_max: Option<f64>,
}

fn load_agg(path: &str) -> anyhow::Result<BTreeMap<String, BenchMetrics>> {
    let text = fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let mut out: BTreeMap<String, BenchMetrics> = BTreeMap::new();
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid JSON root"))?;
    for (bench, val) in obj {
        let get = |k: &str| -> Option<f64> { val.get(k).and_then(|x| x.as_f64()) };
        let m = BenchMetrics {
            p95: get("p95"),
            p95_approx: get("p95_approx"),
            timeout_rate: get("timeout_rate"),
            tp_ops: get("tp_ops"),
        };
        out.insert(bench.clone(), m);
    }
    Ok(out)
}

fn load_raw_values(csv_path: &std::path::Path) -> Option<Vec<f64>> {
    let file = fs::File::open(csv_path).ok()?;
    let mut values: Vec<f64> = Vec::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if l.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
            continue;
        }
        if let Some(first) = l.split(&[',', ';', '\t'][..]).next() {
            let cleaned: String = first
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '.' || *c == 'e' || *c == 'E' || *c == '-')
                .collect();
            if cleaned.is_empty() {
                continue;
            }
            if let Ok(v) = cleaned.parse::<f64>() {
                // Filter: ignore implausible outliers > 10 seconds (in nanoseconds).
                // Filter: ignoriere unplausible Ausreißer > 10 Sekunden (in Nanosekunden)
                const MAX_NS: f64 = 10_000_000_000.0;
                if v.is_finite() && (0.0..=MAX_NS).contains(&v) {
                    values.push(v);
                }
            }
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}
fn percentile_from_values(mut values: Vec<f64>, percentile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let k = ((values.len() as f64) * percentile).clamp(0.0, (values.len() - 1) as f64) as usize;
    values.get(k).copied()
}

fn count_numeric_lines(csv_path: &std::path::Path) -> usize {
    let file = match fs::File::open(csv_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut n: usize = 0;
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let first = l.chars().next().unwrap_or('\0');
        if first == '#' || first.is_alphabetic() {
            continue;
        }
        let token = l.split(&[',', ';', '\t'][..]).next().unwrap_or("");
        let cleaned: String = token
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '.' || *c == 'e' || *c == 'E' || *c == '-')
            .collect();
        if cleaned.is_empty() {
            continue;
        }
        if cleaned.parse::<f64>().is_ok() {
            n += 1;
        }
    }
    n
}

fn read_timeouts_sum(bench: &str) -> Option<u64> {
    let mut p = PathBuf::from("target/criterion_raw");
    p.push(format!("{}_timeouts.txt", bench));
    let file = fs::File::open(&p).ok()?;
    let mut sum: u64 = 0;
    let mut any = false;
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Ok(v) = l.parse::<u64>() {
            sum = sum.saturating_add(v);
            any = true;
        }
    }
    if any {
        Some(sum)
    } else {
        Some(0)
    }
}

fn budgets() -> BTreeMap<String, Budget> {
    use Budget as B;
    let mut m = BTreeMap::new();

    // RPC (libp2p) – tight latency gate.
    // RPC (libp2p) – Latenz-gate eng
    m.insert(
        "p2p_libp2p_rpc_get_headers".into(),
        B {
            p95_max_ns: Some(800_000.0),
            timeout_rate_max: Some(0.001),
            ..B::default()
        },
    );
    m.insert(
        "p2p_libp2p_rpc_get_payloads".into(),
        B {
            p95_max_ns: Some(900_000.0),
            timeout_rate_max: Some(0.001),
            ..B::default()
        },
    );

    // End-to-end RR (libp2p).
    // E2E RR (libp2p)
    m.insert(
        "p2p_libp2p_e2e_inv_to_resp_headers".into(),
        B {
            p95_max_ns: Some(1_200_000.0),
            timeout_rate_max: Some(0.005),
            ..B::default()
        },
    );
    m.insert(
        "p2p_libp2p_e2e_inv_to_resp_payloads".into(),
        B {
            p95_max_ns: Some(1_200_000.0),
            timeout_rate_max: Some(0.005),
            ..B::default()
        },
    );
    m.insert(
        "p2p_libp2p_e2e_inv_to_resp_headers_gossip".into(),
        B {
            p95_max_ns: Some(1_200_000.0),
            timeout_rate_max: Some(0.01),
            ..B::default()
        },
    );
    m.insert(
        "p2p_libp2p_e2e_inv_to_resp_payloads_gossip".into(),
        B {
            p95_max_ns: Some(1_200_000.0),
            timeout_rate_max: Some(0.01),
            ..B::default()
        },
    );

    // Gossip header announce (A/B).
    // Gossip Header Announce (A/B)
    m.insert(
        "p2p_header_announce_gossip".into(),
        B {
            p95_max_ns: Some(25_000_000.0),
            timeout_rate_max: Some(0.01),
            ..B::default()
        },
    );
    m.insert(
        "p2p_header_announce_gossip_relaxed".into(),
        B {
            p95_max_ns: Some(25_000_000.0),
            timeout_rate_max: Some(0.01),
            ..B::default()
        },
    );
    m.insert(
        "p2p_header_announce_gossip_hb_1s".into(),
        B {
            p95_max_ns: Some(40_000_000.0),
            timeout_rate_max: Some(0.05),
            ..B::default()
        },
    );

    // Additional RR benches.
    // Weitere RR-Benches
    m.insert(
        "p2p_batch_headers_inv_rr".into(),
        B {
            p95_max_ns: Some(2_000_000.0),
            timeout_rate_max: Some(0.01),
            ..B::default()
        },
    );
    m.insert(
        "p2p_rpc_notfound_headers".into(),
        B {
            p95_max_ns: Some(5_000_000.0),
            timeout_rate_max: Some(0.01),
            ..B::default()
        },
    );
    m.insert(
        "p2p_rpc_warm_start_get_headers".into(),
        B {
            p95_max_ns: Some(1_500_000.0),
            timeout_rate_max: Some(0.005),
            ..B::default()
        },
    );
    m.insert(
        "p2p_rpc_parallel_get_payloads_8".into(),
        B {
            p95_max_ns: Some(1_500_000.0),
            timeout_rate_max: Some(0.005),
            ..B::default()
        },
    );
    m.insert(
        "p2p_rpc_payload_size_sweep".into(),
        B {
            p95_max_ns: Some(20_000_000.0),
            timeout_rate_max: Some(0.01),
            ..B::default()
        },
    );

    // Throughput.
    // Durchsatz
    m.insert(
        "p2p_throughput_headers".into(),
        B {
            tp_min_ops: Some(4_000.0),
            timeout_rate_max: Some(0.02),
            ..B::default()
        },
    );

    // No hard gates for: backpressure, ratelimit, retry, two_hop, dedupe – these are more for robustness/property tests.
    // Keine harten Gates für: backpressure, ratelimit, retry, two_hop, dedupe – dienen eher Robustheits-/Eigenschaftstests

    m
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("bench_ci_gate: ERROR: {e:?}");
        std::process::exit(2);
    }
}

fn real_main() -> anyhow::Result<()> {
    // 1) Aggregation must exist (run bench_agg beforehand).
    // 1) Aggregation muss vorhanden sein (vorher bench_agg ausführen)
    let agg_path = PathBuf::from("target/criterion_agg.json");
    if !agg_path.exists() {
        anyhow::bail!(
            "target/criterion_agg.json nicht gefunden. Bitte zuerst bench_agg ausführen."
        );
    }

    // 2) Load aggregated data.
    // 2) Laden
    let agg_path_str = agg_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("agg path not utf-8: {}", agg_path.display()))?;
    let mut data = load_agg(agg_path_str)?;
    // Optional: override metrics per budgeted bench with raw data from target/criterion_raw.
    // Optional: Überschreibe Kennzahlen pro budgetiertem Bench mit Rohdaten aus target/criterion_raw
    let budgets = budgets();
    for bench in budgets.keys() {
        if let Some((raw_p95, _src)) = raw_p95_from_candidates(bench) {
            let entry = data.entry(bench.clone()).or_default();
            let agg_p95 = entry.p95;
            let ok_bounds = raw_p95.is_finite() && raw_p95 > 0.0 && raw_p95 < 1_000_000_000.0; // < 1s in ns
            let ok_vs_agg = match agg_p95 {
                Some(v) => raw_p95 <= v * 10.0, // nicht völlig außerhalb der Größenordnung
                None => true,
            };
            if ok_bounds && ok_vs_agg {
                entry.p95 = Some(raw_p95);
            } else {
                eprintln!(
                    "[bench_ci_gate] ignore raw p95 for {}: {:.3} ns (agg={:?})",
                    bench, raw_p95, agg_p95
                );
            }
            // Derive timeout_rate from *_timeouts.txt and CSV lines.
            // timeout_rate aus *_timeouts.txt und CSV-Zeilen ableiten
            let csv = PathBuf::from("target/criterion_raw").join(format!("{}.csv", bench));
            let n = count_numeric_lines(&csv) as u64;
            if let Some(to) = read_timeouts_sum(bench) {
                let total = n.saturating_add(to);
                if total > 0 {
                    entry.timeout_rate = Some(to as f64 / total as f64);
                }
            }
        }
    }
    // budgets is already initialized.
    // budgets ist bereits initialisiert

    // 3) Validate metrics against budgets.
    // 3) Prüfen
    let mut failures: Vec<String> = Vec::new();
    for (bench, bud) in budgets.iter() {
        let Some(m) = data.get(bench) else {
            failures.push(format!("{}: keine Messwerte gefunden", bench));
            continue;
        };
        if std::env::var("BENCH_GATE_DEBUG").as_deref() == Ok("1") {
            eprintln!(
                "[bench_ci_gate][debug] {} => p95={:?} p95_approx={:?} timeout_rate={:?} tp_ops={:?}",
                bench, m.p95, m.p95_approx, m.timeout_rate, m.tp_ops
            );
        }
        // Check p95 (if a budget is set).
        // p95 prüfen (falls Budget gesetzt)
        if let Some(limit) = bud.p95_max_ns {
            let p95 = m.p95.or(m.p95_approx);
            match p95 {
                Some(v) if v <= limit => {}
                Some(v) => failures.push(format!(
                    "{}: p95 {:.0} ns > Limit {:.0} ns",
                    bench, v, limit
                )),
                None => failures.push(format!("{}: p95 fehlt (weder p95 noch p95_approx)", bench)),
            }
        }
        // Check timeout_rate (if a budget is set).
        // timeout_rate prüfen (falls Budget gesetzt)
        if let Some(limit) = bud.timeout_rate_max {
            let tr = m.timeout_rate.unwrap_or(0.0);
            if tr > limit {
                failures.push(format!(
                    "{}: timeout_rate {:.6} > Limit {:.6}",
                    bench, tr, limit
                ));
            }
        }
        // Check throughput (if a budget is set).
        // Durchsatz prüfen (falls Budget gesetzt)
        if let Some(min_tp) = bud.tp_min_ops {
            match m.tp_ops {
                Some(tp) if tp >= min_tp => {}
                Some(tp) => failures.push(format!(
                    "{}: tp_ops {:.3} < Minimum {:.3}",
                    bench, tp, min_tp
                )),
                None => failures.push(format!("{}: tp_ops fehlt", bench)),
            }
        }
    }

    // 4) Result.
    // 4) Ergebnis
    if failures.is_empty() {
        println!(
            "bench_ci_gate: OK – alle Budgets eingehalten ({} geprüfte Benches)",
            budgets.len()
        );
        std::process::exit(0);
    } else {
        eprintln!("bench_ci_gate: FAIL – Verstöße gegen Budgets:");
        for f in &failures {
            eprintln!("- {}", f);
        }
        std::process::exit(1);
    }
}

// Dependencies: anyhow, serde_json (already used in the project).
// Abhängigkeiten: anyhow, serde_json (bereits im Projekt genutzt)
