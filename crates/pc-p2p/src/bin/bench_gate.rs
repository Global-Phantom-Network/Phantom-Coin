// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
struct Metrics {
    p50: Option<f64>,
    p95: Option<f64>,
    timeout_rate: Option<f64>,
    tp_ops: Option<f64>,
}

type Table = BTreeMap<String, Metrics>;

fn parse_csv(path: &Path) -> std::io::Result<Table> {
    let text = fs::read_to_string(path)?;
    let mut lines = text.lines();
    // header
    let _ = lines.next();
    let mut out: Table = BTreeMap::new();
    for l in lines {
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        // Expect format: bench,network_id,mean,p50,stddev,p95,p95_excl_timeouts,p95_approx,n,timeouts,timeout_rate,outliers_mild,outliers_severe,tp_ops
        // Split into up to 14 fields, tolerate missing trailing fields
        let mut parts = l.split(',');
        let bench = parts.next().unwrap_or("").trim().to_string();
        if bench.is_empty() {
            continue;
        }
        let _network_id = parts.next();
        let _mean = parts.next();
        let p50 = parts.next().and_then(|s| s.trim().parse::<f64>().ok());
        let _stddev = parts.next();
        let p95 = parts.next().and_then(|s| s.trim().parse::<f64>().ok());
        let _p95xt = parts.next();
        let _p95a = parts.next();
        let _n = parts.next();
        let _timeouts = parts.next();
        let timeout_rate = parts.next().and_then(|s| s.trim().parse::<f64>().ok());
        // ignore outliers
        let _out_mild = parts.next();
        let _out_severe = parts.next();
        let tp_ops = parts.next().and_then(|s| s.trim().parse::<f64>().ok());
        out.insert(
            bench,
            Metrics {
                p50,
                p95,
                timeout_rate,
                tp_ops,
            },
        );
    }
    Ok(out)
}

fn find_latest_baseline_csv() -> Option<PathBuf> {
    let base_dir = PathBuf::from("crates/pc-p2p/benches/baselines");
    let entries = fs::read_dir(&base_dir).ok()?;
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                dirs.push((name.to_string(), p));
            }
        }
    }
    if dirs.is_empty() {
        return None;
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    let last = match dirs.pop() {
        Some((_name, path)) => path,
        None => return None,
    };
    let csv = last.join("criterion_agg.csv");
    if csv.exists() {
        Some(csv)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct Thresholds {
    p50_tol: f64,
    p95_tol: f64,
    timeout_tol: f64,
    // per-bench overrides (optional)
    p50_overrides: BTreeMap<String, f64>,
    p95_overrides: BTreeMap<String, f64>,
    timeout_overrides: BTreeMap<String, f64>,
    // throughput gates
    tp_tol_neg: f64, // allowed relative drop (fraction), e.g., 0.10 => -10%
    tp_tol_overrides: BTreeMap<String, f64>,
    tp_abs_min: Option<f64>, // absolute minimum ops/s if set
    tp_abs_overrides: BTreeMap<String, f64>,
}

fn parse_overrides_env(name: &str) -> BTreeMap<String, f64> {
    let mut map = BTreeMap::new();
    if let Ok(raw) = env::var(name) {
        for pair in raw.split(',') {
            let p = pair.trim();
            if p.is_empty() {
                continue;
            }
            if let Some((k, v)) = p.split_once('=') {
                let key = k.trim();
                let val_str = v.trim();
                if key.is_empty() {
                    continue;
                }
                if let Ok(val) = val_str.parse::<f64>() {
                    if val >= 0.0 {
                        map.insert(key.to_string(), val);
                    }
                }
            }
        }
    }
    map
}

fn read_thresholds_from_env() -> Thresholds {
    fn get(name: &str, default: f64) -> f64 {
        match env::var(name).ok().and_then(|v| v.parse::<f64>().ok()) {
            Some(x) if x >= 0.0 => x,
            _ => default,
        }
    }
    fn get_opt(name: &str) -> Option<f64> {
        match env::var(name).ok().and_then(|v| v.parse::<f64>().ok()) {
            Some(x) if x >= 0.0 => Some(x),
            _ => None,
        }
    }
    Thresholds {
        p50_tol: get("BENCH_P50_TOL", 0.10),
        p95_tol: get("BENCH_P95_TOL", 0.10),
        timeout_tol: get("BENCH_TIMEOUT_TOL", 0.02),
        p50_overrides: parse_overrides_env("BENCH_P50_TOL_OVERRIDES"),
        p95_overrides: parse_overrides_env("BENCH_P95_TOL_OVERRIDES"),
        timeout_overrides: parse_overrides_env("BENCH_TIMEOUT_TOL_OVERRIDES"),
        tp_tol_neg: get("BENCH_TP_TOL_NEG", 0.10),
        tp_tol_overrides: parse_overrides_env("BENCH_TP_TOL_NEG_OVERRIDES"),
        tp_abs_min: get_opt("BENCH_TP_ABS_MIN"),
        tp_abs_overrides: parse_overrides_env("BENCH_TP_ABS_MIN_OVERRIDES"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut baseline_csv: Option<PathBuf> = None;
    let mut agg_csv: PathBuf = PathBuf::from("target/criterion_agg.csv");

    let mut i = 1;
    while i < args.len() {
        match args.get(i).map(|s| s.as_str()) {
            Some("--baseline") => {
                if let Some(p) = args.get(i + 1) {
                    baseline_csv = Some(PathBuf::from(p));
                    i += 2;
                } else {
                    eprintln!("--baseline benötigt Pfad");
                    std::process::exit(2);
                }
            }
            Some("--agg") => {
                if let Some(p) = args.get(i + 1) {
                    agg_csv = PathBuf::from(p);
                    i += 2;
                } else {
                    eprintln!("--agg benötigt Pfad");
                    std::process::exit(2);
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    let baseline_csv = baseline_csv
        .or_else(find_latest_baseline_csv)
        .unwrap_or_else(|| {
            eprintln!(
                "keine Baseline gefunden (crates/pc-p2p/benches/baselines/*/criterion_agg.csv)"
            );
            std::process::exit(2);
        });

    let thresholds = read_thresholds_from_env();

    let base = match parse_csv(&baseline_csv) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "Baseline CSV lesen fehlgeschlagen: {}: {}",
                baseline_csv.display(),
                e
            );
            std::process::exit(2);
        }
    };
    let curr = match parse_csv(&agg_csv) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "Aggregation CSV lesen fehlgeschlagen: {}: {}",
                agg_csv.display(),
                e
            );
            std::process::exit(2);
        }
    };

    let mut failures: Vec<String> = Vec::new();

    for (bench, cur) in &curr {
        if let Some(base_m) = base.get(bench) {
            // p50
            if let (Some(b), Some(c)) = (base_m.p50, cur.p50) {
                if b > 0.0 {
                    let drift = (c - b) / b;
                    let p50_tol = thresholds
                        .p50_overrides
                        .get(bench)
                        .copied()
                        .unwrap_or(thresholds.p50_tol);
                    if drift > p50_tol {
                        failures.push(format!(
                            "{} p50 drift {:.2}% > {:.2}% (base {:.3}, curr {:.3})",
                            bench,
                            drift * 100.0,
                            p50_tol * 100.0,
                            b,
                            c
                        ));
                    }
                }
            }
            // p95
            if let (Some(b), Some(c)) = (base_m.p95, cur.p95) {
                if b > 0.0 {
                    let drift = (c - b) / b;
                    let p95_tol = thresholds
                        .p95_overrides
                        .get(bench)
                        .copied()
                        .unwrap_or(thresholds.p95_tol);
                    if drift > p95_tol {
                        failures.push(format!(
                            "{} p95 drift {:.2}% > {:.2}% (base {:.3}, curr {:.3})",
                            bench,
                            drift * 100.0,
                            p95_tol * 100.0,
                            b,
                            c
                        ));
                    }
                }
            }
            // timeout rate
            if let (Some(b), Some(c)) = (base_m.timeout_rate, cur.timeout_rate) {
                let inc = c - b; // absolute increase
                let timeout_tol = thresholds
                    .timeout_overrides
                    .get(bench)
                    .copied()
                    .unwrap_or(thresholds.timeout_tol);
                if inc > timeout_tol {
                    failures.push(format!(
                        "{} timeout_rate +{:.2}% > {:.2}% (base {:.2}%, curr {:.2}%)",
                        bench,
                        inc * 100.0,
                        timeout_tol * 100.0,
                        b * 100.0,
                        c * 100.0
                    ));
                }
            } else if let Some(c) = cur.timeout_rate {
                // baseline hatte None/0
                let timeout_tol = thresholds
                    .timeout_overrides
                    .get(bench)
                    .copied()
                    .unwrap_or(thresholds.timeout_tol);
                if c > timeout_tol {
                    failures.push(format!(
                        "{} timeout_rate {:.2}% > {:.2}% (base 0%)",
                        bench,
                        c * 100.0,
                        timeout_tol * 100.0
                    ));
                }
            }
            // throughput relative drop vs baseline
            if let (Some(b), Some(c)) = (base_m.tp_ops, cur.tp_ops) {
                if b > 0.0 {
                    let drop = (b - c) / b;
                    let tp_tol = thresholds
                        .tp_tol_overrides
                        .get(bench)
                        .copied()
                        .unwrap_or(thresholds.tp_tol_neg);
                    if drop > tp_tol {
                        failures.push(format!(
                            "{} tp drop {:.2}% > {:.2}% (base {:.1} ops/s, curr {:.1} ops/s)",
                            bench,
                            drop * 100.0,
                            tp_tol * 100.0,
                            b,
                            c
                        ));
                    }
                }
            }
        }
        // absolute throughput min gate (applies even without baseline)
        if let Some(c) = cur.tp_ops {
            let tp_min = thresholds
                .tp_abs_overrides
                .get(bench)
                .copied()
                .or(thresholds.tp_abs_min)
                .unwrap_or(-1.0);
            if tp_min >= 0.0 && c < tp_min {
                failures.push(format!(
                    "{} tp {:.1} ops/s < min {:.1} ops/s",
                    bench, c, tp_min
                ));
            }
        }
    }

    if failures.is_empty() {
        println!("bench_gate: OK (keine Schwellwert-Verletzungen)");
    } else {
        eprintln!("bench_gate: FEHLER ({} Verletzungen):", failures.len());
        for f in &failures {
            eprintln!("- {}", f);
        }
        std::process::exit(1);
    }
}
