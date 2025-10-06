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
        if l.is_empty() { continue; }
        // Expect format: bench,network_id,mean,p50,stddev,p95,p95_excl_timeouts,p95_approx,n,timeouts,timeout_rate,outliers_mild,outliers_severe
        // Split into up to 13 fields, tolerate missing trailing fields
        let mut parts = l.split(',');
        let bench = parts.next().unwrap_or("").trim().to_string();
        if bench.is_empty() { continue; }
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
        out.insert(bench, Metrics { p50, p95, timeout_rate });
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
    if dirs.is_empty() { return None; }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    let last = dirs.pop().unwrap().1;
    let csv = last.join("criterion_agg.csv");
    if csv.exists() { Some(csv) } else { None }
}

#[derive(Debug, Clone)]
struct Thresholds {
    p50_tol: f64,
    p95_tol: f64,
    timeout_tol: f64,
}

fn read_thresholds_from_env() -> Thresholds {
    fn get(name: &str, default: f64) -> f64 {
        match env::var(name).ok().and_then(|v| v.parse::<f64>().ok()) {
            Some(x) if x >= 0.0 => x,
            _ => default,
        }
    }
    Thresholds {
        p50_tol: get("BENCH_P50_TOL", 0.10),
        p95_tol: get("BENCH_P95_TOL", 0.10),
        timeout_tol: get("BENCH_TIMEOUT_TOL", 0.02),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut baseline_csv: Option<PathBuf> = None;
    let mut agg_csv: PathBuf = PathBuf::from("target/criterion_agg.csv");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--baseline" => {
                if i + 1 < args.len() { baseline_csv = Some(PathBuf::from(&args[i+1])); i += 2; } else { eprintln!("--baseline benötigt Pfad"); std::process::exit(2); }
            }
            "--agg" => {
                if i + 1 < args.len() { agg_csv = PathBuf::from(&args[i+1]); i += 2; } else { eprintln!("--agg benötigt Pfad"); std::process::exit(2); }
            }
            _ => { i += 1; }
        }
    }

    let baseline_csv = baseline_csv.or_else(find_latest_baseline_csv).unwrap_or_else(|| {
        eprintln!("keine Baseline gefunden (crates/pc-p2p/benches/baselines/*/criterion_agg.csv)");
        std::process::exit(2);
    });

    let thresholds = read_thresholds_from_env();

    let base = match parse_csv(&baseline_csv) {
        Ok(t) => t,
        Err(e) => { eprintln!("Baseline CSV lesen fehlgeschlagen: {}: {}", baseline_csv.display(), e); std::process::exit(2); }
    };
    let curr = match parse_csv(&agg_csv) {
        Ok(t) => t,
        Err(e) => { eprintln!("Aggregation CSV lesen fehlgeschlagen: {}: {}", agg_csv.display(), e); std::process::exit(2); }
    };

    let mut failures: Vec<String> = Vec::new();

    for (bench, cur) in &curr {
        if let Some(base_m) = base.get(bench) {
            // p50
            if let (Some(b), Some(c)) = (base_m.p50, cur.p50) {
                if b > 0.0 {
                    let drift = (c - b) / b;
                    if drift > thresholds.p50_tol {
                        failures.push(format!("{} p50 drift {:.2}% > {:.2}% (base {:.3}, curr {:.3})", bench, drift*100.0, thresholds.p50_tol*100.0, b, c));
                    }
                }
            }
            // p95
            if let (Some(b), Some(c)) = (base_m.p95, cur.p95) {
                if b > 0.0 {
                    let drift = (c - b) / b;
                    if drift > thresholds.p95_tol {
                        failures.push(format!("{} p95 drift {:.2}% > {:.2}% (base {:.3}, curr {:.3})", bench, drift*100.0, thresholds.p95_tol*100.0, b, c));
                    }
                }
            }
            // timeout rate
            if let (Some(b), Some(c)) = (base_m.timeout_rate, cur.timeout_rate) {
                let inc = c - b; // absolute increase
                if inc > thresholds.timeout_tol {
                    failures.push(format!("{} timeout_rate +{:.2}% > {:.2}% (base {:.2}%, curr {:.2}%)", bench, inc*100.0, thresholds.timeout_tol*100.0, b*100.0, c*100.0));
                }
            } else if let Some(c) = cur.timeout_rate { // baseline hatte None/0
                if c > thresholds.timeout_tol {
                    failures.push(format!("{} timeout_rate {:.2}% > {:.2}% (base 0%)", bench, c*100.0, thresholds.timeout_tol*100.0));
                }
            }
        }
    }

    if failures.is_empty() {
        println!("bench_gate: OK (keine Schwellwert-Verletzungen)");
    } else {
        eprintln!("bench_gate: FEHLER ({} Verletzungen):", failures.len());
        for f in &failures { eprintln!("- {}", f); }
        std::process::exit(1);
    }
}
