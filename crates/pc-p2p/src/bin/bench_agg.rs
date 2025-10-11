// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct Estimate {
    mean: Option<f64>,
    median: Option<f64>,
    stddev: Option<f64>,
    p95: Option<f64>,
    p95_excl_timeouts: Option<f64>,
    n_samples: Option<usize>,
    timeouts: Option<u64>,
    timeout_rate: Option<f64>,
    mild_outliers: Option<usize>,
    severe_outliers: Option<usize>,
    p95_approx: Option<f64>,
    network_id: Option<String>,
}

fn merge_from_raw_dir(out: &mut BTreeMap<String, Estimate>) {
    let raw_root = PathBuf::from("target").join("criterion_raw");
    if let Ok(entries) = fs::read_dir(&raw_root) {
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_file() { continue; }
            if p.extension().and_then(|s| s.to_str()) != Some("csv") { continue; }
            let name = match p.file_stem().and_then(|s| s.to_str()) { Some(s) => s.to_string(), None => continue };
            // Nur hinzufügen, wenn noch nicht vorhanden
            if out.contains_key(&name) { continue; }
            let mut est = Estimate { mean: None, median: None, stddev: None, p95: None, p95_excl_timeouts: None, n_samples: None, timeouts: None, timeout_rate: None, mild_outliers: None, severe_outliers: None, p95_approx: None, network_id: None };
            if let Some(vals) = load_raw_values(&p) {
                est.n_samples = Some(vals.len());
                if let Some(p95) = percentile_from_values(vals.clone(), 0.95) { est.p95 = Some(p95); }
                est.p95_excl_timeouts = est.p95;
                let (mild, severe) = outliers_from_values(vals);
                est.mild_outliers = Some(mild);
                est.severe_outliers = Some(severe);
                // Versuche network_id aus den ersten Zeilen der CSV zu lesen
                est.network_id = parse_network_id_from_file(&p);
            }
            // Timeouts einlesen, falls vorhanden
            let to_path = raw_root.join(format!("{}_timeouts.txt", name));
            if to_path.exists() {
                if est.network_id.is_none() { est.network_id = parse_network_id_from_file(&to_path); }
                let mut sum: u64 = 0;
                if let Ok(file) = fs::File::open(&to_path) {
                    for line in BufReader::new(file).lines().flatten() {
                        let l = line.trim();
                        if l.starts_with('#') { continue; }
                        if let Ok(v) = l.parse::<u64>() { sum = sum.saturating_add(v); }
                    }
                }
                if sum > 0 { est.timeouts = Some(sum); }
                if let Some(nsucc) = est.n_samples {
                    let total = nsucc as u64 + sum;
                    if total > 0 { est.timeout_rate = Some(sum as f64 / total as f64); }
                }
            }
            // Ohne mean/stddev aus estimates approximieren wir p95_approx nicht (bleibt None)
            out.insert(name, est);
        }
    }
}

fn read_estimates_json(path: &Path) -> Estimate {
    let text = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Estimate { mean: None, median: None, stddev: None, p95: None, p95_excl_timeouts: None, n_samples: None, timeouts: None, timeout_rate: None, mild_outliers: None, severe_outliers: None, p95_approx: None, network_id: None },
    };
    let v: serde_json::Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => return Estimate { mean: None, median: None, stddev: None, p95: None, p95_excl_timeouts: None, n_samples: None, timeouts: None, timeout_rate: None, mild_outliers: None, severe_outliers: None, p95_approx: None, network_id: None } };
    fn get_pe(obj: &serde_json::Value, keys: &[&str]) -> Option<f64> {
        for &k in keys {
            if let Some(o) = obj.get(k) {
                if let Some(pe) = o.get("point_estimate") {
                    if let Some(x) = pe.as_f64() { return Some(x); }
                    if let Some(i) = pe.as_i64() { return Some(i as f64); }
                    if let Some(u) = pe.as_u64() { return Some(u as f64); }
                }
            }
        }
        None
    }
    let mean = get_pe(&v, &["mean", "Mean"]);
    let median = get_pe(&v, &["median", "Median"]);
    let stddev = get_pe(&v, &["std_dev", "StdDev"]);
    Estimate { mean, median, stddev, p95: None, p95_excl_timeouts: None, n_samples: None, timeouts: None, timeout_rate: None, mild_outliers: None, severe_outliers: None, p95_approx: None, network_id: None }
}

fn load_raw_values(csv_path: &Path) -> Option<Vec<f64>> {
    let file = fs::File::open(csv_path).ok()?;
    let mut values: Vec<f64> = Vec::new();
    for line in BufReader::new(file).lines().flatten() {
        let l = line.trim();
        if l.is_empty() { continue; }
        if l.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) { continue; }
        if let Some(first) = l.split(&[',',';','\t'][..]).next() {
            let cleaned: String = first.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == 'e' || *c == 'E' || *c == '-' ).collect();
            if let Ok(v) = cleaned.parse::<f64>() { values.push(v); }
        }
    }

    if values.is_empty() { return None; }
    Some(values)
}

fn percentile_from_values(mut values: Vec<f64>, percentile: f64) -> Option<f64> {
    if values.is_empty() { return None; }
    values.sort_by(|a,b| a.partial_cmp(b).unwrap());
    let k = ((values.len() as f64) * percentile).clamp(0.0, (values.len()-1) as f64) as usize;
    values.get(k).copied()
}

fn outliers_from_values(mut values: Vec<f64>) -> (usize, usize) {
    if values.len() < 4 { return (0, 0); }
    values.sort_by(|a,b| a.partial_cmp(b).unwrap());
    let n = values.len();
    let q1 = values[n / 4];
    let q3 = values[(3 * n) / 4];
    let iqr = q3 - q1;
    let mild_low = q1 - 1.5 * iqr;
    let mild_high = q3 + 1.5 * iqr;
    let severe_low = q1 - 3.0 * iqr;
    let severe_high = q3 + 3.0 * iqr;
    let mut mild = 0usize;
    let mut severe = 0usize;
    for v in values {
        if v < severe_low || v > severe_high {
            severe += 1;
        } else if v < mild_low || v > mild_high {
            mild += 1;
        }
    }
    (mild, severe)
}

fn find_for_bench_dir(dir: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    // Bevorzugt new/estimates.json und new/raw.csv, sonst in dir/
    let new_dir = dir.join("new");
    let est_new = new_dir.join("estimates.json");
    let raw_new = new_dir.join("raw.csv");
    let est_root = dir.join("estimates.json");
    let raw_root = dir.join("raw.csv");
    let est = if est_new.exists() { Some(est_new) } else if est_root.exists() { Some(est_root) } else { None };
    let raw = if raw_new.exists() { Some(raw_new) } else if raw_root.exists() { Some(raw_root) } else { None };
    (est, raw)
}

fn custom_raw_path(bench_dir: &Path, bench_name: &str) -> Option<PathBuf> {
    // Erwarteter benutzerdefinierter Pfad: target/criterion_raw/<bench>.csv
    // bench_dir ist z. B. target/criterion/<bench_name>
    let root = bench_dir.parent()?.parent()?; // -> target/
    let p = root.join("criterion_raw").join(format!("{}.csv", bench_name));
    if p.exists() { Some(p) } else { None }
}

fn custom_timeouts_path(bench_dir: &Path, bench_name: &str) -> Option<PathBuf> {
    // Erwarteter Pfad: target/criterion_raw/<bench>_timeouts.txt
    let root = bench_dir.parent()?.parent()?; // -> target/
    let p = root.join("criterion_raw").join(format!("{}_timeouts.txt", bench_name));
    if p.exists() { Some(p) } else { None }
}

fn parse_network_id_from_file(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    for line in BufReader::new(file).lines().flatten().take(5) {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("# network_id=") {
            let hex = rest.trim();
            if !hex.is_empty() { return Some(hex.to_string()); }
        }
    }
    None
}

fn main() {
    let root = PathBuf::from("target/criterion");

    let mut out: BTreeMap<String, Estimate> = BTreeMap::new();

    // Alle direkten Bench-Verzeichnisse durchlaufen (falls vorhanden)
    if let Ok(entries) = fs::read_dir(&root) {
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_dir() { continue; }
            let bench_name = match p.file_name().and_then(|s| s.to_str()) { Some(s) => s.to_string(), None => continue };
            let (est_path, raw_default) = find_for_bench_dir(&p);
            // Bevorzuge unsere persistierten Rohdaten unter target/criterion_raw/<bench>.csv
            let raw_path = custom_raw_path(&p, &bench_name).or(raw_default);
            let timeouts_path = custom_timeouts_path(&p, &bench_name);
            if est_path.is_none() && raw_path.is_none() { continue; }
            let mut est = est_path.as_ref().map(|pp| read_estimates_json(pp)).unwrap_or(Estimate { mean: None, median: None, stddev: None, p95: None, p95_excl_timeouts: None, n_samples: None, timeouts: None, timeout_rate: None, mild_outliers: None, severe_outliers: None, p95_approx: None, network_id: None });
            if let Some(rp) = raw_path {
                if est.network_id.is_none() {
                    est.network_id = parse_network_id_from_file(&rp);
                }
                if let Some(vals) = load_raw_values(&rp) {
                    est.n_samples = Some(vals.len());
                    if let Some(p) = percentile_from_values(vals.clone(), 0.95) { est.p95 = Some(p); }
                    est.p95_excl_timeouts = est.p95;
                    let (mild, severe) = outliers_from_values(vals);
                    est.mild_outliers = Some(mild);
                    est.severe_outliers = Some(severe);
                }
            }
            if let Some(tp) = timeouts_path {
                if est.network_id.is_none() {
                    est.network_id = parse_network_id_from_file(&tp);
                }
                // summiere alle Zeilen
                let mut sum: u64 = 0;
                if let Ok(file) = fs::File::open(tp) {
                    for line in BufReader::new(file).lines().flatten() {
                        let l = line.trim();
                        if l.starts_with('#') { continue; }
                        if let Ok(v) = l.parse::<u64>() { sum = sum.saturating_add(v); }
                    }
                }
                if sum > 0 { est.timeouts = Some(sum); }
                if let Some(nsucc) = est.n_samples {
                    let total = nsucc as u64 + sum;
                    if total > 0 {
                        est.timeout_rate = Some(sum as f64 / total as f64);
                    }
                }
            }
            // Fallback: p95 approximieren, wenn kein raw vorhanden
            if est.p95.is_none() {
                if let (Some(m), Some(sd)) = (est.mean, est.stddev) {
                    est.p95_approx = Some(m + 1.645 * sd);
                }
            }
            out.insert(bench_name, est);
        }
    }

    // Zusätzlich Rohdaten-Verzeichnis scannen (z. B. QUIC-Benches ohne Criterion-Verzeichnis)
    merge_from_raw_dir(&mut out);

    // JSON-Export
    let mut json_map = serde_json::Map::new();
    for (k, v) in &out {
        let mut m = serde_json::Map::new();
        if let Some(nid) = &v.network_id { m.insert("network_id".into(), serde_json::Value::from(nid.clone())); }
        if let Some(x) = v.mean { m.insert("mean".into(), serde_json::Value::from(x)); }
        if let Some(x) = v.median { m.insert("p50".into(), serde_json::Value::from(x)); }
        if let Some(x) = v.stddev { m.insert("stddev".into(), serde_json::Value::from(x)); }
        if let Some(x) = v.p95 { m.insert("p95".into(), serde_json::Value::from(x)); }
        if let Some(x) = v.p95_excl_timeouts { m.insert("p95_excl_timeouts".into(), serde_json::Value::from(x)); }
        if let Some(x) = v.n_samples { m.insert("n".into(), serde_json::Value::from(x as u64)); }
        if let Some(x) = v.timeouts { m.insert("timeouts".into(), serde_json::Value::from(x as u64)); }
        if let Some(x) = v.timeout_rate { m.insert("timeout_rate".into(), serde_json::Value::from(x)); }
        if let Some(x) = v.mild_outliers { m.insert("outliers_mild".into(), serde_json::Value::from(x as u64)); }
        if let Some(x) = v.severe_outliers { m.insert("outliers_severe".into(), serde_json::Value::from(x as u64)); }
        if let Some(x) = v.p95_approx { m.insert("p95_approx".into(), serde_json::Value::from(x)); }
        json_map.insert(k.clone(), serde_json::Value::Object(m));
    }
    let json_text = serde_json::Value::Object(json_map).to_string();
    let json_out = PathBuf::from("target/criterion_agg.json");
    fs::write(&json_out, json_text).expect("write target/criterion_agg.json");

    // CSV-Export
    let mut csv_text = String::from("bench,network_id,mean,p50,stddev,p95,p95_excl_timeouts,p95_approx,n,timeouts,timeout_rate,outliers_mild,outliers_severe\n");
    for (k, v) in &out {
        let nid = v.network_id.as_deref().unwrap_or("");
        let mean = v.mean.map(|x| x.to_string()).unwrap_or_default();
        let p50 = v.median.map(|x| x.to_string()).unwrap_or_default();
        let stddev = v.stddev.map(|x| x.to_string()).unwrap_or_default();
        let p95 = v.p95.map(|x| x.to_string()).unwrap_or_default();
        let p95xt = v.p95_excl_timeouts.map(|x| x.to_string()).unwrap_or_default();
        let p95a = v.p95_approx.map(|x| x.to_string()).unwrap_or_default();
        let n = v.n_samples.map(|x| x.to_string()).unwrap_or_default();
        let to = v.timeouts.map(|x| x.to_string()).unwrap_or_default();
        let tor = v.timeout_rate.map(|x| x.to_string()).unwrap_or_default();
        let o_m = v.mild_outliers.map(|x| x.to_string()).unwrap_or_default();
        let o_s = v.severe_outliers.map(|x| x.to_string()).unwrap_or_default();
        csv_text.push_str(&format!("{},{},{},{},{},{},{},{},{},{},{},{},{}\n", k, nid, mean, p50, stddev, p95, p95xt, p95a, n, to, tor, o_m, o_s));
    }
    fs::write("target/criterion_agg.csv", csv_text).expect("write target/criterion_agg.csv");

    // Markdown-Export (Kurzreport)
    let mut md = String::from("# Criterion Aggregation\n\n");
    md.push_str("| bench | p50 | p95 | timeout_rate | n | timeouts |\n");
    md.push_str("|---|---:|---:|---:|---:|---:|\n");
    for (k, v) in &out {
        let p50 = v.median.map(|x| x.to_string()).unwrap_or_default();
        let p95 = v.p95.map(|x| x.to_string()).unwrap_or_default();
        let tor = v.timeout_rate.map(|x| x.to_string()).unwrap_or_default();
        let n = v.n_samples.map(|x| x.to_string()).unwrap_or_default();
        let to = v.timeouts.map(|x| x.to_string()).unwrap_or_default();
        md.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n", k, p50, p95, tor, n, to));
    }
    fs::write("target/criterion_agg.md", md).expect("write target/criterion_agg.md");

    println!("Aggregiert: {} Benches -> target/criterion_agg.json & target/criterion_agg.csv & target/criterion_agg.md", out.len());
}
