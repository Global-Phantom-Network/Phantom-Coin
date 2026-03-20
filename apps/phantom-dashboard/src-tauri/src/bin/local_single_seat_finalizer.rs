#![forbid(unsafe_code)]

use pc_consensus::attestation::{committee_precommit_message, committee_vote_message};
use pc_types::{AnchorHeaderV2, AnchorId, ParentList};
use rand_core::{OsRng, RngCore};
use reqwest::Client;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

type FinalizerWorkKey = ([u8; 32], Option<[u8; 32]>);

#[derive(Debug, Clone, Deserialize)]
struct StatusServeLocalPrevoteContextResp {
    ok: bool,
    network_id: String,
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalFinalizerPrevote {
    network_id: [u8; 32],
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct StatusServeLocalPrecommitContextResp {
    ok: bool,
    network_id: String,
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
    post_state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalFinalizerPrecommit {
    network_id: [u8; 32],
    vote_epoch: u64,
    creator_index: u8,
    vote_mask: u64,
    committed_state_root: [u8; 32],
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_hex_array<const N: usize>(s: &str, label: &str) -> Result<[u8; N], String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("{label} ungültig: {e}"))?;
    if bytes.len() != N {
        return Err(format!("{label} muss {N}-Byte Hex sein."));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn last_nonempty_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .last()
        .unwrap_or("")
        .to_string()
}

fn repo_root() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| format!("cwd failed: {e}"))?;
    for _ in 0..10 {
        let cand = dir.join("Cargo.toml");
        if cand.is_file()
            && fs::read_to_string(&cand)
                .ok()
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Ok(dir);
        }
        dir = dir
            .parent()
            .ok_or_else(|| "repo root nicht gefunden".to_string())?
            .to_path_buf();
    }
    Err("repo root nicht gefunden".to_string())
}

fn find_binary(name: &str) -> Result<PathBuf, String> {
    let root = repo_root()?;
    let p = root.join("target").join("debug").join(name);
    if p.is_file() {
        return Ok(p);
    }
    let p = root.join("target").join("release").join(name);
    if p.is_file() {
        return Ok(p);
    }
    Err(format!("{name} binary nicht gefunden"))
}

fn with_temp_secret_file<R, F>(prefix: &str, secret: &str, f: F) -> Result<R, String>
where
    F: FnOnce(&Path) -> Result<R, String>,
{
    let mut path_opt = None;
    for _ in 0..16 {
        let mut rnd = [0u8; 16];
        OsRng.fill_bytes(&mut rnd);
        let name = format!("{}_{}.secret", prefix, hex::encode(rnd));
        let path = std::env::temp_dir().join(name);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut fh) => {
                fh.write_all(secret.as_bytes())
                    .map_err(|e| format!("Temp-Secret-Datei nicht schreibbar: {e}"))?;
                fh.write_all(b"\n")
                    .map_err(|e| format!("Temp-Secret-Datei nicht schreibbar: {e}"))?;
                let _ = fh.flush();
                drop(fh);
                path_opt = Some(path);
                break;
            }
            Err(_) => continue,
        }
    }
    let path = path_opt.ok_or_else(|| "Temp-Secret-Datei nicht erzeugbar".to_string())?;
    let res = f(&path);
    let _ = fs::remove_file(&path);
    res
}

fn with_temp_binary_file<R, F>(prefix: &str, bytes: &[u8], f: F) -> Result<R, String>
where
    F: FnOnce(&Path) -> Result<R, String>,
{
    let mut path_opt = None;
    for _ in 0..16 {
        let mut rnd = [0u8; 16];
        OsRng.fill_bytes(&mut rnd);
        let name = format!("{}_{}.bin", prefix, hex::encode(rnd));
        let path = std::env::temp_dir().join(name);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut fh) => {
                fh.write_all(bytes)
                    .map_err(|e| format!("Temp-Datei nicht schreibbar: {e}"))?;
                let _ = fh.flush();
                drop(fh);
                path_opt = Some(path);
                break;
            }
            Err(_) => continue,
        }
    }
    let path = path_opt.ok_or_else(|| "Temp-Datei nicht erzeugbar".to_string())?;
    let res = f(&path);
    let _ = fs::remove_file(&path);
    res
}

fn validate_loopback_base_url(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("URL ungültig: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("Nur http/https erlaubt".to_string()),
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL ohne Host".to_string())?;
    if host != "127.0.0.1" && host != "localhost" && host != "::1" {
        return Err("Nur Loopback-Hosts erlaubt".to_string());
    }
    if parsed.fragment().is_some() || parsed.query().is_some() {
        return Err("Base-URL darf keine Query/kein Fragment enthalten".to_string());
    }
    let p = parsed.path();
    if !p.is_empty() && p != "/" {
        return Err("Base-URL darf keinen Path enthalten".to_string());
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

async fn status_serve_get(
    status_addr: &str,
    token: &str,
    client: &Client,
    path: &str,
) -> Result<String, String> {
    let base = validate_loopback_base_url(&format!("http://{}", status_addr.trim()))?;
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let mut req = client.get(url);
    if !token.trim().is_empty() {
        req = req.bearer_auth(token.trim());
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("StatusServe Request fehlgeschlagen: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("StatusServe Antwort nicht lesbar: {e}"))?;
    if !status.is_success() {
        return Err(format!("StatusServe {}: {}", status.as_u16(), body));
    }
    Ok(body)
}

async fn resolve_local_finalizer_prevote(
    status_addr: &str,
    token: &str,
    client: &Client,
    payload_root: [u8; 32],
    bls_pk_hex: &str,
) -> Result<LocalFinalizerPrevote, String> {
    let path = format!(
        "/consensus/local_prevote_context?payload_root={}&bls_pk={}",
        hex::encode(payload_root),
        bls_pk_hex
    );
    let body = status_serve_get(status_addr, token, client, &path).await?;
    let value: StatusServeLocalPrevoteContextResp = serde_json::from_str(&body)
        .map_err(|e| format!("LocalPrevoteContext-JSON ungültig: {e}"))?;
    if !value.ok {
        return Err(format!("LocalPrevoteContext-Antwort nicht ok: {}", body));
    }
    Ok(LocalFinalizerPrevote {
        network_id: parse_hex_32(&value.network_id)
            .ok_or_else(|| format!("ungültige network_id: {}", body))?,
        vote_epoch: value.vote_epoch,
        creator_index: value.creator_index,
        vote_mask: value.vote_mask,
    })
}

async fn resolve_local_finalizer_precommit(
    status_addr: &str,
    token: &str,
    client: &Client,
    payload_root: [u8; 32],
    bls_pk_hex: &str,
) -> Result<LocalFinalizerPrecommit, String> {
    let path = format!(
        "/consensus/local_precommit_context?payload_root={}&bls_pk={}",
        hex::encode(payload_root),
        bls_pk_hex
    );
    let body = status_serve_get(status_addr, token, client, &path).await?;
    let value: StatusServeLocalPrecommitContextResp = serde_json::from_str(&body)
        .map_err(|e| format!("LocalPrecommitContext-JSON ungültig: {e}"))?;
    if !value.ok {
        return Err(format!("LocalPrecommitContext-Antwort nicht ok: {}", body));
    }
    Ok(LocalFinalizerPrecommit {
        network_id: parse_hex_32(&value.network_id)
            .ok_or_else(|| format!("ungültige network_id: {}", body))?,
        vote_epoch: value.vote_epoch,
        creator_index: value.creator_index,
        vote_mask: value.vote_mask,
        committed_state_root: parse_hex_32(&value.post_state_root)
            .ok_or_else(|| format!("ungültiger post_state_root: {}", body))?,
    })
}

fn validator_bls_pub_inner(signer_path: &Path, keystore_path: &Path) -> Result<String, String> {
    let out = Command::new(signer_path)
        .arg("export-pub")
        .arg("--keystore")
        .arg(keystore_path.to_string_lossy().to_string())
        .output()
        .map_err(|e| format!("phantom-signer export-pub failed: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            "phantom-signer export-pub fehlgeschlagen".to_string()
        } else {
            format!("phantom-signer export-pub fehlgeschlagen: {stderr}")
        });
    }
    let pk = last_nonempty_line(&String::from_utf8_lossy(&out.stdout));
    if pk.len() != 96 {
        return Err(format!("BLS PubKey hat unerwartete Länge ({})", pk.len()));
    }
    Ok(pk)
}

fn signer_bls_sign_message(
    signer_path: &Path,
    keystore_path: &Path,
    passphrase: &str,
    use_passphrase_role: bool,
    msg: &[u8],
) -> Result<[u8; 96], String> {
    let try_sign = |role_validator: bool| -> Result<[u8; 96], String> {
        with_temp_secret_file("phantom_validator_passphrase", passphrase, |pass_file| {
            with_temp_binary_file("phantom_vote_msg", msg, |msg_file| {
                let mut cmd = Command::new(signer_path);
                cmd.arg("sign")
                    .arg("--keystore")
                    .arg(keystore_path.to_string_lossy().to_string())
                    .arg("--msg")
                    .arg(msg_file.to_string_lossy().to_string())
                    .arg("--passphrase-file")
                    .arg(pass_file.to_string_lossy().to_string());
                if role_validator {
                    cmd.arg("--passphrase-role").arg("validator");
                }
                let out = cmd
                    .output()
                    .map_err(|e| format!("phantom-signer sign failed: {e}"))?;
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    return Err(if stderr.is_empty() {
                        "phantom-signer sign fehlgeschlagen".to_string()
                    } else {
                        format!("phantom-signer sign fehlgeschlagen: {stderr}")
                    });
                }
                decode_hex_array::<96>(
                    &last_nonempty_line(&String::from_utf8_lossy(&out.stdout)),
                    "bls_signature",
                )
            })
        })
    };
    match try_sign(use_passphrase_role) {
        Ok(sig) => Ok(sig),
        Err(e) if e.to_lowercase().contains("decrypt failed") => try_sign(!use_passphrase_role),
        Err(e) => Err(e),
    }
}

fn inject_header_announce_once(
    node_bin: &Path,
    p2p_addr: &str,
    cert_file: &Path,
    header: &AnchorHeaderV2,
) -> Result<(), String> {
    let mut buf = Vec::new();
    let v = vec![header.clone()];
    pc_codec::Encodable::encode(&v, &mut buf).map_err(|e| format!("Header encode failed: {e}"))?;
    with_temp_binary_file("phantom_hdr", &buf, |hdr_file| {
        let out = Command::new(node_bin)
            .arg("p2p-inject-headers")
            .arg("--addr")
            .arg(p2p_addr)
            .arg("--cert-file")
            .arg(cert_file.to_string_lossy().to_string())
            .arg("--headers-file")
            .arg(hdr_file.to_string_lossy().to_string())
            .output()
            .map_err(|e| format!("p2p-inject-headers spawn failed: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                "p2p-inject-headers failed".to_string()
            } else {
                format!("p2p-inject-headers failed: {stderr}")
            });
        }
        Ok(())
    })
}

fn latest_header_parent_from_store(headers_dir: &Path) -> Option<AnchorId> {
    let rd = fs::read_dir(headers_dir).ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf, [u8; 32])> = None;
    for entry in rd.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|s| s.to_str())?;
        let stem = name.strip_suffix(".bin")?;
        let expected_id = parse_hex_32(stem)?;
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        let dominated = match best {
            Some((best_modified, _, best_id)) => {
                modified > best_modified || (modified == best_modified && expected_id > best_id)
            }
            None => true,
        };
        if dominated {
            best = Some((modified, path, expected_id));
        }
    }
    let (_, path, expected_id) = best?;
    let buf = fs::read(&path).ok()?;
    let hdr = pc_codec::decode_exact::<AnchorHeaderV2>(&buf).ok()?;
    if hdr.id_digest() != expected_id {
        return None;
    }
    Some(AnchorId(expected_id))
}

fn finalizer_work_key(root: [u8; 32], parent_tip: Option<AnchorId>) -> FinalizerWorkKey {
    (root, parent_tip.map(|id| id.0))
}

fn print_usage() {
    eprintln!(
        "usage: local_single_seat_finalizer <store_dir> <status_addr> <token_file> <p2p_addr> <passphrase_file> [--use-passphrase-role]"
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        print_usage();
        return Err("zu wenige argumente".to_string());
    }
    let store_dir = PathBuf::from(&args[1]);
    let status_addr = args[2].clone();
    let token_file = PathBuf::from(&args[3]);
    let p2p_addr = args[4].clone();
    let passphrase_file = PathBuf::from(&args[5]);
    let use_passphrase_role = args.iter().any(|a| a == "--use-passphrase-role");

    let token = fs::read_to_string(&token_file)
        .map_err(|e| format!("token_file nicht lesbar: {e}"))?
        .trim()
        .to_string();
    let passphrase = fs::read_to_string(&passphrase_file)
        .map_err(|e| format!("passphrase_file nicht lesbar: {e}"))?
        .trim()
        .to_string();
    if passphrase.is_empty() {
        return Err("passphrase leer".to_string());
    }

    let node_bin = find_binary("phantom-node")?;
    let signer_bin = find_binary("phantom-signer")?;
    let cert_file = store_dir.join("p2p_quic_cert.der");
    let payloads_dir = store_dir.join("payloads");
    let headers_dir = store_dir.join("headers");
    let finalizer_state_path = store_dir.join(".finalizer_state");
    let keystore_path = store_dir.join("validator_bls.ks.toml");
    if !keystore_path.exists() {
        return Err(format!(
            "keystore nicht gefunden: {}",
            keystore_path.display()
        ));
    }
    let bls_pk_hex = validator_bls_pub_inner(&signer_bin, &keystore_path)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client build fehlgeschlagen: {e}"))?;

    let mut seen: HashSet<FinalizerWorkKey> = HashSet::new();
    let mut next_retry_after: HashMap<FinalizerWorkKey, Instant> = HashMap::new();
    let mut parent_tip: Option<AnchorId> =
        if let Ok(hex_str) = fs::read_to_string(&finalizer_state_path) {
            parse_hex_32(hex_str.trim()).map(AnchorId)
        } else {
            latest_header_parent_from_store(&headers_dir)
        };
    eprintln!(
        "[MANUAL-FINALIZER] gestartet p2p={} keystore={} bls_pk={}",
        p2p_addr,
        keystore_path.display(),
        bls_pk_hex
    );
    loop {
        if !cert_file.exists() || !payloads_dir.exists() {
            tokio::time::sleep(Duration::from_millis(800)).await;
            continue;
        }
        let signal_path = payloads_dir.join(".latest");
        let root = match fs::read_to_string(&signal_path) {
            Ok(hex_str) => match parse_hex_32(hex_str.trim()) {
                Some(r) => r,
                None => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            },
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        if parent_tip.is_none() {
            parent_tip = latest_header_parent_from_store(&headers_dir);
        }
        let work_key = finalizer_work_key(root, parent_tip);
        if seen.contains(&work_key) {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        if let Some(retry_at) = next_retry_after.get(&work_key) {
            if Instant::now() < *retry_at {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        }

        let mut parents = ParentList::default();
        if let Some(parent) = parent_tip {
            if let Err(e) = parents.push(parent) {
                eprintln!(
                    "[MANUAL-FINALIZER] parent setup fehlgeschlagen root={} err={}",
                    hex::encode(root),
                    e
                );
                next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                continue;
            }
        }

        let prevote =
            match resolve_local_finalizer_prevote(&status_addr, &token, &client, root, &bls_pk_hex)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "[MANUAL-FINALIZER] prevote context resolve fehlgeschlagen root={} err={}",
                        hex::encode(root),
                        e
                    );
                    next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                    continue;
                }
            };

        let mut prevote_header = AnchorHeaderV2 {
            version: 5,
            shard_id: 0,
            parents: parents.clone(),
            payload_hash: root,
            creator_index: prevote.creator_index,
            vote_mask: prevote.vote_mask,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
            network_id: prevote.network_id,
            vote_epoch: prevote.vote_epoch,
            vote_round: 0,
            attest_sig: None,
            state_root: None,
        };
        let prevote_msg = committee_vote_message(
            &prevote.network_id,
            prevote.vote_epoch,
            &prevote_header.vote_target_hash(),
        );
        let prevote_sig = match signer_bls_sign_message(
            &signer_bin,
            &keystore_path,
            &passphrase,
            use_passphrase_role,
            &prevote_msg,
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[MANUAL-FINALIZER] prevote sign fehlgeschlagen root={} err={}",
                    hex::encode(root),
                    e
                );
                next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                continue;
            }
        };
        prevote_header.attest_sig = Some(prevote_sig);
        if let Err(e) =
            inject_header_announce_once(&node_bin, &p2p_addr, &cert_file, &prevote_header)
        {
            eprintln!(
                "[MANUAL-FINALIZER] prevote inject fehlgeschlagen root={} err={}",
                hex::encode(root),
                e
            );
            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
            continue;
        }

        let resolved = match resolve_local_finalizer_precommit(
            &status_addr,
            &token,
            &client,
            root,
            &bls_pk_hex,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "[MANUAL-FINALIZER] precommit context resolve fehlgeschlagen root={} err={}",
                    hex::encode(root),
                    e
                );
                next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                continue;
            }
        };

        let mut header = AnchorHeaderV2 {
            version: 5,
            shard_id: 0,
            parents,
            payload_hash: root,
            creator_index: resolved.creator_index,
            vote_mask: resolved.vote_mask,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
            network_id: resolved.network_id,
            vote_epoch: resolved.vote_epoch,
            vote_round: 0,
            attest_sig: None,
            state_root: Some(resolved.committed_state_root),
        };
        let vote_msg = committee_precommit_message(
            &resolved.network_id,
            resolved.vote_epoch,
            &header.vote_target_hash(),
            &resolved.committed_state_root,
        );
        let sig = match signer_bls_sign_message(
            &signer_bin,
            &keystore_path,
            &passphrase,
            use_passphrase_role,
            &vote_msg,
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[MANUAL-FINALIZER] precommit sign fehlgeschlagen root={} err={}",
                    hex::encode(root),
                    e
                );
                next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
                continue;
            }
        };
        header.attest_sig = Some(sig);
        let next_parent_tip = AnchorId(header.id_digest());
        if let Err(e) = inject_header_announce_once(&node_bin, &p2p_addr, &cert_file, &header) {
            eprintln!(
                "[MANUAL-FINALIZER] precommit inject fehlgeschlagen root={} err={}",
                hex::encode(root),
                e
            );
            next_retry_after.insert(work_key, Instant::now() + Duration::from_secs(5));
            continue;
        }

        seen.insert(work_key);
        parent_tip = Some(next_parent_tip);
        next_retry_after.remove(&work_key);
        let _ = fs::write(&finalizer_state_path, hex::encode(next_parent_tip.0));
        eprintln!(
            "[MANUAL-FINALIZER] finalized root={} vote_epoch={} parent_count={}",
            hex::encode(root),
            resolved.vote_epoch,
            header.parents.len
        );
        tokio::time::sleep(Duration::from_millis(900)).await;
    }
}
