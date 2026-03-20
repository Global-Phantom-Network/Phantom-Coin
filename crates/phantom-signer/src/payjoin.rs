// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! PayJoin Workflows für Phantom-Coin
//!
//! Implementiert BIP78-ähnlichen PayJoin-Flow mit Phantom-PSBT (TOML).

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use pc_types::{MicroTx, TxIn, TxOut};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use crate::psbt::{decode_tx, encode_tx, Derivation, PhantomPsbtToml};

/// PayJoin-Request (Initiator → Responder)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayJoinRequest {
    pub version: u32,
    pub original_psbt: PhantomPsbtToml,
    pub endpoint: Option<String>, // Optional HTTPS endpoint
}

/// PayJoin-Response (Responder → Initiator)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayJoinResponse {
    pub version: u32,
    pub modified_psbt: PhantomPsbtToml,
    pub inputs_added: usize,
    pub outputs_modified: bool,
}

/// PayJoin-Privacy-Constraints Validator
struct PrivacyValidator {
    #[allow(dead_code)]
    min_output_amount: u64,
    max_dust_amount: u64,
}

impl Default for PrivacyValidator {
    fn default() -> Self {
        Self {
            min_output_amount: 1000, // Min 1000 sats
            max_dust_amount: 546,    // BTC dust limit
        }
    }
}

impl PrivacyValidator {
    /// Validiert, dass keine trivialen Betrags-Anker existieren
    fn validate_no_trivial_amounts(&self, outputs: &[TxOut]) -> Result<()> {
        for out in outputs {
            if out.amount > 0 && out.amount < self.max_dust_amount {
                return Err(anyhow!(
                    "output amount {} below dust limit {}",
                    out.amount,
                    self.max_dust_amount
                ));
            }
        }
        Ok(())
    }

    /// Placeholder for future privacy checks that are compatible with PayJoin.
    /// Duplicate output amounts are valid in BIP78-like flows and must not be rejected.
    fn validate_no_zero_change(&self, _outputs: &[TxOut]) -> Result<()> {
        Ok(())
    }

    /// Validiert Output-Sortierung (deterministisch)
    fn validate_output_sorting(&self, outputs: &[TxOut]) -> Result<()> {
        for (a, b) in outputs.iter().zip(outputs.iter().skip(1)) {
            match a.amount.cmp(&b.amount) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Greater => {
                    return Err(anyhow!("outputs not sorted by amount"));
                }
                std::cmp::Ordering::Equal => {
                    if a.lock.0 > b.lock.0 {
                        return Err(anyhow!("outputs not sorted by lock commitment"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Sortiert Outputs deterministisch (amount aufsteigend, dann lock)
pub fn sort_outputs_deterministic(tx: &mut MicroTx) {
    tx.outputs.sort_by(|a, b| match a.amount.cmp(&b.amount) {
        std::cmp::Ordering::Equal => a.lock.0.cmp(&b.lock.0),
        o => o,
    });
}

/// Initiiert PayJoin-Request (Sender-Seite)
///
/// # Arguments
/// * `original_psbt` - Original PSBT vom Sender
/// * `endpoint` - Optional: HTTPS endpoint des Empfängers
///
/// # Returns
/// PayJoinRequest zum Senden an Responder
pub fn initiate_payjoin(
    original_psbt: PhantomPsbtToml,
    endpoint: Option<String>,
) -> Result<PayJoinRequest> {
    // Validate original PSBT
    let tx_bytes = general_purpose::STANDARD
        .decode(original_psbt.tx_b64.as_bytes())
        .map_err(|e| anyhow!("tx_b64 decode: {e}"))?;
    let tx = decode_tx(&tx_bytes)?;

    if tx.inputs.is_empty() {
        return Err(anyhow!("original tx has no inputs"));
    }
    if tx.outputs.is_empty() {
        return Err(anyhow!("original tx has no outputs"));
    }

    // Privacy pre-check
    let validator = PrivacyValidator::default();
    validator.validate_no_trivial_amounts(&tx.outputs)?;
    if let Some(ep) = endpoint.as_ref() {
        validate_payjoin_endpoint(ep)?;
    }

    Ok(PayJoinRequest {
        version: 1,
        original_psbt,
        endpoint,
    })
}

/// Responder fügt Inputs hinzu (Empfänger-Seite)
///
/// # Arguments
/// * `request` - PayJoin-Request vom Initiator
/// * `additional_inputs` - Inputs die der Responder beisteuert
/// * `additional_derivations` - Derivation-Pfade für zusätzliche Inputs
/// * `modify_outputs` - Optional: Output-Anpassungen (z.B. Betragserhöhung)
///
/// # Returns
/// PayJoinResponse mit modifizierter PSBT
pub fn respond_payjoin(
    request: &PayJoinRequest,
    additional_inputs: Vec<TxIn>,
    additional_derivations: Vec<Derivation>,
    modify_outputs: Option<Vec<TxOut>>,
) -> Result<PayJoinResponse> {
    if request.version != 1 {
        return Err(anyhow!("unsupported payjoin version: {}", request.version));
    }

    if additional_inputs.is_empty() {
        return Err(anyhow!("responder must add at least one input"));
    }

    if additional_inputs.len() != additional_derivations.len() {
        return Err(anyhow!(
            "additional_inputs and additional_derivations length mismatch"
        ));
    }

    // Decode original TX
    let tx_bytes = general_purpose::STANDARD
        .decode(request.original_psbt.tx_b64.as_bytes())
        .map_err(|e| anyhow!("tx_b64 decode: {e}"))?;
    let mut tx = decode_tx(&tx_bytes)?;

    // Merge inputs
    let original_input_count = tx.inputs.len();
    tx.inputs.extend(additional_inputs);

    // Merge derivations
    let mut derivations = request.original_psbt.derivations.clone();
    derivations.extend(additional_derivations);

    // Modify outputs if provided
    let outputs_modified = if let Some(new_outputs) = modify_outputs {
        tx.outputs = new_outputs;
        true
    } else {
        false
    };

    // Sort outputs deterministisch
    sort_outputs_deterministic(&mut tx);

    // Validate privacy constraints
    let validator = PrivacyValidator::default();
    validator.validate_no_trivial_amounts(&tx.outputs)?;
    validator.validate_no_zero_change(&tx.outputs)?;
    validator.validate_output_sorting(&tx.outputs)?;

    // Encode modified TX
    let enc = encode_tx(&tx)?;
    let modified_psbt = PhantomPsbtToml {
        version: 1,
        algo: "schnorr".to_string(),
        tx_b64: general_purpose::STANDARD.encode(enc),
        derivations,
    };

    Ok(PayJoinResponse {
        version: 1,
        modified_psbt,
        inputs_added: tx.inputs.len() - original_input_count,
        outputs_modified,
    })
}

/// Validiert PayJoin-Response (Initiator-Seite)
///
/// # Arguments
/// * `original` - Original PSBT vom Initiator
/// * `response` - Response vom Responder
///
/// # Returns
/// Ok wenn valide, sonst Error
pub fn validate_payjoin_response(
    original: &PhantomPsbtToml,
    response: &PayJoinResponse,
) -> Result<()> {
    if response.version != 1 {
        return Err(anyhow!(
            "unsupported response version: {}",
            response.version
        ));
    }

    // Decode both TXs
    let orig_bytes = general_purpose::STANDARD
        .decode(original.tx_b64.as_bytes())
        .map_err(|e| anyhow!("original tx_b64 decode: {e}"))?;
    let orig_tx = decode_tx(&orig_bytes)?;

    let resp_bytes = general_purpose::STANDARD
        .decode(response.modified_psbt.tx_b64.as_bytes())
        .map_err(|e| anyhow!("response tx_b64 decode: {e}"))?;
    let resp_tx = decode_tx(&resp_bytes)?;

    // Validate inputs were added (not removed)
    if resp_tx.inputs.len() <= orig_tx.inputs.len() {
        return Err(anyhow!("response must add inputs, not remove"));
    }

    // Validate original inputs are preserved (order may change)
    let orig_input_set: HashSet<_> = orig_tx
        .inputs
        .iter()
        .map(|inp| (&inp.prev_out, &inp.witness))
        .collect();
    let resp_input_set: HashSet<_> = resp_tx
        .inputs
        .iter()
        .map(|inp| (&inp.prev_out, &inp.witness))
        .collect();

    for orig_inp in &orig_input_set {
        if !resp_input_set.contains(orig_inp) {
            return Err(anyhow!("original input missing in response"));
        }
    }

    // Validate outputs count (can be modified)
    if resp_tx.outputs.is_empty() {
        return Err(anyhow!("response has no outputs"));
    }

    // Privacy validation
    let validator = PrivacyValidator::default();
    validator.validate_no_trivial_amounts(&resp_tx.outputs)?;
    validator.validate_no_zero_change(&resp_tx.outputs)?;
    validator.validate_output_sorting(&resp_tx.outputs)?;

    // Validate sender outputs are preserved by lock commitment.
    // A responder must not replace sender outputs with different locks.
    let mut orig_per_lock: HashMap<[u8; 32], u64> = HashMap::new();
    for out in &orig_tx.outputs {
        let entry = orig_per_lock.entry(out.lock.0).or_insert(0);
        *entry = entry
            .checked_add(out.amount)
            .ok_or_else(|| anyhow!("original output sum overflow"))?;
    }
    let mut resp_per_lock: HashMap<[u8; 32], u64> = HashMap::new();
    for out in &resp_tx.outputs {
        let entry = resp_per_lock.entry(out.lock.0).or_insert(0);
        *entry = entry
            .checked_add(out.amount)
            .ok_or_else(|| anyhow!("response output sum overflow"))?;
    }
    for (lock, orig_sum) in orig_per_lock {
        let resp_sum = resp_per_lock.get(&lock).copied().unwrap_or(0);
        if resp_sum < orig_sum {
            return Err(anyhow!(
                "sender output for lock {} decreased: response {} < original {}",
                hex::encode(lock),
                resp_sum,
                orig_sum
            ));
        }
    }

    Ok(())
}

/// Speichert PayJoinRequest als TOML
pub fn save_payjoin_request(req: &PayJoinRequest, path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!("file exists, use --force to overwrite"));
    }

    let data = toml::to_string_pretty(req)?;
    fs::write(path, &data)?;
    Ok(())
}

/// Lädt PayJoinRequest aus TOML
pub fn load_payjoin_request(path: &Path) -> Result<PayJoinRequest> {
    let raw = fs::read_to_string(path)?;
    let req: PayJoinRequest = toml::from_str(&raw)?;
    if req.version != 1 {
        return Err(anyhow!(
            "unsupported payjoin request version: {}",
            req.version
        ));
    }
    Ok(req)
}

/// Speichert PayJoinResponse als TOML
pub fn save_payjoin_response(resp: &PayJoinResponse, path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!("file exists, use --force to overwrite"));
    }

    let data = toml::to_string_pretty(resp)?;
    fs::write(path, &data)?;
    Ok(())
}

/// Lädt PayJoinResponse aus TOML
pub fn load_payjoin_response(path: &Path) -> Result<PayJoinResponse> {
    let raw = fs::read_to_string(path)?;
    let resp: PayJoinResponse = toml::from_str(&raw)?;
    if resp.version != 1 {
        return Err(anyhow!(
            "unsupported payjoin response version: {}",
            resp.version
        ));
    }
    Ok(resp)
}

/// Parst `pc:` URI mit PayJoin-Endpoint
///
/// Format: pc:<address>?amount=<sats>&pj=<https://endpoint>
///
/// # Returns
/// (address, amount_opt, payjoin_endpoint_opt)
pub fn parse_pc_uri(uri: &str) -> Result<(String, Option<u64>, Option<String>)> {
    if !uri.starts_with("pc:") {
        return Err(anyhow!("invalid pc: URI scheme"));
    }

    let rest = &uri[3..]; // Strip "pc:"

    // Split address and optional query
    let mut split = rest.splitn(2, '?');
    let address = split.next().unwrap_or_default().to_string();

    let mut amount = None;
    let mut payjoin_endpoint = None;

    if let Some(query) = split.next() {
        for param in query.split('&') {
            let mut kv = param.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("amount"), Some(v)) => {
                    let decoded = percent_decode(v)?;
                    amount = decoded.parse::<u64>().ok();
                }
                (Some("pj"), Some(v)) => {
                    let decoded = percent_decode(v)?;
                    payjoin_endpoint = Some(decoded);
                }
                _ => {}
            }
        }
    }

    Ok((address, amount, payjoin_endpoint))
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn validate_payjoin_endpoint(endpoint: &str) -> Result<()> {
    let url =
        reqwest::Url::parse(endpoint).map_err(|e| anyhow!("invalid payjoin endpoint: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("payjoin endpoint missing host"))?;
    let loopback = is_loopback_host(host);
    if url.scheme() != "https" && !(loopback && url.scheme() == "http") {
        return Err(anyhow!(
            "payjoin endpoint must use https (or loopback http), got '{}'",
            endpoint
        ));
    }
    Ok(())
}

fn percent_decode(input: &str) -> Result<String> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'%' => {
                let Some(&b1) = bytes.get(i + 1) else {
                    out.push(b'%');
                    i += 1;
                    continue;
                };
                let Some(&b2) = bytes.get(i + 2) else {
                    out.push(b'%');
                    i += 1;
                    continue;
                };

                let h1 = b1 as char;
                let h2 = b2 as char;
                let hex = [h1, h2].iter().collect::<String>();
                let val = u8::from_str_radix(&hex, 16)
                    .map_err(|_| anyhow!("invalid percent-encoding near '%{}{}'", h1, h2))?;
                out.push(val);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| anyhow!("invalid UTF-8 in URI query value: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_types::{LockCommitment, OutPoint};

    #[test]
    fn test_output_sorting() {
        let o1 = TxOut {
            amount: 10,
            lock: LockCommitment([2u8; 32]),
        };
        let o2 = TxOut {
            amount: 5,
            lock: LockCommitment([9u8; 32]),
        };
        let o3 = TxOut {
            amount: 10,
            lock: LockCommitment([1u8; 32]),
        };

        let mut tx = MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![o1, o2, o3],
        };

        sort_outputs_deterministic(&mut tx);

        assert_eq!(tx.outputs[0].amount, 5);
        assert_eq!(tx.outputs[1].amount, 10);
        assert_eq!(tx.outputs[2].amount, 10);
        assert!(tx.outputs[1].lock.0 < tx.outputs[2].lock.0);
    }

    #[test]
    fn test_privacy_validator_no_dust() {
        let validator = PrivacyValidator::default();

        let outputs = vec![TxOut {
            amount: 100, // Below dust limit
            lock: LockCommitment([0u8; 32]),
        }];

        assert!(validator.validate_no_trivial_amounts(&outputs).is_err());
    }

    #[test]
    fn test_privacy_validator_allows_duplicate_amounts() {
        let validator = PrivacyValidator::default();

        let outputs = vec![
            TxOut {
                amount: 1000,
                lock: LockCommitment([1u8; 32]),
            },
            TxOut {
                amount: 1000, // Duplicate
                lock: LockCommitment([2u8; 32]),
            },
        ];

        assert!(validator.validate_no_zero_change(&outputs).is_ok());
    }

    #[test]
    fn test_payjoin_initiate() {
        use crate::psbt::to_toml_file;

        let tx = MicroTx {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                witness: vec![],
            }],
            outputs: vec![TxOut {
                amount: 10000,
                lock: LockCommitment([2u8; 32]),
            }],
        };

        let derivations = vec![Derivation {
            path: "m/86'/12345'/0'/0/0".to_string(),
        }];

        let tmp = std::env::temp_dir().join("test_payjoin.toml");
        to_toml_file(&tx, &derivations, &tmp).unwrap();

        let (tx_decoded, derivations_decoded) = crate::psbt::from_toml_file(&tmp).unwrap();
        let enc = encode_tx(&tx_decoded).unwrap();
        let psbt_toml = PhantomPsbtToml {
            version: 1,
            algo: "schnorr".to_string(),
            tx_b64: general_purpose::STANDARD.encode(enc),
            derivations: derivations_decoded,
        };

        let request = initiate_payjoin(psbt_toml, Some("https://receiver.com/pj".to_string()));

        assert!(request.is_ok());
        let req = request.unwrap();
        assert_eq!(req.version, 1);
        assert_eq!(req.endpoint, Some("https://receiver.com/pj".to_string()));

        fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_pc_uri_parsing() {
        // Simple address
        let (addr, amt, pj) = parse_pc_uri("pc:1a2b3c4d5e").unwrap();
        assert_eq!(addr, "1a2b3c4d5e");
        assert_eq!(amt, None);
        assert_eq!(pj, None);

        // With amount
        let (addr, amt, pj) = parse_pc_uri("pc:1a2b3c?amount=1000").unwrap();
        assert_eq!(addr, "1a2b3c");
        assert_eq!(amt, Some(1000));
        assert_eq!(pj, None);

        // With PayJoin
        let (addr, amt, pj) =
            parse_pc_uri("pc:1a2b3c?amount=1000&pj=https://receiver.com/pj").unwrap();
        assert_eq!(addr, "1a2b3c");
        assert_eq!(amt, Some(1000));
        assert_eq!(pj, Some("https://receiver.com/pj".to_string()));

        // URL-decoded endpoint
        let (_addr, _amt, pj) =
            parse_pc_uri("pc:1a2b3c?pj=https%3A%2F%2Freceiver.com%2Fpj%3Fa%3D1").unwrap();
        assert_eq!(pj, Some("https://receiver.com/pj?a=1".to_string()));
    }

    #[test]
    fn test_initiate_rejects_non_https_non_loopback_endpoint() {
        let tx = MicroTx {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                witness: vec![],
            }],
            outputs: vec![TxOut {
                amount: 10_000,
                lock: LockCommitment([2u8; 32]),
            }],
        };
        let psbt_toml = PhantomPsbtToml {
            version: 1,
            algo: "schnorr".to_string(),
            tx_b64: general_purpose::STANDARD.encode(encode_tx(&tx).unwrap()),
            derivations: vec![Derivation {
                path: "m/86'/12345'/0'/0/0".to_string(),
            }],
        };
        let err =
            initiate_payjoin(psbt_toml, Some("http://example.com/pj".to_string())).unwrap_err();
        assert!(format!("{err:#}").contains("must use https"));
    }

    #[test]
    fn test_validate_response_rejects_sender_output_replacement() {
        let orig_tx = MicroTx {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                witness: vec![],
            }],
            outputs: vec![
                TxOut {
                    amount: 10_000,
                    lock: LockCommitment([7u8; 32]),
                },
                TxOut {
                    amount: 5_000,
                    lock: LockCommitment([8u8; 32]),
                },
            ],
        };
        let resp_tx = MicroTx {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: OutPoint {
                        txid: [1u8; 32],
                        vout: 0,
                    },
                    witness: vec![],
                },
                TxIn {
                    prev_out: OutPoint {
                        txid: [2u8; 32],
                        vout: 1,
                    },
                    witness: vec![],
                },
            ],
            outputs: vec![
                TxOut {
                    amount: 1_000,
                    lock: LockCommitment([3u8; 32]),
                },
                TxOut {
                    amount: 15_000,
                    lock: LockCommitment([9u8; 32]), // replaced lock
                },
            ],
        };
        let original = PhantomPsbtToml {
            version: 1,
            algo: "schnorr".to_string(),
            tx_b64: general_purpose::STANDARD.encode(encode_tx(&orig_tx).unwrap()),
            derivations: vec![Derivation {
                path: "m/86'/12345'/0'/0/0".to_string(),
            }],
        };
        let response = PayJoinResponse {
            version: 1,
            modified_psbt: PhantomPsbtToml {
                version: 1,
                algo: "schnorr".to_string(),
                tx_b64: general_purpose::STANDARD.encode(encode_tx(&resp_tx).unwrap()),
                derivations: vec![
                    Derivation {
                        path: "m/86'/12345'/0'/0/0".to_string(),
                    },
                    Derivation {
                        path: "m/86'/12345'/0'/0/1".to_string(),
                    },
                ],
            },
            inputs_added: 1,
            outputs_modified: true,
        };
        let err = validate_payjoin_response(&original, &response).unwrap_err();
        assert!(format!("{err:#}").contains("decreased"));
    }
}
