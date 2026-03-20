// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::address::lock_from_pc_address;
use crate::http::{ensure_bearer_transport_safe, parse_http_url, read_response_text_limited};

const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Clone)]
pub struct HistoryUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub minted_at: u64,
    pub staked: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HistoryResp {
    pub ok: bool,
    pub lock: String,
    #[serde(default)]
    pub balance: u64,
    #[serde(default)]
    pub staked_balance: u64,
    #[serde(default)]
    pub n_utxos: usize,
    pub utxos: Vec<HistoryUtxo>,
}

pub fn fetch_history(
    client: &Client,
    node: &str,
    auth: Option<&str>,
    addr: &str,
) -> Result<HistoryResp> {
    let lock = lock_from_pc_address(addr)?;
    let lock_hex = hex::encode(lock);
    let url = format!("{}/wallet/history/{}", node.trim_end_matches('/'), lock_hex);

    let parsed_url = parse_http_url(&url)?;
    ensure_bearer_transport_safe(&parsed_url, auth)?;
    let mut req = client.get(parsed_url);
    if let Some(tok) = auth.map(str::trim).filter(|s| !s.is_empty()) {
        req = req.bearer_auth(tok);
    }
    let resp = match req.send() {
        Ok(r) => r,
        Err(e) => {
            if e.is_connect() || e.is_timeout() {
                return Err(anyhow!(
                    "history: Node {} nicht erreichbar oder Timeout ({}). Mögliche Ursachen (Beispiele): Node läuft nicht, falsche Node-URL/Port, Netzwerk- oder Firewall-Problem.",
                    node, e
                ));
            } else {
                return Err(anyhow!(
                    "history: HTTP-Fehler beim Request: {}. Mögliche Ursachen (Beispiele): falsches http/https-Schema, TLS-/Zertifikatsproblem, Proxy oder andere Zwischenkomponente blockiert die Anfrage.",
                    e
                ));
            }
        }
    };
    let status = resp.status();
    let text = read_response_text_limited(resp, MAX_HTTP_RESPONSE_BYTES)?;
    if !status.is_success() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(msg) = v.get("error").and_then(|e| e.as_str()) {
                return Err(anyhow!(
                    "history: Node hat History-Request abgelehnt ({}): {}. Mögliche Ursachen (Beispiele): ungültige Adresse, falsches Request-Format, Node-Policy oder fehlende/beschädigte Authentifizierung.",
                    status, msg
                ));
            }
        }
        return Err(anyhow!(
            "history request failed: {} {}. Mögliche Ursachen (Beispiele): Node hat eine unerwartete Antwort geliefert oder eine vorgeschaltete Komponente (Proxy, Load-Balancer) antwortet nicht im erwarteten Format.",
            status, text
        ));
    }
    let parsed: HistoryResp =
        serde_json::from_str(&text).map_err(|e| anyhow!("parse history json: {e}"))?;
    if !parsed.ok {
        return Err(anyhow!(
            "history response ok=false. Mögliche Ursachen (Beispiele): Node hat keine gültige History für diese Adresse geliefert oder die Anfrage intern abgelehnt (Node-Logs und Konfiguration prüfen)."
        ));
    }
    Ok(parsed)
}
