// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use std::io::Read as _;
use std::net::IpAddr;

pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub fn parse_http_url(url: &str) -> Result<reqwest::Url> {
    let trimmed = url.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        // Many wallet inputs are host:port without scheme. Default to https for safety.
        format!("https://{}", trimmed)
    };
    let parsed =
        reqwest::Url::parse(&with_scheme).map_err(|e| anyhow!("invalid URL '{url}': {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => {
            return Err(anyhow!(
                "unsupported URL scheme '{s}' (only http/https are allowed)"
            ))
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(anyhow!("URL must not contain username/password"));
    }
    if parsed.host_str().is_none() {
        return Err(anyhow!("URL missing host"));
    }
    Ok(parsed)
}

pub fn ensure_bearer_transport_safe(url: &reqwest::Url, auth: Option<&str>) -> Result<()> {
    let Some(_) = auth.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let host = url.host_str().ok_or_else(|| anyhow!("URL missing host"))?;
    if !is_loopback_host(host) && url.scheme() != "https" {
        return Err(anyhow!(
            "refusing to send bearer token to non-loopback host over non-HTTPS: {}",
            url
        ));
    }
    Ok(())
}

pub fn read_response_text_limited(
    resp: reqwest::blocking::Response,
    max_bytes: usize,
) -> Result<String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(anyhow!(
                "HTTP response too large (content-length {} > limit {})",
                len,
                max_bytes
            ));
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut r = resp.take((max_bytes + 1) as u64);
    r.read_to_end(&mut buf).context("read HTTP response body")?;
    if buf.len() > max_bytes {
        return Err(anyhow!(
            "HTTP response too large (read {} > limit {})",
            buf.len(),
            max_bytes
        ));
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}
