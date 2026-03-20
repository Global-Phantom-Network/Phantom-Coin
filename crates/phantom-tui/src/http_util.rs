use anyhow::{anyhow, Context, Result};
use futures::StreamExt as _;
use serde::de::DeserializeOwned;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

pub fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub fn is_local_url(url: &str) -> bool {
    let trimmed = url.trim();
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    if let Ok(parsed) = reqwest::Url::parse(&with_scheme) {
        if let Some(host) = parsed.host_str() {
            return is_local_host(host);
        }
    }
    let raw = trimmed
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = raw.split('/').next().unwrap_or(raw);
    let host = host.split(':').next().unwrap_or(host);
    is_local_host(host)
}

pub fn parse_http_url(url: &str) -> Result<reqwest::Url> {
    let trimmed = url.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
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
    if !is_local_host(host) && url.scheme() != "https" {
        return Err(anyhow!(
            "refusing to send bearer token to non-loopback host over non-HTTPS: {}",
            url
        ));
    }
    Ok(())
}

pub fn build_http_client_blocking(
    node_url: &str,
    tls_ca: Option<&Path>,
    tls_client_pem: Option<&Path>,
    insecure_skip_tls_verify: bool,
    timeout: Duration,
    connect_timeout: Duration,
) -> Result<reqwest::blocking::Client> {
    if insecure_skip_tls_verify {
        if tls_ca.is_some() {
            return Err(anyhow!(
                "--insecure-skip-tls-verify kann nicht zusammen mit tls_ca genutzt werden"
            ));
        }
        if !is_local_url(node_url) {
            return Err(anyhow!(
                "refusing to skip TLS verification for non-loopback host: {}",
                node_url
            ));
        }
    }

    let mut builder = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(insecure_skip_tls_verify)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(connect_timeout);
    if let Some(ca_path) = tls_ca {
        let data =
            std::fs::read(ca_path).with_context(|| format!("read tls_ca {}", ca_path.display()))?;
        let cert = reqwest::Certificate::from_pem(&data).context("parse tls_ca pem")?;
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert);
    }
    if let Some(pem_path) = tls_client_pem {
        let data = std::fs::read(pem_path)
            .with_context(|| format!("read tls_client_pem {}", pem_path.display()))?;
        let id = reqwest::Identity::from_pem(&data).context("parse client pem")?;
        builder = builder.identity(id);
    }
    builder.build().context("build reqwest client")
}

pub fn read_response_text_limited_blocking(
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

pub async fn read_response_text_limited(
    resp: reqwest::Response,
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
    let mut out: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read HTTP response chunk")?;
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(anyhow!(
                "HTTP response too large (read {} > limit {})",
                out.len().saturating_add(chunk.len()),
                max_bytes
            ));
        }
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

pub async fn read_json_limited<T: DeserializeOwned>(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<T> {
    let text = read_response_text_limited(resp, max_bytes).await?;
    serde_json::from_str::<T>(&text).context("parse json")
}

pub fn build_http_client(
    node_url: &str,
    tls_ca: Option<&Path>,
    tls_client_pem: Option<&Path>,
    insecure_skip_tls_verify: bool,
    timeout: Duration,
) -> Result<reqwest::Client> {
    if insecure_skip_tls_verify {
        if tls_ca.is_some() {
            return Err(anyhow!(
                "--insecure-skip-tls-verify kann nicht zusammen mit PHANTOM_TLS_CA genutzt werden"
            ));
        }
        if !is_local_url(node_url) {
            return Err(anyhow!(
                "refusing to skip TLS verification for non-loopback host: {}",
                node_url
            ));
        }
    }
    let connect_timeout = std::cmp::min(timeout, Duration::from_secs(5));
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure_skip_tls_verify)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(connect_timeout);
    if let Some(ca_path) = tls_ca {
        let data =
            std::fs::read(ca_path).with_context(|| format!("read tls_ca {}", ca_path.display()))?;
        let cert = reqwest::Certificate::from_pem(&data).context("parse tls_ca pem")?;
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert);
    }
    if let Some(pem_path) = tls_client_pem {
        let data = std::fs::read(pem_path)
            .with_context(|| format!("read tls_client_pem {}", pem_path.display()))?;
        let id = reqwest::Identity::from_pem(&data).context("parse tls_client pem")?;
        builder = builder.identity(id);
    }
    builder.build().context("build http client")
}

pub fn with_temp_secret_file<R, F>(prefix: &str, secret: &str, f: F) -> Result<R>
where
    F: FnOnce(&Path) -> Result<R>,
{
    use rand::RngCore as _;
    let mut path: std::path::PathBuf;
    let mut file = None;
    for _ in 0..16 {
        let mut rnd = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut rnd);
        let name = format!("{}_{}.secret", prefix, hex::encode(rnd));
        path = std::env::temp_dir().join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(fh) => {
                file = Some((path, fh));
                break;
            }
            Err(_) => continue,
        }
    }
    let (path, mut fh) = file.ok_or_else(|| {
        anyhow!(
            "could not create temp secret file in {}",
            std::env::temp_dir().display()
        )
    })?;
    {
        use std::io::Write as _;
        fh.write_all(secret.as_bytes())?;
        fh.write_all(b"\n")?;
        let _ = fh.flush();
    }
    drop(fh);
    let res = f(&path);
    let _ = std::fs::remove_file(&path);
    res
}
