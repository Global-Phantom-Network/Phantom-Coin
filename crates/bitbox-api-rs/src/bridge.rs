use crate::communication::{self, Error as CommunicationError, ReadWrite};
use crate::runtime::Runtime;
use crate::{BitBox, NoiseConfig};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::env;
use std::io::Read;
use std::net::IpAddr;
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};
use url::Url;

const BRIDGE_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const BRIDGE_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BRIDGE_HTTP_BYTES: usize = 1024 * 1024; // 1 MiB
const BRIDGE_OPT_IN_ENV: &str = "PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE";

#[derive(Debug, Deserialize, Clone)]
pub struct BridgeDeviceInfo {
    pub path: String,
    pub product: String,
}

#[derive(Debug, Deserialize)]
struct DevicesResponse {
    devices: Vec<BridgeDeviceInfo>,
}

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("bridge url invalid: {0}")]
    Url(#[from] url::ParseError),
    #[error("bridge url scheme not allowed: {0}")]
    Scheme(String),
    #[error("bridge base url invalid: {0}")]
    InvalidBaseUrl(&'static str),
    #[error("bridge host must be loopback, got: {0}")]
    LoopbackOnly(String),
    #[error("BitBox bridge is disabled by default; set {0}=1 to opt in explicitly")]
    ExplicitOptInRequired(&'static str),
    #[error("bridge http error: {0}")]
    Http(#[source] Box<reqwest::Error>),
    #[error("bridge io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bridge http status: {0}")]
    Status(reqwest::StatusCode),
    #[error("bridge response too large")]
    ResponseTooLarge,
    #[error("bridge json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bridge websocket error: {0}")]
    Ws(#[source] Box<tungstenite::Error>),
    #[error("bridge response is missing devices")]
    DevicesResponse,
    #[error("bitbox02 not found on bridge")]
    NotFound,
    #[error("bitbox connect error: {0}")]
    BitBox(#[from] crate::error::Error),
}

impl From<reqwest::Error> for BridgeError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(Box::new(value))
    }
}

impl From<tungstenite::Error> for BridgeError {
    fn from(value: tungstenite::Error) -> Self {
        Self::Ws(Box::new(value))
    }
}

fn bridge_opt_in_enabled() -> bool {
    matches!(
        env::var(BRIDGE_OPT_IN_ENV),
        Ok(v) if matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    )
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn parse_bridge_base_url(base_url: &str) -> Result<Url, BridgeError> {
    let mut base = Url::parse(base_url.trim_end_matches('/'))?;
    base.set_query(None);
    base.set_fragment(None);
    match base.scheme() {
        "http" | "https" => {}
        other => return Err(BridgeError::Scheme(other.to_string())),
    }
    if !base.username().is_empty() || base.password().is_some() {
        return Err(BridgeError::InvalidBaseUrl(
            "username/password in bridge URL are not allowed",
        ));
    }
    let host = base
        .host_str()
        .ok_or(BridgeError::InvalidBaseUrl("bridge URL missing host"))?;
    if !is_loopback_host(host) {
        return Err(BridgeError::LoopbackOnly(host.to_string()));
    }
    if !matches!(base.path(), "" | "/") {
        return Err(BridgeError::InvalidBaseUrl(
            "bridge base URL must not contain a path",
        ));
    }
    if !bridge_opt_in_enabled() {
        return Err(BridgeError::ExplicitOptInRequired(BRIDGE_OPT_IN_ENV));
    }
    Ok(base)
}

fn build_bridge_http_client() -> Result<reqwest::blocking::Client, BridgeError> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(BRIDGE_HTTP_TIMEOUT)
        .connect_timeout(BRIDGE_HTTP_CONNECT_TIMEOUT)
        // Redirects can be abused as an SSRF bypass vector.
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

fn read_response_bytes_limited(
    resp: reqwest::blocking::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BridgeError> {
    let mut out = Vec::new();
    resp.take((max_bytes + 1) as u64).read_to_end(&mut out)?;
    if out.len() > max_bytes {
        return Err(BridgeError::ResponseTooLarge);
    }
    Ok(out)
}

fn read_json_limited<T: DeserializeOwned>(
    resp: reqwest::blocking::Response,
    max_bytes: usize,
) -> Result<T, BridgeError> {
    let bytes = read_response_bytes_limited(resp, max_bytes)?;
    Ok(serde_json::from_slice::<T>(&bytes)?)
}

pub fn list_devices(base_url: &str) -> Result<Vec<BridgeDeviceInfo>, BridgeError> {
    let url = devices_url(base_url)?;
    let client = build_bridge_http_client()?;
    let resp = client.get(url).send()?;
    let status = resp.status();
    if !status.is_success() {
        return Err(BridgeError::Status(status));
    }
    let resp: DevicesResponse = read_json_limited(resp, MAX_BRIDGE_HTTP_BYTES)?;
    Ok(resp.devices)
}

pub fn pick_bitbox02(devices: &[BridgeDeviceInfo]) -> Option<BridgeDeviceInfo> {
    devices
        .iter()
        .find(|d| d.product.to_lowercase().contains("bitbox02"))
        .cloned()
}

pub async fn connect_any_bitbox02<R: Runtime>(
    base_url: &str,
    noise_config: Box<dyn NoiseConfig>,
) -> Result<BitBox<R>, BridgeError> {
    let devices = list_devices(base_url)?;
    let dev = pick_bitbox02(&devices).ok_or(BridgeError::NotFound)?;
    connect_device(base_url, &dev.path, noise_config).await
}

pub async fn connect_device<R: Runtime>(
    base_url: &str,
    device_path: &str,
    noise_config: Box<dyn NoiseConfig>,
) -> Result<BitBox<R>, BridgeError> {
    let ws_url = ws_url(base_url, device_path)?;
    let (ws, _resp) = connect(ws_url)?;
    let bridge_dev = BridgeDevice::new(ws);
    let comm = Box::new(communication::U2fWsCommunication::from(
        Box::new(bridge_dev),
        communication::FIRMWARE_CMD,
    ));
    let bitbox = BitBox::<R>::from(comm, noise_config).await?;
    Ok(bitbox)
}

fn devices_url(base_url: &str) -> Result<Url, BridgeError> {
    let mut base = parse_bridge_base_url(base_url)?;
    {
        let mut segs = base
            .path_segments_mut()
            .map_err(|_| BridgeError::Url(url::ParseError::RelativeUrlWithoutBase))?;
        segs.pop_if_empty();
        segs.push("api");
        segs.push("v1");
        segs.push("devices");
    }
    Ok(base)
}

fn ws_url(base_url: &str, device_path: &str) -> Result<Url, BridgeError> {
    let mut base = parse_bridge_base_url(base_url)?;
    let new_scheme = match base.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => return Err(BridgeError::Scheme(other.to_string())),
    };
    base.set_scheme(new_scheme)
        .map_err(|_| BridgeError::Scheme(new_scheme.to_string()))?;
    {
        let mut segs = base
            .path_segments_mut()
            .map_err(|_| BridgeError::Url(url::ParseError::RelativeUrlWithoutBase))?;
        segs.pop_if_empty();
        segs.push("api");
        segs.push("v1");
        segs.push("socket");
        // Percent-encode the device path as a single path segment.
        segs.push(device_path);
    }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_rejects_non_loopback_hosts() {
        std::env::set_var(BRIDGE_OPT_IN_ENV, "1");
        let err = parse_bridge_base_url("http://192.168.1.10:8178").unwrap_err();
        assert!(matches!(err, BridgeError::LoopbackOnly(_)));
        std::env::remove_var(BRIDGE_OPT_IN_ENV);
    }

    #[test]
    fn bridge_requires_explicit_opt_in() {
        std::env::remove_var(BRIDGE_OPT_IN_ENV);
        let err = parse_bridge_base_url("http://127.0.0.1:8178").unwrap_err();
        assert!(matches!(err, BridgeError::ExplicitOptInRequired(_)));
    }
}

pub struct BridgeDevice {
    ws: Mutex<WebSocket<MaybeTlsStream<TcpStream>>>,
}

impl BridgeDevice {
    pub fn new(ws: WebSocket<MaybeTlsStream<TcpStream>>) -> Self {
        Self { ws: Mutex::new(ws) }
    }
}

impl crate::util::Threading for BridgeDevice {}

#[cfg_attr(feature = "multithreaded", async_trait)]
#[cfg_attr(not(feature="multithreaded"), async_trait(?Send))]
impl ReadWrite for BridgeDevice {
    fn write(&self, msg: &[u8]) -> Result<usize, CommunicationError> {
        let mut ws = self.ws.lock().map_err(|_| CommunicationError::Write)?;
        ws.send(Message::Binary(msg.to_vec()))
            .map_err(|_| CommunicationError::Write)?;
        Ok(msg.len())
    }

    async fn read(&self) -> Result<Vec<u8>, CommunicationError> {
        let mut ws = self.ws.lock().map_err(|_| CommunicationError::Read)?;
        loop {
            match ws.read() {
                Ok(Message::Binary(b)) => return Ok(b),
                Ok(Message::Close(_)) => return Err(CommunicationError::Read),
                Ok(_) => continue,
                Err(_) => return Err(CommunicationError::Read),
            }
        }
    }
}
