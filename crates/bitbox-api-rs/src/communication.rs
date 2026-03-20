#[cfg(any(
    feature = "usb",
    feature = "simulator",
    feature = "bridge",
    feature = "wasm",
    test
))]
use super::u2fframing::{self, U2FFraming};
use crate::runtime::Runtime;
use crate::util::Threading;
use async_trait::async_trait;
use thiserror::Error;

#[cfg(any(
    feature = "wasm",
    feature = "usb",
    feature = "simulator",
    feature = "bridge"
))]
pub const FIRMWARE_CMD: u8 = 0x80 + 0x40 + 0x01;

#[derive(Error, Debug)]
pub enum Error {
    #[error("unknown error")]
    Unknown,
    #[error("write error")]
    Write,
    #[error("read error")]
    Read,
    #[error("u2f framing decoding error")]
    U2fDecode,
    #[error("error querying device info")]
    Info,
    #[error("firmware version {0} required")]
    Version(&'static str),
}

#[cfg_attr(
    all(feature = "multithreaded", not(target_arch = "wasm32")),
    async_trait
)]
#[cfg_attr(any(not(feature = "multithreaded"), target_arch = "wasm32"), async_trait(?Send))]
pub trait ReadWrite: Threading {
    fn write(&self, msg: &[u8]) -> Result<usize, Error>;
    async fn read(&self) -> Result<Vec<u8>, Error>;

    async fn query(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.write(msg)?;
        self.read().await
    }
}

#[cfg(any(feature = "usb", feature = "simulator", feature = "wasm", test))]
pub struct U2fHidCommunication {
    read_write: Box<dyn ReadWrite>,
    u2fhid: u2fframing::U2fHid,
}

#[cfg(any(feature = "usb", feature = "simulator", feature = "wasm", test))]
impl crate::util::Threading for U2fHidCommunication {}

#[cfg(any(feature = "usb", feature = "simulator", feature = "wasm", test))]
impl U2fHidCommunication {
    pub fn from(read_write: Box<dyn ReadWrite>, cmd: u8) -> Self {
        U2fHidCommunication {
            read_write,
            u2fhid: u2fframing::U2fHid::new(cmd),
        }
    }
}

#[cfg(any(feature = "usb", feature = "simulator", feature = "wasm", test))]
#[cfg_attr(
    all(feature = "multithreaded", not(target_arch = "wasm32")),
    async_trait
)]
#[cfg_attr(any(not(feature = "multithreaded"), target_arch = "wasm32"), async_trait(?Send))]
impl ReadWrite for U2fHidCommunication {
    fn write(&self, msg: &[u8]) -> Result<usize, Error> {
        let mut buf = [0u8; u2fframing::MAX_LEN];
        let size = self
            .u2fhid
            .encode(msg, &mut buf)
            .map_err(|_| Error::Write)?;
        for chunk in buf[..size].chunks(64) {
            self.read_write.write(chunk)?;
        }
        Ok(size)
    }

    async fn read(&self) -> Result<Vec<u8>, Error> {
        let mut readbuf = self.read_write.read().await?;
        loop {
            match self.u2fhid.decode(&readbuf).or(Err(Error::U2fDecode))? {
                Some(d) => {
                    return Ok(d);
                }
                None => {
                    let more = self.read_write.read().await?;
                    readbuf.extend_from_slice(&more);
                }
            }
        }
    }
}

#[cfg(any(feature = "wasm", feature = "bridge"))]
pub struct U2fWsCommunication {
    read_write: Box<dyn ReadWrite>,
    u2fhid: u2fframing::U2fWs,
}

#[cfg(any(feature = "wasm", feature = "bridge"))]
impl Threading for U2fWsCommunication {}

#[cfg(any(feature = "wasm", feature = "bridge"))]
impl U2fWsCommunication {
    pub fn from(read_write: Box<dyn ReadWrite>, cmd: u8) -> Self {
        U2fWsCommunication {
            read_write,
            u2fhid: u2fframing::U2fWs::new(cmd),
        }
    }
}

#[cfg(any(feature = "wasm", feature = "bridge"))]
#[cfg_attr(
    all(feature = "multithreaded", not(target_arch = "wasm32")),
    async_trait
)]
#[cfg_attr(any(not(feature = "multithreaded"), target_arch = "wasm32"), async_trait(?Send))]
impl ReadWrite for U2fWsCommunication {
    fn write(&self, msg: &[u8]) -> Result<usize, Error> {
        let mut buf = [0u8; u2fframing::MAX_LEN];
        let size = self
            .u2fhid
            .encode(msg, &mut buf)
            .map_err(|_| Error::Write)?;
        self.read_write.write(&buf[..size])
    }

    async fn read(&self) -> Result<Vec<u8>, Error> {
        let mut readbuf = self.read_write.read().await?;
        loop {
            match self.u2fhid.decode(&readbuf).or(Err(Error::U2fDecode))? {
                Some(d) => {
                    return Ok(d);
                }
                None => {
                    let more = self.read_write.read().await?;
                    readbuf.extend_from_slice(&more);
                }
            }
        }
    }
}

// sinve v7.0.0, requets and responses are framed with hww* codes.
// hwwReq* are HWW-level framing opcodes of requests.
// New request.
const HWW_REQ_NEW: u8 = 0x00;
// Poll an outstanding request for completion.
const HWW_REQ_RETRY: u8 = 0x01;
// Cancel any outstanding request.
// const HWW_REQ_CANCEL: u8 = 0x02;
// INFO api call (used to be OP_INFO api call), graduated to the toplevel framing so it works
// the same way for all firmware versions.
#[cfg(any(
    feature = "usb",
    feature = "simulator",
    feature = "bridge",
    feature = "wasm"
))]
const HWW_INFO: u8 = b'i';

// hwwRsp* are HWW-level framing pocodes of responses.

// Request finished, payload is valid.
const HWW_RSP_ACK: u8 = 0x00;
// Request is outstanding, retry later with hwwOpRetry.
const HWW_RSP_NOTREADY: u8 = 0x01;
// Device is busy, request was dropped. Client should retry the exact same msg.
const HWW_RSP_BUSY: u8 = 0x02;
// Bad request.
const HWW_RSP_NACK: u8 = 0x03;

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Product {
    Unknown,
    BitBox02Multi,
    BitBox02BtcOnly,
    BitBox02NovaMulti,
    BitBox02NovaBtcOnly,
}

#[derive(Debug)]
pub struct Info {
    pub version: semver::Version,
    pub product: Product,
    #[allow(dead_code)]
    pub unlocked: bool,
    // Is None before firmware version 9.20.0.
    #[allow(dead_code)]
    pub initialized: Option<bool>,
}

pub struct HwwCommunication<R: Runtime> {
    communication: Box<dyn ReadWrite>,
    pub info: Info,
    marker: std::marker::PhantomData<R>,
}

#[cfg(any(
    feature = "usb",
    feature = "simulator",
    feature = "bridge",
    feature = "wasm"
))]
async fn get_info(communication: &dyn ReadWrite) -> Result<Info, Error> {
    let response = communication.query(&[HWW_INFO]).await?;
    let (version_str_len, response) = (
        *response.first().ok_or(Error::Info)? as usize,
        response.get(1..).ok_or(Error::Info)?,
    );
    let (version_bytes, response) = (
        response.get(..version_str_len).ok_or(Error::Info)?,
        response.get(version_str_len..).ok_or(Error::Info)?,
    );
    let version_str = std::str::from_utf8(version_bytes)
        .or(Err(Error::Info))?
        .strip_prefix('v')
        .ok_or(Error::Info)?;

    let version = semver::Version::parse(version_str).or(Err(Error::Info))?;
    const PLATFORM_BITBOX02: u8 = 0x00;
    const PLATFORM_BITBOX02_NOVA: u8 = 0x02;
    const BITBOX02_EDITION_MULTI: u8 = 0x00;
    const BITBOX02_EDITION_BTCONLY: u8 = 0x01;
    let platform_byte = *response.first().ok_or(Error::Info)?;
    let edition_byte = *response.get(1).ok_or(Error::Info)?;
    let unlocked_byte = *response.get(2).ok_or(Error::Info)?;
    let initialized_byte = response.get(3);
    Ok(Info {
        version,
        product: match (platform_byte, edition_byte) {
            (PLATFORM_BITBOX02, BITBOX02_EDITION_MULTI) => Product::BitBox02Multi,
            (PLATFORM_BITBOX02, BITBOX02_EDITION_BTCONLY) => Product::BitBox02BtcOnly,
            (PLATFORM_BITBOX02_NOVA, BITBOX02_EDITION_MULTI) => Product::BitBox02NovaMulti,
            (PLATFORM_BITBOX02_NOVA, BITBOX02_EDITION_BTCONLY) => Product::BitBox02NovaBtcOnly,
            _ => Product::Unknown,
        },
        unlocked: match unlocked_byte {
            0x00 => false,
            0x01 => true,
            _ => return Err(Error::Info),
        },
        initialized: match initialized_byte {
            None => None,
            Some(0x00) => Some(false),
            Some(0x01) => Some(true),
            _ => return Err(Error::Info),
        },
    })
}

impl<R: Runtime> HwwCommunication<R> {
    #[cfg(any(
        feature = "usb",
        feature = "simulator",
        feature = "bridge",
        feature = "wasm"
    ))]
    pub async fn from(communication: Box<dyn ReadWrite>) -> Result<Self, Error> {
        let info = get_info(communication.as_ref()).await?;
        // communication message framing since 7.0.0
        if !semver::VersionReq::parse(">=7.0.0")
            .or(Err(Error::Unknown))?
            .matches(&info.version)
        {
            return Err(Error::Version(">=7.0.0"));
        }

        Ok(HwwCommunication {
            communication,
            info,
            marker: std::marker::PhantomData,
        })
    }

    pub async fn query(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let mut framed_msg = Vec::from([HWW_REQ_NEW]);
        framed_msg.extend_from_slice(msg);

        let mut response = loop {
            let response = self.communication.query(&framed_msg).await?;
            if let Some(&HWW_RSP_BUSY) = response.first() {
                R::sleep(std::time::Duration::from_millis(1000)).await;
                continue;
            }
            break response;
        };
        loop {
            match response.first() {
                Some(&HWW_RSP_ACK) => {
                    return Ok(response.split_off(1));
                }
                Some(&HWW_RSP_BUSY) => {
                    return Err(Error::Info);
                }
                Some(&HWW_RSP_NACK) => {
                    return Err(Error::Info);
                }
                Some(&HWW_RSP_NOTREADY) => {
                    R::sleep(std::time::Duration::from_millis(200)).await;
                    response = self.communication.query(&[HWW_REQ_RETRY]).await?;
                }
                _ => return Err(Error::Info),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct DummyRw {
        writes: Arc<AtomicUsize>,
    }

    impl crate::util::Threading for DummyRw {}

    #[cfg_attr(
        all(feature = "multithreaded", not(target_arch = "wasm32")),
        async_trait::async_trait
    )]
    #[cfg_attr(
        any(not(feature = "multithreaded"), target_arch = "wasm32"),
        async_trait::async_trait(?Send)
    )]
    impl ReadWrite for DummyRw {
        fn write(&self, _msg: &[u8]) -> Result<usize, Error> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        }

        async fn read(&self) -> Result<Vec<u8>, Error> {
            Err(Error::Read)
        }
    }

    #[test]
    fn u2fhid_write_rejects_oversized_message_without_panic() {
        let writes = Arc::new(AtomicUsize::new(0));
        let dummy = Box::new(DummyRw {
            writes: writes.clone(),
        });

        let comm = U2fHidCommunication::from(dummy, 0xE1);
        let msg = vec![0u8; u2fframing::MAX_LEN + 1];

        let err = ReadWrite::write(&comm, &msg).expect_err("oversized message must error");
        assert!(matches!(err, Error::Write), "unexpected error: {err:?}");
        assert_eq!(
            writes.load(Ordering::SeqCst),
            0,
            "inner write must not be called on encode failure"
        );
    }
}
