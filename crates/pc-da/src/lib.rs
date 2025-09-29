// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

/// DA-Skelett: API-Skizze für Datenverfügbarkeit (Attestations, Chunk-Erfassung).
/// Spätere Implementierung asynchron (tokio), mit Erasure Coding und Aggregations-Protokoll.
use pc_types::AnchorHeader;

#[derive(Debug)]
pub enum DaError {
    InvalidConfig,
    ChannelClosed,
}

impl core::fmt::Display for DaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidConfig => write!(f, "invalid da config"),
            Self::ChannelClosed => write!(f, "channel closed"),
        }
    }
}
impl std::error::Error for DaError {}

#[derive(Clone, Debug, Default)]
pub struct DaConfig {
    pub max_chunks: u32,
}

#[derive(Clone, Debug)]
pub struct DaNode {
    _cfg: DaConfig,
}

impl DaNode {
    pub fn new(cfg: DaConfig) -> Result<Self, DaError> {
        if cfg.max_chunks == 0 { return Err(DaError::InvalidConfig); }
        Ok(Self { _cfg: cfg })
    }

    pub fn attest(&self, _hdr: &AnchorHeader) -> Result<(), DaError> {
        Ok(())
    }
}

#[cfg(feature = "async")]
pub mod async_svc {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration};
    use tracing::{info, warn};

    #[derive(Debug)]
    pub enum DaCmd {
        Attest(Box<AnchorHeader>),
        Shutdown,
    }

    #[derive(Clone)]
    pub struct DaService {
        tx: mpsc::Sender<DaCmd>,
    }

    impl DaService {
        pub async fn attest(&self, hdr: AnchorHeader) -> Result<(), DaError> {
            self.tx.send(DaCmd::Attest(Box::new(hdr))).await.map_err(|_| DaError::ChannelClosed)
        }
        pub async fn shutdown(&self) -> Result<(), DaError> {
            self.tx.send(DaCmd::Shutdown).await.map_err(|_| DaError::ChannelClosed)
        }
    }

    pub async fn run_da_loop(cfg: DaConfig, mut rx: mpsc::Receiver<DaCmd>) -> Result<(), DaError> {
        if cfg.max_chunks == 0 { return Err(DaError::InvalidConfig); }
        info!(max_chunks = cfg.max_chunks, "da loop started");
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    match cmd {
                        Some(DaCmd::Attest(hdr)) => {
                            // Später: Erasure Coding/Batch Aggregation; aktuell nur loggen
                            info!(creator = hdr.creator_index, "da attest header");
                        }
                        Some(DaCmd::Shutdown) => {
                            info!("da shutdown received");
                            break;
                        }
                        None => {
                            warn!("da command channel closed");
                            break;
                        }
                    }
                }
                _ = sleep(Duration::from_millis(500)) => {
                    // periodische Aufgaben: Cleanup/Health; später ausbauen
                }
            }
        }
        info!("da loop stopped");
        Ok(())
    }

    pub fn spawn(cfg: DaConfig) -> (DaService, tokio::task::JoinHandle<Result<(), DaError>>) {
        let (tx, rx) = mpsc::channel(1024);
        let handle = tokio::spawn(run_da_loop(cfg, rx));
        (DaService { tx }, handle)
    }
}
