// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Data Availability Gating Module
//!
//! Implements strict "pull-then-vote" mechanism:
//! - Validators must have local data before voting
//! - Fetches missing data with timeout
//! - Rejects votes if data unavailable

pub mod fetcher;
pub mod storage;

use fetcher::FetcherInterface;
use pc_crypto::Hash32;
use pc_types::{payload_merkle_root_v3, AnchorPayloadV3 as AnchorPayload};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use storage::StorageInterface;
use tokio::sync::{oneshot, Mutex};

/// DA Gating Configuration
#[derive(Clone, Debug)]
pub struct DaGatingConfig {
    /// Timeout for fetching missing payload (default: 5s)
    pub fetch_timeout: Duration,
    /// Maximum concurrent pending requests (default: 1000)
    pub max_pending: usize,
    /// Number of retry attempts (default: 3)
    pub retry_attempts: u32,
    /// Delay between retries (default: 1s)
    pub retry_delay: Duration,
}

impl Default for DaGatingConfig {
    fn default() -> Self {
        Self {
            fetch_timeout: Duration::from_secs(5),
            max_pending: 1000,
            retry_attempts: 3,
            retry_delay: Duration::from_secs(1),
        }
    }
}

/// Result of data availability check
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaResult {
    /// Payload is available locally
    Available(Vec<u8>),
    /// Timeout expired before data arrived
    Timeout,
    /// Root mismatch (invalid payload)
    Invalid,
    /// Network unreachable or fetch failed
    Unreachable,
}

/// Pending data request
struct PendingRequest {
    #[allow(dead_code)]
    pub payload_hash: Hash32,
    pub requested_at: Instant,
    pub timeout: Duration,
    pub notifiers: Vec<oneshot::Sender<DaResult>>,
}

/// DA Gating Manager
pub struct DaGatingManager<S: StorageInterface, F: FetcherInterface> {
    storage: Arc<S>,
    fetcher: Arc<F>,
    pending: Arc<Mutex<HashMap<Hash32, PendingRequest>>>,
    config: DaGatingConfig,
}

impl<S: StorageInterface, F: FetcherInterface> DaGatingManager<S, F> {
    /// Create new DA gating manager
    pub fn new(storage: Arc<S>, fetcher: Arc<F>, config: DaGatingConfig) -> Self {
        Self {
            storage,
            fetcher,
            pending: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Check if data is available, fetch if not
    ///
    /// **Strict Pull-then-Vote:**
    /// 1. Check local storage first (O(1))
    /// 2. If not found, initiate fetch
    /// 3. Wait for result or timeout
    /// 4. Return Available only if data present
    pub async fn ensure_data_available(
        &self,
        payload_hash: Hash32,
    ) -> Result<DaResult, DaGatingError> {
        // 1. Check local storage (fast path)
        if let Some(data) = self
            .storage
            .get(&payload_hash)
            .await
            .map_err(|e| DaGatingError::StorageError(e.to_string()))?
        {
            return Ok(DaResult::Available(data));
        }

        // 2. Check if already pending
        {
            let pending = self.pending.lock().await;
            if pending.contains_key(&payload_hash) {
                // Already in flight, attach to existing request
                drop(pending); // Release lock before wait
                return self.wait_for_pending(payload_hash).await;
            }
        }

        // 3. Initiate fetch
        self.fetch_and_wait(payload_hash).await
    }

    /// Fetch payload and wait for result
    async fn fetch_and_wait(&self, payload_hash: Hash32) -> Result<DaResult, DaGatingError> {
        let (tx, rx) = oneshot::channel();

        // Register pending request
        {
            let mut pending = self.pending.lock().await;
            if pending.len() >= self.config.max_pending {
                return Err(DaGatingError::TooManyPending);
            }

            pending.insert(
                payload_hash,
                PendingRequest {
                    payload_hash,
                    requested_at: Instant::now(),
                    timeout: self.config.fetch_timeout,
                    notifiers: vec![tx],
                },
            );
        }

        // Send fetch request
        self.fetcher
            .request_payload(payload_hash)
            .await
            .map_err(|e| DaGatingError::FetchError(e.to_string()))?;

        // Wait for result or timeout
        match tokio::time::timeout(self.config.fetch_timeout, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => {
                self.cleanup_pending(payload_hash).await;
                Ok(DaResult::Unreachable)
            }
            Err(_) => {
                // Timeout
                self.cleanup_pending(payload_hash).await;
                Ok(DaResult::Timeout)
            }
        }
    }

    /// Handle incoming payload response
    pub async fn handle_payload_response(
        &self,
        payload: AnchorPayload,
    ) -> Result<(), DaGatingError> {
        let payload_hash = payload_merkle_root_v3(&payload);

        // Only store payloads that were actually requested, otherwise an attacker can
        // use unsolicited payloads for storage amplification.
        let Some(notifiers) = ({
            let mut pending = self.pending.lock().await;
            pending.remove(&payload_hash).map(|req| req.notifiers)
        }) else {
            return Ok(());
        };

        // Store payload
        if let Err(e) = self.storage.put(&payload_hash, &payload).await {
            for tx in notifiers {
                let _ = tx.send(DaResult::Unreachable);
            }
            return Err(DaGatingError::StorageError(e.to_string()));
        }

        // Return the same bytes for pending-path as fast-path (storage.get()).
        let data = match self.storage.get(&payload_hash).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                for tx in notifiers {
                    let _ = tx.send(DaResult::Unreachable);
                }
                return Err(DaGatingError::StorageError(
                    "payload missing after successful store".to_string(),
                ));
            }
            Err(e) => {
                for tx in notifiers {
                    let _ = tx.send(DaResult::Unreachable);
                }
                return Err(DaGatingError::StorageError(e.to_string()));
            }
        };

        for tx in notifiers {
            let _ = tx.send(DaResult::Available(data.clone()));
        }

        Ok(())
    }

    /// Check if data is locally available (no fetch)
    pub async fn is_available(&self, payload_hash: &Hash32) -> bool {
        self.storage
            .get(payload_hash)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// Wait for already-pending request
    async fn wait_for_pending(&self, payload_hash: Hash32) -> Result<DaResult, DaGatingError> {
        let (tx, rx) = oneshot::channel();

        // Attach to existing request
        {
            let mut pending = self.pending.lock().await;
            if let Some(req) = pending.get_mut(&payload_hash) {
                req.notifiers.push(tx);
            } else {
                // Race: request completed between checks
                // Check storage again (no recursion)
                drop(pending);
                if let Some(data) = self
                    .storage
                    .get(&payload_hash)
                    .await
                    .map_err(|e| DaGatingError::StorageError(e.to_string()))?
                {
                    return Ok(DaResult::Available(data));
                } else {
                    // Still not there, timeout
                    return Ok(DaResult::Timeout);
                }
            }
        }

        // Wait for result
        match tokio::time::timeout(self.config.fetch_timeout, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Ok(DaResult::Unreachable),
            Err(_) => Ok(DaResult::Timeout),
        }
    }

    /// Cleanup expired pending request
    async fn cleanup_pending(&self, payload_hash: Hash32) {
        let mut pending = self.pending.lock().await;
        pending.remove(&payload_hash);
    }

    /// Periodic cleanup of stale requests
    ///
    /// Call this periodically (e.g., every 10s) to prevent memory leaks
    pub async fn cleanup_stale(&self) {
        let mut pending = self.pending.lock().await;
        let now = Instant::now();
        pending.retain(|_, req| {
            // Keep requests younger than 2x timeout
            now.duration_since(req.requested_at) < req.timeout * 2
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaGatingError {
    #[error("storage error: {0}")]
    StorageError(String),
    #[error("fetch error: {0}")]
    FetchError(String),
    #[error("too many pending requests")]
    TooManyPending,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_gating::fetcher::MockFetcher;
    use crate::da_gating::storage::InMemoryStorage;
    use std::error::Error;

    fn mk_payload(id: u8) -> AnchorPayload {
        use pc_types::MicroTx;
        AnchorPayload {
            version: 3,
            micro_txs: vec![MicroTx {
                version: 1,
                inputs: vec![],
                outputs: vec![],
            }],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [id; 32],
            genesis_note: None,
            null_mint: false,
        }
    }

    #[tokio::test]
    async fn available_fast_path() -> Result<(), Box<dyn Error + Send + Sync>> {
        let storage = Arc::new(InMemoryStorage::new());
        let fetcher = Arc::new(MockFetcher::new());
        let mgr = DaGatingManager::new(storage.clone(), fetcher.clone(), DaGatingConfig::default());

        let payload = mk_payload(7);
        let h = payload_merkle_root_v3(&payload);
        storage.put(&h, &payload).await?;

        let res = mgr.ensure_data_available(h).await?;
        match res {
            DaResult::Available(data) => assert!(!data.is_empty()),
            other => return Err(format!("expected Available, got {other:?}").into()),
        }
        assert_eq!(fetcher.request_count().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn pending_dedup_attaches_waiters() -> Result<(), Box<dyn Error + Send + Sync>> {
        let storage = Arc::new(InMemoryStorage::new());
        let fetcher = Arc::new(MockFetcher::new());
        let mgr = Arc::new(DaGatingManager::new(
            storage.clone(),
            fetcher.clone(),
            DaGatingConfig {
                fetch_timeout: Duration::from_millis(200),
                ..DaGatingConfig::default()
            },
        ));

        let payload = mk_payload(9);
        let h = payload_merkle_root_v3(&payload);

        let mgr1 = mgr.clone();
        let mgr2 = mgr.clone();

        let t1 = tokio::spawn(async move { mgr1.ensure_data_available(h).await });
        let t2 = tokio::spawn(async move { mgr2.ensure_data_available(h).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        mgr.handle_payload_response(payload).await?;

        let r1 = t1.await??;
        let r2 = t2.await??;
        let d1 = match r1 {
            DaResult::Available(v) => v,
            other => return Err(format!("expected Available, got {other:?}").into()),
        };
        let d2 = match r2 {
            DaResult::Available(v) => v,
            other => return Err(format!("expected Available, got {other:?}").into()),
        };
        assert!(!d1.is_empty());
        assert_eq!(d1, d2);
        assert_eq!(fetcher.request_count().await, 1);
        Ok(())
    }

    #[tokio::test]
    async fn unsolicited_payload_response_is_ignored() -> Result<(), Box<dyn Error + Send + Sync>> {
        let storage = Arc::new(InMemoryStorage::new());
        let fetcher = Arc::new(MockFetcher::new());
        let mgr = DaGatingManager::new(
            storage.clone(),
            fetcher,
            DaGatingConfig {
                fetch_timeout: Duration::from_millis(25),
                ..DaGatingConfig::default()
            },
        );

        let payload = mk_payload(42);
        mgr.handle_payload_response(payload).await?;
        assert_eq!(storage.size().await, 0);

        Ok(())
    }
}
