// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Fetcher Interface for DA Gating
//!
//! Provides pluggable fetcher backend for requesting payloads from network.

use async_trait::async_trait;
use pc_crypto::Hash32;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Fetcher interface trait
#[async_trait]
pub trait FetcherInterface: Send + Sync + 'static {
    /// Request single payload from network
    async fn request_payload(&self, payload_hash: Hash32) -> Result<(), FetcherError>;

    /// Request multiple payloads from network
    async fn request_payloads(&self, payload_hashes: Vec<Hash32>) -> Result<(), FetcherError>;

    /// Check if request is currently pending
    async fn is_pending(&self, payload_hash: &Hash32) -> bool;
}

/// Fetcher errors
#[derive(Debug, thiserror::Error)]
pub enum FetcherError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Timeout")]
    Timeout,
}

/// Mock fetcher for testing
pub struct MockFetcher {
    pending: Arc<Mutex<HashSet<Hash32>>>,
    request_count: Arc<Mutex<u32>>,
}

impl MockFetcher {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashSet::new())),
            request_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Get number of requests made
    pub async fn request_count(&self) -> u32 {
        let count = self.request_count.lock().await;
        *count
    }

    /// Reset request counter
    pub async fn reset_counter(&self) {
        let mut count = self.request_count.lock().await;
        *count = 0;
    }
}

impl Default for MockFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FetcherInterface for MockFetcher {
    async fn request_payload(&self, payload_hash: Hash32) -> Result<(), FetcherError> {
        let mut pending = self.pending.lock().await;
        if pending.contains(&payload_hash) {
            return Ok(()); // Already requested (deduplication)
        }

        pending.insert(payload_hash);

        // Increment counter
        let mut count = self.request_count.lock().await;
        *count += 1;

        Ok(())
    }

    async fn request_payloads(&self, payload_hashes: Vec<Hash32>) -> Result<(), FetcherError> {
        let mut pending = self.pending.lock().await;

        let new_hashes: Vec<Hash32> = payload_hashes
            .into_iter()
            .filter(|h| !pending.contains(h))
            .collect();

        for h in &new_hashes {
            pending.insert(*h);
        }

        if !new_hashes.is_empty() {
            // Increment counter once for batch
            let mut count = self.request_count.lock().await;
            *count += 1;
        }

        Ok(())
    }

    async fn is_pending(&self, payload_hash: &Hash32) -> bool {
        let pending = self.pending.lock().await;
        pending.contains(payload_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetcher_deduplicates_requests() -> Result<(), FetcherError> {
        let fetcher = MockFetcher::new();

        let hash = [1u8; 32];

        // First request
        fetcher.request_payload(hash).await?;
        assert_eq!(fetcher.request_count().await, 1);

        // Second request (should be deduplicated)
        fetcher.request_payload(hash).await?;
        assert_eq!(fetcher.request_count().await, 1); // Still 1

        // Different hash
        fetcher.request_payload([2u8; 32]).await?;
        assert_eq!(fetcher.request_count().await, 2);
        Ok(())
    }

    #[tokio::test]
    async fn fetcher_batch_request() -> Result<(), FetcherError> {
        let fetcher = MockFetcher::new();

        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        fetcher.request_payloads(hashes.clone()).await?;
        assert_eq!(fetcher.request_count().await, 1); // One batch request

        // All should be marked as pending
        for hash in &hashes {
            assert!(fetcher.is_pending(hash).await);
        }

        // Requesting again should not increment counter
        fetcher.request_payloads(hashes).await?;
        assert_eq!(fetcher.request_count().await, 1); // Still 1
        Ok(())
    }

    #[tokio::test]
    async fn fetcher_is_pending() -> Result<(), FetcherError> {
        let fetcher = MockFetcher::new();

        let hash = [5u8; 32];

        assert!(!fetcher.is_pending(&hash).await);

        fetcher.request_payload(hash).await?;

        assert!(fetcher.is_pending(&hash).await);
        Ok(())
    }

    #[tokio::test]
    async fn fetcher_reset_counter() -> Result<(), FetcherError> {
        let fetcher = MockFetcher::new();

        fetcher.request_payload([1u8; 32]).await?;
        fetcher.request_payload([2u8; 32]).await?;
        assert_eq!(fetcher.request_count().await, 2);

        fetcher.reset_counter().await;
        assert_eq!(fetcher.request_count().await, 0);
        Ok(())
    }
}
