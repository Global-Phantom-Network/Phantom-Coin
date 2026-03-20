// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Storage Interface for DA Gating
//!
//! Provides pluggable storage backend for payload persistence.

use async_trait::async_trait;
use pc_codec::Encodable as _;
use pc_crypto::Hash32;
use pc_types::AnchorPayloadV3 as AnchorPayload;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Storage interface trait
#[async_trait]
pub trait StorageInterface: Send + Sync + 'static {
    /// Get payload by hash
    async fn get(&self, payload_hash: &Hash32) -> Result<Option<Vec<u8>>, StorageError>;

    /// Store payload
    async fn put(&self, payload_hash: &Hash32, payload: &AnchorPayload)
        -> Result<(), StorageError>;

    /// Delete payload
    async fn delete(&self, payload_hash: &Hash32) -> Result<(), StorageError>;

    /// List all stored payload hashes
    async fn list(&self) -> Result<Vec<Hash32>, StorageError>;
}

/// Storage errors
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Not found")]
    NotFound,
}

/// In-memory storage implementation (for testing and small deployments)
pub struct InMemoryStorage {
    store: Arc<Mutex<HashMap<Hash32, Vec<u8>>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get current storage size
    pub async fn size(&self) -> usize {
        let store = self.store.lock().await;
        store.len()
    }

    /// Clear all stored data
    pub async fn clear(&self) {
        let mut store = self.store.lock().await;
        store.clear();
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageInterface for InMemoryStorage {
    async fn get(&self, payload_hash: &Hash32) -> Result<Option<Vec<u8>>, StorageError> {
        let store = self.store.lock().await;
        Ok(store.get(payload_hash).cloned())
    }

    async fn put(
        &self,
        payload_hash: &Hash32,
        payload: &AnchorPayload,
    ) -> Result<(), StorageError> {
        let mut data: Vec<u8> = Vec::with_capacity(payload.encoded_len());
        payload
            .encode(&mut data)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let mut store = self.store.lock().await;
        store.insert(*payload_hash, data);
        Ok(())
    }

    async fn delete(&self, payload_hash: &Hash32) -> Result<(), StorageError> {
        let mut store = self.store.lock().await;
        store.remove(payload_hash);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Hash32>, StorageError> {
        let store = self.store.lock().await;
        Ok(store.keys().copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_payload() -> AnchorPayload {
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
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        }
    }

    #[tokio::test]
    async fn storage_put_get_roundtrip() -> Result<(), StorageError> {
        let storage = InMemoryStorage::new();
        let payload = create_test_payload();
        let hash = [1u8; 32];

        // Put payload
        storage.put(&hash, &payload).await?;

        // Get payload
        let retrieved = storage.get(&hash).await?;
        let data = match retrieved {
            Some(v) => v,
            None => return Err(StorageError::NotFound),
        };
        // Data is present (format doesn't matter for DA gating logic)
        assert!(!data.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn storage_delete_removes_entry() -> Result<(), StorageError> {
        let storage = InMemoryStorage::new();
        let payload = create_test_payload();
        let hash = [2u8; 32];

        // Put and verify
        storage.put(&hash, &payload).await?;
        assert!(storage.get(&hash).await?.is_some());

        // Delete
        storage.delete(&hash).await?;
        assert!(storage.get(&hash).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn storage_list_returns_all_keys() -> Result<(), StorageError> {
        let storage = InMemoryStorage::new();

        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        for hash in &hashes {
            let payload = create_test_payload();
            storage.put(hash, &payload).await?;
        }

        let listed = storage.list().await?;
        assert_eq!(listed.len(), 3);

        for hash in &hashes {
            assert!(listed.contains(hash));
        }
        Ok(())
    }

    #[tokio::test]
    async fn storage_size_tracking() -> Result<(), StorageError> {
        let storage = InMemoryStorage::new();
        assert_eq!(storage.size().await, 0);

        let payload = create_test_payload();
        storage.put(&[1u8; 32], &payload).await?;
        assert_eq!(storage.size().await, 1);

        storage.put(&[2u8; 32], &payload).await?;
        assert_eq!(storage.size().await, 2);

        storage.delete(&[1u8; 32]).await?;
        assert_eq!(storage.size().await, 1);

        storage.clear().await;
        assert_eq!(storage.size().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn storage_get_nonexistent_returns_none() -> Result<(), StorageError> {
        let storage = InMemoryStorage::new();
        let hash = [99u8; 32];

        let result = storage.get(&hash).await?;
        assert!(result.is_none());
        Ok(())
    }
}
