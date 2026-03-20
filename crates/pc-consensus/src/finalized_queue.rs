// SPDX-License-Identifier: AGPL-3.0-only
//! Deterministic total-order queue for finalized payloads.
//!
//! Entries are sorted by `(vote_epoch, shard_id, header_hash)`.
//! `pop_next(num_shards)` releases entries epoch by epoch:
//! - Single-shard (`num_shards <= 1`): releases entries in sorted order.
//! - Multi-shard: waits until all shards `0..num_shards` have at least one
//!   entry for the lowest pending epoch before releasing.

use std::collections::{BTreeMap, HashMap, HashSet};

/// Composite key for deterministic ordering.
type OrdKey = (u64, u16, [u8; 32]);

#[derive(Debug)]
pub struct FinalizedQueue<T> {
    pending: BTreeMap<OrdKey, T>,
    epoch_shards: HashMap<u64, HashSet<u16>>,
}

impl<T> Default for FinalizedQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FinalizedQueue<T> {
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            epoch_shards: HashMap::new(),
        }
    }

    /// Insert an entry into the queue.
    pub fn insert(&mut self, epoch: u64, shard_id: u16, key: [u8; 32], value: T) {
        self.pending.insert((epoch, shard_id, key), value);
        self.epoch_shards.entry(epoch).or_default().insert(shard_id);
    }

    /// Pop the next entry in deterministic order, if its epoch is ready.
    ///
    /// `get_num_shards_for_epoch` is a closure that returns the expected number of shards for a given epoch.
    /// An epoch is ready when:
    /// - `num_shards <= 1`: always (entries released in sorted order)
    /// - `num_shards > 1`: all shards `0..num_shards` have at least one entry
    pub fn pop_next<F>(&mut self, get_num_shards_for_epoch: F) -> Option<(u64, u16, [u8; 32], T)>
    where
        F: Fn(u64) -> u16,
    {
        let &(epoch, _, _) = self.pending.keys().next()?;
        let num_shards = get_num_shards_for_epoch(epoch);

        if num_shards > 1 {
            let seen = self.epoch_shards.get(&epoch).map_or(0, |s| s.len());
            if seen < num_shards as usize {
                return None;
            }
        }

        let ((e, s, k), v) = self.pending.pop_first()?;

        // Clean up epoch tracking if this was the last entry for the epoch.
        if !self
            .pending
            .keys()
            .next()
            .is_some_and(|&(ne, _, _)| ne == e)
        {
            self.epoch_shards.remove(&e);
        }

        Some((e, s, k, v))
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_shard_releases_in_epoch_order() {
        let mut q: FinalizedQueue<&str> = FinalizedQueue::new();
        // Insert out of order: epoch 3 before epoch 1
        q.insert(3, 0, [0x33; 32], "e3");
        q.insert(1, 0, [0x11; 32], "e1");
        q.insert(2, 0, [0x22; 32], "e2");

        let (e, _, _, v) = q.pop_next(|_| 1).unwrap();
        assert_eq!((e, v), (1, "e1"));
        let (e, _, _, v) = q.pop_next(|_| 1).unwrap();
        assert_eq!((e, v), (2, "e2"));
        let (e, _, _, v) = q.pop_next(|_| 1).unwrap();
        assert_eq!((e, v), (3, "e3"));
        assert!(q.pop_next(|_| 1).is_none());
    }

    #[test]
    fn same_epoch_sorted_by_shard_then_hash() {
        let mut q: FinalizedQueue<u8> = FinalizedQueue::new();
        q.insert(1, 1, [0xBB; 32], 2);
        q.insert(1, 0, [0xAA; 32], 1);
        q.insert(1, 0, [0xCC; 32], 3);

        let (_, s0, k0, _) = q.pop_next(|_| 1).unwrap();
        assert_eq!(s0, 0);
        assert_eq!(k0, [0xAA; 32]);

        let (_, s1, k1, _) = q.pop_next(|_| 1).unwrap();
        assert_eq!(s1, 0);
        assert_eq!(k1, [0xCC; 32]);

        let (_, s2, _, _) = q.pop_next(|_| 1).unwrap();
        assert_eq!(s2, 1);

        assert!(q.pop_next(|_| 1).is_none());
    }

    #[test]
    fn multi_shard_blocks_until_all_shards_present() {
        let mut q: FinalizedQueue<&str> = FinalizedQueue::new();
        // 2 shards, only shard 0 reported for epoch 1
        q.insert(1, 0, [0x11; 32], "s0e1");

        // Should block: shard 1 missing for epoch 1
        assert!(q.pop_next(|_| 2).is_none());

        // Add shard 1
        q.insert(1, 1, [0x22; 32], "s1e1");

        // Now both shards present, should release in order
        let (e, s, _, v) = q.pop_next(|_| 2).unwrap();
        assert_eq!((e, s, v), (1, 0, "s0e1"));
        let (e, s, _, v) = q.pop_next(|_| 2).unwrap();
        assert_eq!((e, s, v), (1, 1, "s1e1"));
        assert!(q.pop_next(|_| 2).is_none());
    }

    #[test]
    fn multi_shard_does_not_release_later_epoch_early() {
        let mut q: FinalizedQueue<&str> = FinalizedQueue::new();
        // Epoch 2 complete (both shards), epoch 1 incomplete
        q.insert(2, 0, [0xA0; 32], "s0e2");
        q.insert(2, 1, [0xA1; 32], "s1e2");
        q.insert(1, 0, [0xB0; 32], "s0e1");
        // Epoch 1 only has shard 0 → blocked (epoch 1 is lowest)
        assert!(q.pop_next(|_| 2).is_none());

        // Complete epoch 1
        q.insert(1, 1, [0xB1; 32], "s1e1");

        // Now epoch 1 is ready, releases first
        let (e, s, _, _) = q.pop_next(|_| 2).unwrap();
        assert_eq!((e, s), (1, 0));
        let (e, s, _, _) = q.pop_next(|_| 2).unwrap();
        assert_eq!((e, s), (1, 1));
        // Now epoch 2 is the lowest and it's complete
        let (e, s, _, _) = q.pop_next(|_| 2).unwrap();
        assert_eq!((e, s), (2, 0));
        let (e, s, _, _) = q.pop_next(|_| 2).unwrap();
        assert_eq!((e, s), (2, 1));
        assert!(q.pop_next(|_| 2).is_none());
    }

    #[test]
    fn empty_queue_returns_none() {
        let mut q: FinalizedQueue<()> = FinalizedQueue::new();
        assert!(q.pop_next(|_| 1).is_none());
        assert!(q.pop_next(|_| 4).is_none());
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
    }

    #[test]
    fn determinism_different_insert_order() {
        // Same entries, different insert order → same pop order
        let entries = vec![
            (2u64, 1u16, [0xDD; 32], "a"),
            (1, 0, [0xAA; 32], "b"),
            (2, 0, [0xCC; 32], "c"),
            (1, 0, [0xBB; 32], "d"),
        ];
        let reversed: Vec<_> = entries.iter().rev().cloned().collect();

        let mut q1: FinalizedQueue<&str> = FinalizedQueue::new();
        for (e, s, k, v) in &entries {
            q1.insert(*e, *s, *k, v);
        }
        let mut q2: FinalizedQueue<&str> = FinalizedQueue::new();
        for (e, s, k, v) in &reversed {
            q2.insert(*e, *s, *k, v);
        }

        let mut out1 = Vec::new();
        while let Some(x) = q1.pop_next(|_| 1) {
            out1.push((x.0, x.1, x.2));
        }
        let mut out2 = Vec::new();
        while let Some(x) = q2.pop_next(|_| 1) {
            out2.push((x.0, x.1, x.2));
        }
        assert_eq!(out1, out2);
    }
}
