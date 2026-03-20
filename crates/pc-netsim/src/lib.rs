// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Network Simulation Framework for Phantom Coin
//!
//! Provides tools to simulate network conditions for testing:
//! - Packet loss
//! - Network delay
//! - Bandwidth limits
//! - Network partitions
//! - Byzantine nodes

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::Mutex;
use std::time::Duration;

/// Network condition configuration
#[derive(Debug, Clone)]
pub struct NetworkCondition {
    /// Packet loss rate (0.0 = no loss, 1.0 = 100% loss)
    pub packet_loss_rate: f64,
    /// Network delay (min, max)
    pub delay_range: (Duration, Duration),
    /// Bandwidth limit in bytes/sec (None = unlimited)
    pub bandwidth_limit: Option<usize>,
    /// Simulate partitioned network
    pub partition: bool,
}

impl NetworkCondition {
    /// No network issues (perfect conditions)
    pub fn perfect() -> Self {
        Self {
            packet_loss_rate: 0.0,
            delay_range: (Duration::from_millis(0), Duration::from_millis(0)),
            bandwidth_limit: None,
            partition: false,
        }
    }

    /// Realistic internet conditions (1% loss, 10-50ms delay)
    pub fn realistic() -> Self {
        Self {
            packet_loss_rate: 0.01,
            delay_range: (Duration::from_millis(10), Duration::from_millis(50)),
            bandwidth_limit: Some(10_000_000), // 10 MB/s
            partition: false,
        }
    }

    /// Poor network (5% loss, 50-200ms delay)
    pub fn poor() -> Self {
        Self {
            packet_loss_rate: 0.05,
            delay_range: (Duration::from_millis(50), Duration::from_millis(200)),
            bandwidth_limit: Some(1_000_000), // 1 MB/s
            partition: false,
        }
    }

    /// Terrible network (25% loss, 200-1000ms delay)
    pub fn terrible() -> Self {
        Self {
            packet_loss_rate: 0.25,
            delay_range: (Duration::from_millis(200), Duration::from_millis(1000)),
            bandwidth_limit: Some(100_000), // 100 KB/s
            partition: false,
        }
    }

    /// Network partition (100% packet loss)
    pub fn partitioned() -> Self {
        Self {
            packet_loss_rate: 1.0,
            delay_range: (Duration::from_secs(0), Duration::from_secs(0)),
            bandwidth_limit: None,
            partition: true,
        }
    }

    /// Check if message should be dropped
    pub fn should_drop_packet(&self) -> bool {
        let mut rng = rand::thread_rng();
        self.should_drop_packet_with_rng(&mut rng)
    }

    /// Get random delay
    pub fn get_delay(&self) -> Duration {
        let mut rng = rand::thread_rng();
        self.get_delay_with_rng(&mut rng)
    }

    fn should_drop_packet_with_rng<R: Rng + ?Sized>(&self, rng: &mut R) -> bool {
        rng.gen::<f64>() < self.packet_loss_rate
    }

    fn get_delay_with_rng<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        let min_ms = self.delay_range.0.as_millis() as u64;
        let max_ms = self.delay_range.1.as_millis() as u64;

        if min_ms == max_ms {
            return Duration::from_millis(min_ms);
        }

        let delay_ms = rng.gen_range(min_ms..=max_ms);
        Duration::from_millis(delay_ms)
    }
}

/// Simulated network node
#[derive(Debug)]
pub struct SimNode {
    pub id: u32,
    pub condition: NetworkCondition,
    rng: Mutex<StdRng>,
}

impl SimNode {
    pub fn new(id: u32, condition: NetworkCondition) -> Self {
        let seed: u64 = rand::thread_rng().gen();
        Self::new_with_seed(id, condition, seed)
    }

    pub fn new_with_seed(id: u32, condition: NetworkCondition, seed: u64) -> Self {
        Self {
            id,
            condition,
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
        }
    }

    /// Simulate sending a message
    pub async fn send_message(&self, _data: &[u8]) -> Result<(), SimError> {
        // Do not hold the RNG lock across await points.
        let (should_drop, delay) = {
            let mut rng = self
                .rng
                .lock()
                .map_err(|_| SimError::Internal("rng mutex poisoned"))?;
            let should_drop = self.condition.should_drop_packet_with_rng(&mut *rng);
            let delay = self.condition.get_delay_with_rng(&mut *rng);
            (should_drop, delay)
        };

        // Check packet loss
        if should_drop {
            return Err(SimError::PacketLost);
        }

        // Simulate delay
        if delay > Duration::from_millis(0) {
            tokio::time::sleep(delay).await;
        }

        Ok(())
    }
}

/// Network simulation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimError {
    PacketLost,
    Timeout,
    Partitioned,
    BandwidthExceeded,
    Internal(&'static str),
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketLost => write!(f, "packet lost"),
            Self::Timeout => write!(f, "timeout"),
            Self::Partitioned => write!(f, "network partitioned"),
            Self::BandwidthExceeded => write!(f, "bandwidth limit exceeded"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for SimError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_with_fixed_seed() {
        let cond = NetworkCondition::realistic();
        let mut rng1 = StdRng::seed_from_u64(123);
        let mut rng2 = StdRng::seed_from_u64(123);
        for _ in 0..1000 {
            assert_eq!(
                cond.should_drop_packet_with_rng(&mut rng1),
                cond.should_drop_packet_with_rng(&mut rng2)
            );
            assert_eq!(
                cond.get_delay_with_rng(&mut rng1),
                cond.get_delay_with_rng(&mut rng2)
            );
        }
    }

    #[test]
    fn network_condition_perfect() {
        let cond = NetworkCondition::perfect();
        assert_eq!(cond.packet_loss_rate, 0.0);
        assert!(!cond.should_drop_packet());
    }

    #[test]
    fn network_condition_partitioned() {
        let cond = NetworkCondition::partitioned();
        assert_eq!(cond.packet_loss_rate, 1.0);
        assert!(cond.should_drop_packet());
        assert!(cond.partition);
    }

    #[test]
    fn network_condition_delay_range() {
        let cond = NetworkCondition::poor();
        let delay = cond.get_delay();
        assert!(delay >= Duration::from_millis(50));
        assert!(delay <= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn sim_node_send_perfect() {
        let node = SimNode::new(1, NetworkCondition::perfect());
        let result = node.send_message(b"test").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn sim_node_send_partitioned() {
        let node = SimNode::new(1, NetworkCondition::partitioned());
        let result = node.send_message(b"test").await;
        assert!(matches!(result, Err(SimError::PacketLost)));
    }
}
