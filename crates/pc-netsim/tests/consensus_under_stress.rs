// SPDX-License-Identifier: AGPL-3.0-only

//! Consensus tests under various network conditions

use pc_netsim::{NetworkCondition, SimNode};

#[tokio::test]
async fn consensus_under_packet_loss_5pct() {
    // Simulate 3 nodes with 5% packet loss
    let nodes = vec![
        SimNode::new(1, NetworkCondition::poor()),
        SimNode::new(2, NetworkCondition::poor()),
        SimNode::new(3, NetworkCondition::poor()),
    ];

    // Simulate message exchange
    let mut successful = 0;
    let mut failed = 0;

    for _ in 0..100 {
        for node in &nodes {
            match node.send_message(b"vote").await {
                Ok(_) => successful += 1,
                Err(_) => failed += 1,
            }
        }
    }

    // With 5% loss, we expect ~95% success rate
    let success_rate = successful as f64 / (successful + failed) as f64;
    assert!(
        success_rate >= 0.90,
        "Success rate {} too low",
        success_rate
    );
    assert!(
        success_rate <= 1.00,
        "Success rate {} too high",
        success_rate
    );
}

#[tokio::test]
async fn consensus_under_packet_loss_20pct() {
    // Simulate 3 nodes with 25% packet loss (terrible network)
    let nodes = vec![
        SimNode::new(1, NetworkCondition::terrible()),
        SimNode::new(2, NetworkCondition::terrible()),
        SimNode::new(3, NetworkCondition::terrible()),
    ];

    let mut successful = 0;
    let mut failed = 0;

    for _ in 0..100 {
        for node in &nodes {
            match node.send_message(b"vote").await {
                Ok(_) => successful += 1,
                Err(_) => failed += 1,
            }
        }
    }

    // With 25% loss, we expect ~75% success rate
    let success_rate = successful as f64 / (successful + failed) as f64;
    assert!(
        success_rate >= 0.60,
        "Success rate {} too low",
        success_rate
    );
    assert!(
        success_rate <= 0.85,
        "Success rate {} too high",
        success_rate
    );
}

#[tokio::test]
async fn finality_with_network_delay() {
    use std::time::Instant;

    // Simulate node with 200ms delay
    let node = SimNode::new(1, NetworkCondition::terrible());

    let mut attempts = 0u32;
    let max_attempts = 50u32;
    loop {
        attempts += 1;
        let start = Instant::now();
        match node.send_message(b"anchor").await {
            Ok(_) => {
                let elapsed = start.elapsed();
                assert!(elapsed >= std::time::Duration::from_millis(200));
                assert!(elapsed <= std::time::Duration::from_millis(1500));
                break;
            }
            Err(_) if attempts < max_attempts => continue,
            Err(e) => panic!("message repeatedly dropped under terrible network: {:?}", e),
        }
    }
}

#[tokio::test]
async fn partition_recovery_test() {
    // Start with partitioned network
    let mut node = SimNode::new(1, NetworkCondition::partitioned());

    // All messages should fail
    for _ in 0..10 {
        let result = node.send_message(b"test").await;
        assert!(
            result.is_err(),
            "Message should fail in partitioned network"
        );
    }

    // Recover from partition
    node.condition = NetworkCondition::perfect();

    // Messages should succeed now
    for _ in 0..10 {
        let result = node.send_message(b"test").await;
        assert!(
            result.is_ok(),
            "Message should succeed after partition recovery"
        );
    }
}

#[tokio::test]
async fn realistic_network_stress_test() {
    // Simulate 5 nodes with realistic network conditions
    let nodes: Vec<_> = (0..5)
        .map(|i| SimNode::new(i, NetworkCondition::realistic()))
        .collect();

    let mut total_sent = 0;
    let mut total_success = 0;

    // Simulate 1000 messages across all nodes
    for _ in 0..200 {
        for node in &nodes {
            total_sent += 1;
            if node.send_message(b"message").await.is_ok() {
                total_success += 1;
            }
        }
    }

    // With 1% packet loss, expect ~99% success
    let success_rate = total_success as f64 / total_sent as f64;
    assert!(
        success_rate >= 0.95,
        "Success rate too low: {}",
        success_rate
    );
}
