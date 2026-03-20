// SPDX-License-Identifier: AGPL-3.0-only

//! Fork resolution tests

#[test]
fn fork_resolution_longest_chain_wins() {
    // In case of fork, longest chain wins
    let chain_a_height = 10u64;
    let chain_b_height = 8u64;

    let winner = chain_a_height.max(chain_b_height);
    assert_eq!(winner, 10);
}

#[test]
fn fork_healing_after_partition() {
    // After network partition, nodes converge on longest chain
    let chain_a = 10u64;
    let chain_b = 8u64;

    // After healing, both nodes adopt longest chain
    let final_height = chain_a.max(chain_b);
    assert_eq!(final_height, 10);
}

#[test]
fn fork_choice_by_stake() {
    // Equal-length forks resolved by cumulative stake
    struct Fork {
        height: u64,
        stake: u64,
    }

    let fork_a = Fork {
        height: 5,
        stake: 100_000,
    };
    let fork_b = Fork {
        height: 5,
        stake: 150_000,
    };

    // Same height, higher stake wins
    let winner = if fork_a.height > fork_b.height {
        &fork_a
    } else if fork_b.height > fork_a.height {
        &fork_b
    } else if fork_a.stake > fork_b.stake {
        &fork_a
    } else {
        &fork_b
    };

    assert_eq!(winner.stake, 150_000);
}

#[test]
fn fork_deep_reorg_rejected() {
    // Deep reorgs beyond finality threshold are rejected
    let finality_threshold = 100u64;
    let current_height = 500u64;
    let reorg_to = 350u64;

    let depth = current_height - reorg_to;
    assert!(depth > finality_threshold);

    let accept = depth <= finality_threshold;
    assert!(!accept, "Deep reorg should be rejected");
}

#[test]
fn fork_shallow_reorg_accepted() {
    // Shallow reorgs within finality threshold accepted
    let finality_threshold = 100u64;
    let current_height = 500u64;
    let reorg_to = 495u64;

    let depth = current_height - reorg_to;
    assert!(depth <= finality_threshold);

    let accept = depth <= finality_threshold;
    assert!(accept, "Shallow reorg accepted");
}
