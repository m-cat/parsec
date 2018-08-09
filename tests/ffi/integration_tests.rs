// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/parsec"
)]
#![forbid(
    exceeding_bitshifts, mutable_transmutes, no_mangle_const_items, unknown_crate_types, warnings
)]
#![deny(
    bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
    overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
    stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused_allocation,
    unused_attributes, unused_comparisons, unused_features, unused_parens, while_true
)]
#![warn(
    trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
    unused_qualifications, unused_results
)]
#![allow(
    box_pointers, missing_copy_implementations, missing_debug_implementations,
    variant_size_differences
)]

extern crate maidsafe_utilities;
extern crate parsec;
extern crate rand;
#[macro_use]
extern crate unwrap;

mod utils;

use self::utils::{
    Environment, Schedule, PeerCount, TransactionCount, ScheduleOptions,
};

// Alter the seed here to reproduce failures
static SEED: Option<[u32; 4]> = None;

#[test]
fn ffi_minimal_network() {
    // 4 is the minimal network size for which the super majority is less than it.
    let num_peers = 4;
    let mut env = Environment::new(&PeerCount(num_peers), &TransactionCount(1), SEED);

    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            votes_before_gossip: true,
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_multiple_votes_before_gossip() {
    let num_transactions = 10;
    let mut env = Environment::new(&PeerCount(4), &TransactionCount(num_transactions), SEED);

    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            votes_before_gossip: true,
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_multiple_votes_during_gossip() {
    let num_transactions = 10;
    let mut env = Environment::new(&PeerCount(4), &TransactionCount(num_transactions), SEED);

    let schedule = Schedule::new(&mut env, &Default::default());
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_duplicate_votes_before_gossip() {
    let mut env = Environment::new(&PeerCount(4), &TransactionCount(1), SEED);

    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            votes_before_gossip: true,
            prob_vote_duplication: 0.5,
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_faulty_third_never_gossip() {
    let num_peers = 10;
    let num_transactions = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(
        &PeerCount(num_peers),
        &TransactionCount(num_transactions),
        SEED,
    );

    let mut failures = BTreeMap::new();
    let _ = failures.insert(0, num_faulty);
    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            deterministic_failures: failures,
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_faulty_third_terminate_concurrently() {
    let num_peers = 10;
    let num_transactions = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(
        &PeerCount(num_peers),
        &TransactionCount(num_transactions),
        SEED,
    );

    let mut failures = BTreeMap::new();
    let _ = failures.insert(env.rng.gen_range(10, 50), num_faulty);
    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            deterministic_failures: failures,
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_faulty_nodes_terminate_at_random_points() {
    let num_peers = 10;
    let num_transactions = 10;
    let prob_failure = 0.05;
    let mut env = Environment::new(
        &PeerCount(num_peers),
        &TransactionCount(num_transactions),
        SEED,
    );
    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            prob_failure,
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_random_schedule_no_delays() {
    let num_transactions = 10;
    let mut env = Environment::new(&PeerCount(4), &TransactionCount(num_transactions), SEED);
    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            delay_distr: DelayDistribution::Constant(0),
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn ffi_random_schedule_probabilistic_gossip() {
    let num_transactions = 10;
    let mut env = Environment::new(&PeerCount(4), &TransactionCount(num_transactions), SEED);
    let schedule = Schedule::new(
        &mut env,
        &ScheduleOptions {
            gossip_strategy: GossipStrategy::Probabilistic(0.8),
            ..Default::default()
        },
    );
    env.network.execute_schedule(schedule);

    let result = env.network.blocks_all_in_sequence();
    assert!(result.is_ok(), "{:?}", result);
}
