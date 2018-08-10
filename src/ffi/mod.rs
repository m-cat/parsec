// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! FFI.
//!
//! # Memory checking
//!
//! Below we have documented some of the ways in which the FFI module is checked for memory leaks or
//! other memory errors:
//!
//! ## Procinfo (Linux only)
//!
//! Our smoke tests measure memory both before and after each test and will print a warning if
//! memory grew, which could indicate a memory leak. The tests must be run with `--nocapture` to
//! print output and `--test-threads=1` for accurate results. As Procinfo is a Linux-only crate, we
//! only measure memory when testing on Linux.
//!
//! ## Running sanitizers (requires nightly)
//!
//! You can run several different sanitizers using variations of the following command:
//!
//! ```text
//! RUSTFLAGS="-Z sanitizer=address" cargo test ffi --target x86_64-apple-darwin -- --nocapture
//! ```
//!
//! Possible targets are limited to:
//!
//! * x86_64-unknown-linux-gnu: supports the `address`, `leak`, `memory`, and `thread` sanitizers.
//! * x86_64-apple-darwin: supports the `address` and `thread` sanitizers.
//!
//! More information can be found at https://github.com/japaric/rust-san.
//!
//! ## Checking for memory leaks (requires nightly)
//!
//! You can check for memory leaks using Valgrind. Make sure you have it installed on your system.
//!
//! First, you will need to set the global allocator:
//!
//! ```ignore
//! #![feature(global_allocator)]
//! #![feature(allocator_api)]
//!
//! use std::alloc::System;
//!
//! #[global_allocator]
//! static GLOBAL: System = System;
//! ```
//!
//! Build the example:
//!
//! ```text
//! cargo test ffi --no-run
//! ```
//!
//! Then run valgrind:
//!
//! ```text
//! valgrind --leak-check=full target/debug/<executable>
//! ```
//!
//! You should see a leak summary. The fields that concern us are "definitely lost" and "indirectly
//! lost": these should be 0. The other fields can likely be ignored -- "possibly lost" seems to
//! always report some bytes.

#![allow(unsafe_code)]

#[macro_use]
pub mod utils;

/// Functions defining blocks API.
pub mod block;
/// Functions for getting and clearing FFI errors.
pub mod error;
/// Functions defining public and private identity traits and objects.
pub mod id;
/// Message objects.
pub mod message;
/// Functions defining public interface for core Parsec functions.
pub mod parsec;
/// Functions defining votes API.
pub mod vote;

use mock;
use network_event::NetworkEvent as NetEvent;

pub(crate) type NetworkEvent = Vec<u8>;
pub(crate) type PeerId = mock::PeerId;

impl NetEvent for Vec<u8> {}

pub use ffi::block::*;
pub use ffi::error::*;
pub use ffi::id::*;
pub use ffi::message::*;
pub use ffi::parsec::*;
pub use ffi::vote::*;
