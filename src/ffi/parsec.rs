// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use ffi::message::{Request, Response};
use ffi::utils;
use ffi::{Block, NetworkEvent, PeerId, PublicId, SecretId};
use parsec::Parsec as NativeParsec;
use std::collections::BTreeSet;
use std::{ptr, slice};

/// Serves as an opaque pointer to `Parsec` struct.
///
/// Should be deallocated with `parsec_free`.
pub struct Parsec(NativeParsec<NetworkEvent, PeerId>);

/// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
/// You should initialise these IDs through functions like `public_id_from_bytes`.
/// Returns an opaque pointer to the `Parsec` structure.
///
/// `o_parsec` must be freed using `parsec_free`.
#[no_mangle]
pub unsafe extern "C" fn parsec_new(
    our_id: *const SecretId,
    genesis_group: *const *const PublicId,
    genesis_group_len: usize,
    o_parsec: *mut *mut Parsec,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let genesis_vec = slice::from_raw_parts(genesis_group, genesis_group_len);
        let genesis_group_set: BTreeSet<_> =
            genesis_vec.iter().map(|id| (**id).0.clone()).collect();

        let native_parsec = NativeParsec::new((*our_id).0.clone(), &genesis_group_set)?;
        let parsec = Box::new(Parsec(native_parsec));

        *o_parsec = Box::into_raw(parsec);
        Ok(())
    })
}

/// Adds a vote for `network_event`. Returns an error if we have already voted for this.
#[no_mangle]
pub unsafe extern "C" fn parsec_vote_for(
    parsec: *mut Parsec,
    network_event: *const u8,
    network_event_len: usize,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let network_event = slice::from_raw_parts(network_event, network_event_len).to_vec();
        (*parsec).0.vote_for(network_event)?;
        Ok(())
    })
}

/// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
/// that peer needs.  If `peer_id` is `NULL`, a message containing all known gossip events is
/// returned.  If `peer_id` is an id and the given peer is unknown to this node, an error is
/// returned.
/// Returns an opaque `request`.
///
/// `o_request` must be freed using `request_free`.
#[no_mangle]
pub unsafe extern "C" fn parsec_create_gossip(
    parsec: *const Parsec,
    peer_id: *const PublicId,
    o_request: *mut *const Request,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let peer = if peer_id.is_null() {
            None
        } else {
            Some((*peer_id).0.clone())
        };

        let req = (*parsec).0.create_gossip(peer)?;
        *o_request = Box::into_raw(Box::new(Request(req)));
        Ok(())
    })
}

/// Handles a received request (`req`) from `src` peer.
/// Returns an opaque `response` to be sent back to `src`
/// or an error if the request was not valid.
///
/// `o_response` must be freed using `response_free`.
#[no_mangle]
pub unsafe extern "C" fn parsec_handle_request(
    parsec: *mut Parsec,
    src: *const PublicId,
    req: *const Request,
    o_response: *mut *const Response,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let resp = (*parsec).0.handle_request(&(*src).0, (*req).0.clone())?;
        *o_response = Box::into_raw(Box::new(Response(resp)));
        Ok(())
    })
}

/// Handles a received response (`resp`) from `src` peer.
/// Returns an error if the response was not valid.
#[no_mangle]
pub unsafe extern "C" fn parsec_handle_response(
    parsec: *mut Parsec,
    src: *const PublicId,
    resp: *const Response,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        (*parsec).0.handle_response(&(*src).0, (*resp).0.clone())?;
        Ok(())
    })
}

/// Steps the algorithm and returns the next stable block, if any.
/// Returns an opaque block (`o_block`) if there's a block or a null pointer instead.
///
/// If non-null pointer is returned, it's a user's responsibility to free it after use
/// by calling `block_free`.
#[no_mangle]
pub unsafe extern "C" fn parsec_poll(parsec: *mut Parsec, o_block: *mut *const Block) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let res = (*parsec).0.poll();
        *o_block = if let Some(block) = res {
            let block = Block(block);
            Box::into_raw(Box::new(block))
        } else {
            ptr::null()
        };
        Ok(())
    })
}

/// Checks if the given `network_event` has already been voted for by us.
/// Returns 0 (false) or 1 (true) in `o_result`.
#[no_mangle]
pub unsafe extern "C" fn parsec_have_voted_for(
    parsec: *const Parsec,
    network_event: *const u8,
    network_event_len: usize,
    o_result: *mut u8,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let network_event = slice::from_raw_parts(network_event, network_event_len).to_vec();
        *o_result = (*parsec).0.have_voted_for(&network_event) as u8;
        Ok(())
    })
}

/// Frees this `Parsec` instance and its associated data.
#[no_mangle]
pub unsafe extern "C" fn parsec_free(parsec: *mut Parsec) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(parsec);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use ffi::*;

    #[test]
    fn ffi_parsec_new() {
        utils::memory_check("ffi_error", 100, || {
            let bytes = b"test";
            let net_event = b"event";

            unsafe {
                let secret_id = unwrap!(utils::get_1(|out| secret_id_from_bytes(
                    bytes.as_ptr(),
                    bytes.len(),
                    out
                )));
                let public_id = unwrap!(utils::get_1(|out| public_id_from_bytes(
                    bytes.as_ptr(),
                    bytes.len(),
                    out
                )));
                let group = &[public_id];

                let parsec = unwrap!(utils::get_1(|out| parsec_new(
                    secret_id,
                    group.as_ptr(),
                    group.len(),
                    out
                )));

                let voted_for = unwrap!(utils::get_1(|out| parsec_have_voted_for(
                    parsec,
                    net_event.as_ptr(),
                    net_event.len(),
                    out
                )));
                assert_eq!(voted_for, 0);

                // FIXME: Memory leak in this function call.
                unwrap!(utils::get_0(|| parsec_vote_for(
                    parsec,
                    net_event.as_ptr(),
                    net_event.len(),
                )));

                let voted_for = unwrap!(utils::get_1(|out| parsec_have_voted_for(
                    parsec,
                    net_event.as_ptr(),
                    net_event.len(),
                    out
                )));
                assert_eq!(voted_for, 1);

                // Free everything.
                unwrap!(utils::get_0(|| secret_id_free(secret_id)));
                unwrap!(utils::get_0(|| public_id_free(public_id)));
                unwrap!(utils::get_0(|| parsec_free(parsec)));
            }
        })
    }
}
