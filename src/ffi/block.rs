// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Block FFI.

use block::Block as NativeBlock;
use error::Error;
use ffi::utils::catch_unwind_err_set;
use ffi::{NetworkEvent, PeerId};
use ffi::{ProofList, Vote};

/// Block FFI object.
#[repr(C)]
pub struct Block(pub(crate) NativeBlock<NetworkEvent, PeerId>);

/// Create a new block from `payload` and the `public_ids` with their corresponding `votes`.
#[no_mangle]
pub unsafe extern "C" fn new_block(
    payload: *const u8,
    public_ids: *const *const u8,
    votes: *const *const Vote,
    votes_len: usize,
    o_block: *mut *const Block,
) -> i32 {
    // let block = Box::new(Block(NativeBlock::new(payload, votes)));
    // *o_block = Box::into_raw(block);
    // mem::forget(block);
    catch_unwind_err_set(|| -> Result<_, Error> { Ok(()) })
}

/// Returns the Payload of this block.
#[no_mangle]
pub unsafe extern "C" fn block_payload(
    block: *const Block,
    o_payload: *mut *const u8,
    o_payload_len: *mut usize,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let payload = (*block).0.payload();

        *o_payload = payload.as_ptr();
        *o_payload_len = payload.len();

        Ok(())
    })
}

/// Returns the Proofs of this block.
///
/// This block's Proofs should not be freed manually -- `block_free` takes care of that.
#[no_mangle]
pub unsafe extern "C" fn block_proofs(block: *const Block, o_proofs: *mut *const ProofList) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> { Ok(()) })
}

/// Converts `vote` to a `Proof` and attempts to add it to the block. Returns an error if `vote` is
/// invalid (i.e. signature check fails or the `vote` is for a different network event). Sets
/// `o_new_proof` to `1` if the `Proof` wasn't previously held in this `Block`, or `0` if it was
/// previously held.
#[no_mangle]
pub unsafe extern "C" fn block_add_vote(
    block: *const Block,
    peer_id: *const u8,
    vote: *const Vote,
    o_new_proof: *mut u8,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> { Ok(()) })
}

/// Frees this block and its associated data.
#[no_mangle]
pub unsafe extern "C" fn block_free(block: *mut Block) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(block);
        Ok(())
    })
}