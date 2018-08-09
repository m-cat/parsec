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
use ffi::{NetworkEvent, PeerId, Proof, ProofList, PublicId, Vote};
use std::collections::BTreeMap;
use std::{mem, slice};

/// Block FFI object.
pub struct Block(pub(crate) NativeBlock<NetworkEvent, PeerId>);

/// Create a new block from `payload` and the `public_ids` with their corresponding `votes`.
/// `items_len` corresponds to a number of `votes` and `public_ids` which must be the same.
#[no_mangle]
pub unsafe extern "C" fn block_new(
    payload: *const u8,
    payload_len: usize,
    public_ids: *const *const PublicId,
    votes: *const *const Vote,
    items_len: usize,
    o_block: *mut *const Block,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let payload = slice::from_raw_parts(payload, payload_len).to_vec();
        let public_ids = slice::from_raw_parts(public_ids, items_len);
        let votes = slice::from_raw_parts(votes, items_len);

        let mut votes_map = BTreeMap::new();

        public_ids.iter().zip(votes.iter()).for_each(|(id, vote)| {
            let _ = votes_map.insert((**id).0.clone(), (**vote).0.clone());
        });

        let block = Box::new(Block(NativeBlock::new(payload, &votes_map)?));
        *o_block = Box::into_raw(block);

        Ok(())
    })
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
pub unsafe extern "C" fn block_proofs(block: *const Block, o_proofs: *mut ProofList) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let proofs: Vec<_> = (*block)
            .0
            .proofs()
            .iter()
            .map(|proof| Box::into_raw(Box::new(Proof(proof.clone()))))
            .collect();

        *o_proofs = ProofList {
            proofs: proofs.as_ptr() as *const _,
            proofs_len: proofs.len(),
            proofs_cap: proofs.capacity(),
        };

        mem::forget(proofs);

        Ok(())
    })
}

/// Converts `vote` to a `Proof` and attempts to add it to the block. Returns an error if `vote` is
/// invalid (i.e. signature check fails or the `vote` is for a different network event). Sets
/// `o_new_proof` to `1` if the `Proof` wasn't previously held in this `Block`, or `0` if it was
/// previously held.
#[no_mangle]
pub unsafe extern "C" fn block_add_vote(
    block: *mut Block,
    peer_id: *const PublicId,
    vote: *const Vote,
    o_new_proof: *mut u8,
) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        *o_new_proof = (*block).0.add_vote(&(*peer_id).0, &(*vote).0)? as u8;
        Ok(())
    })
}

/// Frees this block and its associated data.
#[no_mangle]
pub unsafe extern "C" fn block_free(block: *mut Block) -> i32 {
    catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(block);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use ffi::*;
    use mock;
    use std::{mem, ptr, slice};

    #[test]
    fn ffi_block_new() {
        utils::memory_check("ffi_block_new", 10000, || {
            let payload = b"hello world";

            unsafe {
                let mut block = mem::zeroed();

                assert_ffi!(block_new(
                    payload.as_ptr(),
                    payload.len(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    &mut block,
                ));

                let payload_output = unwrap!(utils::get_vec_u8(|output, len| block_payload(
                    block, output, len
                )));

                assert_eq!(payload_output.len(), payload.len());
                assert_eq!(payload_output.as_slice(), &payload[..]);

                assert_ffi!(block_free(block as *mut _));
            }
        })
    }

    #[test]
    fn ffi_block_add_vote() {
        utils::memory_check("ffi_block_add_vote", 100, || {
            let ids_count = 4;
            let ids = mock::create_ids(ids_count);

            let payload = b"hello world";

            unsafe {
                let mut public_ids = Vec::with_capacity(ids_count);
                let mut votes = Vec::with_capacity(ids_count);

                for id in &ids {
                    let id_bytes = id.as_bytes();
                    public_ids.push(unwrap!(utils::get_1(|id| public_id_from_bytes(
                        id_bytes.as_ptr(),
                        id_bytes.len(),
                        id
                    ))));
                }

                for id in &ids {
                    let id_bytes = id.as_bytes();
                    let secret_id = unwrap!(utils::get_1(|id| secret_id_from_bytes(
                        id_bytes.as_ptr(),
                        id_bytes.len(),
                        id
                    )));

                    votes.push(unwrap!(utils::get_1(|vote| vote_new(
                        secret_id,
                        payload.as_ptr(),
                        payload.len(),
                        vote
                    ))));

                    assert_ffi!(secret_id_free(secret_id));
                }

                // Create a new block
                let mut block = mem::zeroed();

                assert_ffi!(block_new(
                    payload.as_ptr(),
                    payload.len(),
                    public_ids.as_ptr(),
                    votes.as_ptr(),
                    ids_count - 1,
                    &mut block,
                ));

                // Try to add new votes
                let proof_not_held = unwrap!(utils::get_1(|proof| block_add_vote(
                    block as *mut _,
                    public_ids[ids_count - 2],
                    votes[ids_count - 2],
                    proof
                )));
                assert_eq!(proof_not_held, 0);

                let proof_not_held = unwrap!(utils::get_1(|proof| block_add_vote(
                    block as *mut _,
                    public_ids[ids_count - 1],
                    votes[ids_count - 1],
                    proof
                )));
                assert_eq!(proof_not_held, 1);

                // Get list of proofs
                let proof_list = unwrap!(utils::get_1(|out| block_proofs(block, out)));
                assert_eq!(proof_list.proofs_len, ids_count);

                let proofs = slice::from_raw_parts(proof_list.proofs, proof_list.proofs_len);

                for proof in proofs {
                    let is_valid = unwrap!(utils::get_1(|out| proof_is_valid(
                        proof,
                        payload.as_ptr(),
                        payload.len(),
                        out
                    )));

                    assert_eq!(is_valid, 1);
                }

                // Free memory
                assert_ffi!(proof_list_free(&proof_list));
                for id in public_ids {
                    assert_ffi!(public_id_free(id));
                }
                for vote in votes {
                    assert_ffi!(vote_free(vote));
                }
                assert_ffi!(block_free(block as *mut _));
            }
        })
    }
}
