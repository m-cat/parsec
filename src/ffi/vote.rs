// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use ffi::id::Proof;
use ffi::{utils, NetworkEvent, PeerId, PublicId, SecretId};
use std::slice;
use vote::Vote as NativeVote;

/// Serves as an opaque pointer to `Vote` struct.
pub struct Vote(pub(crate) NativeVote<NetworkEvent, PeerId>);

/// Creates a vote for the given `payload` and writes it to `o_vote`.
#[no_mangle]
pub unsafe extern "C" fn vote_new(
    secret_id: *const SecretId,
    payload: *const u8,
    payload_len: usize,
    o_vote: *mut *const Vote,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<(), Error> {
        let payload_vec = slice::from_raw_parts(payload, payload_len).to_vec();

        let native_vote = NativeVote::new(&(*secret_id).0, payload_vec)?;

        *o_vote = Box::into_raw(Box::new(Vote(native_vote)));
        Ok(())
    })
}

/// Returns the payload being voted for.
#[no_mangle]
pub unsafe extern "C" fn vote_payload(
    vote: *const Vote,
    o_payload: *mut *const u8,
    o_payload_len: *mut usize,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let payload = (*vote).0.payload();

        *o_payload = payload.as_ptr();
        *o_payload_len = payload.len();
        Ok(())
    })
}

/// Returns the signature of this vote's payload.
#[no_mangle]
pub unsafe extern "C" fn vote_signature(
    vote: *const Vote,
    o_signature: *mut *const u8,
    o_signature_len: *mut usize,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let signature = (*vote).0.signature().as_bytes();

        *o_signature = signature.as_ptr();
        *o_signature_len = signature.len();
        Ok(())
    })
}

/// Validates this vote's signature and payload against the given public ID.
#[no_mangle]
pub unsafe extern "C" fn vote_is_valid(
    vote: *const Vote,
    public_id: *const PublicId,
    o_is_valid: *mut u8,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        if (*vote).0.is_valid(&(*public_id).0) {
            *o_is_valid = 1
        } else {
            *o_is_valid = 0
        }

        Ok(())
    })
}

/// Creates a proof from this vote and writes it to `o_proof`.
/// Returns error if this vote is not valid (i.e. if !vote_is_valid()).
#[no_mangle]
pub unsafe extern "C" fn vote_create_proof(
    vote: *const Vote,
    public_id: *const PublicId,
    o_proof: *mut *const Proof,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let native_proof = (*vote).0.create_proof(&(*public_id).0)?;

        *o_proof = Box::into_raw(Box::new(Proof(native_proof)));
        Ok(())
    })
}

/// Deallocates vote.
#[no_mangle]
pub unsafe extern "C" fn vote_free(vote: *const Vote) -> i32 {
    let _ = Box::from_raw(vote as *mut Vote);
    0
}

#[cfg(test)]
mod tests {
    use ffi::*;

    #[test]
    fn ffi_vote_new() {
        utils::memory_check("ffi_vote_new", 10000, || {
            let secret_id_bytes = b"hello";
            let payload = b"testing";

            unsafe {
                let secret_id = unwrap!(utils::get_1(|out| secret_id_from_bytes(
                    secret_id_bytes.as_ptr(),
                    secret_id_bytes.len(),
                    out
                )));

                let vote = unwrap!(utils::get_1(|out| vote_new(
                    secret_id,
                    payload.as_ptr(),
                    payload.len(),
                    out
                )));

                let result = unwrap!(utils::get_vec_u8(|out, len| vote_payload(vote, out, len)));
                assert_eq!(result, payload);

                // let public_id =
                //     unsafe { unwrap!(utils::get_1(|out| secret_id_public(secret_id, out))) };

                // let is_valid =
                //     unsafe { unwrap!(utils::get_1(|out| vote_is_valid(vote, public_id, out))) };
                // assert_eq!(is_valid, 1);

                unwrap!(utils::get_0(|| secret_id_free(secret_id)));
                unwrap!(utils::get_0(|| vote_free(vote)));
            }
        })
    }
}
