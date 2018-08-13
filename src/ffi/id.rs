// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use ffi::utils;
use id::Proof as NativeProof;
use mock::PeerId;
use std::{slice, str};

/// Secret peer signing key.
///
/// Should be deallocated with `secret_id_free`.
pub struct SecretId(pub(crate) PeerId);
/// Public peer signing key.
///
/// Should be deallocated with `public_id_free`.
pub struct PublicId(pub(crate) PeerId);

/// Creates a public ID from raw bytes pointed by `id` with a size `id_len`.
/// Returns the opaque pointer to `o_public_id`.
///
/// `o_public_id` must be freed using `public_id_free`.
#[no_mangle]
pub unsafe extern "C" fn public_id_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    o_public_id: *mut *const PublicId,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let public_id = slice::from_raw_parts(bytes, bytes_len);
        let peer_id = PeerId::new(str::from_utf8(public_id)?);

        *o_public_id = Box::into_raw(Box::new(PublicId(peer_id)));
        Ok(())
    })
}

/// Returns the bytes contained in `public_id`.
#[no_mangle]
pub unsafe extern "C" fn public_id_as_bytes(
    public_id: *const PublicId,
    o_bytes: *mut *const u8,
    o_bytes_len: *mut usize,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let bytes = (*public_id).0.as_bytes();

        *o_bytes = bytes.as_ptr();
        *o_bytes_len = bytes.len();
        Ok(())
    })
}

/// Deallocates a public id.
#[no_mangle]
pub unsafe extern "C" fn public_id_free(public_id: *const PublicId) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(public_id as *mut PublicId);
        Ok(())
    })
}

/// Creates a secret ID from raw bytes pointed by `id` with a size `id_len`.
/// Returns the opaque pointer to the `o_secret_id`.
///
/// `o_secret_id` must be freed using `secret_id_free`.
#[no_mangle]
pub unsafe extern "C" fn secret_id_from_bytes(
    bytes: *const u8,
    bytes_len: usize,
    o_secret_id: *mut *const SecretId,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<(), Error> {
        let public_id = slice::from_raw_parts(bytes, bytes_len);
        let peer_id = PeerId::new(str::from_utf8(public_id)?);

        *o_secret_id = Box::into_raw(Box::new(SecretId(peer_id)));
        Ok(())
    })
}

/// Returns the bytes contained in `secret_id`.
#[no_mangle]
pub unsafe extern "C" fn secret_id_as_bytes(
    secret_id: *const SecretId,
    o_bytes: *mut *const u8,
    o_bytes_len: *mut usize,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let bytes = (*secret_id).0.as_bytes();

        *o_bytes = bytes.as_ptr();
        *o_bytes_len = bytes.len();
        Ok(())
    })
}

/// Deallocates a secret id.
#[no_mangle]
pub unsafe extern "C" fn secret_id_free(secret_id: *const SecretId) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<(), Error> {
        let _ = Box::from_raw(secret_id as *mut SecretId);
        Ok(())
    })
}

/// Serves as an opaque pointer to `Proof` struct.
///
/// Should be deallocated with `proof_free`.
#[derive(Debug)]
pub struct Proof(pub(crate) NativeProof<PeerId>);

/// Returns a public ID to `o_public_id` associated with a `proof`.
///
/// `o_public_id` must be freed using `public_id_free`.
#[no_mangle]
pub unsafe extern "C" fn proof_public_id(
    proof: *const Proof,
    o_public_id: *mut *const PublicId,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let native_public_id = (*proof).0.public_id().clone();

        let public_id = PublicId(native_public_id);
        *o_public_id = Box::into_raw(Box::new(public_id));
        Ok(())
    })
}

/// Returns a signature associated with a `proof`.
#[no_mangle]
pub unsafe extern "C" fn proof_signature(
    proof: *const Proof,
    o_signature: *mut *const u8,
    o_signature_len: *mut usize,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let native_signature = (*proof).0.signature().as_bytes();

        *o_signature = native_signature.as_ptr();
        *o_signature_len = native_signature.len();
        Ok(())
    })
}

/// Verifies the `proof` against data. Writes `1` to `o_is_valid` if valid.
#[no_mangle]
pub unsafe extern "C" fn proof_is_valid(
    proof: *const Proof,
    data: *const u8,
    data_len: usize,
    o_is_valid: *mut u8,
) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let data_slice = slice::from_raw_parts(data, data_len);

        if (*proof).0.is_valid(data_slice) {
            *o_is_valid = 1;
        } else {
            *o_is_valid = 0;
        }

        Ok(())
    })
}

/// Deallocates proof.
#[no_mangle]
pub unsafe extern "C" fn proof_free(proof: *const Proof) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let _ = Box::from_raw(proof as *mut Proof);
        Ok(())
    })
}

/// Container for a list of proofs.
///
/// Should be deallocated with `proof_list_free`.
#[repr(C)]
#[derive(Debug)]
pub struct ProofList {
    /// Pointer to a sequential list of proofs.
    pub proofs: *const *const Proof,
    /// Size of the proofs list.
    pub proofs_len: usize,
    /// Internal implementation detail (Rust vector capacity).
    pub proofs_cap: usize,
}

/// Deallocates proof list.
#[no_mangle]
pub unsafe extern "C" fn proof_list_free(proof_list: *const ProofList) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<_, Error> {
        let vec = Vec::from_raw_parts(
            (*proof_list).proofs as *mut _,
            (*proof_list).proofs_len,
            (*proof_list).proofs_cap,
        );

        for proof in vec {
            let _ = proof_free(proof);
        }

        let _ = Box::from_raw(proof_list as *mut ProofList);
        Ok(())
    })
}
