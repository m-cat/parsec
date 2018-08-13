// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use ffi::{utils, NetworkEvent, PeerId};
use gossip::{Request as ParsecReq, Response as ParsecResp};

/// Opaque structure holding a request from a peer.
///
/// Should be deallocated with `request_free`.
pub struct Request(pub(crate) ParsecReq<NetworkEvent, PeerId>);
/// Opaque structure holding a response from a peer.
///
/// Should be deallocated with `response_free`.
pub struct Response(pub(crate) ParsecResp<NetworkEvent, PeerId>);

/// Deallocates a request.
#[no_mangle]
pub unsafe extern "C" fn request_free(request: *const Request) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<(), Error> {
        let _ = Box::from_raw(request as *mut Request);
        Ok(())
    })
}

/// Deallocates a response.
#[no_mangle]
pub unsafe extern "C" fn response_free(response: *const Response) -> i32 {
    utils::catch_unwind_err_set(|| -> Result<(), Error> {
        let _ = Box::from_raw(response as *mut Response);
        Ok(())
    })
}
