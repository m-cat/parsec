// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

use super::{BlockImpl, ParsecImpl};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use parsec::ffi::*;
use parsec::mock::{PeerId, Transaction};
use parsec::Error;
use std::collections::BTreeSet;
use std::{mem, ptr, slice};

pub struct ParsecFfiImpl {
    parsec: *mut Parsec,
}

impl Drop for ParsecFfiImpl {
    fn drop(&mut self) {
        unsafe {
            assert_ffi!(parsec_free(self.parsec));
        }
    }
}

impl ParsecImpl for ParsecFfiImpl {
    type Block = BlockFfiImpl;
    type Request = *const Request;
    type Response = *const Response;

    fn new(our_id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        unsafe {
            let genesis_vec: Vec<*const PublicId> = genesis_group
                .iter()
                .map(|id| {
                    let mut pub_id = mem::zeroed();
                    let id_bytes = id.as_bytes();
                    assert_ffi!(public_id_from_bytes(
                        id_bytes.as_ptr(),
                        id_bytes.len(),
                        &mut pub_id
                    ));
                    pub_id
                })
                .collect();

            let mut parsec: *mut Parsec = mem::zeroed();
            let mut our_secret_id = mem::zeroed();

            let id = our_id.as_bytes();

            assert_ffi!(secret_id_from_bytes(
                id.as_ptr(),
                id.len(),
                &mut our_secret_id
            ));

            assert_ffi!(parsec_new(
                our_secret_id,
                genesis_vec.as_ptr(),
                genesis_vec.len(),
                &mut parsec,
            ));

            genesis_vec.into_iter().for_each(|id| {
                assert_ffi!(public_id_free(id));
            });

            assert_ffi!(secret_id_free(our_secret_id));

            Self { parsec }
        }
    }

    fn poll(&mut self) -> Option<Self::Block> {
        unsafe {
            let mut o_block = mem::zeroed();
            assert_ffi!(parsec_poll(self.parsec, &mut o_block));

            if o_block.is_null() {
                None
            } else {
                Some(BlockFfiImpl(o_block))
            }
        }
    }

    fn have_voted_for(&mut self, event: &Transaction) -> bool {
        let event_data = unwrap!(serialise(event));
        unsafe {
            let mut voted = 0;
            assert_ffi!(parsec_have_voted_for(
                self.parsec,
                event_data.as_ptr(),
                event_data.len(),
                &mut voted,
            ));
            voted == 1
        }
    }

    fn vote_for(&mut self, event: Transaction) -> Result<(), Error> {
        let event_data = unwrap!(serialise(&event));
        unsafe {
            assert_ffi!(parsec_vote_for(
                self.parsec,
                event_data.as_ptr(),
                event_data.len()
            ));
        }
        Ok(())
    }

    fn handle_request(
        &mut self,
        src: &PeerId,
        req: Self::Request,
    ) -> Result<Self::Response, Error> {
        let mut o_resp = unsafe { mem::zeroed() };
        let src_bytes = src.as_bytes();
        unsafe {
            let mut src_id = mem::zeroed();

            assert_ffi!(public_id_from_bytes(
                src_bytes.as_ptr(),
                src_bytes.len(),
                &mut src_id
            ));
            assert_ffi!(parsec_handle_request(self.parsec, src_id, req, &mut o_resp));
            assert_ffi!(public_id_free(src_id));
        }
        Ok(o_resp)
    }

    fn handle_response(&mut self, src: &PeerId, resp: Self::Response) -> Result<(), Error> {
        let src_bytes = src.as_bytes();
        unsafe {
            let mut src_id = mem::zeroed();

            assert_ffi!(public_id_from_bytes(
                src_bytes.as_ptr(),
                src_bytes.len(),
                &mut src_id
            ));
            assert_ffi!(parsec_handle_response(self.parsec, src_id, resp));
            assert_ffi!(public_id_free(src_id));
        }
        Ok(())
    }

    fn create_gossip(&self, _peer_id: Option<PeerId>) -> Result<Self::Request, Error> {
        unsafe {
            let mut o_request = mem::zeroed();
            assert_ffi!(parsec_create_gossip(
                self.parsec,
                ptr::null(),
                &mut o_request
            ));
            Ok(o_request)
        }
    }
}

#[derive(Debug)]
pub struct BlockFfiImpl(*const Block);

impl Drop for BlockFfiImpl {
    fn drop(&mut self) {
        unsafe {
            assert_ffi!(block_free(self.0 as *mut _));
        }
    }
}

impl BlockImpl for BlockFfiImpl {
    fn payload(&self) -> Transaction {
        let mut payload_bytes: *const u8 = unsafe { mem::zeroed() };
        let mut payload_len: usize = 0;

        let payload: &[u8] = unsafe {
            assert_ffi!(block_payload(self.0, &mut payload_bytes, &mut payload_len));
            slice::from_raw_parts(payload_bytes, payload_len)
        };

        unwrap!(deserialise(&payload))
    }
}
