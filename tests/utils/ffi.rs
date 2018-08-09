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
use parsec::mock::PeerId;
use parsec::Error;
use std::collections::BTreeSet;
use std::{mem, ptr, slice};

pub struct ParsecFfiImpl {
    parsec: *mut Parsec,
}

impl ParsecImpl for ParsecFfiImpl {
    type Block = BlockFfiImpl;
    type Request = *const Request;
    type Response = *const Response;

    fn new(_our_id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        let genesis_vec: Vec<&PeerId> = genesis_group.iter().collect();

        let mut parsec: *mut Parsec = unsafe { mem::zeroed() };

        // secret_id_new()

        unsafe {
            let _ = parsec_new(
                ptr::null(), // our_id
                genesis_vec.as_ptr() as *const _,
                genesis_vec.len(),
                &mut parsec,
            );
        }

        Self { parsec }
    }

    fn poll(&mut self) -> Option<Self::Block> {
        unsafe {
            let mut o_block = mem::zeroed();
            let _ = parsec_poll(self.parsec, &mut o_block);
        }
        None
    }

    fn have_voted_for(&mut self, event: &Transaction) -> bool {
        let event_data = unwrap!(serialise(event));
        let _ =
            unsafe { parsec_have_voted_for(self.parsec, event_data.as_ptr(), event_data.len()) };
        true
    }

    fn vote_for(&mut self, event: Transaction) -> Result<(), Error> {
        let event_data = unwrap!(serialise(&event));
        unsafe {
            let _ = parsec_vote_for(self.parsec, event_data.as_ptr(), event_data.len());
        }
        Ok(())
    }

    fn handle_request(
        &mut self,
        _src: &PeerId,
        req: Self::Request,
    ) -> Result<Self::Response, Error> {
        let mut o_resp = unsafe { mem::zeroed() };
        // let id = unwrap!(serialise(&src));
        // src -> public_id_new()
        unsafe {
            let _ = parsec_handle_request(self.parsec, ptr::null(), req, &mut o_resp);
        }
        Ok(o_resp)
    }

    fn handle_response(&mut self, _src: &PeerId, resp: Self::Response) -> Result<(), Error> {
        // let id = unwrap!(serialise(&src));
        // src -> public_id_new()
        unsafe {
            let _ = parsec_handle_response(self.parsec, ptr::null(), resp);
        }
        Ok(())
    }

    fn create_gossip(&self, _peer_id: Option<PeerId>) -> Result<Self::Request, Error> {
        let mut o_request = unsafe { mem::zeroed() };
        unsafe {
            let _ = parsec_create_gossip(self.parsec, ptr::null(), &mut o_request);
        }
        Ok(o_request)
    }
}

#[derive(Debug)]
pub struct BlockFfiImpl(*const Block);

impl BlockImpl for BlockFfiImpl {
    fn payload(&self) -> Transaction {
        let mut payload_bytes: *const u8 = unsafe { mem::zeroed() };
        let mut payload_len: usize = 0;

        let payload: &[u8] = unsafe {
            let _ = block_payload(self.0, &mut payload_bytes, &mut payload_len);
            slice::from_raw_parts(payload_bytes, payload_len)
        };

        unwrap!(deserialise(&payload))
    }
}
