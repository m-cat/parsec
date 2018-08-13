// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use parsec::mock::{PeerId, Transaction};
use parsec::{Block, Error, Parsec, Request as ParsecReq, Response as ParsecResp};
use std::collections::BTreeSet;
use std::fmt::Debug;

/// Provides a wrapper for testing of different PARSEC facades (FFI and native).
/// It is biased for `Transaction` as a payload and `PeerId` as the peer identity.
pub trait ParsecImpl {
    type Block: BlockImpl;
    type Response;
    type Request;

    fn new(our_id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self;

    fn poll(&mut self) -> Option<Self::Block>;

    fn have_voted_for(&mut self, network_event: &Transaction) -> bool;

    fn vote_for(&mut self, network_event: Transaction) -> Result<(), Error>;

    fn handle_request(&mut self, src: &PeerId, req: Self::Request)
        -> Result<Self::Response, Error>;

    fn handle_response(&mut self, src: &PeerId, resp: Self::Response) -> Result<(), Error>;

    fn create_gossip(&self, peer_id: Option<PeerId>) -> Result<Self::Request, Error>;
}

pub trait BlockImpl: Debug {
    fn payload(&self) -> Transaction;
}

#[derive(Debug)]
pub struct BlockRustImpl(Block<Transaction, PeerId>);

impl BlockImpl for BlockRustImpl {
    fn payload(&self) -> Transaction {
        self.0.payload().clone()
    }
}

pub struct ParsecRustImpl(Parsec<Transaction, PeerId>);

impl ParsecImpl for ParsecRustImpl {
    type Block = BlockRustImpl;
    type Request = ParsecReq<Transaction, PeerId>;
    type Response = ParsecResp<Transaction, PeerId>;

    fn new(our_id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        ParsecRustImpl(unwrap!(Parsec::new(our_id, genesis_group)))
    }

    fn poll(&mut self) -> Option<Self::Block> {
        self.0.poll().map(BlockRustImpl)
    }

    fn have_voted_for(&mut self, network_event: &Transaction) -> bool {
        self.0.have_voted_for(network_event)
    }

    fn vote_for(&mut self, network_event: Transaction) -> Result<(), Error> {
        self.0.vote_for(network_event)
    }

    fn handle_request(
        &mut self,
        src: &PeerId,
        req: Self::Request,
    ) -> Result<Self::Response, Error> {
        self.0.handle_request(src, req)
    }

    fn handle_response(&mut self, src: &PeerId, resp: Self::Response) -> Result<(), Error> {
        self.0.handle_response(src, resp)
    }

    fn create_gossip(&self, peer_id: Option<PeerId>) -> Result<Self::Request, Error> {
        self.0.create_gossip(peer_id)
    }
}
