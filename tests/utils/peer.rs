// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{BlockImpl, ParsecImpl};
use parsec::mock::{PeerId, Transaction};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

pub struct Peer<P: ParsecImpl> {
    pub id: PeerId,
    pub parsec: P,
    // The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    pub blocks: Vec<P::Block>,
}

impl<P: ParsecImpl> Peer<P> {
    pub fn new(id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        Self {
            id: id.clone(),
            parsec: P::new(id, genesis_group),
            blocks: vec![],
        }
    }

    pub fn vote_for(&mut self, transaction: &Transaction) -> bool {
        if !self.parsec.have_voted_for(transaction) {
            unwrap!(self.parsec.vote_for(transaction.clone()));
            true
        } else {
            false
        }
    }

    pub fn poll(&mut self) {
        while let Some(block) = self.parsec.poll() {
            self.blocks.push(block)
        }
    }

    // Returns the payloads of `self.blocks` in the order in which they were returned by `poll()`.
    pub fn blocks_payloads(&self) -> Vec<Transaction> {
        self.blocks.iter().map(P::Block::payload).collect()
    }
}

impl<P: ParsecImpl> Debug for Peer<P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}: Blocks: {:?}", self.id, self.blocks)
    }
}
