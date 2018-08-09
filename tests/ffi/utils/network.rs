// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use parsec::ffi::mock::{self, PeerId, Transaction};
use parsec::ffi::{Request, Response, self};
use std::collections::{BTreeMap, BTreeSet};
use utils::{self, Peer, RequestTiming, Schedule, ScheduleEvent};

enum Message {
    Request(*const Request, usize),
    Response(*const Response),
}

impl Drop for Message {
    fn drop(&mut self) {
        // TODO: drop this enum, free resources
    }
}

struct QueueEntry {
    pub sender: *const PeerId,
    pub message: Message,
    pub deliver_after: usize,
}

impl Drop for QueueEntry {
    fn drop(&mut self) {
        // TODO: drop this struct, free resources
    }
}

pub struct Network {
    pub peers: Vec<Peer>,
    msg_queue: BTreeMap<*const PeerId, Vec<QueueEntry>>,
}

impl Network {
    /// Create test network with the given initial number of peers (the genesis group).
    pub fn new(count: usize) -> Self {
        let genesis_group: Vec<*const PeerId> = unsafe {
            unwrap!(test_utils::get_vec(|out, out_len| mock::create_ids(
                count, out, out_len
            )))
        };
        let peers = genesis_group
            .iter()
            .map(|id| Peer::new(id, genesis_group.clone()))
            .collect();
        Network {
            peers,
            msg_queue: BTreeMap::new(),
        }
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    pub fn blocks_all_in_sequence(
        &self,
    ) -> Result<
        (),
        (
            *const PeerId,
            Vec<*const Transaction>,
            *const PeerId,
            Vec<*const Transaction>,
        ),
    > {
        let payloads = self.peers[0].blocks_payloads();
        if let Some(peer) = self
            .peers
            .iter()
            .find(|peer| peer.blocks_payloads() != payloads)
        {
            Err((
                &self.peers[0].id,
                payloads,
                &peer.id,
                peer.blocks_payloads(),
            ))
        } else {
            Ok(())
        }
    }

    fn peer(&mut self, id: *const PeerId) -> &Peer {
        unwrap!(self.peers.iter().find(|peer| peer.id == *id))
    }

    fn peer_mut(&mut self, id: *const PeerId) -> &mut Peer {
        unwrap!(self.peers.iter_mut().find(|peer| peer.id == *id))
    }

    fn send_message(
        &mut self,
        src: *const PeerId,
        dst: *const PeerId,
        message: Message,
        deliver_after: usize,
    ) {
        self.msg_queue
            .entry(dst.clone())
            .or_insert_with(Vec::new)
            .push(QueueEntry {
                sender: src,
                message,
                deliver_after,
            });
    }

    /// Handles incoming requests and responses
    fn handle_messages(&mut self, peer: *const PeerId, step: usize) -> bool {
        if let Some(msgs) = self.msg_queue.remove(peer) {
            let (to_handle, rest) = msgs
                .into_iter()
                .partition(|entry| entry.deliver_after <= step);
            let _ = self.msg_queue.insert(peer, rest);
            let result = !to_handle.is_empty();
            for entry in to_handle {
                match entry.message {
                    Message::Request(req, resp_delay) => {
                        let response = unwrap!(
                            self.peer_mut(peer)
                                .parsec
                                .handle_request(&entry.sender, req)
                        );
                        self.send_message(
                            peer,
                            entry.sender,
                            Message::Response(response),
                            step + resp_delay,
                        );
                    }
                    Message::Response(resp) => {
                        unwrap!(
                            self.peer_mut(peer)
                                .parsec
                                .handle_response(&entry.sender, resp)
                        );
                    }
                }
            }
            result
        } else {
            false
        }
    }

    fn consensus_broken(&self) -> bool {
        let mut block_order = BTreeMap::new();
        for peer in &self.peers {
            for (index, block) in peer.blocks_payloads().into_iter().enumerate() {
                let old_index = block_order.insert(block, index);
                if old_index.map(|idx| idx != index).unwrap_or(false) {
                    // old index exists and isn't equal to the new one
                    return true;
                }
            }
        }
        false
    }

    fn consensus_complete(&self, num_transactions: usize) -> bool {
        self.peers[0].blocks_payloads().len() == num_transactions
            && self.blocks_all_in_sequence().is_ok()
    }

    /// Simulates the network according to the given schedule
    pub fn execute_schedule(&mut self, schedule: Schedule) {
        let mut started_up = BTreeSet::new();
        let Schedule {
            num_transactions,
            events,
        } = schedule;
        for event in events {
            match event {
                ScheduleEvent::LocalStep {
                    global_step,
                    peer,
                    request_timing,
                } => {
                    let has_new_data = self.handle_messages(&peer, global_step);
                    self.peer_mut(&peer).poll();
                    let mut handle_req = |req: utils::Request| {
                        let request = unwrap!(
                            self.peer(&peer)
                                .parsec
                                .create_gossip(Some(req.recipient.clone()))
                        );
                        self.send_message(
                            peer.clone(),
                            req.recipient,
                            Message::Request(request, req.resp_delay),
                            global_step + req.req_delay,
                        );
                    };
                    match request_timing {
                        RequestTiming::DuringThisStep(req) => {
                            handle_req(req);
                        }
                        RequestTiming::DuringThisStepIfNewData(req) => {
                            if has_new_data || !started_up.contains(&peer) {
                                let _ = started_up.insert(peer.clone());
                                handle_req(req);
                            }
                        }
                        RequestTiming::Later => (),
                    }
                }
                ScheduleEvent::VoteFor(peer, transaction) => {
                    let _ = self.peer_mut(&peer).vote_for(&transaction);
                }
                ScheduleEvent::Fail(peer) => {
                    self.peers.retain(|p| p.id != peer);
                }
            }
            if self.consensus_broken() || self.consensus_complete(num_transactions) {
                break;
            }
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        // TODO: complete this
    }
}
