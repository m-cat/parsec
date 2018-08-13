// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ffi_utils::ErrorCode;

quick_error! {
    /// Parsec error variants.
    #[derive(Debug)]
    pub enum Error {
        /// Payload of a `Vote` doesn't match the payload of a `Block`.
        MismatchedPayload {
            description("Payload doesn't match")
            display("The payload of the vote doesn't match the payload of targeted block.")
        }
        /// Failed to verify signature.
        SignatureFailure {
            description("Signature cannot be verified")
            display("The message or signature might be corrupted, or the signer is wrong.")
        }
        /// Serialisation Error.
        Serialisation(error: ::maidsafe_utilities::serialisation::SerialisationError) {
            description(error.description())
            display("Serialisation error: {}", error)
            from()
        }
        /// String Error.
        String(error: ::ffi_utils::StringError) {
            description("Error occurred while performing a String conversion.")
            display("String error: {:?}", error)
            from()
        }
        /// Peer is not known to this node.
        UnknownPeer {
            description("Peer is not known")
            display("The peer_id is not known to this node's peer_manager.")
        }
        /// The given event is invalid or malformed.
        InvalidEvent {
            description("Invalid event")
            display("The given event is invalid or malformed.")
        }
        /// This event's self-parent or other-parent is unknown to this node.
        UnknownParent {
            description("Parent event(s) not known")
            display("This event's self-parent or other-parent is unknown to this node.")
        }
        /// This node has already voted for this network event.
        DuplicateVote {
            description("Duplicate vote")
            display("This node has already voted for this network event.")
        }
        /// Utf8 Error.
        Utf8(error: ::std::str::Utf8Error) {
            description(error.description())
            display("Utf8 error: {:?}", error)
            from()
        }
        /// Logic error.
        Logic {
            description("Logic error")
            display("This a logic error and represents a flaw in the code.")
        }
        /// Unexpected error. Contains custom error message.
        Unexpected(error: String) {
            description("An unexpected error has occurred.")
            display("Unexpected error: {}", error)
        }
    }
}

#[allow(missing_docs)]
mod codes {
    pub const ERR_MISMATCHED_PAYLOAD: i32 = -1;
    pub const ERR_SIGNATURE_FAILURE: i32 = -2;
    pub const ERR_SERIALISATION: i32 = -3;
    pub const ERR_STRING: i32 = -4;
    pub const ERR_UNKNOWN_PEER: i32 = -5;
    pub const ERR_INVALID_EVENT: i32 = -6;
    pub const ERR_UNKNOWN_PARENT: i32 = -7;
    pub const ERR_DUPLICATE_VOTE: i32 = -8;
    pub const ERR_UTF8: i32 = -9;

    pub const ERR_LOGIC: i32 = -100;
    pub const ERR_UNEXPECTED: i32 = -101;
}

impl ErrorCode for Error {
    fn error_code(&self) -> i32 {
        use error::codes::*;

        match *self {
            Error::MismatchedPayload => ERR_MISMATCHED_PAYLOAD,
            Error::SignatureFailure => ERR_SIGNATURE_FAILURE,
            Error::Serialisation(_) => ERR_SERIALISATION,
            Error::String(_) => ERR_STRING,
            Error::UnknownPeer => ERR_UNKNOWN_PEER,
            Error::InvalidEvent => ERR_INVALID_EVENT,
            Error::UnknownParent => ERR_UNKNOWN_PARENT,
            Error::DuplicateVote => ERR_DUPLICATE_VOTE,
            Error::Utf8(_) => ERR_UTF8,

            Error::Logic => ERR_LOGIC,
            Error::Unexpected(_) => ERR_UNEXPECTED,
        }
    }
}

impl<'a> From<&'a str> for Error {
    fn from(s: &'a str) -> Self {
        Error::Unexpected(s.to_string())
    }
}
