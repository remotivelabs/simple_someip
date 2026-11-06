pub mod byte_order;
mod error;
mod header;
mod message;
mod message_id;
mod message_type;
mod return_code;

/// Service Discovery
pub mod sd;

/// SOME/IP-TP
pub mod tp;

pub use error::Error;
pub use header::{Header, HeaderView};
#[cfg(feature = "server")]
pub(crate) use message::messages;
pub use message::{Message, MessageView};
pub use message_id::MessageId;
pub use message_type::{MessageType, MessageTypeField};
pub use return_code::ReturnCode;
