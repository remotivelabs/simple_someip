//! Requests to an offered service, and what answers them.
//!
//! A request (`feat_req_someip_141`) is answered by a response message, or by an exception
//! message when the server is configured to send those for errors (`feat_req_someip_726`); a
//! fire-and-forget request is not answered at all (`feat_req_someip_345`). The answer copies the
//! request's message id, request id and versions (`feat_req_someip_338`, `feat_req_someip_655`)
//! and goes back to the address and port the request came from (`feat_req_someip_49`).
//!
//! The server's receive loop tells a [`RequestObserver`] about every request. The observer does
//! not answer inline: it keeps the request's [`ResponseTarget`] and answers later, from any task,
//! through [`EventPublisher::respond_with_buffers`](super::EventPublisher::respond_with_buffers)
//! or its allocating wrapper, `respond`.

use core::net::SocketAddrV4;

use crate::e2e::E2ECheckStatus;
use crate::protocol::{HeaderView, MessageType, ReturnCode};

/// What a response or exception copies from the request it answers, and where it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseTarget {
    source: SocketAddrV4,
    service_id: u16,
    method_id: u16,
    request_id: u32,
    protocol_version: u8,
    interface_version: u8,
}

impl ResponseTarget {
    /// The target for a request with `header` received from `source`.
    #[must_use]
    pub fn new(source: SocketAddrV4, header: &HeaderView<'_>) -> Self {
        let id = header.message_id();
        Self {
            source,
            service_id: id.service_id(),
            method_id: id.method_id(),
            request_id: header.request_id(),
            protocol_version: header.protocol_version(),
            interface_version: header.interface_version(),
        }
    }

    /// Where the request came from: where the answer goes (`feat_req_someip_49`).
    #[must_use]
    pub const fn source(self) -> SocketAddrV4 {
        self.source
    }

    /// The requested service.
    #[must_use]
    pub const fn service_id(self) -> u16 {
        self.service_id
    }

    /// The requested method.
    #[must_use]
    pub const fn method_id(self) -> u16 {
        self.method_id
    }

    /// The request id the answer echoes: client id and session id.
    #[must_use]
    pub const fn request_id(self) -> u32 {
        self.request_id
    }

    /// The client id, the upper half of the request id.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn client_id(self) -> u16 {
        (self.request_id >> 16) as u16
    }

    /// The session id, the lower half of the request id.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn session_id(self) -> u16 {
        (self.request_id & 0xFFFF) as u16
    }

    /// The protocol version the answer echoes.
    #[must_use]
    pub const fn protocol_version(self) -> u8 {
        self.protocol_version
    }

    /// The interface version the answer echoes.
    #[must_use]
    pub const fn interface_version(self) -> u8 {
        self.interface_version
    }
}

/// A request to an offered service, as received. Borrows the receive buffer.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    target: ResponseTarget,
    message_type: MessageType,
    payload: &'a [u8],
    e2e_status: E2ECheckStatus,
}

impl<'a> Request<'a> {
    pub(super) const fn new(
        target: ResponseTarget,
        message_type: MessageType,
        payload: &'a [u8],
        e2e_status: E2ECheckStatus,
    ) -> Self {
        Self {
            target,
            message_type,
            payload,
            e2e_status,
        }
    }

    /// What an answer to this request copies, and where it goes.
    #[must_use]
    pub const fn target(&self) -> ResponseTarget {
        self.target
    }

    /// `MessageType::Request` or `MessageType::RequestNoReturn`.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Whether the client awaits an answer: a fire-and-forget request gets none, not even an
    /// error (`feat_req_someip_345`, `feat_req_someip_654`).
    #[must_use]
    pub const fn expects_response(&self) -> bool {
        matches!(self.message_type, MessageType::Request)
    }

    /// The bytes after the SOME/IP header, with any E2E header stripped.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The outcome of the E2E check: `Unchecked` when no profile is registered for the method.
    #[must_use]
    pub const fn e2e_status(&self) -> E2ECheckStatus {
        self.e2e_status
    }

    /// A copy that outlives the receive buffer.
    #[cfg(feature = "_alloc")]
    #[must_use]
    pub fn to_owned(&self) -> OwnedRequest {
        OwnedRequest {
            target: self.target,
            message_type: self.message_type,
            payload: self.payload.into(),
            e2e_status: self.e2e_status,
        }
    }
}

/// A [`Request`] that owns its payload.
#[cfg(feature = "_alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRequest {
    target: ResponseTarget,
    message_type: MessageType,
    payload: alloc::vec::Vec<u8>,
    e2e_status: E2ECheckStatus,
}

#[cfg(feature = "_alloc")]
impl OwnedRequest {
    /// What an answer to this request copies, and where it goes.
    #[must_use]
    pub const fn target(&self) -> ResponseTarget {
        self.target
    }

    /// `MessageType::Request` or `MessageType::RequestNoReturn`.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Whether the client awaits an answer; see [`Request::expects_response`].
    #[must_use]
    pub const fn expects_response(&self) -> bool {
        matches!(self.message_type, MessageType::Request)
    }

    /// The bytes after the SOME/IP header, with any E2E header stripped.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The outcome of the E2E check; see [`Request::e2e_status`].
    #[must_use]
    pub const fn e2e_status(&self) -> E2ECheckStatus {
        self.e2e_status
    }
}

/// Told about every request to an offered service, on the server's receive loop.
///
/// `on_request` runs on the receive loop and must not block or wait: hand the request over and
/// return. The answer is sent later through
/// [`EventPublisher::respond_with_buffers`](super::EventPublisher::respond_with_buffers), with the request's
/// [`target`](Request::target).
pub trait RequestObserver {
    /// A request to an offered service arrived.
    fn on_request(&self, request: &Request<'_>);
}

impl<O: RequestObserver + ?Sized> RequestObserver for &O {
    fn on_request(&self, request: &Request<'_>) {
        (**self).on_request(request);
    }
}

#[cfg(feature = "_alloc")]
impl<O: RequestObserver + ?Sized> RequestObserver for alloc::sync::Arc<O> {
    fn on_request(&self, request: &Request<'_>) {
        (**self).on_request(request);
    }
}

/// How a server holds its request observer: shared on an allocator, `'static` without one.
#[cfg(feature = "_alloc")]
pub type RequestObserverHandle = alloc::sync::Arc<dyn RequestObserver + Send + Sync>;
/// How a server holds its request observer: shared on an allocator, `'static` without one.
#[cfg(not(feature = "_alloc"))]
pub type RequestObserverHandle = &'static (dyn RequestObserver + Sync);

/// The observer in `handle`, as the receive loop takes it.
#[cfg(feature = "_alloc")]
pub(super) fn observer(
    handle: Option<&RequestObserverHandle>,
) -> Option<&(dyn RequestObserver + Sync)> {
    handle.map(|observer| &**observer as &(dyn RequestObserver + Sync))
}

/// The observer in `handle`, as the receive loop takes it.
#[cfg(not(feature = "_alloc"))]
pub(super) fn observer(
    handle: Option<&RequestObserverHandle>,
) -> Option<&(dyn RequestObserver + Sync)> {
    handle.copied()
}

/// A [`RequestObserver`] that queues requests on a tokio channel, for a task to answer them.
///
/// A request that arrives while the channel is full is dropped with a warning, so the receive
/// loop never waits on the consumer.
#[cfg(feature = "server-tokio")]
#[derive(Debug, Clone)]
pub struct RequestSender(tokio::sync::mpsc::Sender<OwnedRequest>);

#[cfg(feature = "server-tokio")]
impl RequestSender {
    /// A sender and the receiver its requests arrive on, holding up to `capacity` unanswered.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, tokio::sync::mpsc::Receiver<OwnedRequest>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        (Self(sender), receiver)
    }
}

#[cfg(feature = "server-tokio")]
impl RequestObserver for RequestSender {
    fn on_request(&self, request: &Request<'_>) {
        if let Err(e) = self.0.try_send(request.to_owned()) {
            crate::log::warn!(
                "request 0x{:04X}/0x{:04X} from {} dropped: {}",
                request.target().service_id(),
                request.target().method_id(),
                request.target().source(),
                e
            );
        }
    }
}

/// What answers a request: a response, or an exception carrying an error
/// (`feat_req_someip_141`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    message_type: MessageType,
    return_code: ReturnCode,
}

impl Reply {
    /// A response with `E_OK`.
    pub const OK: Self = Self::response(ReturnCode::Ok);

    /// A response message with `return_code`. Errors travel in response messages unless
    /// exception messages are configured (`feat_req_someip_726`).
    #[must_use]
    pub const fn response(return_code: ReturnCode) -> Self {
        Self {
            message_type: MessageType::Response,
            return_code,
        }
    }

    /// An exception message with `return_code`, which is an error: an exception never carries
    /// `E_OK` (`feat_req_someip_683`).
    ///
    /// # Errors
    ///
    /// When `return_code` is `E_OK`.
    pub const fn exception(return_code: ReturnCode) -> Result<Self, ExceptionWithoutError> {
        if matches!(return_code, ReturnCode::Ok) {
            return Err(ExceptionWithoutError);
        }
        Ok(Self {
            message_type: MessageType::Error,
            return_code,
        })
    }

    /// `MessageType::Response` or `MessageType::Error`.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        self.message_type
    }

    /// The return code sent.
    #[must_use]
    pub const fn return_code(self) -> ReturnCode {
        self.return_code
    }
}

/// An exception message was asked to carry `E_OK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionWithoutError;

impl core::fmt::Display for ExceptionWithoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("an exception message carries an error return code, never E_OK")
    }
}

impl core::error::Error for ExceptionWithoutError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Header, MessageId, MessageTypeField};
    use automotive_wire_codec::Encode;
    use core::net::Ipv4Addr;

    fn header_bytes(message_type: MessageType, request_id: u32) -> [u8; 16] {
        let header = Header::new(
            MessageId::new_from_service_and_method(0x1234, 0x0007),
            request_id,
            1,
            3,
            MessageTypeField::new(message_type, false),
            ReturnCode::Ok,
            0,
        );
        let mut buf = [0u8; 16];
        header.encode_to_slice(&mut buf).unwrap();
        buf
    }

    const SOURCE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 40_000);

    #[test]
    fn the_target_copies_what_an_answer_echoes() {
        let bytes = header_bytes(MessageType::Request, 0x00AB_0005);
        let (header, _) = HeaderView::parse(&bytes).unwrap();
        let target = ResponseTarget::new(SOURCE, &header);

        assert_eq!(target.source(), SOURCE);
        assert_eq!(target.service_id(), 0x1234);
        assert_eq!(target.method_id(), 0x0007);
        assert_eq!(target.request_id(), 0x00AB_0005);
        assert_eq!(target.client_id(), 0x00AB);
        assert_eq!(target.session_id(), 0x0005);
        assert_eq!(target.protocol_version(), 1);
        assert_eq!(target.interface_version(), 3);
    }

    #[test]
    fn only_a_request_expects_a_response() {
        let bytes = header_bytes(MessageType::RequestNoReturn, 1);
        let (header, _) = HeaderView::parse(&bytes).unwrap();
        let target = ResponseTarget::new(SOURCE, &header);
        let fire_and_forget = Request::new(
            target,
            MessageType::RequestNoReturn,
            &[1, 2],
            E2ECheckStatus::Unchecked,
        );
        let request = Request::new(target, MessageType::Request, &[1, 2], E2ECheckStatus::Ok);

        assert!(!fire_and_forget.expects_response());
        assert!(request.expects_response());
        assert_eq!(request.payload(), &[1, 2]);
        assert_eq!(request.e2e_status(), E2ECheckStatus::Ok);
    }

    #[test]
    fn an_exception_carries_an_error() {
        assert_eq!(Reply::OK.message_type(), MessageType::Response);
        assert_eq!(Reply::OK.return_code(), ReturnCode::Ok);
        assert_eq!(
            Reply::response(ReturnCode::NotReady).message_type(),
            MessageType::Response
        );
        let exception = Reply::exception(ReturnCode::UnknownMethod).unwrap();
        assert_eq!(exception.message_type(), MessageType::Error);
        assert_eq!(exception.return_code(), ReturnCode::UnknownMethod);
        assert_eq!(Reply::exception(ReturnCode::Ok), Err(ExceptionWithoutError));
    }
}
