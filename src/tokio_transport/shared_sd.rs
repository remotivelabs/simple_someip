//! One pair of SD sockets shared by every SOME/IP participant in a process.
//!
//! An ECU exchanges service discovery on one port, 30490 unless configured otherwise
//! (`feat_req_someipsd_1095`), on which it both offers its services and subscribes to others'.
//! A client and a server each bind that port on the ECU's interface, so one of each in a
//! process on one interface would share the port through `SO_REUSEPORT`, which hands each
//! unicast datagram to one of them at random. [`SharedSd`] binds the port once, a unicast socket
//! on the interface and a multicast socket on every interface that joins the SD group, and
//! every participant takes a [`SharedTap`] on them: it receives a copy of each datagram its
//! [`Origin`] admits and sends through the unicast socket.
//!
//! A server is served through [`SharedSd::serve`], which gives it a tap of both origins for its
//! SD socket. A client takes [`SharedSd::transport`] as its factory: the discovery bind on the
//! unspecified address gets a multicast tap, the one on the interface a unicast tap, and every
//! other bind its own socket.
//!
//! The endpoint sockets are shared too, as different services share one port
//! (`feat_req_someip_445`): every server served on a `local_port` takes an [`EndpointTap`] on the
//! port's socket, which receives the messages of its service, and a client bind on that port
//! takes one for the messages of the rest, the responses and events of the services it
//! consumes. Two instances of one service listen on different ports (`feat_req_someip_648`), so a
//! second one on a port is refused.

use std::boxed::Box;
use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Weak};
use std::vec::Vec;

use tokio::sync::mpsc;

use super::{TokioSocket, TokioTimer, TokioTransport};
use crate::protocol::sd::SdEndpoint;
use crate::server::{
    EventPublisher, SdStateManager, Server, ServerConfig, ServerDeps, ServerHandles, ServerStorage,
    SubscriptionHandle,
};
use crate::transport::{
    E2ERegistryHandle, IoErrorKind, ReceivedDatagram, SocketOptions, TransportError,
    TransportFactory, TransportSocket,
};

/// How many datagrams a tap holds for a participant that is behind; older ones are dropped.
const TAP_DEPTH: usize = 64;
/// The largest UDP datagram.
const MAX_DATAGRAM: usize = 65_535;

/// Which of the two sockets a tap receives from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The unicast socket on the interface.
    Unicast,
    /// The multicast socket on every interface, joined to the SD group.
    Multicast,
    /// Both.
    Both,
}

impl Origin {
    const fn admits(self, from: Origin) -> bool {
        matches!(
            (self, from),
            (Origin::Both, _)
                | (Origin::Unicast, Origin::Unicast)
                | (Origin::Multicast, Origin::Multicast)
        )
    }
}

struct Datagram {
    bytes: Vec<u8>,
    source: SocketAddrV4,
}

struct Inner {
    unicast: TokioSocket,
    multicast: TokioSocket,
    interface: Ipv4Addr,
    endpoint: SdEndpoint,
    taps: Mutex<Vec<(Origin, mpsc::Sender<Arc<Datagram>>)>>,
    /// The endpoint sockets by port.
    endpoints: tokio::sync::Mutex<HashMap<u16, Arc<Endpoint>>>,
}

/// Which messages a tap on an endpoint socket receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serves {
    /// One service's: a server's.
    Service(u16),
    /// Those of no service served on the socket: a client's, the responses and events of the
    /// services it consumes.
    Rest,
}

/// One endpoint socket of the interface, shared by the servers and the client on its port.
struct Endpoint {
    socket: TokioSocket,
    taps: Mutex<Vec<(Serves, mpsc::Sender<Arc<Datagram>>)>>,
}

impl Endpoint {
    /// A tap for `serves`. A second server of one service on the socket is refused: the
    /// service's instances listen on different ports.
    fn tap(self: &Arc<Self>, serves: Serves) -> Result<EndpointTap, TransportError> {
        let mut taps = self
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if serves != Serves::Rest && taps.iter().any(|(taken, _)| *taken == serves) {
            return Err(TransportError::AddressInUse);
        }
        let (sender, received) = mpsc::channel(TAP_DEPTH);
        taps.push((serves, sender));
        Ok(EndpointTap {
            endpoint: Arc::clone(self),
            received: tokio::sync::Mutex::new(received),
        })
    }
}

/// The SD port of one interface, bound once for every participant in the process.
#[derive(Clone)]
pub struct SharedSd {
    inner: Arc<Inner>,
}

impl SharedSd {
    /// Bind `endpoint`'s port: a unicast socket on `interface`, and a multicast socket on every
    /// interface that joins `endpoint`'s group on `interface`. `multicast_loopback` is whether
    /// the host's own SD multicast is received too, as a client's and a server's.
    ///
    /// # Errors
    ///
    /// When a socket cannot be bound or the group not joined.
    pub async fn bind(
        interface: Ipv4Addr,
        endpoint: SdEndpoint,
        multicast_loopback: bool,
    ) -> Result<Self, TransportError> {
        let mut options = SocketOptions::new();
        options.reuse_address = true;
        options.reuse_port = true;
        options.multicast_if_v4 = Some(interface);
        options.multicast_loop_v4 = Some(multicast_loopback);
        let unicast = TokioTransport
            .bind(SocketAddrV4::new(interface, endpoint.port()), &options)
            .await?;
        let multicast = TokioTransport
            .bind(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, endpoint.port()),
                &options,
            )
            .await?;
        multicast.join_multicast_v4(endpoint.group(), interface)?;
        let inner = Arc::new(Inner {
            unicast,
            multicast,
            interface,
            endpoint,
            taps: Mutex::new(Vec::new()),
            endpoints: tokio::sync::Mutex::new(HashMap::new()),
        });
        tokio::spawn(fan_out(Arc::downgrade(&inner), Origin::Unicast));
        tokio::spawn(fan_out(Arc::downgrade(&inner), Origin::Multicast));
        Ok(Self { inner })
    }

    /// The interface the unicast socket is on.
    #[must_use]
    pub fn interface(&self) -> Ipv4Addr {
        self.inner.interface
    }

    /// Where SD is exchanged.
    #[must_use]
    pub fn endpoint(&self) -> SdEndpoint {
        self.inner.endpoint
    }

    /// A participant's view of the sockets: every datagram `origin` admits, sends through the
    /// unicast socket.
    #[must_use]
    pub fn tap(&self, origin: Origin) -> SharedTap {
        let (sender, received) = mpsc::channel(TAP_DEPTH);
        self.inner
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((origin, sender));
        SharedTap {
            inner: Arc::clone(&self.inner),
            received: tokio::sync::Mutex::new(received),
        }
    }

    /// A client's transport factory: a tap for each discovery bind on the SD port, its own
    /// socket for everything else.
    #[must_use]
    pub fn transport(&self) -> SharedTransport {
        SharedTransport {
            shared: self.clone(),
        }
    }

    /// The endpoint socket on `port`, bound on first use.
    async fn endpoint_socket(&self, port: u16) -> Result<Arc<Endpoint>, TransportError> {
        let mut endpoints = self.inner.endpoints.lock().await;
        if let Some(endpoint) = endpoints.get(&port) {
            return Ok(Arc::clone(endpoint));
        }
        let socket = TokioTransport
            .bind(
                SocketAddrV4::new(self.inner.interface, port),
                &SocketOptions::new(),
            )
            .await?;
        let endpoint = Arc::new(Endpoint {
            socket,
            taps: Mutex::new(Vec::new()),
        });
        tokio::spawn(fan_out_endpoint(Arc::downgrade(&endpoint)));
        endpoints.insert(port, Arc::clone(&endpoint));
        Ok(endpoint)
    }

    /// Serve a service through the shared sockets: the server's SD socket is a tap of both
    /// origins, and its unicast socket the interface's endpoint socket on `config.local_port`,
    /// shared with the other services served there and a client consuming through it; on port
    /// 0 it is a socket of its own. `config`'s interface and SD endpoint are the shared
    /// sockets'.
    ///
    /// # Errors
    ///
    /// When the unicast socket cannot be bound, or an instance of the service is served on the
    /// port already.
    pub async fn serve<R, Sub>(
        &self,
        deps: ServerDeps<TokioTransport, TokioTimer, R, Sub>,
        config: ServerConfig,
    ) -> Result<
        (
            SharedServer<R, Sub>,
            ServerHandles<SharedPublisher<R, Sub>>,
            impl Future<Output = Result<(), crate::server::Error>> + Send + 'static,
        ),
        crate::server::Error,
    >
    where
        R: E2ERegistryHandle + Send + Sync,
        Sub: SubscriptionHandle + Send + Sync,
        for<'a> Sub::SubscribeFuture<'a>: Send,
        for<'a> Sub::UnsubscribeFuture<'a>: Send,
    {
        let config = config
            .with_interface(self.inner.interface)
            .with_sd_endpoint(self.inner.endpoint);
        let unicast_socket = if config.local_port == 0 {
            SharedSocket::Own(
                TokioTransport
                    .bind(
                        SocketAddrV4::new(self.inner.interface, 0),
                        &SocketOptions::new(),
                    )
                    .await?,
            )
        } else {
            SharedSocket::Endpoint(
                self.endpoint_socket(config.local_port)
                    .await?
                    .tap(Serves::Service(config.service_id))?,
            )
        };
        let unicast_socket = Arc::new(unicast_socket);
        let publisher = Arc::new(EventPublisher::new(
            deps.subscriptions.clone(),
            Arc::clone(&unicast_socket),
            deps.e2e_registry.clone(),
        ));
        let storage = ServerStorage {
            factory: self.transport(),
            timer: deps.timer,
            e2e_registry: deps.e2e_registry,
            subscriptions: deps.subscriptions,
            unicast_socket,
            sd_socket: Arc::new(SharedSocket::Tap(self.tap(Origin::Both))),
            sd_state: Arc::new(SdStateManager::new()),
            publisher,
            started: Arc::new(AtomicBool::new(false)),
            non_sd_observer: deps.non_sd_observer,
            request_observer: deps.request_observer,
        };
        let server = Server::new_with_handles(storage, config)?;
        let handles = ServerHandles {
            publisher: server.publisher(),
        };
        let run = server.run();
        Ok((server, handles, run))
    }
}

/// A server served through [`SharedSd::serve`].
pub type SharedServer<R, Sub> = Server<
    SharedTransport,
    TokioTimer,
    R,
    Sub,
    Arc<SharedSocket>,
    Arc<SdStateManager>,
    SharedPublisher<R, Sub>,
>;

/// The publisher of a server served through [`SharedSd::serve`].
pub type SharedPublisher<R, Sub> = Arc<EventPublisher<R, Sub, Arc<SharedSocket>, SharedSocket>>;

/// Every datagram one socket receives, copied to every tap that admits it. Ends once the
/// shared sockets are gone.
async fn fan_out(inner: Weak<Inner>, from: Origin) {
    let mut buf = std::vec![0u8; MAX_DATAGRAM];
    loop {
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let socket = match from {
            Origin::Unicast => &inner.unicast,
            Origin::Multicast | Origin::Both => &inner.multicast,
        };
        let received = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                crate::log::warn!("shared SD socket ({:?}) failed: {:?}", from, e);
                return;
            }
        };
        let datagram = Arc::new(Datagram {
            bytes: buf[..received.bytes_received].to_vec(),
            source: received.source,
        });
        inner
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(origin, tap)| {
                if !origin.admits(from) {
                    return true;
                }
                match tap.try_send(Arc::clone(&datagram)) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        crate::log::warn!(
                            "SD tap behind: datagram from {} dropped",
                            datagram.source
                        );
                        true
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                }
            });
    }
}

/// Every datagram an endpoint socket receives, message by message: each to the tap serving the
/// message's service, else to the taps of the rest, else to the first tap, so that one server
/// answers for an unknown service. Ends once the socket is gone.
async fn fan_out_endpoint(endpoint: Weak<Endpoint>) {
    let mut buf = std::vec![0u8; MAX_DATAGRAM];
    loop {
        let Some(endpoint) = endpoint.upgrade() else {
            return;
        };
        let received = match endpoint.socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                crate::log::warn!("shared endpoint socket failed: {:?}", e);
                return;
            }
        };
        let mut taps = endpoint
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        taps.retain(|(_, tap)| !tap.is_closed());
        for (service, bytes) in messages(&buf[..received.bytes_received]) {
            let datagram = Arc::new(Datagram {
                bytes: bytes.to_vec(),
                source: received.source,
            });
            for tap in takers(&taps, service) {
                if let Err(mpsc::error::TrySendError::Full(_)) = tap.try_send(Arc::clone(&datagram))
                {
                    crate::log::warn!(
                        "endpoint tap behind: message from {} dropped",
                        datagram.source
                    );
                }
            }
        }
    }
}

/// The taps a message of `service` goes to.
fn takers(
    taps: &[(Serves, mpsc::Sender<Arc<Datagram>>)],
    service: Option<u16>,
) -> Vec<&mpsc::Sender<Arc<Datagram>>> {
    let served = service.and_then(|id| {
        taps.iter()
            .find(|(serves, _)| *serves == Serves::Service(id))
    });
    if let Some((_, tap)) = served {
        return std::vec![tap];
    }
    let rest: Vec<_> = taps
        .iter()
        .filter(|(serves, _)| *serves == Serves::Rest)
        .map(|(_, tap)| tap)
        .collect();
    if rest.is_empty() {
        taps.first().map(|(_, tap)| tap).into_iter().collect()
    } else {
        rest
    }
}

/// The SOME/IP messages of a datagram, each with its service id: a header's length counts the
/// bytes behind its first eight. What does not parse as one is one message of no service.
fn messages(datagram: &[u8]) -> Vec<(Option<u16>, &[u8])> {
    let mut messages = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let size = rest
            .get(4..8)
            .and_then(|len| {
                usize::try_from(u32::from_be_bytes([len[0], len[1], len[2], len[3]])).ok()
            })
            .and_then(|len| len.checked_add(8));
        match size {
            Some(size) if size >= 16 && size <= rest.len() => {
                let (message, behind) = rest.split_at(size);
                messages.push((Some(u16::from_be_bytes([message[0], message[1]])), message));
                rest = behind;
            }
            _ => {
                messages.push((None, rest));
                break;
            }
        }
    }
    messages
}

/// The next datagram a tap received, into `buf`.
async fn next_datagram(
    received: &tokio::sync::Mutex<mpsc::Receiver<Arc<Datagram>>>,
    buf: &mut [u8],
) -> Result<ReceivedDatagram, TransportError> {
    let mut received = received.lock().await;
    let Some(datagram) = received.recv().await else {
        return Err(TransportError::Io(IoErrorKind::Other));
    };
    let bytes_received = datagram.bytes.len().min(buf.len());
    buf[..bytes_received].copy_from_slice(&datagram.bytes[..bytes_received]);
    Ok(ReceivedDatagram {
        bytes_received,
        source: datagram.source,
        truncated: datagram.bytes.len() > buf.len(),
    })
}

/// One participant's view of the shared SD sockets.
pub struct SharedTap {
    inner: Arc<Inner>,
    received: tokio::sync::Mutex<mpsc::Receiver<Arc<Datagram>>>,
}

type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl TransportSocket for SharedTap {
    type SendFuture<'a> = BoxedFuture<'a, Result<(), TransportError>>;
    type RecvFuture<'a> = BoxedFuture<'a, Result<ReceivedDatagram, TransportError>>;

    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddrV4) -> Self::SendFuture<'a> {
        Box::pin(self.inner.unicast.send_to(buf, target))
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> Self::RecvFuture<'a> {
        Box::pin(next_datagram(&self.received, buf))
    }

    fn local_addr(&self) -> Result<SocketAddrV4, TransportError> {
        self.inner.unicast.local_addr()
    }

    /// The shared multicast socket joined the SD group when it was bound; nothing else is
    /// joined through a tap.
    fn join_multicast_v4(&self, _group: Ipv4Addr, _iface: Ipv4Addr) -> Result<(), TransportError> {
        Ok(())
    }

    fn leave_multicast_v4(&self, _group: Ipv4Addr, _iface: Ipv4Addr) -> Result<(), TransportError> {
        Ok(())
    }
}

/// One participant's view of a shared endpoint socket.
pub struct EndpointTap {
    endpoint: Arc<Endpoint>,
    received: tokio::sync::Mutex<mpsc::Receiver<Arc<Datagram>>>,
}

impl TransportSocket for EndpointTap {
    type SendFuture<'a> = BoxedFuture<'a, Result<(), TransportError>>;
    type RecvFuture<'a> = BoxedFuture<'a, Result<ReceivedDatagram, TransportError>>;

    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddrV4) -> Self::SendFuture<'a> {
        Box::pin(self.endpoint.socket.send_to(buf, target))
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> Self::RecvFuture<'a> {
        Box::pin(next_datagram(&self.received, buf))
    }

    fn local_addr(&self) -> Result<SocketAddrV4, TransportError> {
        self.endpoint.socket.local_addr()
    }

    fn join_multicast_v4(&self, group: Ipv4Addr, iface: Ipv4Addr) -> Result<(), TransportError> {
        self.endpoint.socket.join_multicast_v4(group, iface)
    }

    fn leave_multicast_v4(&self, group: Ipv4Addr, iface: Ipv4Addr) -> Result<(), TransportError> {
        self.endpoint.socket.leave_multicast_v4(group, iface)
    }
}

/// What [`SharedTransport`] binds: a tap on the SD port, a tap on a served endpoint port, a
/// socket of its own elsewhere.
pub enum SharedSocket {
    Tap(SharedTap),
    Endpoint(EndpointTap),
    Own(TokioSocket),
}

impl TransportSocket for SharedSocket {
    type SendFuture<'a> = BoxedFuture<'a, Result<(), TransportError>>;
    type RecvFuture<'a> = BoxedFuture<'a, Result<ReceivedDatagram, TransportError>>;

    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddrV4) -> Self::SendFuture<'a> {
        match self {
            Self::Tap(tap) => tap.send_to(buf, target),
            Self::Endpoint(tap) => tap.send_to(buf, target),
            Self::Own(socket) => Box::pin(socket.send_to(buf, target)),
        }
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> Self::RecvFuture<'a> {
        match self {
            Self::Tap(tap) => tap.recv_from(buf),
            Self::Endpoint(tap) => tap.recv_from(buf),
            Self::Own(socket) => Box::pin(socket.recv_from(buf)),
        }
    }

    fn local_addr(&self) -> Result<SocketAddrV4, TransportError> {
        match self {
            Self::Tap(tap) => tap.local_addr(),
            Self::Endpoint(tap) => tap.local_addr(),
            Self::Own(socket) => socket.local_addr(),
        }
    }

    fn join_multicast_v4(&self, group: Ipv4Addr, iface: Ipv4Addr) -> Result<(), TransportError> {
        match self {
            Self::Tap(tap) => tap.join_multicast_v4(group, iface),
            Self::Endpoint(tap) => tap.join_multicast_v4(group, iface),
            Self::Own(socket) => socket.join_multicast_v4(group, iface),
        }
    }

    fn leave_multicast_v4(&self, group: Ipv4Addr, iface: Ipv4Addr) -> Result<(), TransportError> {
        match self {
            Self::Tap(tap) => tap.leave_multicast_v4(group, iface),
            Self::Endpoint(tap) => tap.leave_multicast_v4(group, iface),
            Self::Own(socket) => socket.leave_multicast_v4(group, iface),
        }
    }
}

/// A transport factory over the shared sockets: a bind on the SD port is a tap, a multicast one
/// on the unspecified address and a unicast one on an interface; a bind on a port a server is
/// served on is a tap of that endpoint socket, for the messages of the services none of them
/// serves; any other bind is a socket of its own.
#[derive(Clone)]
pub struct SharedTransport {
    shared: SharedSd,
}

impl TransportFactory for SharedTransport {
    type Socket = SharedSocket;
    type BindFuture<'a> = BoxedFuture<'a, Result<SharedSocket, TransportError>>;

    fn bind<'a>(&'a self, addr: SocketAddrV4, options: &'a SocketOptions) -> Self::BindFuture<'a> {
        Box::pin(async move {
            if addr.port() == self.shared.inner.endpoint.port() {
                let origin = if addr.ip().is_unspecified() {
                    Origin::Multicast
                } else {
                    Origin::Unicast
                };
                return Ok(SharedSocket::Tap(self.shared.tap(origin)));
            }
            if addr.port() != 0 {
                let endpoints = self.shared.inner.endpoints.lock().await;
                if let Some(endpoint) = endpoints.get(&addr.port()) {
                    return endpoint.tap(Serves::Rest).map(SharedSocket::Endpoint);
                }
            }
            TokioTransport
                .bind(addr, options)
                .await
                .map(SharedSocket::Own)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port no other test binds, so the taps see this test's datagrams alone.
    const PORT: u16 = 30497;

    async fn next<T: TransportSocket>(tap: &T) -> (Vec<u8>, SocketAddrV4) {
        let mut buf = [0u8; 64];
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(2), tap.recv_from(&mut buf))
                .await
                .expect("a datagram within two seconds")
                .expect("received");
        (buf[..received.bytes_received].to_vec(), received.source)
    }

    #[tokio::test]
    async fn a_unicast_datagram_reaches_the_taps_that_admit_unicast() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 251), PORT).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let unicast = shared.tap(Origin::Unicast);
        let both = shared.tap(Origin::Both);
        let multicast = shared.tap(Origin::Multicast);

        let peer = tokio::net::UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .unwrap();
        peer.send_to(b"hello", (Ipv4Addr::LOCALHOST, PORT))
            .await
            .unwrap();
        let from = match peer.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => unreachable!(),
        };

        assert_eq!(next(&unicast).await, (b"hello".to_vec(), from));
        assert_eq!(next(&both).await, (b"hello".to_vec(), from));
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                multicast.recv_from(&mut buf)
            )
            .await
            .is_err(),
            "the multicast tap admits no unicast datagram"
        );
        assert_eq!(
            unicast.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT)
        );
    }

    /// A SOME/IP message of `service`, method 1, with `payload`.
    fn message(service: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = service.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0, 1]);
        bytes.extend_from_slice(&(8 + u32::try_from(payload.len()).unwrap()).to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 1, 1, 1, 0, 0]);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[tokio::test]
    async fn an_endpoint_hands_each_message_to_the_tap_serving_its_service() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 249), PORT + 2).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let port = PORT + 3;
        let one = shared
            .endpoint_socket(port)
            .await
            .unwrap()
            .tap(Serves::Service(1))
            .unwrap();
        let two = shared
            .endpoint_socket(port)
            .await
            .unwrap()
            .tap(Serves::Service(2))
            .unwrap();
        let rest = shared
            .transport()
            .bind(
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
                &SocketOptions::new(),
            )
            .await
            .unwrap();
        assert!(
            matches!(rest, SharedSocket::Endpoint(_)),
            "a bind on a served port taps its socket"
        );
        assert!(
            matches!(
                shared
                    .endpoint_socket(port)
                    .await
                    .unwrap()
                    .tap(Serves::Service(1)),
                Err(TransportError::AddressInUse)
            ),
            "a second instance of one service on the port is refused"
        );

        let peer = tokio::net::UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .unwrap();
        let std::net::SocketAddr::V4(from) = peer.local_addr().unwrap() else {
            unreachable!()
        };
        let mut datagram = message(1, b"one");
        datagram.extend(message(2, b"two"));
        datagram.extend(message(9, b"nine"));
        peer.send_to(&datagram, (Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();

        assert_eq!(next(&one).await, (message(1, b"one"), from));
        assert_eq!(next(&two).await, (message(2, b"two"), from));
        assert_eq!(next(&rest).await, (message(9, b"nine"), from));
        assert_eq!(
            one.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
        );
    }

    #[test]
    fn what_is_no_message_is_one_message_of_no_service() {
        assert_eq!(messages(b"short"), std::vec![(None, b"short".as_slice())]);
        let mut datagram = message(3, b"x");
        datagram.extend_from_slice(b"junk");
        assert_eq!(
            messages(&datagram),
            std::vec![
                (Some(3), message(3, b"x").as_slice()),
                (None, b"junk".as_slice())
            ]
        );
    }

    #[tokio::test]
    async fn a_tap_sends_from_the_shared_unicast_socket() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 250), PORT + 1).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let tap = shared.tap(Origin::Both);
        let peer = tokio::net::UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .unwrap();
        let std::net::SocketAddr::V4(peer_addr) = peer.local_addr().unwrap() else {
            unreachable!()
        };

        tap.send_to(b"offer", peer_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"offer");
        assert_eq!(
            from,
            std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT + 1))
        );
    }
}
