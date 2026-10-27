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

use std::boxed::Box;
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

    /// Serve a service through the shared SD sockets: the server's unicast socket is its own,
    /// bound on this interface at `config.local_port`, and its SD socket is a tap of both
    /// origins. `config`'s interface and SD endpoint are the shared sockets'.
    ///
    /// # Errors
    ///
    /// When the unicast socket cannot be bound.
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
        let unicast = TokioTransport
            .bind(
                SocketAddrV4::new(self.inner.interface, config.local_port),
                &SocketOptions::new(),
            )
            .await?;
        let unicast_socket = Arc::new(SharedSocket::Own(unicast));
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
        Box::pin(async move {
            let mut received = self.received.lock().await;
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
        })
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

/// What [`SharedTransport`] binds: a tap on the SD port, a socket of its own elsewhere.
pub enum SharedSocket {
    Tap(SharedTap),
    Own(TokioSocket),
}

impl TransportSocket for SharedSocket {
    type SendFuture<'a> = BoxedFuture<'a, Result<(), TransportError>>;
    type RecvFuture<'a> = BoxedFuture<'a, Result<ReceivedDatagram, TransportError>>;

    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddrV4) -> Self::SendFuture<'a> {
        match self {
            Self::Tap(tap) => tap.send_to(buf, target),
            Self::Own(socket) => Box::pin(socket.send_to(buf, target)),
        }
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> Self::RecvFuture<'a> {
        match self {
            Self::Tap(tap) => tap.recv_from(buf),
            Self::Own(socket) => Box::pin(socket.recv_from(buf)),
        }
    }

    fn local_addr(&self) -> Result<SocketAddrV4, TransportError> {
        match self {
            Self::Tap(tap) => tap.local_addr(),
            Self::Own(socket) => socket.local_addr(),
        }
    }

    fn join_multicast_v4(&self, group: Ipv4Addr, iface: Ipv4Addr) -> Result<(), TransportError> {
        match self {
            Self::Tap(tap) => tap.join_multicast_v4(group, iface),
            Self::Own(socket) => socket.join_multicast_v4(group, iface),
        }
    }

    fn leave_multicast_v4(&self, group: Ipv4Addr, iface: Ipv4Addr) -> Result<(), TransportError> {
        match self {
            Self::Tap(tap) => tap.leave_multicast_v4(group, iface),
            Self::Own(socket) => socket.leave_multicast_v4(group, iface),
        }
    }
}

/// A transport factory over the shared SD sockets: a bind on the SD port is a tap, a multicast
/// one on the unspecified address and a unicast one on an interface; any other bind is a socket
/// of its own.
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

    async fn next(tap: &SharedTap) -> (Vec<u8>, SocketAddrV4) {
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
