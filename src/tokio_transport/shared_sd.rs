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
//! unspecified address gets a multicast tap, the one on the interface a unicast tap, a bind on
//! a fixed port an endpoint tap, and a bind on port 0 its own socket.
//!
//! The endpoint sockets are shared too, as different services share one port
//! (`feat_req_someip_445`): every server served on a `local_port` takes an [`EndpointTap`] on the
//! interface's socket on that port, which receives the requests to its service, and a client
//! bind on the port takes one for the responses and events of the services it consumes,
//! whichever comes first. Two instances of one service listen on different ports
//! (`feat_req_someip_648`), so a second one on a port is refused.

use std::boxed::Box;
use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;
use std::vec::Vec;

use tokio::sync::mpsc;

use super::{TokioSocket, TokioTimer, TokioTransport};
use crate::Encode;
use crate::protocol::sd::{self, Entry, EntryType, Flags, OptionsCount, SdEndpoint};
use crate::protocol::{Header as SomeIpHeader, MessageView};
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
/// How many receive errors in a row, none of them transient, end a worker.
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 16;

/// A worker's run of receive errors. A transient one, such as an ICMP port unreachable, is
/// passed over; a run of [`MAX_CONSECUTIVE_RECV_ERRORS`] others ends the worker.
#[derive(Default)]
struct RecvErrors(u32);

impl RecvErrors {
    /// Whether the worker gives up after `error`.
    fn give_up(&mut self, error: TransportError) -> bool {
        if matches!(error, TransportError::Io(kind) if kind.is_transient_recv()) {
            return false;
        }
        self.0 += 1;
        self.0 >= MAX_CONSECUTIVE_RECV_ERRORS
    }
}

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
    /// What the servers served on these sockets offer, each while its server lives.
    offered: Mutex<Vec<Offered>>,
    /// The endpoint sockets by port, while a participant holds them.
    endpoints: tokio::sync::Mutex<HashMap<u16, Weak<Endpoint>>>,
    /// The session id and reboot flag of every SD message sent from the unicast socket.
    session: SdStateManager,
    /// Held from taking a session id to sending the message, so that the ids go out in order.
    sending: tokio::sync::Mutex<()>,
    workers: Workers,
}

/// A service instance a server served on the shared sockets offers, while the server holds its
/// SD socket.
struct Offered {
    service: u16,
    instance: u16,
    by: Weak<SharedSocket>,
}

impl Inner {
    /// Notes what the server `config` describes offers, its own instance and its accepted
    /// offers, for as long as it holds `sd_socket`.
    fn offer(&self, config: &ServerConfig, sd_socket: &Arc<SharedSocket>) {
        let by = Arc::downgrade(sd_socket);
        let mut offered = self
            .offered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        offered.push(Offered {
            service: config.service_id,
            instance: config.instance_id,
            by: by.clone(),
        });
        for offer in &config.accepted_offers {
            offered.push(Offered {
                service: offer.service_id,
                instance: offer.instance_id,
                by: by.clone(),
            });
        }
    }

    /// Refuses, for the servers, every subscription in `datagram` to a service instance none of
    /// them offers: each server leaves a subscription to another instance to the others, so
    /// without this nobody would answer it and the subscriber would wait out its TTL.
    async fn refuse_unoffered(&self, datagram: &[u8], subscriber: SocketAddrV4) {
        let refused = self.unoffered_subscriptions(datagram);
        if refused.is_empty() {
            return;
        }
        let nack = sd::Header::new(Flags::new_sd(sd::RebootFlag::Continuous), &refused, &[]);
        let mut payload = Vec::new();
        let mut message = Vec::new();
        if nack.encode(&mut payload).is_err()
            || SomeIpHeader::new_sd(0, payload.len())
                .encode(&mut message)
                .is_err()
        {
            return;
        }
        message.extend_from_slice(&payload);
        let Some(stamped) = self.stamped(&message) else {
            return;
        };
        let _sending = self.sending.lock().await;
        if let Err(e) = self.unicast.send_to(&stamped, subscriber).await {
            crate::log::warn!("SubscribeNack to {} not sent: {:?}", subscriber, e);
        }
    }

    /// The subscriptions in `datagram`, an SD message, to service instances no living server
    /// offers, each as the entry that refuses it. None while no server is served.
    fn unoffered_subscriptions(&self, datagram: &[u8]) -> Vec<Entry> {
        let Ok(sd_view) = MessageView::parse(datagram).and_then(|view| view.sd_header()) else {
            return Vec::new();
        };
        let mut offered = self
            .offered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        offered.retain(|offer| offer.by.strong_count() > 0);
        if offered.is_empty() {
            return Vec::new();
        }
        sd_view
            .entries()
            .filter(|entry| entry.entry_type().ok() == Some(EntryType::Subscribe))
            .filter(|entry| entry.ttl() != 0)
            .filter(|entry| {
                !offered.iter().any(|offer| {
                    offer.service == entry.service_id() && offer.instance == entry.instance_id()
                })
            })
            .map(|entry| {
                Entry::SubscribeAckEventGroup(sd::EventGroupEntry {
                    index_first_options_run: 0,
                    index_second_options_run: 0,
                    options_count: OptionsCount::new(0, 0),
                    service_id: entry.service_id(),
                    instance_id: entry.instance_id(),
                    major_version: entry.major_version(),
                    ttl: 0,
                    counter: entry.counter(),
                    event_group_id: entry.event_group_id(),
                })
            })
            .collect()
    }

    /// `message` with the next session id and the reboot flag of the shared socket, when it is
    /// an SD message. A peer detects a reboot from the session ids and reboot flags of a sender
    /// address, and the participants' own counters, interleaved, would look like one.
    fn stamped(&self, message: &[u8]) -> Option<Vec<u8>> {
        const SD_MESSAGE_ID: [u8; 4] = [0xFF, 0xFF, 0x81, 0x00];
        const FLAGS: usize = 16;
        const REBOOT: u8 = 0x80;
        if message.len() <= FLAGS || message[..4] != SD_MESSAGE_ID {
            return None;
        }
        let (request_id, reboot) = self.session.next_session_id_with_reboot_flag();
        let mut stamped = message.to_vec();
        stamped[8..12].copy_from_slice(&request_id.to_be_bytes());
        if bool::from(reboot) {
            stamped[FLAGS] |= REBOOT;
        } else {
            stamped[FLAGS] &= !REBOOT;
        }
        Some(stamped)
    }
}

/// The receive workers of the sockets' owner, cancelled when it drops. A worker holds its owner
/// only while it polls the socket, so the sockets close when their last participant drops them.
#[derive(Default)]
struct Workers(Mutex<Vec<tokio::task::AbortHandle>>);

impl Workers {
    fn add(&self, worker: tokio::task::AbortHandle) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(worker);
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        let workers = self
            .0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for worker in workers.iter() {
            worker.abort();
        }
    }
}

/// The next datagram on `socket` of `owner`, holding `owner` only while polling; `None` once
/// it is gone.
async fn receive<O>(
    owner: &Weak<O>,
    socket: fn(&O) -> &TokioSocket,
    buf: &mut [u8],
) -> Option<(Arc<O>, Result<ReceivedDatagram, TransportError>)> {
    std::future::poll_fn(|cx| {
        let Some(owner) = owner.upgrade() else {
            return Poll::Ready(None);
        };
        let polled = Pin::new(&mut socket(&owner).recv_from(&mut *buf)).poll(cx);
        polled.map(|received| Some((owner, received)))
    })
    .await
}

/// Which messages a tap on an endpoint socket receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serves {
    /// The requests to one service: a server's.
    Service(u16),
    /// The responses, errors and events: a client's, of the services it consumes.
    Rest,
}

/// What an endpoint socket hands on: a message with its service, and whether it is a request,
/// which goes to the service's server, or a response, error or event, which goes to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Addressed {
    service: u16,
    request: bool,
}

/// One endpoint socket of the interface, shared by the servers and the client on its port.
struct Endpoint {
    socket: TokioSocket,
    taps: Mutex<Vec<(Serves, mpsc::Sender<Arc<Datagram>>)>>,
    workers: Workers,
}

impl Endpoint {
    /// A tap for `serves`. A second server of one service on the socket is refused: the
    /// service's instances listen on different ports. A second client is refused too: the
    /// responses are told apart only by their client id, which tells clients apart only within
    /// one (`feat_req_someip_699`), and every client here has the same. A dropped participant's
    /// tap is no participant.
    fn tap(self: &Arc<Self>, serves: Serves) -> Result<EndpointTap, TransportError> {
        self.tap_all(&[serves])
    }

    /// One tap for everything in `serves`: a server offering several services takes the requests
    /// to each.
    fn tap_all(self: &Arc<Self>, serves: &[Serves]) -> Result<EndpointTap, TransportError> {
        let mut taps = self
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        taps.retain(|(_, tap)| !tap.is_closed());
        if taps.iter().any(|(taken, _)| serves.contains(taken)) {
            return Err(TransportError::AddressInUse);
        }
        let (sender, received) = mpsc::channel(TAP_DEPTH);
        for serves in serves {
            taps.push((*serves, sender.clone()));
        }
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
            offered: Mutex::new(Vec::new()),
            endpoints: tokio::sync::Mutex::new(HashMap::new()),
            session: SdStateManager::new(),
            sending: tokio::sync::Mutex::new(()),
            workers: Workers::default(),
        });
        for origin in [Origin::Unicast, Origin::Multicast] {
            let worker = tokio::spawn(fan_out(Arc::downgrade(&inner), origin));
            inner.workers.add(worker.abort_handle());
        }
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
    /// unicast socket. A dropped participant's tap is no participant.
    #[must_use]
    pub fn tap(&self, origin: Origin) -> SharedTap {
        let (sender, received) = mpsc::channel(TAP_DEPTH);
        let mut taps = self
            .inner
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        taps.retain(|(_, tap)| !tap.is_closed());
        taps.push((origin, sender));
        drop(taps);
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
        if let Some(endpoint) = endpoints.get(&port).and_then(Weak::upgrade) {
            return Ok(endpoint);
        }
        endpoints.retain(|_, endpoint| endpoint.strong_count() > 0);
        let socket = TokioTransport
            .bind(
                SocketAddrV4::new(self.inner.interface, port),
                &SocketOptions::new(),
            )
            .await?;
        let endpoint = Arc::new(Endpoint {
            socket,
            taps: Mutex::new(Vec::new()),
            workers: Workers::default(),
        });
        let worker = tokio::spawn(fan_out_endpoint(Arc::downgrade(&endpoint)));
        endpoint.workers.add(worker.abort_handle());
        endpoints.insert(port, Arc::downgrade(&endpoint));
        Ok(endpoint)
    }

    /// Serve a service through the shared sockets: the server's SD socket is a tap of both
    /// origins, on which it leaves the subscriptions to other services to their servers, and its
    /// unicast socket the interface's endpoint socket on `config.local_port`, shared with the
    /// other services served there and a client consuming through it; on port 0 it is a socket
    /// of its own. `config`'s interface and SD endpoint are the shared sockets'.
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
            .with_sd_endpoint(self.inner.endpoint)
            .with_other_services_nacked(false);
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
            let mut services = std::vec![Serves::Service(config.service_id)];
            for offer in &config.accepted_offers {
                let service = Serves::Service(offer.service_id);
                if !services.contains(&service) {
                    services.push(service);
                }
            }
            SharedSocket::Endpoint(
                self.endpoint_socket(config.local_port)
                    .await?
                    .tap_all(&services)?,
            )
        };
        let unicast_socket = Arc::new(unicast_socket);
        let sd_socket = Arc::new(SharedSocket::Tap(self.tap(Origin::Both)));
        self.inner.offer(&config, &sd_socket);
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
            sd_socket,
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
    let socket: fn(&Inner) -> &TokioSocket = match from {
        Origin::Unicast => |inner| &inner.unicast,
        Origin::Multicast | Origin::Both => |inner| &inner.multicast,
    };
    let mut errors = RecvErrors::default();
    loop {
        let Some((inner, received)) = receive(&inner, socket, &mut buf).await else {
            return;
        };
        let received = match received {
            Ok(received) => {
                errors = RecvErrors::default();
                received
            }
            Err(e) => {
                crate::log::warn!("shared SD socket ({:?}) failed: {:?}", from, e);
                if errors.give_up(e) {
                    // Closing the taps that admit this socket tells their participants.
                    inner
                        .taps
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .retain(|(origin, _)| !origin.admits(from));
                    return;
                }
                continue;
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
        inner
            .refuse_unoffered(&datagram.bytes, datagram.source)
            .await;
    }
}

/// Every datagram an endpoint socket receives, message by message, each to its [`takers`]. Ends
/// once the socket is gone.
async fn fan_out_endpoint(endpoint: Weak<Endpoint>) {
    let mut buf = std::vec![0u8; MAX_DATAGRAM];
    let mut errors = RecvErrors::default();
    loop {
        let Some((endpoint, received)) =
            receive(&endpoint, |endpoint| &endpoint.socket, &mut buf).await
        else {
            return;
        };
        let received = match received {
            Ok(received) => {
                errors = RecvErrors::default();
                received
            }
            Err(e) => {
                crate::log::warn!("shared endpoint socket failed: {:?}", e);
                if errors.give_up(e) {
                    // Closing the taps tells their participants.
                    endpoint
                        .taps
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clear();
                    return;
                }
                continue;
            }
        };
        let mut taps = endpoint
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        taps.retain(|(_, tap)| !tap.is_closed());
        for (addressed, bytes) in messages(&buf[..received.bytes_received]) {
            let datagram = Arc::new(Datagram {
                bytes: bytes.to_vec(),
                source: received.source,
            });
            for tap in takers(&taps, addressed) {
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

/// The taps a message goes to. A request goes to the server of its service, else to any server,
/// so that one answers it with `E_UNKNOWN_SERVICE`. A response, error or event goes to the clients,
/// so that a client consuming a service that a server on the port offers too gets its answers.
/// What is no message goes to the clients. A message no tap of its kind takes goes to the
/// first tap.
fn takers(
    taps: &[(Serves, mpsc::Sender<Arc<Datagram>>)],
    addressed: Option<Addressed>,
) -> Vec<&mpsc::Sender<Arc<Datagram>>> {
    let of = |wanted: &dyn Fn(Serves) -> bool| -> Vec<_> {
        taps.iter()
            .filter(|(serves, _)| wanted(*serves))
            .map(|(_, tap)| tap)
            .collect()
    };
    let chosen = match addressed {
        Some(Addressed {
            service,
            request: true,
        }) => {
            let served = of(&|serves| serves == Serves::Service(service));
            if served.is_empty() {
                of(&|serves| serves != Serves::Rest)
                    .into_iter()
                    .take(1)
                    .collect()
            } else {
                served
            }
        }
        _ => of(&|serves| serves == Serves::Rest),
    };
    if chosen.is_empty() {
        taps.first().map(|(_, tap)| tap).into_iter().collect()
    } else {
        chosen
    }
}

/// The message type values of a request: `REQUEST` and `REQUEST_NO_RETURN`, alone or with the
/// TP flag.
fn is_request(message_type: u8) -> bool {
    matches!(message_type & !0x20, 0x00 | 0x01)
}

/// The SOME/IP messages of a datagram, each with where it goes: a header's length counts the
/// bytes behind its first eight. Fewer bytes than a header behind the last message are padding
/// and go nowhere. What else does not parse as a message is one message going nowhere in
/// particular.
fn messages(datagram: &[u8]) -> Vec<(Option<Addressed>, &[u8])> {
    const HEADER: usize = 16;
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
            Some(size) if size >= HEADER && size <= rest.len() => {
                let (message, behind) = rest.split_at(size);
                let addressed = Addressed {
                    service: u16::from_be_bytes([message[0], message[1]]),
                    request: is_request(message[14]),
                };
                messages.push((Some(addressed), message));
                rest = behind;
            }
            _ if !messages.is_empty() && rest.len() < HEADER => break,
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

    /// Sends `buf` from the unicast socket; an SD message with the socket's session id and
    /// reboot flag in place of the participant's.
    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddrV4) -> Self::SendFuture<'a> {
        Box::pin(async move {
            let _sending = self.inner.sending.lock().await;
            match self.inner.stamped(buf) {
                Some(stamped) => self.inner.unicast.send_to(&stamped, target).await,
                None => self.inner.unicast.send_to(buf, target).await,
            }
        })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> Self::RecvFuture<'a> {
        Box::pin(next_datagram(&self.received, buf))
    }

    fn local_addr(&self) -> Result<SocketAddrV4, TransportError> {
        self.inner.unicast.local_addr()
    }

    /// The shared multicast socket joined the SD group on the interface when it was bound;
    /// joining that again is a no-op, and any other group or interface is
    /// [`TransportError::Unsupported`], as the tap could not receive it.
    fn join_multicast_v4(&self, group: Ipv4Addr, iface: Ipv4Addr) -> Result<(), TransportError> {
        if group == self.inner.endpoint.group() && iface == self.inner.interface {
            Ok(())
        } else {
            Err(TransportError::Unsupported)
        }
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

    /// Refused: the endpoint socket is bound to the interface's address, so it never receives
    /// what is sent to a group, and joining one would only look like it worked.
    fn join_multicast_v4(&self, _group: Ipv4Addr, _iface: Ipv4Addr) -> Result<(), TransportError> {
        Err(TransportError::Unsupported)
    }

    fn leave_multicast_v4(&self, _group: Ipv4Addr, _iface: Ipv4Addr) -> Result<(), TransportError> {
        Ok(())
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
/// on the unspecified address and a unicast one on an interface; a bind on another fixed port is
/// a tap of the interface's endpoint socket on that port, for the responses and events of the
/// services the client consumes; a bind on port 0 is a socket of its own.
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
                return self
                    .shared
                    .endpoint_socket(addr.port())
                    .await?
                    .tap(Serves::Rest)
                    .map(SharedSocket::Endpoint);
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
    const PORT: u16 = 31497;

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

    /// A SOME/IP request to `service`, method 1, with `payload`.
    fn message(service: u16, payload: &[u8]) -> Vec<u8> {
        typed(service, 0x00, payload)
    }

    /// A SOME/IP message of `service`, method 1, of `message_type`, with `payload`.
    fn typed(service: u16, message_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = service.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0, 1]);
        bytes.extend_from_slice(&(8 + u32::try_from(payload.len()).unwrap()).to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 1, 1, 1, message_type, 0]);
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
        datagram.extend(typed(1, 0x80, b"answer"));
        datagram.extend(typed(2, 0x02, b"event"));
        datagram.extend(message(9, b"nine"));
        peer.send_to(&datagram, (Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();

        assert_eq!(next(&one).await, (message(1, b"one"), from));
        assert_eq!(next(&two).await, (message(2, b"two"), from));
        assert_eq!(
            next(&rest).await,
            (typed(1, 0x80, b"answer"), from),
            "a response goes to the client, though a server on the port offers its service"
        );
        assert_eq!(next(&rest).await, (typed(2, 0x02, b"event"), from));
        assert_eq!(
            next(&one).await,
            (message(9, b"nine"), from),
            "a request to a service no one serves goes to a server"
        );
        assert_eq!(
            one.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
        );
    }

    #[tokio::test]
    async fn a_service_is_served_on_a_port_a_client_bound_first() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 244), PORT + 8).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let port = PORT + 9;
        let client = shared
            .transport()
            .bind(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
                &SocketOptions::new(),
            )
            .await
            .unwrap();
        assert!(matches!(client, SharedSocket::Endpoint(_)));

        let server = shared
            .endpoint_socket(port)
            .await
            .unwrap()
            .tap(Serves::Service(1))
            .expect("the server taps the client's socket");

        assert_eq!(
            server.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
        );
    }

    /// A subscription in SD to a service instance none of the served servers offers.
    fn subscription(service: u16, instance: u16, subscriber_port: u16) -> Vec<u8> {
        let entries = [Entry::SubscribeEventGroup(sd::EventGroupEntry::new(
            service, instance, 1, 3, 0x01,
        ))];
        let options = [sd::Options::IpV4Endpoint {
            ip: Ipv4Addr::LOCALHOST,
            protocol: sd::TransportProtocol::Udp,
            port: subscriber_port,
        }];
        let header = sd::Header::new(
            Flags::new_sd(sd::RebootFlag::RecentlyRebooted),
            &entries,
            &options,
        );
        let mut payload = Vec::new();
        header.encode(&mut payload).unwrap();
        let mut message = Vec::new();
        SomeIpHeader::new_sd(1, payload.len())
            .encode(&mut message)
            .unwrap();
        message.extend_from_slice(&payload);
        message
    }

    /// The service and TTL of the first entry of the next SD message `subscriber` receives: a
    /// TTL of zero is a Nack.
    async fn answered(subscriber: &tokio::net::UdpSocket) -> (u16, u32) {
        let mut buf = [0u8; 256];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            subscriber.recv_from(&mut buf),
        )
        .await
        .expect("an answer within two seconds")
        .unwrap();
        let view = MessageView::parse(&buf[..len]).unwrap();
        let sd_view = view.sd_header().unwrap();
        let entry = sd_view.entries().next().expect("an entry");
        assert_eq!(entry.entry_type().unwrap(), EntryType::SubscribeAck);
        (entry.service_id(), entry.ttl())
    }

    async fn nothing_more(subscriber: &tokio::net::UdpSocket) -> bool {
        let mut buf = [0u8; 256];
        tokio::time::timeout(
            std::time::Duration::from_millis(300),
            subscriber.recv_from(&mut buf),
        )
        .await
        .is_err()
    }

    /// Servers on the shared sockets leave a subscription to another service to its server. One
    /// to an instance none of them offers is refused once, by the shared socket, so that the
    /// subscriber does not wait out its TTL.
    #[tokio::test]
    async fn a_subscription_to_an_instance_no_server_offers_is_refused_once() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 237), PORT + 17).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let mut servers = Vec::new();
        for service in [0x5B, 0x5C] {
            let (server, _handles, run) = shared
                .serve(ServerDeps::tokio(), ServerConfig::new(service, 1))
                .await
                .unwrap();
            tokio::spawn(run);
            servers.push(server);
        }
        let subscriber = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let subscriber_port = subscriber.local_addr().unwrap().port();
        let sd_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT + 17);

        for (service, instance) in [(0x5B, 2), (0x99, 1)] {
            subscriber
                .send_to(
                    &subscription(service, instance, subscriber_port),
                    sd_address,
                )
                .await
                .unwrap();
            assert_eq!(answered(&subscriber).await, (service, 0));
        }
        assert!(nothing_more(&subscriber).await, "one Nack per subscription");

        subscriber
            .send_to(&subscription(0x5C, 1, subscriber_port), sd_address)
            .await
            .unwrap();
        let (service, ttl) = answered(&subscriber).await;
        assert_eq!(service, 0x5C);
        assert_ne!(ttl, 0, "its server acknowledges it");
        assert!(nothing_more(&subscriber).await, "nobody refuses it");
    }

    #[tokio::test]
    async fn a_dropped_participants_tap_is_not_kept() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 242), PORT + 11).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let _kept = shared.tap(Origin::Both);
        for _ in 0..10 {
            drop(shared.tap(Origin::Unicast));
        }

        let _taken = shared.tap(Origin::Multicast);

        let taps = shared.inner.taps.lock().unwrap().len();
        assert_eq!(taps, 2);
    }

    /// A client that moves its SD endpoint to another port binds its multicast discovery
    /// socket there, which is a tap of the endpoint socket bound to the interface's address: it
    /// cannot receive what is sent to a group, so joining one is refused and the move fails.
    #[tokio::test]
    async fn an_endpoint_tap_refuses_to_join_a_group() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 236), PORT + 15).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let discovery = shared
            .transport()
            .bind(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT + 16),
                &SocketOptions::new(),
            )
            .await
            .unwrap();

        assert!(matches!(
            discovery.join_multicast_v4(Ipv4Addr::new(239, 255, 0, 235), Ipv4Addr::LOCALHOST),
            Err(TransportError::Unsupported)
        ));
    }

    #[tokio::test]
    async fn a_second_client_on_the_port_is_refused_until_the_first_drops() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 240), PORT + 13).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let socket = shared.endpoint_socket(PORT + 14).await.unwrap();
        let client = socket.tap(Serves::Rest).unwrap();

        assert!(matches!(
            socket.tap(Serves::Rest),
            Err(TransportError::AddressInUse)
        ));
        drop(client);
        assert!(socket.tap(Serves::Rest).is_ok());
    }

    #[tokio::test]
    async fn a_dropped_servers_service_can_be_served_again_on_the_port() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 248), PORT + 4).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let port = PORT + 5;
        let socket = shared.endpoint_socket(port).await.unwrap();
        let _client = socket.tap(Serves::Rest).unwrap();

        drop(socket.tap(Serves::Service(1)).unwrap());

        assert!(socket.tap(Serves::Service(1)).is_ok());
    }

    /// Plain sockets without address reuse bind only once nothing else holds the address.
    fn bind_alone(port: u16) -> std::io::Result<std::net::UdpSocket> {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
    }

    #[tokio::test]
    async fn the_sockets_close_with_their_last_participant() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 245), PORT + 6).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let port = PORT + 7;
        let server = shared
            .endpoint_socket(port)
            .await
            .unwrap()
            .tap(Serves::Service(1))
            .unwrap();
        let tap = shared.tap(Origin::Both);
        tokio::task::yield_now().await;
        drop(shared);
        assert!(bind_alone(PORT + 6).is_err(), "the tap holds the SD socket");
        assert!(bind_alone(port).is_err(), "the server holds the endpoint");

        drop(server);
        assert!(bind_alone(port).is_ok(), "the endpoint socket is closed");
        drop(tap);
        assert!(bind_alone(PORT + 6).is_ok(), "the SD sockets are closed");
    }

    /// An SD message's first 17 bytes: the header with `session`, and the flags with the
    /// reboot flag as `rebooted`.
    fn sd_message(session: u16, rebooted: bool) -> Vec<u8> {
        let mut bytes = std::vec![0xFF, 0xFF, 0x81, 0x00, 0, 0, 0, 12, 0, 0];
        bytes.extend_from_slice(&session.to_be_bytes());
        bytes.extend_from_slice(&[1, 1, 0x02, 0x00]);
        bytes.extend_from_slice(&[if rebooted { 0xC0 } else { 0x40 }, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes
    }

    #[tokio::test]
    async fn the_participants_sd_messages_carry_one_session() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 243), PORT + 10).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let server = shared.tap(Origin::Both);
        let client = shared.tap(Origin::Unicast);
        let peer = tokio::net::UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .unwrap();
        let std::net::SocketAddr::V4(peer_addr) = peer.local_addr().unwrap() else {
            unreachable!()
        };

        server
            .send_to(&sd_message(5, false), peer_addr)
            .await
            .unwrap();
        client
            .send_to(&sd_message(120, false), peer_addr)
            .await
            .unwrap();
        server.send_to(b"no SD message", peer_addr).await.unwrap();

        let mut sessions = Vec::new();
        for _ in 0..2 {
            let mut buf = [0u8; 64];
            let (n, _) = peer.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 24);
            assert_eq!(buf[16] & 0x80, 0x80, "a fresh socket has recently rebooted");
            assert_eq!(buf[16] & 0x40, 0x40, "the other flags are kept");
            sessions.push(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]));
        }
        assert_eq!(sessions[1], sessions[0] + 1);
        let mut buf = [0u8; 64];
        let (n, _) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"no SD message");
    }

    #[tokio::test]
    async fn the_session_goes_out_in_the_order_the_sd_messages_are_sent() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 241), PORT + 12).unwrap();
        let shared = SharedSd::bind(Ipv4Addr::LOCALHOST, endpoint, true)
            .await
            .unwrap();
        let server = shared.tap(Origin::Both);
        let client = shared.tap(Origin::Unicast);
        let peer = tokio::net::UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .unwrap();
        let std::net::SocketAddr::V4(peer_addr) = peer.local_addr().unwrap() else {
            unreachable!()
        };
        let message = sd_message(1, false);

        let first = server.send_to(&message, peer_addr);
        let second = client.send_to(&message, peer_addr);
        second.await.unwrap();
        first.await.unwrap();

        let mut sessions = Vec::new();
        for _ in 0..2 {
            let mut buf = [0u8; 64];
            peer.recv_from(&mut buf).await.unwrap();
            sessions.push(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]));
        }
        assert_eq!(sessions[1], sessions[0] + 1);
    }

    #[test]
    fn a_worker_gives_up_after_a_run_of_errors_that_are_not_transient() {
        let mut errors = RecvErrors::default();
        for _ in 0..100 {
            assert!(!errors.give_up(TransportError::Io(IoErrorKind::ConnectionRefused)));
        }
        for _ in 1..MAX_CONSECUTIVE_RECV_ERRORS {
            assert!(!errors.give_up(TransportError::Io(IoErrorKind::Other)));
        }
        assert!(errors.give_up(TransportError::Io(IoErrorKind::Other)));
    }

    #[test]
    fn what_is_no_message_is_one_message_going_nowhere_in_particular() {
        assert_eq!(messages(b"short"), std::vec![(None, b"short".as_slice())]);
        let junk = b"junk, and enough of it to be a header";
        let mut datagram = message(3, b"x");
        datagram.extend_from_slice(junk);
        assert_eq!(
            messages(&datagram),
            std::vec![
                (
                    Some(Addressed {
                        service: 3,
                        request: true
                    }),
                    message(3, b"x").as_slice()
                ),
                (None, junk.as_slice())
            ]
        );
    }

    #[test]
    fn fewer_bytes_than_a_header_behind_the_messages_are_padding_and_go_nowhere() {
        let mut datagram = message(3, b"x");
        datagram.extend_from_slice(&[0, 0, 0]);

        let found = messages(&datagram);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, message(3, b"x").as_slice());
    }

    #[tokio::test]
    async fn a_tap_sends_from_the_shared_unicast_socket_and_joins_only_its_group() {
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

        assert!(
            tap.join_multicast_v4(endpoint.group(), Ipv4Addr::LOCALHOST)
                .is_ok()
        );
        assert!(matches!(
            tap.join_multicast_v4(Ipv4Addr::new(239, 255, 0, 1), Ipv4Addr::LOCALHOST),
            Err(TransportError::Unsupported)
        ));
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
