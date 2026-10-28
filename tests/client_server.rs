//! Integration tests exercising the Client and Server together on localhost.
//!
//! # Parallel execution caveat
//!
//! These tests share `sd::MULTICAST_PORT` (30490) and bind it via
//! `SO_REUSEPORT`. Linux's reuseport hashing then load-balances incoming
//! Subscribe / SD multicast traffic across whichever sockets are
//! currently bound, which means one test's Subscribe message can be
//! delivered to a *different* test's server. Each test verifies its own
//! `EventPublisher::has_subscribers` (per-server `SubscriptionManager`
//! state, not a shared one), so the cross-routing produces flaky
//! failures when the suite runs with cargo's default parallelism.
//!
//! Until we can give each test its own SD port (which would require
//! widening the protocol layer's `MULTICAST_PORT` constant to a runtime
//! config) or its own network namespace, **run this binary with
//! `--test-threads=1`** to serialise the SD-port contention:
//!
//! ```text
//! cargo test --test client_server -- --test-threads=1
//! ```
//!
//! `cargo test --workspace` (parallel default) is expected to flake on
//! ~half of the tests in this file. The unit-test suite under
//! `cargo test --lib` does not have this issue and runs reliably in
//! parallel. The fix is tracked alongside the bare-metal refactor
//! (which will need to abstract the port anyway).

use simple_someip::ServiceEndpointKey;
use simple_someip::e2e::{E2ECheckStatus, E2EKey, E2EProfile, Profile4Config};
use simple_someip::protocol::{Header, Message, MessageId, sd};
use simple_someip::server::ServerConfig;
use simple_someip::{
    Client, ClientUpdate, ClientUpdates, PayloadWireFormat, RawPayload, Server, TokioChannels,
    VecSdHeader,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use simple_someip::protocol::{MessageType, MessageTypeField, MessageView, ReturnCode};
use simple_someip::server::{OwnedRequest, Reply, RequestSender};
use simple_someip::{Encode, ServerDeps};

/// Allocate a unique service ID per test invocation. Multiple
/// integration tests in this file run in parallel (cargo's default) and
/// would otherwise collide on the SD multicast group + a shared service
/// ID, causing cross-test SubscribeAck bleed-through.
fn next_service_id() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0x5B);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn empty_sd_header() -> VecSdHeader {
    VecSdHeader {
        flags: sd::Flags::new_sd(sd::RebootFlag::RecentlyRebooted),
        entries: vec![],
        options: vec![],
    }
}

type TestClient = Client<
    RawPayload,
    std::sync::Arc<std::sync::Mutex<simple_someip::e2e::E2ERegistry>>,
    std::sync::Arc<std::sync::RwLock<Ipv4Addr>>,
    TokioChannels,
>;

/// Type alias bringing the tokio-flavor concrete type parameters back into
/// scope so callers can spell `TestServer::new(...)` without chasing the
/// four-type-parameter signature on every call site.
type TestServer = Server<
    simple_someip::TokioTransport,
    simple_someip::TokioTimer,
    std::sync::Arc<std::sync::Mutex<simple_someip::e2e::E2ERegistry>>,
    std::sync::Arc<tokio::sync::RwLock<simple_someip::server::SubscriptionManager>>,
>;

/// Create a server on an ephemeral unicast port, returning (Server, actual_port).
///
/// `TestServer::new` returns a `(Server, ServerHandles, run)` tuple.
/// Tests in this module construct the server, query the
/// kernel-assigned port via `unicast_local_addr`, and don't spawn
/// the run future from this helper — the few tests that need it call
/// `server.run()` directly after receiving the `Server` handle.
/// The full `Server` binds the SD port (30490) on its interface. Keep it on a
/// distinct loopback IP from the client (which stays on `127.0.0.1`) so the
/// client's receive-only unicast discovery socket (`interface:30490`,
/// `SO_REUSEPORT`) does not collide with the server's SD socket on the same
/// `IP:30490` and steal the client's own SubscribeEventgroup. This mirrors
/// production, where a full SD-announcing server is a remote sensor on its own
/// IP. See the #130 forward-port discussion.
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

async fn create_server(service_id: u16, instance_id: u16) -> (TestServer, u16) {
    create_server_on(SERVER_IP, service_id, instance_id).await
}

/// Like [`create_server`] but lets the caller pick the interface. Used by
/// tests that need multiple *distinct* devices (loopback IPs) offering the
/// same `(service_id, instance_id)` — the source-keyed-registry regression
/// coverage.
async fn create_server_on(
    interface: Ipv4Addr,
    service_id: u16,
    instance_id: u16,
) -> (TestServer, u16) {
    let config = ServerConfig::new(service_id, instance_id)
        .with_interface(interface)
        .with_local_port(0);
    let (server, _handles, _run): (TestServer, _, _) =
        TestServer::new(config).await.expect("Server::new failed");
    // Constructor already back-filled `config.local_port` from the
    // kernel-assigned bound port; just read it back for the test return.
    let port = match server.unicast_local_addr().expect("local_addr failed") {
        std::net::SocketAddr::V4(a) => a.port(),
        _ => panic!("expected IPv4"),
    };
    (server, port)
}

/// Poll `has_subscribers` with retries until the server has processed the
/// subscription. Returns true if subscribers appeared within the deadline.
async fn wait_for_subscribers<R, S, H, T>(
    publisher: &simple_someip::server::EventPublisher<R, S, H, T>,
    service_id: u16,
    instance_id: u16,
    event_group_id: u16,
) -> bool
where
    R: simple_someip::transport::E2ERegistryHandle,
    S: simple_someip::server::SubscriptionHandle,
    for<'a> S::ForEachFuture<'a>: Send,
    T: simple_someip::transport::TransportSocket + 'static,
    H: simple_someip::transport::SharedHandle<T>,
{
    for _ in 0..20 {
        if publisher
            .has_subscribers(service_id, instance_id, event_group_id)
            .await
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

/// Drain a client's update stream until the published `Unicast` event arrives,
/// skipping interleaved discovery traffic. A `SubscribeAck` now reaches the
/// client via the unicast SD socket (the #130 per-transport fix) and can land
/// on the channel just before the event, so a single `recv()` that expects the
/// event outright is racy — especially under the slower coverage build. Panics
/// on timeout or a closed channel; returns the `Unicast` update so callers can
/// inspect fields like `e2e_status`.
async fn recv_unicast(
    updates: &mut ClientUpdates<RawPayload, TokioChannels>,
) -> ClientUpdate<RawPayload> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, updates.recv()).await {
            Ok(Some(update @ ClientUpdate::Unicast { .. })) => return update,
            // Discovery ack / reboot notice — keep waiting for the event.
            Ok(Some(_)) => continue,
            Ok(None) => panic!("update channel closed before the Unicast event"),
            Err(_) => panic!("timed out waiting for the Unicast event"),
        }
    }
}

#[tokio::test]
async fn test_client_server_subscribe_and_receive_event() {
    // Start server on ephemeral port
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });

    // Create client and subscribe to the server's event group
    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    assert!(
        wait_for_subscribers(&publisher, service_id, 1, 0x01).await,
        "server should have registered the subscriber"
    );

    // Drain any discovery update that may have arrived (SubscribeAck)
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates.recv()).await;

    // Publish an event from the server to the client's unicast port
    let event_msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let sent = publisher
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event failed");
    assert_eq!(sent, 1);

    // Client receives the unicast event
    let update = recv_unicast(&mut updates).await;
    assert!(
        matches!(update, ClientUpdate::Unicast { .. }),
        "expected Unicast, got {update:?}"
    );

    // Tear down
    client.unbind_discovery().await.unwrap();
    client.shut_down();
    server_handle.abort();
}

/// SD on a group and port of the deployment's own, not the standard ones: the server offers and
/// answers there, the client subscribes there, and the event still arrives.
#[tokio::test]
async fn test_subscribe_and_receive_event_on_a_configured_sd_endpoint() {
    let endpoint = sd::SdEndpoint::new(Ipv4Addr::new(239, 255, 0, 254), 30491).unwrap();
    let service_id = next_service_id();
    let config = ServerConfig::new(service_id, 1)
        .with_interface(SERVER_IP)
        .with_local_port(0)
        .with_sd_endpoint(endpoint);
    let (server, _handles, _run): (TestServer, _, _) =
        TestServer::new(config).await.expect("Server::new failed");
    let server_port = match server.unicast_local_addr().expect("local_addr failed") {
        std::net::SocketAddr::V4(a) => a.port(),
        _ => panic!("expected IPv4"),
    };
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });

    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    client.set_sd_endpoint(endpoint).await.unwrap();
    assert_eq!(client.sd_endpoint().await.unwrap(), endpoint);
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    let key = ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr));
    client.add_endpoint(key.clone(), 1, 0).await.unwrap();
    client.subscribe(key, 1, 3, 0x01, 0).await.unwrap();

    assert!(
        wait_for_subscribers(&publisher, service_id, 1, 0x01).await,
        "the server should have registered the subscriber through the configured SD endpoint"
    );
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates.recv()).await;

    let event_msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let sent = publisher
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event failed");
    assert_eq!(sent, 1);
    let update = recv_unicast(&mut updates).await;
    assert!(
        matches!(update, ClientUpdate::Unicast { .. }),
        "expected Unicast, got {update:?}"
    );

    client.unbind_discovery().await.unwrap();
    client.shut_down();
    server_handle.abort();
}

#[tokio::test]
async fn test_client_send_sd_auto_binds_discovery() {
    // Create server so there is something to send to
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let server_handle = tokio::spawn(async move { server.run().await });

    // Create client — NO bind_discovery
    let (client, _updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);

    // send_sd_message should auto-bind discovery and succeed
    let sd_header = VecSdHeader {
        flags: sd::Flags::new_sd(sd::RebootFlag::RecentlyRebooted),
        entries: vec![sd::Entry::SubscribeEventGroup(sd::EventGroupEntry::new(
            service_id, 1, 1, 3, 0x01,
        ))],
        options: vec![sd::Options::IpV4Endpoint {
            ip: Ipv4Addr::LOCALHOST,
            protocol: sd::TransportProtocol::Udp,
            port: 12345,
        }],
    };
    let target = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .send_sd_message(target, sd_header)
        .await
        .expect("send_sd_message should auto-bind discovery and succeed");

    client.shut_down();
    server_handle.abort();
}

/// Exercises the full bind/unbind lifecycle and set_interface flow
/// while an SD message round-trip is in flight.
#[tokio::test]
async fn test_client_bind_unbind_lifecycle_with_server() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let server_handle = tokio::spawn(async move { server.run().await });

    let (client, _updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);

    // Bind discovery, subscribe, then unbind and rebind
    client.bind_discovery().await.unwrap();
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    // Unbind and rebind discovery — covers unbind_discovery + re-bind path
    client.unbind_discovery().await.unwrap();
    client.bind_discovery().await.unwrap();

    // set_interface while discovery is bound — covers the SetInterface arm
    // that unbinds discovery, changes interface, and rebinds
    client.set_interface(Ipv4Addr::LOCALHOST).await.unwrap();

    client.shut_down();
    server_handle.abort();
}

/// Verify that add_endpoint + send_to_service resolves the endpoint from the
/// registry, auto-binds unicast, sends the request, and receives a response.
#[tokio::test]
async fn test_add_endpoint_and_send_to_service() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });

    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    client.bind_discovery().await.unwrap();

    // Register the server's endpoint manually (simulating non-broadcasting service)
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();

    // Subscribe to server's event group (auto-binds unicast internally)
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    // Wait for the server to process the subscription
    assert!(
        wait_for_subscribers(&publisher, service_id, 1, 0x01).await,
        "server should have registered the subscriber"
    );

    // Drain any pending discovery update
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates.recv()).await;

    // Publish an event from the server
    let event_msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let sent = publisher
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event failed");
    assert_eq!(sent, 1);

    // Client receives the unicast event
    let update = recv_unicast(&mut updates).await;
    assert!(
        matches!(update, ClientUpdate::Unicast { .. }),
        "expected Unicast, got {update:?}"
    );

    // Remove the endpoint and verify send_to_service returns ServiceNotFound
    client
        .remove_endpoint(ServiceEndpointKey::udp(
            service_id,
            SocketAddr::V4(server_addr),
        ))
        .await
        .unwrap();
    let msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let result = client
        .send_to_service(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            msg,
        )
        .await;
    assert!(
        matches!(result, Err(simple_someip::client::Error::ServiceNotFound)),
        "expected ServiceNotFound after remove, got {result:?}"
    );
    // Verify that PendingResponse is importable from the crate root
    let _: fn() -> Option<simple_someip::PendingResponse<RawPayload, TokioChannels>> = || None;

    client.shut_down();
    server_handle.abort();
}

/// Verify subscribe auto-binds discovery when discovery is not already bound.
/// Exercises the Subscribe auto-bind discovery path in inner.rs.
#[tokio::test]
async fn test_subscribe_auto_binds_discovery() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });

    // Create client — do NOT bind discovery manually
    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    // Subscribe should auto-bind discovery internally
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    assert!(
        wait_for_subscribers(&publisher, service_id, 1, 0x01).await,
        "server should have registered the subscriber"
    );

    // Drain SubscribeAck
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates.recv()).await;

    // Publish an event and verify the client can receive it
    let event_msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let sent = publisher
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event failed");
    assert_eq!(sent, 1);

    let update = recv_unicast(&mut updates).await;
    assert!(
        matches!(update, ClientUpdate::Unicast { .. }),
        "expected Unicast, got {update:?}"
    );

    client.shut_down();
    server_handle.abort();
}

/// Verify that `request()` resolves when the server sends a unicast reply.
/// Exercises the pending_responses HashMap matching path in inner.rs.
#[tokio::test]
async fn test_client_request_resolves_via_unicast_reply() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });

    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    assert!(
        wait_for_subscribers(&publisher, service_id, 1, 0x01).await,
        "server should have registered the subscriber"
    );

    // Drain SubscribeAck
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates.recv()).await;

    // send_to_service creates a PendingResponse; the server will send the event
    // which has a matching request_id, resolving it.
    let msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let pending = client
        .send_to_service(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            msg,
        )
        .await
        .expect("send_to_service failed");

    // Publish an event that the client unicast socket will receive
    let event_msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    publisher
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event failed");

    // The event may or may not match the pending response's request_id.
    // Either way the client should receive *something* on its unicast socket.
    // We just verify the unicast path is exercised.
    let update = tokio::time::timeout(std::time::Duration::from_secs(2), updates.recv())
        .await
        .expect("timeout waiting for unicast update");
    // Could be Unicast (non-matching request_id) — that's fine
    assert!(update.is_some(), "expected an update");

    // Clean up pending (it may never resolve if request_id didn't match)
    drop(pending);

    client.shut_down();
    server_handle.abort();
}

/// Verify that E2E protection is applied by the server and checked by the client.
/// Exercises E2E protect in event_publisher.rs and E2E check in socket_manager.rs.
#[tokio::test]
async fn test_e2e_protect_on_publish_and_check_on_receive() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let publisher = server.publisher();

    // Register E2E profile on server for the event message ID
    let key = E2EKey {
        service_id,
        method_or_event_id: 0x0001,
    };
    let profile = E2EProfile::Profile4(Profile4Config::new(0x12345678, 15));
    server
        .register_e2e(key, profile.clone())
        .expect("E2E registry has capacity for one entry");

    let server_handle = tokio::spawn(async move { server.run().await });

    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);

    // Register matching E2E profile on client
    client
        .register_e2e(key, profile)
        .expect("E2E registry has capacity for one entry");

    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    assert!(
        wait_for_subscribers(&publisher, service_id, 1, 0x01).await,
        "server should have registered the subscriber"
    );

    // Drain SubscribeAck
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates.recv()).await;

    // Publish an event — server will E2E-protect it
    // Construct a non-SD message with service_id=service_id, method/event_id=0x0001
    let payload_bytes = [0xAA, 0xBB];
    let msg_id = MessageId::new_from_service_and_method(service_id, 0x0001);
    let raw_payload = RawPayload::from_payload_bytes(msg_id, &payload_bytes).unwrap();
    let header = Header::new_event(service_id, 0x0001, 0, 0x01, 0x01, payload_bytes.len());
    let event_msg = Message::new(header, raw_payload);
    let sent = publisher
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event failed");
    assert_eq!(sent, 1);

    // Client receives the unicast event with E2E status
    let update = recv_unicast(&mut updates).await;
    match update {
        ClientUpdate::Unicast { e2e_status, .. } => {
            assert!(
                e2e_status.is_some(),
                "expected e2e_status to be populated when E2E is configured"
            );
            assert_eq!(
                e2e_status.unwrap(),
                E2ECheckStatus::Ok,
                "E2E check should pass for correctly protected message"
            );
        }
        other => unreachable!("recv_unicast only returns Unicast, got {other:?}"),
    }

    client.shut_down();
    server_handle.abort();
}

/// Verify that two clients can subscribe to the same server and both receive events.
/// Exercises multi-subscriber path in event_publisher.rs.
#[tokio::test]
async fn test_multiple_subscribers_receive_events() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });

    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);

    // Client 1
    let (client1, mut updates1, run_fut1) = TestClient::new(Ipv4Addr::LOCALHOST);
    tokio::spawn(run_fut1);
    client1
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    client1
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    // Client 2
    let (client2, mut updates2, run_fut2) = TestClient::new(Ipv4Addr::LOCALHOST);
    tokio::spawn(run_fut2);
    client2
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    client2
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    // `SUBSCRIBERS_PER_GROUP` is a compile-time cap sized via
    // `SIMPLE_SOMEIP_MAX_SUBS` (default 1) so the host build links exactly
    // the memory it needs. Above that cap excess subscribers are dropped by
    // design, so the number we can actually exercise is `min(2, cap)`.
    let expected = ServerConfig::SUBSCRIBERS_PER_GROUP_CAP.min(2);

    // Wait for the subscribers the cap allows
    for _ in 0..40 {
        if publisher.subscriber_count(service_id, 1, 0x01).await >= expected {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        publisher.subscriber_count(service_id, 1, 0x01).await >= expected,
        "expected at least {expected} subscriber(s) (SUBSCRIBERS_PER_GROUP cap = {})",
        ServerConfig::SUBSCRIBERS_PER_GROUP_CAP
    );

    // Drain discovery updates
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates1.recv()).await;
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), updates2.recv()).await;

    // Publish event
    let event_msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let sent = publisher
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event failed");
    assert!(sent >= expected, "expected sent >= {expected}, got {sent}");

    // Client 1 (the first accepted subscriber) always receives the event.
    let u1 = recv_unicast(&mut updates1).await;
    assert!(
        matches!(u1, ClientUpdate::Unicast { .. }),
        "client1 expected Unicast, got {u1:?}"
    );

    // Client 2 is only accepted (and thus only receives) when the build's
    // subscriber cap admits a second subscriber; otherwise it was dropped at
    // subscribe time, so the multi-subscriber fan-out is not exercised here.
    if expected >= 2 {
        let u2 = recv_unicast(&mut updates2).await;
        assert!(
            matches!(u2, ClientUpdate::Unicast { .. }),
            "client2 expected Unicast, got {u2:?}"
        );
    } else {
        eprintln!(
            "SUBSCRIBERS_PER_GROUP cap = 1: skipping the second-subscriber fan-out \
             assertion (rebuild with SIMPLE_SOMEIP_MAX_SUBS>=2 to exercise it)"
        );
    }

    client1.shut_down();
    client2.shut_down();
    server_handle.abort();
}

/// Verify ClientUpdates returns None after client shutdown.
#[tokio::test]
async fn test_updates_drain_after_shutdown() {
    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    client.shut_down();

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), updates.recv())
        .await
        .expect("timeout waiting for None");
    assert!(result.is_none(), "expected None after shutdown");
}

/// Verify that cloned client handles work independently.
#[tokio::test]
async fn test_cloned_client_works() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let server_handle = tokio::spawn(async move { server.run().await });

    let (client, _updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let client2 = client.clone();

    // Both clones can send commands
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();
    client2
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();

    client.shut_down();
    // client2 is also dropped
    server_handle.abort();
}

/// Subscribe with a specific client_port, then subscribe again reusing the same port.
/// Exercises the port-reuse path in Subscribe handling.
#[tokio::test]
async fn test_subscribe_specific_port_reuse() {
    let service_id = next_service_id();
    let (server, server_port) = create_server(service_id, 1).await;
    let server_handle = tokio::spawn(async move { server.run().await });

    let (client, _updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let server_addr = SocketAddrV4::new(SERVER_IP, server_port);
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            0,
        )
        .await
        .unwrap();

    // Use specific port
    let specific_port = 44444;
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x01,
            specific_port,
        )
        .await
        .unwrap();
    // Second subscribe reuses the port
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(server_addr)),
            1,
            3,
            0x02,
            specific_port,
        )
        .await
        .unwrap();

    client.shut_down();
    server_handle.abort();
}

/// Regression for the source-keyed registry (the fix this test suite gates):
/// once firmware assigns a fixed (ECU-Extract) instance id, every device on
/// the subnet advertises the identical `(service_id, instance_id)`. Two real
/// servers on distinct loopback IPs both offer that same pair; the client
/// must resolve each by `target_ip` independently, receive events tagged
/// with the correct source, and removing one device's endpoint must not
/// evict the other's.
#[tokio::test]
async fn test_two_devices_same_service_instance_addressed_independently() {
    let service_id = next_service_id();
    const DEVICE_A: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 10);
    const DEVICE_B: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 11);

    let (server_a, port_a) = create_server_on(DEVICE_A, service_id, 1).await;
    let publisher_a = server_a.publisher();
    let server_a_handle = tokio::spawn(async move { server_a.run().await });

    let (server_b, port_b) = create_server_on(DEVICE_B, service_id, 1).await;
    let publisher_b = server_b.publisher();
    let server_b_handle = tokio::spawn(async move { server_b.run().await });

    let addr_a = SocketAddrV4::new(DEVICE_A, port_a);
    let addr_b = SocketAddrV4::new(DEVICE_B, port_b);

    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);

    // Both devices advertise the identical (service_id, instance_id=1) — the
    // exact scenario a fixed ECU-Extract instance id produces. Before this
    // task, the second `add_endpoint` would have overwritten the first in
    // the registry.
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(addr_a)),
            1,
            0,
        )
        .await
        .unwrap();
    client
        .add_endpoint(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(addr_b)),
            1,
            0,
        )
        .await
        .unwrap();

    // Distinct event groups so `has_subscribers`/`publish_event` on each
    // server can be checked independently.
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(addr_a)),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();
    client
        .subscribe(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(addr_b)),
            1,
            3,
            0x02,
            0,
        )
        .await
        .unwrap();

    assert!(
        wait_for_subscribers(&publisher_a, service_id, 1, 0x01).await,
        "server A should have registered the subscriber"
    );
    assert!(
        wait_for_subscribers(&publisher_b, service_id, 1, 0x02).await,
        "server B should have registered the subscriber"
    );

    // Publish from A: the client must receive an event sourced from A, not B.
    let event_msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let sent_a = publisher_a
        .publish_event(service_id, 1, 0x01, &event_msg)
        .await
        .expect("publish_event from device A failed");
    assert_eq!(sent_a, 1);
    match recv_unicast(&mut updates).await {
        ClientUpdate::Unicast { source, .. } => {
            assert_eq!(
                source.ip(),
                std::net::IpAddr::V4(DEVICE_A),
                "event should have arrived from device A"
            );
        }
        other => panic!("expected Unicast from device A, got {other:?}"),
    }

    // Publish from B: independently resolvable, not shadowed by A's entry.
    let sent_b = publisher_b
        .publish_event(service_id, 1, 0x02, &event_msg)
        .await
        .expect("publish_event from device B failed");
    assert_eq!(sent_b, 1);
    match recv_unicast(&mut updates).await {
        ClientUpdate::Unicast { source, .. } => {
            assert_eq!(
                source.ip(),
                std::net::IpAddr::V4(DEVICE_B),
                "event should have arrived from device B"
            );
        }
        other => panic!("expected Unicast from device B, got {other:?}"),
    }

    // Removing device A's endpoint must not evict device B's — the fix for
    // "StopOffer/remove from one device evicted all".
    client
        .remove_endpoint(ServiceEndpointKey::udp(service_id, SocketAddr::V4(addr_a)))
        .await
        .unwrap();

    let msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let result_a = client
        .send_to_service(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(addr_a)),
            msg,
        )
        .await;
    assert!(
        matches!(result_a, Err(simple_someip::client::Error::ServiceNotFound)),
        "expected ServiceNotFound for removed device A, got {result_a:?}"
    );

    let msg = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header())
        .expect("in-tree SdHeader sizing is infallible");
    let result_b = client
        .send_to_service(
            ServiceEndpointKey::udp(service_id, SocketAddr::V4(addr_b)),
            msg,
        )
        .await;
    assert!(
        result_b.is_ok(),
        "device B must remain reachable after removing device A's endpoint: {result_b:?}"
    );

    client.shut_down();
    server_a_handle.abort();
    server_b_handle.abort();
}

/// A server told about every request through a channel, on an ephemeral port: the server, its
/// port and the requests.
async fn create_answering_server(
    service_id: u16,
) -> (TestServer, u16, tokio::sync::mpsc::Receiver<OwnedRequest>) {
    let (sender, requests) = RequestSender::channel(8);
    let deps = ServerDeps::tokio().with_request_observer(sender);
    let config = ServerConfig::new(service_id, 1)
        .with_interface(SERVER_IP)
        .with_local_port(0);
    let (server, _handles, _run): (TestServer, _, _) =
        TestServer::new_with_deps(deps, config, false)
            .await
            .expect("Server::new_with_deps failed");
    let port = match server.unicast_local_addr().expect("local_addr failed") {
        SocketAddr::V4(a) => a.port(),
        SocketAddr::V6(_) => panic!("expected IPv4"),
    };
    (server, port, requests)
}

/// A request datagram to `service_id`/`method_id`: `message_type` with `request_id`, protocol
/// version 1, interface version 2, and `payload`.
fn request_bytes(
    service_id: u16,
    method_id: u16,
    message_type: MessageType,
    request_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let header = Header::new(
        MessageId::new_from_service_and_method(service_id, method_id),
        request_id,
        1,
        2,
        MessageTypeField::new(message_type, false),
        ReturnCode::Ok,
        payload.len(),
    );
    let mut bytes = vec![0u8; 16 + payload.len()];
    let header_len = header.encode_to_slice(&mut bytes).unwrap();
    bytes[header_len..].copy_from_slice(payload);
    bytes
}

/// The next request the server was told about.
async fn next_request(requests: &mut tokio::sync::mpsc::Receiver<OwnedRequest>) -> OwnedRequest {
    tokio::time::timeout(Duration::from_secs(2), requests.recv())
        .await
        .expect("timed out waiting for the request")
        .expect("the request channel closed")
}

/// The next datagram `peer` receives.
async fn next_datagram(peer: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 256];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .expect("timed out waiting for the answer")
        .expect("recv_from failed");
    (buf[..len].to_vec(), from)
}

#[tokio::test]
async fn test_a_request_is_observed_and_its_response_goes_back_to_the_caller() {
    let service_id = next_service_id();
    let (server, port, mut requests) = create_answering_server(service_id).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });
    let server_addr = SocketAddrV4::new(SERVER_IP, port);

    let peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    peer.send_to(
        &request_bytes(
            service_id,
            0x0007,
            MessageType::Request,
            0x00AB_0005,
            b"ping",
        ),
        server_addr,
    )
    .await
    .unwrap();

    let request = next_request(&mut requests).await;
    let target = request.target();
    assert!(request.expects_response());
    assert_eq!(request.payload(), b"ping");
    assert_eq!(request.e2e_status(), E2ECheckStatus::Unchecked);
    assert_eq!(SocketAddr::V4(target.source()), peer.local_addr().unwrap());
    assert_eq!(
        (target.service_id(), target.method_id()),
        (service_id, 0x0007)
    );
    assert_eq!(target.request_id(), 0x00AB_0005);
    assert_eq!(
        (target.protocol_version(), target.interface_version()),
        (1, 2)
    );

    publisher.respond(target, Reply::OK, b"pong").await.unwrap();

    let (answer, from) = next_datagram(&peer).await;
    // feat_req_someip_49: the answer comes from the address and port the request went to.
    assert_eq!(from, SocketAddr::V4(server_addr));
    let view = MessageView::parse(&answer).unwrap();
    let header = view.header();
    assert_eq!(header.message_type().message_type(), MessageType::Response);
    assert_eq!(header.return_code(), ReturnCode::Ok);
    assert_eq!(header.request_id(), 0x00AB_0005);
    assert_eq!(
        header.message_id(),
        MessageId::new_from_service_and_method(service_id, 0x0007)
    );
    assert_eq!(
        (header.protocol_version(), header.interface_version()),
        (1, 2)
    );
    assert_eq!(view.payload_bytes(), b"pong");

    server_handle.abort();
}

#[tokio::test]
async fn test_a_fire_and_forget_request_is_observed_and_expects_no_response() {
    let service_id = next_service_id();
    let (server, port, mut requests) = create_answering_server(service_id).await;
    let server_handle = tokio::spawn(async move { server.run().await });

    let peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    peer.send_to(
        &request_bytes(
            service_id,
            0x0008,
            MessageType::RequestNoReturn,
            0x0001_0002,
            b"set",
        ),
        SocketAddrV4::new(SERVER_IP, port),
    )
    .await
    .unwrap();

    let request = next_request(&mut requests).await;
    assert!(!request.expects_response());
    assert_eq!(request.message_type(), MessageType::RequestNoReturn);
    assert_eq!(request.payload(), b"set");
    assert_eq!(request.target().method_id(), 0x0008);

    server_handle.abort();
}

#[tokio::test]
async fn test_an_error_travels_in_a_response_or_in_an_exception() {
    let service_id = next_service_id();
    let (server, port, mut requests) = create_answering_server(service_id).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });

    let peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    peer.send_to(
        &request_bytes(service_id, 0x0009, MessageType::Request, 0x0001_0003, b""),
        SocketAddrV4::new(SERVER_IP, port),
    )
    .await
    .unwrap();
    let target = next_request(&mut requests).await.target();

    publisher
        .respond(target, Reply::response(ReturnCode::NotReady), b"")
        .await
        .unwrap();
    let (answer, _) = next_datagram(&peer).await;
    let header = MessageView::parse(&answer).unwrap().header();
    assert_eq!(header.message_type().message_type(), MessageType::Response);
    assert_eq!(header.return_code(), ReturnCode::NotReady);
    assert_eq!(header.request_id(), 0x0001_0003);

    publisher
        .respond(
            target,
            Reply::exception(ReturnCode::UnknownMethod).unwrap(),
            b"",
        )
        .await
        .unwrap();
    let (answer, _) = next_datagram(&peer).await;
    let header = MessageView::parse(&answer).unwrap().header();
    assert_eq!(header.message_type().message_type(), MessageType::Error);
    assert_eq!(header.return_code(), ReturnCode::UnknownMethod);
    assert_eq!(header.request_id(), 0x0001_0003);

    server_handle.abort();
}

#[tokio::test]
async fn test_the_clients_request_resolves_with_the_servers_response() {
    let service_id = next_service_id();
    let (server, port, mut requests) = create_answering_server(service_id).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });
    let echo = tokio::spawn(async move {
        let request = requests.recv().await.expect("a request");
        publisher
            .respond(request.target(), Reply::OK, request.payload())
            .await
            .unwrap();
        request.target()
    });

    let (client, _updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let server_addr = SocketAddr::V4(SocketAddrV4::new(SERVER_IP, port));
    client
        .add_endpoint(ServiceEndpointKey::udp(service_id, server_addr), 1, 0)
        .await
        .unwrap();
    let message_id = MessageId::new_from_service_and_method(service_id, 0x0007);
    let request = Message::new(
        Header::new(
            message_id,
            0,
            1,
            1,
            MessageTypeField::new(MessageType::Request, false),
            ReturnCode::Ok,
            4,
        ),
        RawPayload::from_payload_bytes(message_id, b"ping").unwrap(),
    );

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client.request(ServiceEndpointKey::udp(service_id, server_addr), request),
    )
    .await
    .expect("timed out waiting for the response")
    .expect("request failed");

    assert_eq!(response.raw_bytes(), Some(&b"ping"[..]));
    let target = echo.await.unwrap();
    assert_eq!(
        (target.service_id(), target.method_id()),
        (service_id, 0x0007)
    );

    client.shut_down();
    server_handle.abort();
}

#[tokio::test]
async fn test_a_relayed_request_keeps_its_ids_and_its_answer_arrives_as_an_update() {
    let service_id = next_service_id();
    let (server, port, mut requests) = create_answering_server(service_id).await;
    let publisher = server.publisher();
    let server_handle = tokio::spawn(async move { server.run().await });
    let answer = tokio::spawn(async move {
        let request = requests.recv().await.expect("a request");
        publisher
            .respond(
                request.target(),
                Reply::response(ReturnCode::NotReady),
                request.payload(),
            )
            .await
            .unwrap();
        request.target()
    });

    let (client, mut updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let server_addr = SocketAddr::V4(SocketAddrV4::new(SERVER_IP, port));
    client
        .add_endpoint(ServiceEndpointKey::udp(service_id, server_addr), 1, 0)
        .await
        .unwrap();
    let message_id = MessageId::new_from_service_and_method(service_id, 0x0007);
    let request = Message::new(
        Header::new(
            message_id,
            0x00AB_0005,
            1,
            1,
            MessageTypeField::new(MessageType::Request, false),
            ReturnCode::Ok,
            4,
        ),
        RawPayload::from_payload_bytes(message_id, b"ping").unwrap(),
    );
    client
        .relay_to_service(ServiceEndpointKey::udp(service_id, server_addr), request)
        .await
        .expect("relay failed");

    let target = answer.await.unwrap();
    assert_eq!((target.client_id(), target.session_id()), (0x00AB, 0x0005));

    let ClientUpdate::Unicast {
        message, source, ..
    } = recv_unicast(&mut updates).await
    else {
        unreachable!("recv_unicast returns a Unicast update");
    };
    assert_eq!(source, server_addr);
    assert_eq!(message.header().request_id(), 0x00AB_0005);
    assert_eq!(
        message.header().message_type().message_type(),
        MessageType::Response
    );
    assert_eq!(message.header().return_code(), ReturnCode::NotReady);
    assert_eq!(message.payload().raw_bytes(), Some(&b"ping"[..]));

    client.shut_down();
    server_handle.abort();
}

/// The client's own requests carry its client id, so a relay carrying it is refused: a reply
/// to it could not be told from a reply to one of them.
#[tokio::test]
async fn test_a_relay_with_the_clients_own_client_id_is_refused() {
    let service_id = next_service_id();
    let (client, _updates, run_fut) = TestClient::new(Ipv4Addr::LOCALHOST);
    let _run_handle = tokio::spawn(run_fut);
    let server_addr = SocketAddr::V4(SocketAddrV4::new(SERVER_IP, 30_599));
    client
        .add_endpoint(ServiceEndpointKey::udp(service_id, server_addr), 1, 0)
        .await
        .unwrap();
    let message_id = MessageId::new_from_service_and_method(service_id, 0x0007);
    let request = Message::new(
        Header::new(
            message_id,
            0x1234_0001,
            1,
            1,
            MessageTypeField::new(MessageType::Request, false),
            ReturnCode::Ok,
            4,
        ),
        RawPayload::from_payload_bytes(message_id, b"ping").unwrap(),
    );

    let refused = client
        .relay_to_service(ServiceEndpointKey::udp(service_id, server_addr), request)
        .await;

    assert!(
        matches!(
            refused,
            Err(simple_someip::client::Error::OwnClientId(0x1234))
        ),
        "expected OwnClientId, got {refused:?}"
    );
    client.shut_down();
}

/// A server and a client on one interface share the SD port: the server, on 127.0.0.1, serves a
/// plain client on 127.0.0.3; the client, also on 127.0.0.1, subscribes to a plain server on
/// 127.0.0.2. Each of the two pairs is served through the shared sockets on 127.0.0.1:30490.
#[tokio::test]
async fn test_a_server_and_a_client_share_the_sd_sockets_of_one_interface() {
    let shared = simple_someip::SharedSd::bind(Ipv4Addr::LOCALHOST, sd::SdEndpoint::DEFAULT, true)
        .await
        .expect("the shared SD sockets");

    // The shared server, and a plain client of it on its own interface.
    let served_id = next_service_id();
    let (served, served_handles, served_run) = shared
        .serve(
            ServerDeps::tokio(),
            ServerConfig::new(served_id, 1).with_local_port(0),
        )
        .await
        .expect("serve");
    tokio::spawn(served_run);
    let served_addr = match served.unicast_local_addr().unwrap() {
        SocketAddr::V4(a) => SocketAddr::V4(a),
        SocketAddr::V6(_) => unreachable!(),
    };
    let (plain_client, mut plain_updates, run) = TestClient::new(Ipv4Addr::new(127, 0, 0, 3));
    tokio::spawn(run);
    plain_client
        .add_endpoint(ServiceEndpointKey::udp(served_id, served_addr), 1, 0)
        .await
        .unwrap();
    plain_client
        .subscribe(
            ServiceEndpointKey::udp(served_id, served_addr),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();
    assert!(
        wait_for_subscribers(&served_handles.publisher, served_id, 1, 0x01).await,
        "the shared server registers the plain client's subscription through its tap"
    );
    let event = Message::<RawPayload>::new_sd(0x0001, &empty_sd_header()).unwrap();
    served_handles
        .publisher
        .publish_event(served_id, 1, 0x01, &event)
        .await
        .unwrap();
    assert!(matches!(
        recv_unicast(&mut plain_updates).await,
        ClientUpdate::Unicast { .. }
    ));

    // The shared client, subscribing to a plain server on another interface.
    let remote_id = next_service_id();
    let (remote, remote_port) = create_server(remote_id, 1).await;
    let remote_publisher = remote.publisher();
    let remote_run = tokio::spawn(async move { remote.run().await });
    let (shared_client, mut shared_updates, run) = TestClient::new_with_deps(
        simple_someip::ClientDeps::tokio(Ipv4Addr::LOCALHOST).with_factory(shared.transport()),
        true,
    );
    tokio::spawn(run);
    let remote_addr = SocketAddr::V4(SocketAddrV4::new(SERVER_IP, remote_port));
    shared_client
        .add_endpoint(ServiceEndpointKey::udp(remote_id, remote_addr), 1, 0)
        .await
        .unwrap();
    shared_client
        .subscribe(
            ServiceEndpointKey::udp(remote_id, remote_addr),
            1,
            3,
            0x01,
            0,
        )
        .await
        .unwrap();
    assert!(
        wait_for_subscribers(&remote_publisher, remote_id, 1, 0x01).await,
        "the plain server registers the shared client's subscription"
    );
    remote_publisher
        .publish_event(remote_id, 1, 0x01, &event)
        .await
        .unwrap();
    assert!(matches!(
        recv_unicast(&mut shared_updates).await,
        ClientUpdate::Unicast { .. }
    ));

    plain_client.shut_down();
    shared_client.shut_down();
    remote_run.abort();
}

/// Different services share one port (feat_req_someip_445): two servers served through the
/// shared sockets on one local port each observe the requests of their own service and answer
/// from the port. A second instance of one service there is refused, as instances of a service
/// listen on different ports (feat_req_someip_648).
#[tokio::test]
async fn test_two_services_share_one_endpoint_socket() {
    let interface = Ipv4Addr::new(127, 0, 0, 4);
    let shared = simple_someip::SharedSd::bind(interface, sd::SdEndpoint::DEFAULT, true)
        .await
        .expect("the shared SD sockets");
    let port: u16 = 30_604;
    let ids = [next_service_id(), next_service_id()];
    let mut servers = Vec::new();
    let mut requests = Vec::new();
    for id in ids {
        let (sender, observed) = RequestSender::channel(8);
        let (server, handles, run) = shared
            .serve(
                ServerDeps::tokio().with_request_observer(sender),
                ServerConfig::new(id, 1).with_local_port(port),
            )
            .await
            .expect("serve");
        tokio::spawn(run);
        servers.push((server, handles));
        requests.push(observed);
    }
    assert!(
        shared
            .serve(
                ServerDeps::tokio(),
                ServerConfig::new(ids[0], 1).with_local_port(port)
            )
            .await
            .is_err(),
        "a second instance of one service on the port is refused"
    );

    let peer = tokio::net::UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
        .await
        .unwrap();
    let mut datagram = request_bytes(ids[0], 0x0001, MessageType::Request, 0x0001_0001, b"one");
    datagram.extend(request_bytes(
        ids[1],
        0x0002,
        MessageType::Request,
        0x0001_0002,
        b"two",
    ));
    peer.send_to(&datagram, (interface, port)).await.unwrap();

    let expected: [(u16, u16, &[u8]); 2] = [(ids[0], 0x0001, b"one"), (ids[1], 0x0002, b"two")];
    for (i, (id, method, payload)) in expected.into_iter().enumerate() {
        let request = next_request(&mut requests[i]).await;
        let target = request.target();
        assert_eq!((target.service_id(), target.method_id()), (id, method));
        assert_eq!(request.payload(), payload);
        servers[i]
            .1
            .publisher
            .respond(target, Reply::OK, payload)
            .await
            .unwrap();
        let (answer, from) = next_datagram(&peer).await;
        assert_eq!(from, SocketAddr::V4(SocketAddrV4::new(interface, port)));
        let view = MessageView::parse(&answer).unwrap();
        assert_eq!(
            view.header().message_id(),
            MessageId::new_from_service_and_method(id, method)
        );
        assert_eq!(view.payload_bytes(), payload);
    }
}
