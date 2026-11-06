mod entry;
mod error;
mod flags;
mod header;
mod options;

#[cfg(test)]
pub(crate) mod test_support;

use core::net::{Ipv4Addr, SocketAddrV4};

/// Standard SOME/IP-SD multicast group address (239.255.0.255).
pub const MULTICAST_IP: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 255);
/// Standard SOME/IP-SD port (30490).
pub const MULTICAST_PORT: u16 = 30490;

/// Where SOME/IP-SD messages are exchanged on a network: the multicast group every
/// participant joins, and the UDP port, which is also the port a unicast SD message to a peer
/// goes to.
///
/// Both are configuration, not constants of the protocol: an SD endpoint option carries the
/// SD port, "currently" 30490 (`feat_req_someipsd_1095`), and statically configured addresses
/// and ports give way to those in received options (`feat_req_someipsd_778`). The defaults are
/// [`MULTICAST_IP`] and [`MULTICAST_PORT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SdEndpoint {
    group: Ipv4Addr,
    port: u16,
}

impl SdEndpoint {
    /// [`MULTICAST_IP`] and [`MULTICAST_PORT`].
    pub const DEFAULT: Self = Self {
        group: MULTICAST_IP,
        port: MULTICAST_PORT,
    };

    /// The endpoint on `group` and `port`.
    ///
    /// # Errors
    ///
    /// When `group` is not a multicast address: a multicast endpoint names a multicast IP
    /// address (`feat_req_someipsd_1163`'s option checks).
    pub const fn new(group: Ipv4Addr, port: u16) -> Result<Self, NotMulticast> {
        if group.is_multicast() {
            Ok(Self { group, port })
        } else {
            Err(NotMulticast(group))
        }
    }

    /// The multicast group.
    #[must_use]
    pub const fn group(self) -> Ipv4Addr {
        self.group
    }

    /// The SD port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Where a multicast SD message goes.
    #[must_use]
    pub const fn multicast(self) -> SocketAddrV4 {
        SocketAddrV4::new(self.group, self.port)
    }

    /// Where a unicast SD message to `peer` goes: its SD port.
    #[must_use]
    pub const fn unicast(self, peer: Ipv4Addr) -> SocketAddrV4 {
        SocketAddrV4::new(peer, self.port)
    }
}

impl Default for SdEndpoint {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// An address given as an SD multicast group that is not a multicast address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotMulticast(pub Ipv4Addr);

impl core::fmt::Display for NotMulticast {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} is not a multicast address", self.0)
    }
}

impl core::error::Error for NotMulticast {}

#[cfg(test)]
mod sd_endpoint_tests {
    use super::*;

    #[test]
    fn the_default_is_the_standard_group_and_port() {
        assert_eq!(SdEndpoint::default(), SdEndpoint::DEFAULT);
        assert_eq!(SdEndpoint::DEFAULT.group(), MULTICAST_IP);
        assert_eq!(SdEndpoint::DEFAULT.port(), MULTICAST_PORT);
        assert_eq!(
            SdEndpoint::DEFAULT.multicast(),
            SocketAddrV4::new(MULTICAST_IP, MULTICAST_PORT)
        );
    }

    #[test]
    fn a_unicast_sd_message_goes_to_the_peers_sd_port() {
        let endpoint = SdEndpoint::new(Ipv4Addr::new(224, 0, 55, 55), 30491).unwrap();
        assert_eq!(
            endpoint.unicast(Ipv4Addr::new(10, 0, 0, 7)),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 30491)
        );
        assert_eq!(
            endpoint.multicast(),
            SocketAddrV4::new(Ipv4Addr::new(224, 0, 55, 55), 30491)
        );
    }

    #[test]
    fn a_unicast_address_is_no_group() {
        assert_eq!(
            SdEndpoint::new(Ipv4Addr::new(10, 0, 0, 1), 30490),
            Err(NotMulticast(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }
}
/// SOME/IP Message ID for service discovery messages (`0xFFFF_8100`).
pub const MESSAGE_ID_VALUE: u32 = 0xffff_8100;

// Export all definitions from the service discovery mod

pub use entry::{
    Entry, EntryIter, EntryType, EntryView, EventGroupEntry, OptionsCount, ServiceEntry,
};
pub use error::Error;
pub use flags::{Flags, RebootFlag};
pub use header::{Header, SdBody, SdHeaderView};
pub use options::{
    MAX_CONFIGURATION_STRING_LENGTH, OptionIter, OptionType, OptionView, Options,
    TransportProtocol, extract_ipv4_endpoint,
};
