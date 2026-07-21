//! L1 — reaching a peer through Tor (roadmap Phase 5).
//!
//! This is the transport that recovers the one property direct QUIC cannot
//! provide. `CLAUDE.md` §10 states it plainly: a direct connection tells both
//! ISPs that A talked to B, when, and for how long, and no amount of padding
//! inside the flow changes that. Routing the same session through an onion
//! circuit is the only answer this project has, short of not connecting at all.
//!
//! # What this module is
//!
//! Two thin pieces of glue and one guard:
//!
//! * [`connect_onion`] — reach an onion address through a Tor SOCKS5 proxy and
//!   hand back a stream. Feed it to [`TlsSession::connect`].
//! * [`OnionListener`] — accept the plaintext side of an onion service. Tor
//!   forwards circuits to a local TCP port; this listens on it.
//! * [`OnionAddress`] — a validated v3 onion address, which exists so a
//!   clearnet host can never be passed where an onion was meant.
//!
//! The crypto is unchanged: the stream goes straight into [`TlsSession`], which
//! runs the same hybrid-PQ, mutually-pinned handshake as the QUIC path.
//!
//! # The guard, and why it matters more than it looks
//!
//! [`connect_onion`] accepts only a validated `.onion` address. This is not
//! input tidiness — it is the difference between anonymity and deanonymisation.
//! A hostname that reaches the SOCKS proxy is resolved *by Tor*; a hostname
//! resolved locally leaks a DNS query that names the peer, and a direct TCP
//! fallback would announce the connection to the user's ISP with the user still
//! believing they were on Tor. There is deliberately **no fallback path** here:
//! if Tor is unreachable the connection fails, loudly.
//!
//! # What Tor does not give you
//!
//! * **Not a post-quantum circuit.** Onion v3 identities are Ed25519 and ntor is
//!   X25519 — outside our control. The session inside is hybrid-PQ, which is
//!   real defence in depth, but this is not a post-quantum Tor path and must
//!   never be described as one (roadmap §8).
//! * **Not free.** Circuits are slower and higher-latency than a direct path,
//!   which matters for a multi-gigabyte vault and interacts with the pacing
//!   rate: a rate above what a circuit sustains silently stops being constant
//!   (see [`crate::pacing`]).
//! * **Not a substitute for the pairing channel.** The onion address still has
//!   to reach the peer somehow; it travels in a ticket, over the SPAKE2 pairing
//!   channel, exactly as an IP address would.

use std::fmt;

use tokio::net::{TcpListener, TcpStream};

use crate::Error;

/// Default SOCKS port of a system Tor daemon.
pub const DEFAULT_TOR_SOCKS_PORT: u16 = 9050;

/// Length of a v3 onion address without the `.onion` suffix: 56 base32
/// characters encoding a 32-byte Ed25519 key, a checksum and a version byte.
const V3_ONION_LABEL_LEN: usize = 56;

/// A validated v3 onion address.
///
/// Constructing one is the only way to reach [`connect_onion`], so a clearnet
/// host cannot be passed where an onion was meant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnionAddress {
    host: String,
    port: u16,
}

impl OnionAddress {
    /// Parse `<56-char>.onion` with an explicit port.
    ///
    /// v2 addresses (16 characters) are rejected outright rather than attempted:
    /// they were removed from the Tor network, are cryptographically weak, and
    /// an address of that shape today is a sign of stale or hostile input.
    pub fn new(host: &str, port: u16) -> Result<Self, Error> {
        let host = host.trim().to_lowercase();
        let label = host
            .strip_suffix(".onion")
            .ok_or_else(|| Error::Connect(format!("{host} is not a .onion address")))?;

        if label.len() != V3_ONION_LABEL_LEN {
            return Err(Error::Connect(format!(
                "{host} is not a v3 onion address ({} characters, expected {V3_ONION_LABEL_LEN})",
                label.len()
            )));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(Error::Connect(format!(
                "{host} contains characters that are not valid base32"
            )));
        }
        if port == 0 {
            return Err(Error::Connect("onion port must not be zero".into()));
        }

        Ok(OnionAddress { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Connect to `addr` through the Tor SOCKS5 proxy at `socks`.
///
/// The hostname is passed to the proxy **unresolved**, so Tor performs the
/// lookup inside the network and no DNS query naming the peer ever leaves this
/// machine. There is no non-Tor fallback: if the proxy is unreachable this
/// fails rather than connecting directly.
///
/// Hand the returned stream to [`TlsSession::connect`]; the session layer is
/// identical to the QUIC path from that point on.
///
/// [`TlsSession::connect`]: crate::tls::TlsSession::connect
pub async fn connect_onion(
    socks: std::net::SocketAddr,
    addr: &OnionAddress,
) -> Result<TcpStream, Error> {
    let stream = tokio_socks::tcp::Socks5Stream::connect(socks, (addr.host(), addr.port()))
        .await
        .map_err(|e| {
            Error::Connect(format!(
                "could not reach {addr} through the Tor proxy at {socks}: {e}"
            ))
        })?;
    Ok(stream.into_inner())
}

/// Reach the peer named by `ticket` over Tor and return an established session.
///
/// The counterpart of [`crate::rendezvous::rendezvous`] for the onion path.
/// There is no hole punching and no role negotiation: an onion service is
/// reachable by definition, so one side simply connects.
///
/// Fails if the ticket offers no onion address. It does **not** fall back to the
/// ticket's direct addresses — a caller who asked for Tor and silently got a
/// direct connection would have the exposure they were trying to avoid.
pub async fn dial(
    socks: std::net::SocketAddr,
    ticket: &crate::ticket::Ticket,
    local: &crate::bundle::LocalBundle,
) -> Result<crate::tls::TlsSession<TcpStream>, Error> {
    ticket.check_valid()?;

    let onions = ticket.onion_hints();
    let addr = onions.first().ok_or_else(|| {
        Error::Connect(
            "this ticket carries no onion address, so it cannot be reached over Tor; \
             ask the peer for a ticket that offers one"
                .into(),
        )
    })?;

    let stream = connect_onion(socks, addr).await?;
    let mut session =
        crate::tls::TlsSession::connect(stream, local.classical(), ticket.identity.classical())
            .await?;
    // Same reasoning as the direct rendezvous: the post-quantum proof runs here,
    // not in the caller, so it cannot be skipped by omission.
    crate::pq_auth::authenticate(
        &mut session,
        local,
        &ticket.identity,
        crate::pq_auth::Side::Initiator,
    )
    .await?;
    Ok(session)
}

/// Accept a circuit on `listener` and complete both authentication steps.
///
/// The onion counterpart of [`dial`]. `peer` is the pinned identity bundle from
/// the peer's ticket.
pub async fn accept(
    listener: &OnionListener,
    local: &crate::bundle::LocalBundle,
    peer: &crate::bundle::IdentityBundle,
) -> Result<crate::tls::TlsSession<TcpStream>, Error> {
    let stream = listener.accept().await?;
    let mut session =
        crate::tls::TlsSession::accept(stream, local.classical(), peer.classical()).await?;
    crate::pq_auth::authenticate(&mut session, local, peer, crate::pq_auth::Side::Responder)
        .await?;
    Ok(session)
}

/// The local side of an onion service.
///
/// Tor terminates circuits and forwards them to a plain TCP port on localhost —
/// configured out of band, by a `HiddenServicePort` line in `torrc` or by the
/// embedded Tor client the rest of the workspace uses. This type is that port.
///
/// **Bind to loopback.** Binding to a routable address would leave the service
/// reachable directly, off-circuit, defeating the entire point of putting it
/// behind an onion.
#[derive(Debug)]
pub struct OnionListener {
    listener: TcpListener,
}

impl OnionListener {
    /// Listen on `bind` for circuits Tor forwards here.
    pub async fn bind(bind: std::net::SocketAddr) -> Result<Self, Error> {
        if !bind.ip().is_loopback() {
            return Err(Error::Connect(format!(
                "refusing to bind an onion service to {bind}: it must listen on \
                 loopback, or the service is reachable directly and the circuit \
                 is pointless"
            )));
        }
        let listener = TcpListener::bind(bind).await?;
        Ok(OnionListener { listener })
    }

    /// The bound local address (useful when `bind` used port 0).
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, Error> {
        self.listener.local_addr().map_err(Error::Io)
    }

    /// Accept the next forwarded circuit.
    ///
    /// The peer address is deliberately not returned: it is always Tor on
    /// localhost and says nothing about who is calling. Authentication comes
    /// from the pinned raw public key in the session handshake, exactly as it
    /// does over QUIC.
    pub async fn accept(&self) -> Result<TcpStream, Error> {
        let (stream, _) = self.listener.accept().await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    #[test]
    fn a_valid_v3_address_parses() {
        let a = OnionAddress::new(VALID, 4433).unwrap();
        assert_eq!(a.host(), VALID);
        assert_eq!(a.port(), 4433);
        assert_eq!(a.to_string(), format!("{VALID}:4433"));
    }

    #[test]
    fn addresses_are_normalised() {
        let upper = OnionAddress::new(&format!("  {}  ", VALID.to_uppercase()), 80).unwrap();
        assert_eq!(upper, OnionAddress::new(VALID, 80).unwrap());
    }

    /// **The guard that matters.** A clearnet host must never be accepted where
    /// an onion was meant — passing one through would resolve a name that
    /// identifies the peer and could route the connection outside Tor entirely.
    #[test]
    fn clearnet_hosts_are_refused() {
        for host in [
            "example.com",
            "192.0.2.1",
            "localhost",
            "evil.com/x.onion",
            "",
            ".onion",
        ] {
            assert!(
                OnionAddress::new(host, 443).is_err(),
                "{host} must not be accepted as an onion address"
            );
        }
    }

    /// v2 onions are dead and cryptographically weak; an address of that shape
    /// is stale or hostile input, not something to try anyway.
    #[test]
    fn v2_onion_addresses_are_refused() {
        let err = OnionAddress::new("abcdefghijklmnop.onion", 443).unwrap_err();
        assert!(err.to_string().contains("not a v3"), "got: {err}");
    }

    #[test]
    fn malformed_v3_addresses_are_refused() {
        // Right length, characters outside the base32 alphabet ('1', '8', '9').
        let bad = format!("{}189.onion", &VALID[..53]);
        assert!(OnionAddress::new(&bad, 443).is_err());
        // Zero port.
        assert!(OnionAddress::new(VALID, 0).is_err());
    }

    /// An onion service that also answers off-circuit is not hidden. Binding
    /// anywhere but loopback must be refused rather than warned about.
    #[tokio::test]
    async fn a_non_loopback_bind_is_refused() {
        let err = OnionListener::bind("0.0.0.0:0".parse().unwrap())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("loopback"), "got: {err}");

        assert!(
            OnionListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .is_ok()
        );
    }

    /// There is no non-Tor fallback: with no proxy listening, connecting fails
    /// rather than quietly going direct.
    #[tokio::test]
    async fn a_missing_proxy_fails_rather_than_going_direct() {
        // A port nothing is listening on.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = dead.local_addr().unwrap();
        drop(dead);

        let addr = OnionAddress::new(VALID, 4433).unwrap();
        let err = connect_onion(socks, &addr).await.unwrap_err();
        assert!(
            err.to_string().contains("Tor proxy"),
            "the failure must name the proxy, got: {err}"
        );
    }
}
