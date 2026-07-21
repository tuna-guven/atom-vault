//! L1 — meeting on the wire without a broker (roadmap Phase 3).
//!
//! Both peers run [`rendezvous`] with each other's ticket at roughly the same
//! time. There is **no discovery server, no relay, and no signalling channel** —
//! per `CLAUDE.md` §6 the addresses came from the humans, and the only thing this
//! module does is get packets flowing between two of them.
//!
//! # Why both sides must send
//!
//! A stateful NAT forwards an inbound packet only if it matches a mapping some
//! earlier *outbound* packet created. If only one peer transmits, its packets
//! hit the other's NAT with no mapping and are dropped. So both peers transmit
//! from the start: the peer that will not end up dialling still sends packets
//! purely to open its own mapping. That is the whole trick behind hole punching.
//!
//! # Why the roles are fixed in advance
//!
//! If both peers simply dialled and accepted, two connections could form and
//! each side might keep a different one — a sender talking on one connection to a
//! receiver listening on another. The tie is broken with no extra round trip by
//! comparing the two identity keys, which both sides already hold from the
//! tickets: **the lexicographically smaller identity dials, the larger accepts.**
//! Deterministic, symmetric, and requires no negotiation.
//!
//! # What this does and does not defeat
//!
//! It gets through the common cases: full-cone, restricted-cone and
//! port-restricted NATs, where the mapping a peer opens is reusable by the other
//! peer's address. It does **not** defeat symmetric NAT or carrier-grade NAT,
//! which allocate a fresh external port per destination — the address in the
//! ticket is then simply wrong for this flow. There is no relay fallback by
//! design (a relay is a broker), so those cases need port forwarding, a VPN, or
//! the Tor transport (Phase 5).
//!
//! # Metadata, stated plainly
//!
//! A successful rendezvous means each peer's ISP observes a UDP flow to the
//! other's address. That pairing is visible and this module cannot hide it —
//! per `CLAUDE.md` §10, if the pairing itself must stay hidden then the direct
//! transport is the wrong tool and the Tor path is the answer.

use std::net::SocketAddr;
use std::time::Duration;

use crate::identity::LocalIdentity;
use crate::session::{QuicSession, SERVER_NAME, client_session, server_session, transport_config};
use crate::ticket::Ticket;
use crate::{Error, client_config, server_config};

/// How long to wait on a single connection attempt before retrying. Short,
/// because the first attempts are *expected* to fail: they are what opens the
/// NAT mapping the later ones travel through.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// Gap between attempts, keeping the mapping warm without flooding.
const RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Default overall budget. Rendezvous is a human-coordinated act ("call me and
/// we'll both hit enter"), so the window has to tolerate people.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Which side of the connection this peer takes.
///
/// Derived from the identity keys alone, so both peers compute the same answer
/// without exchanging anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Smaller identity: opens the connection.
    Dialer,
    /// Larger identity: accepts it, while still transmitting to punch.
    Accepter,
}

/// Decide roles by comparing raw public keys.
///
/// Keys are distinct in any real pairing (they are different peers), but the
/// equal case is defined rather than left to chance: it means a peer is being
/// pointed at itself, which cannot succeed and is reported as an error by
/// [`rendezvous`] rather than deadlocking.
pub fn role_for(local: &LocalIdentity, peer: &Ticket) -> Role {
    if local.public_key().as_der() < peer.identity.as_der() {
        Role::Dialer
    } else {
        Role::Accepter
    }
}

/// Meet the peer described by `ticket` and return an established session.
///
/// `bind` is the local UDP address; the port must be the one advertised in *our*
/// ticket, since that is the mapping the peer will aim at.
///
/// Both peers call this with the same wall-clock intent. It returns as soon as a
/// session is established, or [`Error::Connect`] when the budget expires.
pub async fn rendezvous(
    bind: SocketAddr,
    ticket: &Ticket,
    local: &LocalIdentity,
    timeout: Duration,
) -> Result<QuicSession, Error> {
    ticket.check_valid()?;

    if local.public_key() == &ticket.identity {
        return Err(Error::Connect(
            "this ticket is our own identity — a peer cannot rendezvous with itself".into(),
        ));
    }
    if ticket.hints.is_empty() {
        return Err(Error::Connect(
            "ticket carries no address hints; enter the peer's address manually or \
             ask them for a ticket that includes one"
                .into(),
        ));
    }

    let peer = &ticket.identity;
    let mut client_cfg = client_config(local, peer)?;
    client_cfg.transport_config(transport_config());
    let mut server_cfg = server_config(local, peer)?;
    server_cfg.transport_config(transport_config());

    // One socket doing both jobs. This matters beyond tidiness: the NAT mapping
    // is per local port, so punching and connecting must happen on the *same*
    // port or the mapping opened is not the one used.
    let mut endpoint = quinn::Endpoint::server(server_cfg, bind)?;
    endpoint.set_default_client_config(client_cfg);

    let role = role_for(local, ticket);
    let deadline = tokio::time::Instant::now() + timeout;

    let result = match role {
        Role::Dialer => dial_loop(&endpoint, ticket, deadline).await,
        Role::Accepter => accept_loop(&endpoint, ticket, deadline).await,
    };

    match result {
        Ok(session) => Ok(session),
        Err(e) => {
            endpoint.close(0u32.into(), b"rendezvous failed");
            Err(e)
        }
    }
}

/// Retry outbound connections across every hint until one completes.
async fn dial_loop(
    endpoint: &quinn::Endpoint,
    ticket: &Ticket,
    deadline: tokio::time::Instant,
) -> Result<QuicSession, Error> {
    let mut last = String::from("no attempt completed");

    while tokio::time::Instant::now() < deadline {
        for hint in &ticket.hints {
            match attempt_connect(endpoint, *hint).await {
                Ok(conn) => {
                    return client_session(endpoint.clone(), conn, &ticket.identity).await;
                }
                Err(e) => last = e,
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }

    Err(Error::Connect(format!(
        "rendezvous timed out while dialling {:?}; last error: {last}. If both peers \
         were online, the addresses are probably wrong or a symmetric NAT is \
         rewriting ports.",
        ticket.hints
    )))
}

/// Wait for the peer's connection while transmitting often enough to keep our
/// own NAT mapping open.
async fn accept_loop(
    endpoint: &quinn::Endpoint,
    ticket: &Ticket,
    deadline: tokio::time::Instant,
) -> Result<QuicSession, Error> {
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Connect(format!(
                "rendezvous timed out waiting for the peer to connect from {:?}. \
                 Either they were not running at the same time, or our address is \
                 not reachable from theirs.",
                ticket.hints
            )));
        }

        tokio::select! {
            // Our side of the punch: an outbound attempt we do not expect to
            // succeed. The peer is not accepting, so it will fail — but the
            // packets left our NAT, which is the entire purpose.
            _ = punch(endpoint, &ticket.hints) => {}

            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return Err(Error::Connect("endpoint closed while awaiting the peer".into()));
                };
                match incoming.await {
                    Ok(conn) => return server_session(endpoint.clone(), conn, &ticket.identity).await,
                    // A failed inbound handshake here is normal: it is usually the
                    // peer's own punch traffic, which by design nobody accepts.
                    // Keep waiting rather than giving up on the rendezvous.
                    Err(_) => continue,
                }
            }

            _ = tokio::time::sleep(remaining) => continue,
        }
    }
}

/// Fire a short-lived connection attempt at each hint purely to create outbound
/// NAT state. The result is deliberately discarded.
async fn punch(endpoint: &quinn::Endpoint, hints: &[SocketAddr]) {
    for hint in hints {
        // The future must be polled for packets to actually be sent, so this
        // awaits briefly rather than dropping the attempt immediately.
        let _ = attempt_connect(endpoint, *hint).await;
    }
    tokio::time::sleep(RETRY_INTERVAL).await;
}

/// One bounded connection attempt.
async fn attempt_connect(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
) -> Result<quinn::Connection, String> {
    let connecting = endpoint
        .connect(addr, SERVER_NAME)
        .map_err(|e| format!("{addr}: {e}"))?;

    match tokio::time::timeout(ATTEMPT_TIMEOUT, connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(format!("{addr}: {e}")),
        Err(_) => Err(format!("{addr}: attempt timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ticket::Ticket;

    fn ticket_for(id: &LocalIdentity, addr: &str) -> Ticket {
        Ticket::new(id.public_key().clone(), vec![addr.parse().unwrap()]).unwrap()
    }

    /// Both peers must independently compute complementary roles, or two
    /// connections form and the two ends talk past each other.
    #[test]
    fn roles_are_complementary_and_deterministic() {
        for _ in 0..32 {
            let a = LocalIdentity::generate().unwrap();
            let b = LocalIdentity::generate().unwrap();
            let (ta, tb) = (ticket_for(&a, "10.0.0.1:1"), ticket_for(&b, "10.0.0.2:2"));

            let role_a = role_for(&a, &tb);
            let role_b = role_for(&b, &ta);
            assert_ne!(
                role_a, role_b,
                "exactly one peer must dial; both sides computed {role_a:?}"
            );
            // Stable across calls.
            assert_eq!(role_a, role_for(&a, &tb));
        }
    }

    #[tokio::test]
    async fn an_expired_ticket_is_refused_before_any_packet() {
        let a = LocalIdentity::generate().unwrap();
        let b = LocalIdentity::generate().unwrap();
        let stale = ticket_for(&b, "10.0.0.2:2").expiring_at(0);

        let err = rendezvous(
            "127.0.0.1:0".parse().unwrap(),
            &stale,
            &a,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "got: {err}");
    }

    #[tokio::test]
    async fn a_ticket_without_hints_is_refused() {
        let a = LocalIdentity::generate().unwrap();
        let b = LocalIdentity::generate().unwrap();
        let no_hints = Ticket::new(b.public_key().clone(), vec![]).unwrap();

        let err = rendezvous(
            "127.0.0.1:0".parse().unwrap(),
            &no_hints,
            &a,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no address hints"), "got: {err}");
    }

    /// Pointing a peer at its own ticket must fail fast rather than hang: both
    /// sides would compute `Accepter` and wait forever.
    #[tokio::test]
    async fn rendezvous_with_self_is_refused() {
        let a = LocalIdentity::generate().unwrap();
        let mine = ticket_for(&a, "127.0.0.1:1");

        let err = rendezvous(
            "127.0.0.1:0".parse().unwrap(),
            &mine,
            &a,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("own identity"), "got: {err}");
    }
}
