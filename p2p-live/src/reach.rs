//! Connecting to a peer from an ID alone (roadmap Phase 8).
//!
//! # What changes for the user
//!
//! Before this module, reaching a peer meant a human carrying a fresh `ip:port`
//! to the other human every time either of them changed networks. After it,
//! pairing happens **once** and connecting afterwards needs nothing but the peer
//! being online — the Syncthing property, without Syncthing's discovery server
//! learning who talks to whom (see [`crate::discovery`] for exactly how, and for
//! the leak that remains).
//!
//! # The ladder
//!
//! [`connect`] tries the cheapest and least-exposing path first and only spends
//! privacy when it has to:
//!
//! | Rung | Third parties | When it works |
//! |------|---------------|---------------|
//! | Cached address | **none** | the peer has not moved since last time |
//! | Blind rendezvous | one endpoint, which sees an opaque tag | the peer has published recently |
//! | Onion | Tor | always, if the peer offers one |
//!
//! The cached rung matters more than it looks: most reconnections are to a peer
//! who has not moved, and it resolves them without touching any substrate at all.
//!
//! # What still has to be solved out of band
//!
//! Discovery answers "where is my peer", not "where am I". A peer behind NAT does
//! not know its own external `ip:port`, and nothing in this module can tell it —
//! that is what [`crate::stun`] is for, with the disclosure warning it carries, or
//! a forwarded port, or a static address. **This is the honest cost of the ID-only
//! path:** it makes STUN (or a manually configured port) close to mandatory,
//! where before it was a convenience. A peer that cannot determine its own
//! address can still *receive* on the onion rung, but cannot publish a direct one.

use std::net::SocketAddr;
use std::time::Duration;

use crate::bundle::{IdentityBundle, LocalBundle};
use crate::discovery::{AddressRecord, Discovery, PublishReport, RendezvousSecret};
use crate::ticket::{Endpoint, Ticket};
use crate::{Error, rendezvous};

/// Longest slice of the budget spent on a cached address before moving on.
///
/// Short: a cached address that no longer works usually fails because the peer
/// moved, and no amount of retrying fixes that. Long enough that a peer who
/// simply has not started yet is not abandoned instantly.
const CACHED_ATTEMPT_MAX: Duration = Duration::from_secs(20);

/// Everything a peer's record has to remember between connections.
///
/// All four fields belong in the encrypted peer store: the identity is what
/// authenticates, the secret addresses the rendezvous, and the last two are the
/// state that makes reconnection cheap and replay detectable.
#[derive(Clone, Debug)]
pub struct PeerState {
    /// Pinned at pairing. **This is the only thing that authenticates the peer**,
    /// and nothing discovered at runtime may ever replace it.
    pub identity: IdentityBundle,
    /// The pairwise discovery secret from [`crate::pairing`].
    pub rendezvous: RendezvousSecret,
    /// Where this peer was last reached, tried first on the next connection.
    pub last_known: Vec<Endpoint>,
    /// Highest record sequence accepted from this peer, refusing replays.
    pub newest_seen: Option<u64>,
}

impl PeerState {
    /// A peer known only by identity, with nowhere to try yet.
    ///
    /// Prefer [`PeerState::from_ticket`] straight after pairing: a peer built
    /// this way has an empty `last_known`, so the very first connection skips
    /// the free rung and goes to an endpoint even though the peer just told us
    /// where they are.
    pub fn new(identity: IdentityBundle, rendezvous: RendezvousSecret) -> Self {
        PeerState {
            identity,
            rendezvous,
            last_known: Vec::new(),
            newest_seen: None,
        }
    }

    /// A freshly paired peer, seeded with the address from their ticket.
    ///
    /// The ticket's hints are exactly "where this peer said they were a moment
    /// ago", which is the best cached address there is — and using it means the
    /// first connection after pairing touches no third party at all.
    pub fn from_ticket(ticket: &Ticket, rendezvous: RendezvousSecret) -> Self {
        PeerState {
            identity: ticket.identity.clone(),
            rendezvous,
            last_known: ticket.hints.clone(),
            newest_seen: None,
        }
    }

    /// Fold a freshly resolved record into the remembered state.
    fn absorb(&mut self, record: &AddressRecord) {
        self.last_known = record.hints.clone();
        self.newest_seen = Some(record.seq);
    }

    /// The ticket the rendezvous wants, built from what we know.
    ///
    /// Discovery's whole job, framed precisely: it manufactures the ticket a
    /// human used to carry by hand. The identity in it is always the **pinned**
    /// one, never anything a substrate supplied.
    fn ticket(&self, hints: Vec<Endpoint>) -> Result<Ticket, Error> {
        Ticket::new(self.identity.clone(), hints)
    }
}

/// Which rung of the ladder produced the connection.
///
/// Surfaced rather than hidden: the rungs differ in who learns about the
/// connection, and a user is entitled to know which one they ended up on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// Reached at the remembered address. No third party involved.
    Cached,
    /// Reached at an address looked up through a blind endpoint.
    Discovered,
    /// Reached over Tor.
    Onion,
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Path::Cached => f.write_str("the remembered address (no third party)"),
            Path::Discovered => f.write_str("an address found through a blind rendezvous endpoint"),
            Path::Onion => f.write_str("Tor"),
        }
    }
}

/// An established session, whichever transport carried it.
///
/// Boxed as a trait object rather than an enum of the two concrete types: every
/// caller does the same thing with it — hand it to [`crate::transfer::Transfer`],
/// which already takes `&mut dyn SecureSession` — so making them match on the
/// transport would only invite them to treat the two differently.
pub type Reached = Box<dyn crate::SecureSession>;

/// Knobs for [`connect`].
#[derive(Clone, Debug)]
pub struct Options {
    /// Overall budget across every rung.
    pub timeout: Duration,
    /// SOCKS5 proxy for the onion rung. Without one, that rung is skipped.
    pub socks: Option<SocketAddr>,
    /// Whether to consult the blind rendezvous at all.
    ///
    /// Off means strictly no third party: the connection succeeds only if the
    /// cached address still works. Offered because for some pairs "fail rather
    /// than touch an endpoint" is the correct policy.
    pub use_discovery: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            timeout: rendezvous::DEFAULT_TIMEOUT,
            socks: None,
            use_discovery: true,
        }
    }
}

/// Publish our current addresses so this peer can find us.
///
/// `hints` must be the addresses the peer should actually try — an external
/// `ip:port` from [`crate::stun`], a forwarded port, or an onion. Determining
/// them is the caller's job precisely because the direct ones cannot be found
/// without either disclosing this machine's address to a STUN server or being
/// configured by hand, and that choice belongs to the user rather than to this
/// function.
pub async fn announce(
    local: &LocalBundle,
    peer: &PeerState,
    discovery: &Discovery,
    hints: Vec<Endpoint>,
) -> Result<PublishReport, Error> {
    let record = AddressRecord::new(hints, crate::discovery::secret::now_secs()?)?;
    discovery
        .publish(&peer.rendezvous, &local.id(), &peer.identity.id(), &record)
        .await
}

/// Connect to a paired peer, given only their identity.
///
/// `bind` must use **the same local port that was announced**, since that is the
/// NAT mapping the peer will aim at. `peer` is updated in place with anything
/// learned, and the caller should persist it afterwards.
pub async fn connect(
    bind: SocketAddr,
    local: &LocalBundle,
    peer: &mut PeerState,
    discovery: &Discovery,
    opts: &Options,
) -> Result<(Reached, Path), Error> {
    if local.id() == peer.identity.id() {
        return Err(Error::Connect(
            "this peer record is our own identity — a peer cannot connect to itself".into(),
        ));
    }

    let deadline = tokio::time::Instant::now() + opts.timeout;
    let mut attempts: Vec<String> = Vec::new();

    // One socket for every direct rung. Binding per rung would be wrong twice
    // over: the second bind fails outright, because the first endpoint's socket
    // is not released the instant it is closed; and even if it succeeded, a new
    // port would discard the NAT mapping the first attempt just spent its budget
    // opening. The endpoint is peer-specific — both directions pinned — so it is
    // built after the self-check above and used for this peer only.
    let endpoint = rendezvous::bind_endpoint(bind, local, &peer.identity)?;

    // --- Rung 1: the address we remember. No third party sees anything. ---
    let cached_direct = direct_only(&peer.last_known);
    if !cached_direct.is_empty() {
        let budget = budget_for_cache(remaining(deadline));
        match rendezvous::rendezvous_on(
            &endpoint,
            &peer.ticket(cached_direct.clone())?,
            local,
            budget,
        )
        .await
        {
            Ok(session) => return Ok((Box::new(session), Path::Cached)),
            Err(e) => attempts.push(format!("remembered address: {e}")),
        }
    }

    // --- Rung 2: ask a blind endpoint where they are now. ---
    if opts.use_discovery && !discovery.is_empty() && !remaining(deadline).is_zero() {
        match discovery
            .resolve(
                &peer.rendezvous,
                &local.id(),
                &peer.identity.id(),
                peer.newest_seen,
            )
            .await
        {
            Ok(record) => {
                // Absorbed before the attempt, not after: even a record that
                // fails to connect is the freshest thing we know, and dropping
                // it would make the next attempt repeat a stale address.
                peer.absorb(&record);

                let direct = record.direct_hints();
                if !direct.is_empty() && !remaining(deadline).is_zero() {
                    let hints = direct.into_iter().map(Endpoint::Direct).collect();
                    match rendezvous::rendezvous_on(
                        &endpoint,
                        &peer.ticket(hints)?,
                        local,
                        remaining(deadline),
                    )
                    .await
                    {
                        Ok(session) => return Ok((Box::new(session), Path::Discovered)),
                        Err(e) => attempts.push(format!("discovered address: {e}")),
                    }
                }
            }
            Err(e) => attempts.push(format!("rendezvous lookup: {e}")),
        }
    }

    // No direct rung succeeded, so the socket has no further use. Released
    // before the Tor attempt rather than after, so a long onion connection does
    // not sit on a bound port nothing is listening on.
    endpoint.close(0u32.into(), b"no direct path");

    // --- Rung 3: Tor, if the peer offers an onion and we have a proxy. ---
    let onions = onion_only(&peer.last_known);
    if let (Some(socks), false) = (opts.socks, onions.is_empty()) {
        match crate::tor::dial(socks, &peer.ticket(onions)?, local).await {
            Ok(session) => return Ok((Box::new(session), Path::Onion)),
            Err(e) => attempts.push(format!("onion: {e}")),
        }
    }

    Err(Error::Connect(format!(
        "could not reach this peer. Tried:\n  - {}\n\
         If they are online, either they have not published an address since moving, \
         or both sides are behind NATs that direct hole punching cannot cross.",
        attempts.join("\n  - ")
    )))
}

/// How much of the budget is left.
fn remaining(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

/// How long to spend on a cached address before giving up on it.
///
/// Half the remaining budget, capped. Half rather than all because a peer who
/// *has* moved can never be reached at the cached address, and burning the whole
/// window there would mean never looking up where they went; capped because
/// beyond [`CACHED_ATTEMPT_MAX`] the extra retries are not buying anything a
/// fresh lookup would not buy faster.
fn budget_for_cache(left: Duration) -> Duration {
    (left / 2).min(CACHED_ATTEMPT_MAX)
}

fn direct_only(hints: &[Endpoint]) -> Vec<Endpoint> {
    hints
        .iter()
        .filter(|h| matches!(h, Endpoint::Direct(_)))
        .cloned()
        .collect()
}

fn onion_only(hints: &[Endpoint]) -> Vec<Endpoint> {
    hints
        .iter()
        .filter(|h| matches!(h, Endpoint::Onion(_)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor::OnionAddress;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn state() -> PeerState {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).unwrap();
        PeerState::new(
            LocalBundle::generate().unwrap().bundle(),
            RendezvousSecret::from_bytes(raw),
        )
    }

    fn direct(s: &str) -> Endpoint {
        Endpoint::Direct(s.parse().unwrap())
    }

    /// The ticket handed to the rendezvous must carry the **pinned** identity.
    /// If a discovered record could ever substitute an identity here, discovery
    /// would become an authentication path — the canonical bug this layer is
    /// built to avoid.
    #[test]
    fn a_synthesised_ticket_always_carries_the_pinned_identity() {
        let peer = state();
        let ticket = peer.ticket(vec![direct("203.0.113.1:443")]).unwrap();
        assert_eq!(ticket.identity, peer.identity);
        assert!(ticket.is_hybrid(), "the post-quantum half must survive");
    }

    /// A resolved record replaces what we knew and advances the replay floor.
    #[test]
    fn absorbing_a_record_updates_the_cache_and_the_replay_floor() {
        let mut peer = state();
        assert!(peer.last_known.is_empty());
        assert_eq!(peer.newest_seen, None);

        let record = AddressRecord {
            hints: vec![direct("203.0.113.9:4433")],
            seq: 42,
            not_after: u64::MAX / 2,
        };
        peer.absorb(&record);

        assert_eq!(peer.last_known, record.hints);
        assert_eq!(peer.newest_seen, Some(42));
    }

    /// The two rungs consume different hint families and must not steal each
    /// other's: a direct rendezvous handed an onion would dial nonsense, and the
    /// Tor path handed an IP would connect off-circuit.
    #[test]
    fn hints_are_partitioned_by_transport() {
        let mixed = vec![
            direct("203.0.113.1:1"),
            Endpoint::Onion(OnionAddress::new(ONION, 4433).unwrap()),
            direct("[2001:db8::1]:2"),
        ];
        assert_eq!(direct_only(&mixed).len(), 2);
        assert_eq!(onion_only(&mixed).len(), 1);
    }

    /// The cached rung must never consume the whole budget — a peer who moved
    /// would then never get looked up.
    #[test]
    fn the_cached_rung_leaves_budget_for_the_others() {
        for secs in [2u64, 10, 60, 120, 600] {
            let total = Duration::from_secs(secs);
            let spent = budget_for_cache(total);
            assert!(
                spent < total,
                "{secs}s budget was fully consumed by the cache"
            );
            assert!(spent <= CACHED_ATTEMPT_MAX);
            assert!(!spent.is_zero(), "{secs}s budget gave the cache no chance");
        }
    }

    #[test]
    fn a_zero_budget_is_handled_without_panicking() {
        assert!(budget_for_cache(Duration::ZERO) <= Duration::from_secs(1));
    }

    /// Pointing a peer record at ourselves must fail fast with a clear message
    /// rather than spending the whole budget failing to punch to ourselves.
    #[tokio::test]
    async fn connecting_to_ourselves_is_refused() {
        let local = LocalBundle::generate().unwrap();
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).unwrap();
        let mut me = PeerState::new(local.bundle(), RendezvousSecret::from_bytes(raw));

        let err = connect(
            "127.0.0.1:0".parse().unwrap(),
            &local,
            &mut me,
            &Discovery::new(vec![]),
            &Options {
                timeout: Duration::from_millis(50),
                ..Default::default()
            },
        )
        .await
        .err()
        .expect("connecting to our own identity must fail");
        assert!(err.to_string().contains("own identity"), "got: {err}");
    }

    /// With nothing cached, no substrate and no proxy there is genuinely nowhere
    /// to try — the error must say so rather than time out silently.
    #[tokio::test]
    async fn with_nothing_to_try_the_failure_names_what_was_attempted() {
        let local = LocalBundle::generate().unwrap();
        let mut peer = state();

        let err = connect(
            "127.0.0.1:0".parse().unwrap(),
            &local,
            &mut peer,
            &Discovery::new(vec![]),
            &Options {
                timeout: Duration::from_millis(50),
                ..Default::default()
            },
        )
        .await
        .err()
        .expect("there was nowhere to connect");
        assert!(err.to_string().contains("could not reach"), "got: {err}");
    }

    /// Turning discovery off must genuinely mean no substrate is touched, not
    /// merely that it is tried last.
    #[tokio::test]
    async fn discovery_can_be_refused_entirely() {
        use crate::discovery::Substrate;
        use async_trait::async_trait;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counting(AtomicUsize);

        #[async_trait]
        impl Substrate for Counting {
            fn name(&self) -> &str {
                "counting"
            }
            async fn put(&self, _: &str, _: &[u8], _: Duration) -> Result<(), Error> {
                Ok(())
            }
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, Error> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
        }

        let counting = Arc::new(Counting(AtomicUsize::new(0)));
        let local = LocalBundle::generate().unwrap();
        let mut peer = state();

        let _ = connect(
            "127.0.0.1:0".parse().unwrap(),
            &local,
            &mut peer,
            &Discovery::new(vec![counting.clone()]),
            &Options {
                timeout: Duration::from_millis(50),
                use_discovery: false,
                ..Default::default()
            },
        )
        .await;

        assert_eq!(
            counting.0.load(Ordering::SeqCst),
            0,
            "an endpoint was contacted despite discovery being switched off"
        );
    }
}
