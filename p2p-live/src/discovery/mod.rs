//! Reachability from an ID alone (roadmap Phase 8).
//!
//! # The problem
//!
//! Everything before this phase required a human to carry an `ip:port` to their
//! peer. Home and mobile addresses are dynamic, so that ticket is stale within
//! days and the pair has to re-exchange out of band every time either of them
//! moves. What people actually want is Syncthing's property: **hand over an ID
//! once, and it keeps working.**
//!
//! # What Syncthing actually does, since it is the model
//!
//! It is worth being exact, because the property is often described as if it were
//! free. A Syncthing device announces `device-ID -> current addresses` to global
//! discovery servers and looks peers up there by ID; when hole punching fails it
//! falls back to a relay pool. The device ID is a hash of the device's key, so a
//! malicious discovery server **cannot impersonate** anyone — it can only send
//! you to an address where the handshake fails.
//!
//! But it does learn every announcing device's current IP, and from the queries
//! it learns **who is looking for whom**. That is the peer-pairing metadata
//! `CLAUDE.md` §2.1 is built to deny. So "only an ID is enough" is not
//! broker-free; it trades a broker that cannot lie to you for a broker that
//! watches you. This module keeps the first property and removes as much of the
//! second as is achievable without Tor.
//!
//! # How this differs
//!
//! Nothing here is filed under an identity. A record is filed under a
//! [`secret::Slot`] — an opaque label derived from a secret only the two paired
//! peers hold, rotated hourly — and sealed under a key derived alongside it. A
//! substrate therefore holds a rotating random-looking label pointing at a
//! fixed-size opaque blob. It cannot say whose record it is, cannot follow a pair
//! across epochs, and **cannot be compelled to watch a named person**, because
//! computing that person's labels needs a secret it never sees.
//!
//! # The leak that remains — stated plainly
//!
//! A substrate sees *"IP `X` wrote tag `T`"* and later *"IP `Y` read tag `T`"*.
//! It does not learn who `X` and `Y` are, and the tag is meaningless an hour
//! later, but for that hour it can infer that those two addresses are **a pair**.
//! Nothing in this design removes that; only not using a substrate at all does.
//! Hence the ladder in [`Discovery::resolve`] tries the substrate-free paths
//! first, and hence the recommendation to run your own endpoint, where "the
//! operator" is you.
//!
//! # Discovery can never weaken authentication
//!
//! This is the invariant that makes the whole layer safe to add, and it must
//! survive every future change here: **a record supplies hints, never identity.**
//! The peer is authenticated by the mutually-pinned hybrid-PQ handshake against
//! the [`crate::bundle::IdentityBundle`] fixed at pairing time. A substrate that
//! serves a forged, stale, or attacker-chosen record cannot cause a session with
//! the wrong peer — only a failed connection. If a change here ever lets a
//! discovered record influence *who* is trusted rather than *where* they are
//! tried, that is the canonical bug in this module.

pub mod blind;
pub mod record;
pub mod secret;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::Error;
use crate::bundle::BundleId;

pub use blind::{BlindEndpoint, CertPin, parse_pin};
pub use record::{AddressRecord, SEALED_LEN};
pub use secret::{Direction, EPOCH_SECS, RendezvousSecret, Slot};

/// A dumb key-value store that holds sealed records for a while.
///
/// The interface is deliberately this small. A substrate is asked to store
/// opaque bytes under an opaque label and hand them back; it is given no
/// identity, no authentication, and no way to distinguish one client from
/// another. Anything richer would be something for an operator to log.
#[async_trait]
pub trait Substrate: Send + Sync {
    /// Short name for diagnostics. Must not include credentials.
    fn name(&self) -> &str;

    /// Store `sealed` under `tag`, replacing anything already there, for `ttl`.
    async fn put(&self, tag: &str, sealed: &[u8], ttl: Duration) -> Result<(), Error>;

    /// Fetch what is stored under `tag`, or `None` if nothing is.
    async fn get(&self, tag: &str) -> Result<Option<Vec<u8>>, Error>;
}

/// The resolver: turns a peer's ID into somewhere to try.
pub struct Discovery {
    substrates: Vec<Arc<dyn Substrate>>,
}

/// What a publish attempt achieved.
///
/// Publishing is best-effort across substrates — one reachable endpoint is
/// enough for the peer to find us — but the failures are reported rather than
/// swallowed, because "silently stopped being reachable" is the failure mode
/// that wastes an hour of two people's time.
#[derive(Debug, Default)]
pub struct PublishReport {
    /// Names of substrates that accepted every slot.
    pub succeeded: Vec<String>,
    /// Substrate name and the error it returned.
    pub failed: Vec<(String, String)>,
}

impl PublishReport {
    /// Whether the record reached anywhere at all.
    pub fn is_reachable(&self) -> bool {
        !self.succeeded.is_empty()
    }
}

impl Discovery {
    /// Build a resolver over the configured substrates, in no particular order —
    /// [`Discovery::resolve`] randomises which one it asks.
    pub fn new(substrates: Vec<Arc<dyn Substrate>>) -> Self {
        Discovery { substrates }
    }

    /// Whether any substrate is configured at all.
    pub fn is_empty(&self) -> bool {
        self.substrates.is_empty()
    }

    /// Publish our current addresses so `peer` can find us.
    ///
    /// Written to **every** configured substrate, because we cannot know which
    /// one the peer will ask. The cost is explicit and worth stating in the UI:
    /// each configured endpoint learns this machine's IP. Configuring exactly one
    /// endpoint, self-hosted, is the least-exposure choice.
    pub async fn publish(
        &self,
        secret: &RendezvousSecret,
        local: &BundleId,
        peer: &BundleId,
        record: &AddressRecord,
    ) -> Result<PublishReport, Error> {
        if self.substrates.is_empty() {
            return Err(Error::Discovery(
                "no rendezvous endpoint is configured, so this peer cannot be found \
                 by ID alone — add one, or exchange an address manually"
                    .into(),
            ));
        }

        let direction = Direction::publishing(local, peer);
        let now = secret::now_secs()?;
        let slots = secret.publish_slots(direction, now);

        // Sealed once per slot, not once per substrate: the same bytes go
        // everywhere, so two endpoints colluding see identical blobs and learn
        // nothing from comparing them that one endpoint did not already know.
        let mut sealed = Vec::with_capacity(slots.len());
        for slot in &slots {
            sealed.push((slot.tag_hex(), record.seal(slot)?));
        }

        // The record must outlive the slot it sits in, or it vanishes from the
        // current epoch just as the peer looks. Two epochs of headroom.
        let ttl = Duration::from_secs(record::MAX_TTL_SECS.min(2 * EPOCH_SECS));

        let mut report = PublishReport::default();
        for substrate in &self.substrates {
            let mut error = None;
            for (tag, bytes) in &sealed {
                if let Err(e) = substrate.put(tag, bytes, ttl).await {
                    error = Some(e.to_string());
                    break;
                }
            }
            match error {
                None => report.succeeded.push(substrate.name().to_string()),
                Some(e) => report.failed.push((substrate.name().to_string(), e)),
            }
        }
        Ok(report)
    }

    /// Look up where `peer` currently is.
    ///
    /// `newest_seen` is the highest `seq` already accepted from this peer;
    /// anything not newer is refused, which is what stops a substrate replaying a
    /// stale record forever.
    ///
    /// Substrates are tried in **random order, one at a time**, stopping at the
    /// first that answers. Asking all of them in parallel would be faster and
    /// would show this machine's IP to every operator on every lookup; asking one
    /// keeps the exposure to one. Within a substrate all three candidate slots
    /// are always queried, never stopping early, so the request pattern says
    /// nothing about how far the two clocks have drifted.
    pub async fn resolve(
        &self,
        secret: &RendezvousSecret,
        local: &BundleId,
        peer: &BundleId,
        newest_seen: Option<u64>,
    ) -> Result<AddressRecord, Error> {
        if self.substrates.is_empty() {
            return Err(Error::Discovery(
                "no rendezvous endpoint is configured, so this peer's address cannot \
                 be looked up — add one, or ask them for an address directly"
                    .into(),
            ));
        }

        // We read the slot the *peer* publishes into, which is the flip of ours.
        let direction = Direction::publishing(local, peer).flip();
        let now = secret::now_secs()?;
        let slots = secret.lookup_slots(direction, now);

        let mut last_error = String::from("no substrate was reachable");

        for substrate in shuffled(&self.substrates)? {
            let mut best: Option<AddressRecord> = None;

            for slot in &slots {
                let fetched = match substrate.get(&slot.tag_hex()).await {
                    Ok(v) => v,
                    Err(e) => {
                        last_error = format!("{}: {e}", substrate.name());
                        continue;
                    }
                };
                let Some(bytes) = fetched else { continue };

                // A record that fails to open is not an error worth surfacing: an
                // unrelated tenant of a shared endpoint may legitimately hold a
                // colliding tag, and a hostile one can always serve garbage.
                let Ok(candidate) = AddressRecord::open(&bytes, slot, now) else {
                    continue;
                };
                if !candidate.supersedes(newest_seen) {
                    last_error = format!(
                        "{}: only a stale record was served — the peer may not have \
                         published since moving, or the endpoint is replaying an old one",
                        substrate.name()
                    );
                    continue;
                }
                // Newest wins: with three epochs in play, more than one slot can
                // legitimately hold a valid record.
                if best.as_ref().is_none_or(|b| candidate.seq > b.seq) {
                    best = Some(candidate);
                }
            }

            if let Some(record) = best {
                return Ok(record);
            }
        }

        Err(Error::Discovery(format!(
            "could not find a current address for this peer. Last outcome: {last_error}. \
             Either they are not running, or they have not published since their address \
             changed."
        )))
    }
}

/// Fisher–Yates over the substrate list, using the OS CSPRNG.
///
/// The order must not be predictable: a fixed order would make the first
/// configured endpoint see every lookup this machine ever makes.
fn shuffled(substrates: &[Arc<dyn Substrate>]) -> Result<Vec<Arc<dyn Substrate>>, Error> {
    let mut out: Vec<Arc<dyn Substrate>> = substrates.to_vec();
    if out.len() < 2 {
        return Ok(out);
    }

    let mut noise = vec![0u8; out.len() * 8];
    getrandom::fill(&mut noise)
        .map_err(|e| Error::Discovery(format!("OS random number generator unavailable: {e}")))?;

    for i in (1..out.len()).rev() {
        let bytes: [u8; 8] = noise[i * 8..i * 8 + 8].try_into().expect("8 bytes");
        // Modulo bias over a 64-bit draw into a list of a handful of endpoints is
        // far below anything observable, and this is a privacy shuffle rather
        // than a cryptographic permutation.
        let j = (u64::from_be_bytes(bytes) % (i as u64 + 1)) as usize;
        out.swap(i, j);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::LocalBundle;
    use crate::ticket::Endpoint;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An in-memory substrate that records what it was asked for, so the tests
    /// can assert on what an operator would actually observe.
    struct Memory {
        name: String,
        stored: Mutex<HashMap<String, Vec<u8>>>,
        gets: Mutex<Vec<String>>,
        fail: bool,
    }

    impl Memory {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Memory {
                name: name.to_string(),
                stored: Mutex::new(HashMap::new()),
                gets: Mutex::new(Vec::new()),
                fail: false,
            })
        }

        fn failing(name: &str) -> Arc<Self> {
            Arc::new(Memory {
                name: name.to_string(),
                stored: Mutex::new(HashMap::new()),
                gets: Mutex::new(Vec::new()),
                fail: true,
            })
        }
    }

    #[async_trait]
    impl Substrate for Memory {
        fn name(&self) -> &str {
            &self.name
        }

        async fn put(&self, tag: &str, sealed: &[u8], _ttl: Duration) -> Result<(), Error> {
            if self.fail {
                return Err(Error::Discovery("endpoint down".into()));
            }
            self.stored
                .lock()
                .unwrap()
                .insert(tag.to_string(), sealed.to_vec());
            Ok(())
        }

        async fn get(&self, tag: &str) -> Result<Option<Vec<u8>>, Error> {
            self.gets.lock().unwrap().push(tag.to_string());
            if self.fail {
                return Err(Error::Discovery("endpoint down".into()));
            }
            Ok(self.stored.lock().unwrap().get(tag).cloned())
        }
    }

    fn pair() -> (BundleId, BundleId, RendezvousSecret) {
        let a = LocalBundle::generate().unwrap().id();
        let b = LocalBundle::generate().unwrap().id();
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).unwrap();
        (a, b, RendezvousSecret::from_bytes(raw))
    }

    fn record() -> AddressRecord {
        AddressRecord::new(
            vec![Endpoint::Direct("203.0.113.9:4433".parse().unwrap())],
            secret::now_secs().unwrap(),
        )
        .unwrap()
    }

    /// The end-to-end property this module exists for: one peer publishes, the
    /// other resolves, and neither ever handled an address by hand.
    #[tokio::test]
    async fn a_published_record_resolves_from_the_other_side() {
        let (a, b, secret) = pair();
        let store = Memory::new("memory");
        let d = Discovery::new(vec![store]);

        let rec = record();
        assert!(
            d.publish(&secret, &a, &b, &rec)
                .await
                .unwrap()
                .is_reachable()
        );

        // B resolves A: same secret, roles reversed, nothing else exchanged.
        let found = d.resolve(&secret, &b, &a, None).await.unwrap();
        assert_eq!(found.hints, rec.hints);
    }

    /// Both peers must be able to publish in the same epoch without one
    /// overwriting the other.
    #[tokio::test]
    async fn both_peers_can_publish_at_once() {
        let (a, b, secret) = pair();
        let store = Memory::new("memory");
        let d = Discovery::new(vec![store]);

        let from_a = AddressRecord::new(
            vec![Endpoint::Direct("203.0.113.1:1".parse().unwrap())],
            secret::now_secs().unwrap(),
        )
        .unwrap();
        let from_b = AddressRecord::new(
            vec![Endpoint::Direct("203.0.113.2:2".parse().unwrap())],
            secret::now_secs().unwrap(),
        )
        .unwrap();

        d.publish(&secret, &a, &b, &from_a).await.unwrap();
        d.publish(&secret, &b, &a, &from_b).await.unwrap();

        assert_eq!(
            d.resolve(&secret, &b, &a, None).await.unwrap().hints,
            from_a.hints,
            "B must read A's record"
        );
        assert_eq!(
            d.resolve(&secret, &a, &b, None).await.unwrap().hints,
            from_b.hints,
            "A must read B's record"
        );
    }

    /// What the operator sees must be opaque: no identifier of either peer may
    /// appear in the tag or the stored bytes.
    #[tokio::test]
    async fn the_substrate_sees_no_identity() {
        let (a, b, secret) = pair();
        let store = Memory::new("memory");
        let d = Discovery::new(vec![store.clone()]);
        d.publish(&secret, &a, &b, &record()).await.unwrap();

        let stored = store.stored.lock().unwrap();
        for (tag, bytes) in stored.iter() {
            assert_eq!(bytes.len(), SEALED_LEN, "records must be a uniform size");
            for id in [&a, &b] {
                assert!(
                    !tag.contains(&id.to_string()),
                    "an identity leaked into the tag"
                );
                assert!(
                    bytes
                        .windows(id.as_bytes().len())
                        .all(|w| w != id.as_bytes()),
                    "an identity leaked into the stored record"
                );
            }
        }
    }

    /// A lookup must always ask for the same number of tags, whatever the state
    /// of the clock — an adaptive count would leak that state to the operator.
    #[tokio::test]
    async fn a_lookup_always_queries_three_tags() {
        let (a, b, secret) = pair();
        let store = Memory::new("memory");
        let d = Discovery::new(vec![store.clone()]);

        let _ = d.resolve(&secret, &b, &a, None).await;
        assert_eq!(store.gets.lock().unwrap().len(), 3);
    }

    /// A substrate replaying a record we have already seen must not be able to
    /// pass it off as current.
    #[tokio::test]
    async fn a_replayed_record_is_refused() {
        let (a, b, secret) = pair();
        let store = Memory::new("memory");
        let d = Discovery::new(vec![store]);

        let rec = record();
        d.publish(&secret, &a, &b, &rec).await.unwrap();

        let err = d
            .resolve(&secret, &b, &a, Some(rec.seq))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("stale"), "got: {err}");
    }

    /// One dead endpoint must not take reachability with it.
    #[tokio::test]
    async fn a_failing_substrate_is_reported_but_not_fatal() {
        let (a, b, secret) = pair();
        let good = Memory::new("good");
        let bad = Memory::failing("bad");
        let d = Discovery::new(vec![bad, good]);

        let report = d.publish(&secret, &a, &b, &record()).await.unwrap();
        assert!(report.is_reachable());
        assert_eq!(report.succeeded, vec!["good"]);
        assert_eq!(report.failed.len(), 1);

        // And resolution still works through the surviving endpoint, whichever
        // order the shuffle picked.
        assert!(d.resolve(&secret, &b, &a, None).await.is_ok());
    }

    /// With nothing configured the caller must be told, not silently left
    /// unreachable.
    #[tokio::test]
    async fn no_substrate_is_an_explicit_error() {
        let (a, b, secret) = pair();
        let d = Discovery::new(vec![]);
        assert!(d.is_empty());
        assert!(d.publish(&secret, &a, &b, &record()).await.is_err());
        assert!(d.resolve(&secret, &b, &a, None).await.is_err());
    }

    /// A third party who holds neither the secret nor the tags must not be able
    /// to resolve the pair, even with full read access to the substrate.
    #[tokio::test]
    async fn an_unrelated_pair_cannot_resolve_the_record() {
        let (a, b, secret) = pair();
        let (_, _, other_secret) = pair();
        let store = Memory::new("memory");
        let d = Discovery::new(vec![store]);
        d.publish(&secret, &a, &b, &record()).await.unwrap();

        assert!(d.resolve(&other_secret, &b, &a, None).await.is_err());
    }
}
