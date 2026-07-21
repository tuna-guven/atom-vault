//! Phase 8 end-to-end — pair once, then connect knowing only an ID.
//!
//! This is the property the phase exists for, exercised the way two people would
//! actually hit it: they pair on Monday at one address, Alice's address changes,
//! and on Tuesday Bob connects without anyone having exchanged anything.
//!
//! The substrate here is in-memory, which is exactly what a real one is from the
//! protocol's point of view — a dumb map from an opaque tag to opaque bytes. It
//! also lets the test assert on **what the operator would see**, which is the
//! part that cannot be checked by a connection succeeding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use p2p_live::Error;
use p2p_live::bundle::LocalBundle;
use p2p_live::discovery::{Discovery, Substrate};
use p2p_live::pacing::Pacing;
use p2p_live::pairing::{self, PairingCode};
use p2p_live::reach::{self, Options, Path, PeerState};
use p2p_live::ticket::{Endpoint, Ticket};
use p2p_live::transfer::{EncryptedAtRest, Transfer};

/// Everything a rendezvous endpoint ever holds, plus a log of what it was asked.
#[derive(Default)]
struct Store {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    seen_tags: Mutex<Vec<String>>,
}

#[async_trait]
impl Substrate for Store {
    fn name(&self) -> &str {
        "test-store"
    }

    async fn put(&self, tag: &str, sealed: &[u8], _ttl: Duration) -> Result<(), Error> {
        self.seen_tags.lock().unwrap().push(tag.to_string());
        self.blobs
            .lock()
            .unwrap()
            .insert(tag.to_string(), sealed.to_vec());
        Ok(())
    }

    async fn get(&self, tag: &str) -> Result<Option<Vec<u8>>, Error> {
        self.seen_tags.lock().unwrap().push(tag.to_string());
        Ok(self.blobs.lock().unwrap().get(tag).cloned())
    }
}

fn shaped() -> Transfer {
    Transfer::new(EncryptedAtRest::aegis_vault())
        .chunk_len(64 * 1024)
        .pacing(
            Pacing::default()
                .at_rate(32 * 1024 * 1024)
                .with_bounds(16, 8),
        )
}

/// Claim a loopback port, then release it so the endpoint can take it.
fn reserve_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
    let addr = s.local_addr().expect("local addr");
    drop(s);
    addr
}

/// Run the real SPAKE2 pairing and return both sides' peer state.
///
/// Crucially this uses the actual pairing code path rather than handing both
/// sides a shared constant: the rendezvous secret has to *come out of* pairing
/// identically on both ends, and a test that injected it would prove nothing.
fn pair(
    alice: &LocalBundle,
    bob: &LocalBundle,
    alice_ticket: Ticket,
    bob_ticket: Ticket,
) -> (PeerState, PeerState) {
    let code = PairingCode::generate().unwrap();

    let (a_state, a_msg) = pairing::start(&code);
    let (b_state, b_msg) = pairing::start(&PairingCode::parse(&code.display()).unwrap());

    let a_channel = a_state.finish(&b_msg).unwrap();
    let b_channel = b_state.finish(&a_msg).unwrap();

    // Each side seals its own ticket and opens the other's, as the UI drives it.
    let a_sealed = a_channel.seal_ticket(&alice_ticket).unwrap();
    let b_sealed = b_channel.seal_ticket(&bob_ticket).unwrap();
    let alice_sees = a_channel.open_ticket(&b_sealed).unwrap();
    let bob_sees = b_channel.open_ticket(&a_sealed).unwrap();

    assert_eq!(alice_sees.id(), bob.id());
    assert_eq!(bob_sees.id(), alice.id());

    // The two independently-derived secrets must be the same 32 bytes, or the
    // peers address different slots and never find each other.
    let a_secret = a_channel.rendezvous_secret();
    let b_secret = b_channel.rendezvous_secret();
    assert_eq!(
        a_secret.expose(),
        b_secret.expose(),
        "pairing produced two different rendezvous secrets"
    );

    (
        PeerState::from_ticket(&alice_sees, a_secret),
        PeerState::from_ticket(&bob_sees, b_secret),
    )
}

/// The whole point: Alice moves, publishes, and Bob reaches her by ID alone.
#[tokio::test]
async fn a_peer_who_moved_is_found_by_id_and_delivers_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("my_data.aegis");
    let dst = dir.path().join("received.aegis");
    let vault: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &vault).unwrap();

    let alice = LocalBundle::generate().unwrap();
    let bob = LocalBundle::generate().unwrap();

    // --- Monday: they pair, at addresses that will not survive the week. ---
    let stale: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (alice_sees_bob, mut bob_sees_alice) = pair(
        &alice,
        &bob,
        Ticket::new(alice.bundle(), vec![Endpoint::Direct(stale)]).unwrap(),
        Ticket::new(bob.bundle(), vec![Endpoint::Direct(stale)]).unwrap(),
    );

    let store = Arc::new(Store::default());
    let discovery = Discovery::new(vec![store.clone()]);

    // --- Tuesday: both have new addresses. Each publishes its own. ---
    let alice_addr = reserve_port();
    let bob_addr = reserve_port();

    reach::announce(
        &alice,
        &alice_sees_bob,
        &discovery,
        vec![Endpoint::Direct(alice_addr)],
    )
    .await
    .expect("alice publishes")
    .is_reachable()
    .then_some(())
    .expect("alice's record reached the store");

    reach::announce(
        &bob,
        &bob_sees_alice,
        &discovery,
        vec![Endpoint::Direct(bob_addr)],
    )
    .await
    .expect("bob publishes");

    // --- Both connect, holding only the identity they pinned on Monday. ---
    let opts = Options {
        timeout: Duration::from_secs(12),
        socks: None,
        use_discovery: true,
    };

    let alice_side = {
        let d = Discovery::new(vec![store.clone()]);
        let mut peer = alice_sees_bob.clone();
        tokio::spawn(async move {
            let opts = Options {
                timeout: Duration::from_secs(12),
                socks: None,
                use_discovery: true,
            };
            let (session, path) = reach::connect(alice_addr, &alice, &mut peer, &d, &opts)
                .await
                .expect("alice reaches bob");
            (session, path, peer)
        })
    };

    let (mut bob_session, bob_path) =
        reach::connect(bob_addr, &bob, &mut bob_sees_alice, &discovery, &opts)
            .await
            .expect("bob reaches alice");

    let (mut alice_session, alice_path, alice_learned) = alice_side.await.unwrap();

    // Neither side used the stale address from pairing; both were discovered.
    assert_eq!(alice_path, Path::Discovered, "alice took the wrong rung");
    assert_eq!(bob_path, Path::Discovered, "bob took the wrong rung");

    // What was learned is what a caller would persist for next time.
    assert_eq!(
        alice_learned.last_known,
        vec![Endpoint::Direct(bob_addr)],
        "alice must remember where bob actually was"
    );
    assert!(alice_learned.newest_seen.is_some());

    // --- And the session is a real one: move the vault over it. ---
    let sender = tokio::spawn(async move {
        let r = shaped()
            .send(alice_session.as_mut(), &src, &mut |_| {})
            .await;
        let _ = alice_session.close().await;
        r
    });

    let received = shaped()
        .recv(bob_session.as_mut(), &dst, &mut |_| {})
        .await
        .expect("bob receives the vault");
    let _ = bob_session.close().await;
    sender.await.unwrap().expect("alice sends the vault");

    assert_eq!(received.total, vault.len() as u64);
    assert_eq!(std::fs::read(&dst).unwrap(), vault, "vault must survive");
}

/// What the endpoint operator sees, asserted directly.
///
/// A successful connection proves the mechanism works; it does not prove the
/// mechanism is blind. This does.
#[tokio::test]
async fn the_endpoint_learns_nothing_that_identifies_either_peer() {
    let alice = LocalBundle::generate().unwrap();
    let bob = LocalBundle::generate().unwrap();
    let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();

    let (alice_sees_bob, _) = pair(
        &alice,
        &bob,
        Ticket::new(alice.bundle(), vec![Endpoint::Direct(addr)]).unwrap(),
        Ticket::new(bob.bundle(), vec![Endpoint::Direct(addr)]).unwrap(),
    );

    let store = Arc::new(Store::default());
    let discovery = Discovery::new(vec![store.clone()]);
    reach::announce(
        &alice,
        &alice_sees_bob,
        &discovery,
        vec![Endpoint::Direct(addr)],
    )
    .await
    .unwrap();

    let tags = store.seen_tags.lock().unwrap().clone();
    let blobs = store.blobs.lock().unwrap();

    assert!(!tags.is_empty(), "nothing was published");

    for id in [alice.id(), bob.id()] {
        let id_b32 = id.to_base32();
        for tag in &tags {
            assert!(!tag.contains(&id_b32), "an identity appeared in a tag");
        }
        for blob in blobs.values() {
            assert!(
                blob.windows(id.as_bytes().len())
                    .all(|w| w != id.as_bytes()),
                "an identity appeared in a stored record"
            );
        }
    }

    // The address itself must not be readable either — that is the whole reason
    // the record is sealed rather than merely tagged.
    let address_bytes = addr.ip().to_string().into_bytes();
    for blob in blobs.values() {
        assert!(
            blob.windows(address_bytes.len())
                .all(|w| w != address_bytes.as_slice()),
            "the published address was readable in the stored record"
        );
        assert_eq!(
            blob.len(),
            p2p_live::discovery::SEALED_LEN,
            "records must be a uniform width"
        );
    }
}

/// A peer that has not moved must be reconnected with the endpoint untouched.
///
/// This is the rung that matters most in practice — most reconnections are to a
/// peer at the same address — and the one whose failure would be invisible,
/// since connecting via the endpoint also works.
#[tokio::test]
async fn an_unmoved_peer_is_reached_without_contacting_any_endpoint() {
    let alice = LocalBundle::generate().unwrap();
    let bob = LocalBundle::generate().unwrap();
    let alice_addr = reserve_port();
    let bob_addr = reserve_port();

    let (mut alice_sees_bob, mut bob_sees_alice) = pair(
        &alice,
        &bob,
        Ticket::new(alice.bundle(), vec![Endpoint::Direct(alice_addr)]).unwrap(),
        Ticket::new(bob.bundle(), vec![Endpoint::Direct(bob_addr)]).unwrap(),
    );

    // Nothing was ever published; the addresses came from the tickets.
    let store = Arc::new(Store::default());
    let opts = Options {
        timeout: Duration::from_secs(12),
        socks: None,
        use_discovery: true,
    };

    let alice_side = {
        let s = store.clone();
        tokio::spawn(async move {
            let d = Discovery::new(vec![s]);
            let opts = Options {
                timeout: Duration::from_secs(12),
                socks: None,
                use_discovery: true,
            };
            reach::connect(alice_addr, &alice, &mut alice_sees_bob, &d, &opts)
                .await
                .map(|(mut s, p)| {
                    tokio::spawn(async move {
                        let _ = s.close().await;
                    });
                    p
                })
        })
    };

    let (mut session, bob_path) = reach::connect(
        bob_addr,
        &bob,
        &mut bob_sees_alice,
        &Discovery::new(vec![store.clone()]),
        &opts,
    )
    .await
    .expect("bob reaches alice at the address from pairing");
    let _ = session.close().await;

    let alice_path = alice_side.await.unwrap().expect("alice reaches bob");

    assert_eq!(bob_path, Path::Cached);
    assert_eq!(alice_path, Path::Cached);
    assert!(
        store.seen_tags.lock().unwrap().is_empty(),
        "the endpoint was contacted for a peer that had not moved"
    );
}
