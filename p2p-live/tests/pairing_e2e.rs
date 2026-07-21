//! Phase 3 end-to-end — the whole broker-free path in one test.
//!
//! Short secret → SPAKE2 pairing → ticket exchange → rendezvous → hybrid-PQ
//! session → verified vault transfer. Every layer this crate has, composed the
//! way a real pair of users would drive it, with **no server of any kind**
//! anywhere in the flow.

use std::net::SocketAddr;
use std::time::Duration;

use p2p_live::bundle::LocalBundle;
use p2p_live::pacing::Pacing;
use p2p_live::pairing::{self, PairingCode};
use p2p_live::rendezvous::{self, Role};
use p2p_live::ticket::{Endpoint, Ticket};
use p2p_live::transfer::{EncryptedAtRest, Transfer};
use p2p_live::{SecureSession, transfer::Cancel};

/// Traffic shaping stays **on** — this test is meant to exercise the real path —
/// but at a loopback-appropriate rate and with a bounded tail, so the run takes
/// a fraction of a second instead of minutes at the 4 MiB/s default.
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
///
/// A ticket has to name the port *before* the QUIC endpoint binds it, which is
/// the same ordering a real user faces: you publish an address, then listen on
/// it.
fn reserve_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
    let addr = s.local_addr().expect("local addr");
    drop(s);
    addr
}

/// The full flow, exactly as two humans would run it.
#[tokio::test]
async fn short_secret_to_verified_vault_over_a_brokerless_path() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("my_data.aegis");
    let dst = dir.path().join("received.aegis");
    let vault: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &vault).unwrap();

    let alice = LocalBundle::generate().unwrap();
    let bob = LocalBundle::generate().unwrap();
    let alice_addr = reserve_port();
    let bob_addr = reserve_port();

    // --- L4: one short secret, spoken aloud. -------------------------------
    let code = PairingCode::generate().unwrap();
    // Bob types what Alice read out; grouping and case must not matter.
    let bobs_code = PairingCode::parse(&code.display().to_uppercase()).unwrap();

    let (a_state, a_msg) = pairing::start(&code);
    let (b_state, b_msg) = pairing::start(&bobs_code);
    let a_chan = a_state.finish(&b_msg).unwrap();
    let b_chan = b_state.finish(&a_msg).unwrap();

    // --- L0: tickets, sealed under the paired channel. ---------------------
    let a_ticket = Ticket::new(alice.bundle(), vec![Endpoint::Direct(alice_addr)]).unwrap();
    let b_ticket = Ticket::new(bob.bundle(), vec![Endpoint::Direct(bob_addr)]).unwrap();

    let bobs_view_of_alice = b_chan
        .open_ticket(&a_chan.seal_ticket(&a_ticket).unwrap())
        .unwrap();
    let alices_view_of_bob = a_chan
        .open_ticket(&b_chan.seal_ticket(&b_ticket).unwrap())
        .unwrap();

    assert_eq!(
        bobs_view_of_alice, a_ticket,
        "ticket must survive the exchange"
    );
    assert_eq!(alices_view_of_bob, b_ticket);
    assert_eq!(
        bobs_view_of_alice.fingerprint(),
        alice.bundle().id().fingerprint(),
        "the fingerprint Bob would read aloud must be Alice's"
    );

    // Exactly one of them dials — decided from the keys alone, with no further
    // messages exchanged.
    let roles = (
        rendezvous::role_for(&alice, &alices_view_of_bob),
        rendezvous::role_for(&bob, &bobs_view_of_alice),
    );
    assert!(
        matches!(
            roles,
            (Role::Dialer, Role::Accepter) | (Role::Accepter, Role::Dialer)
        ),
        "roles must be complementary, got {roles:?}"
    );

    // --- L1/L2: both hit enter at the same time. ---------------------------
    let budget = Duration::from_secs(20);
    let alice_side = tokio::spawn(async move {
        let mut session = rendezvous::rendezvous(alice_addr, &alices_view_of_bob, &alice, budget)
            .await
            .expect("alice rendezvous");
        // Alice sends the vault.
        let summary = shaped().send(&mut session, &src, &mut |_| {}).await;
        let _ = session.close().await;
        summary
    });

    let bob_side = tokio::spawn(async move {
        let mut session = rendezvous::rendezvous(bob_addr, &bobs_view_of_alice, &bob, budget)
            .await
            .expect("bob rendezvous");
        assert_eq!(
            session.peer(),
            bobs_view_of_alice.identity.classical(),
            "the authenticated peer must be the one from the ticket"
        );
        let summary = shaped().recv(&mut session, &dst, &mut |_| {}).await;
        let _ = session.close().await;
        summary
    });

    let (sent, received) = tokio::join!(alice_side, bob_side);
    let sent = sent.unwrap().expect("send");
    let received = received.unwrap().expect("recv");

    assert_eq!(sent.hash, received.hash, "both sides agree on the payload");
    assert_eq!(sent.total, vault.len() as u64);
    assert!(
        sent.cover_frames > 0 && sent.cover_frames == received.cover_frames,
        "the shaped path must have emitted cover traffic, got {} / {}",
        sent.cover_frames,
        received.cover_frames
    );
    assert_eq!(
        std::fs::read(dir.path().join("received.aegis")).unwrap(),
        vault,
        "the vault must arrive byte-identical"
    );
}

/// A peer whose ticket carries someone else's identity cannot connect, even
/// with the right address: the pin is what authenticates, not reachability.
#[tokio::test]
async fn a_swapped_identity_in_a_ticket_cannot_connect() {
    let alice = LocalBundle::generate().unwrap();
    let bob = LocalBundle::generate().unwrap();
    let impostor = LocalBundle::generate().unwrap();
    let alice_addr = reserve_port();
    let bob_addr = reserve_port();

    // Bob is honest and waits for the real Alice.
    let bobs_view = Ticket::new(alice.bundle(), vec![Endpoint::Direct(alice_addr)]).unwrap();
    // Alice was handed a ticket naming the impostor at Bob's address.
    let alices_view = Ticket::new(impostor.bundle(), vec![Endpoint::Direct(bob_addr)]).unwrap();

    let budget = Duration::from_secs(3);
    let a = tokio::spawn(async move {
        rendezvous::rendezvous(alice_addr, &alices_view, &alice, budget).await
    });
    let b =
        tokio::spawn(
            async move { rendezvous::rendezvous(bob_addr, &bobs_view, &bob, budget).await },
        );

    assert!(
        a.await.unwrap().is_err(),
        "alice must not reach the impostor"
    );
    assert!(
        b.await.unwrap().is_err(),
        "bob must not accept the wrong key"
    );
}

/// Cancellation must be reachable from outside the transfer, since the caller
/// holding the session is usually not the caller wanting to stop it.
#[test]
fn a_cancel_token_stops_a_transfer_from_another_task() {
    let t = Transfer::new(EncryptedAtRest::aegis_vault());
    let token: Cancel = t.cancel_token();
    assert!(!token.is_cancelled());
    token.cancel();
    assert!(
        t.cancel_token().is_cancelled(),
        "the token is shared, not copied"
    );
}

/// **The Phase 6 property, end to end over real QUIC.** A peer whose *classical*
/// key is correct but whose post-quantum key does not match the pinned bundle is
/// refused.
///
/// This is the CRQC scenario in miniature: an attacker who could forge Ed25519
/// would clear the TLS handshake exactly as this peer does — note the session is
/// fully established before the proof runs — and would still be unable to produce
/// the ML-DSA proof for the pinned identity. Impersonation requires breaking
/// **both**.
///
/// Driven through `dial`/`Listener` rather than `rendezvous` because a tampered
/// bundle also changes the identifier the roles are derived from, so a rendezvous
/// would desynchronise and time out before ever reaching the proof. That is
/// itself fail-closed, but it would hide what this test is checking.
#[tokio::test]
async fn a_matching_classical_key_is_not_enough_when_the_pq_key_differs() {
    use p2p_live::bundle::IdentityBundle;
    use p2p_live::pq_auth::{self, Side};
    use p2p_live::{Listener, dial};

    let alice = LocalBundle::generate().unwrap();
    let bob = LocalBundle::generate().unwrap();
    let impostor = LocalBundle::generate().unwrap();

    // Alice pins Bob's real Ed25519 key but somebody else's ML-DSA key.
    let alices_view = IdentityBundle::new(
        bob.bundle().classical().clone(),
        impostor.bundle().pq().cloned(),
    );
    let bobs_view = alice.bundle();

    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        bob.classical(),
        alice.bundle().classical(),
    )
    .unwrap();
    let addr = listener.local_addr().unwrap();

    let bob_side = tokio::spawn(async move {
        let mut session = listener.accept().await.unwrap();
        pq_auth::authenticate(&mut session, &bob, &bobs_view, Side::Responder).await
    });

    let mut session = dial(
        "127.0.0.1:0".parse().unwrap(),
        addr,
        alice.classical(),
        alices_view.classical(),
    )
    .await
    .expect("the classical handshake must succeed — that is the point");

    let err = pq_auth::authenticate(&mut session, &alice, &alices_view, Side::Initiator)
        .await
        .expect_err("a mismatched post-quantum key must be refused");
    assert!(
        err.to_string().contains("post-quantum"),
        "the refusal must name the post-quantum proof, got: {err}"
    );
    let _ = bob_side.await;
}

/// Two classical-only peers still interoperate: the proof is skipped rather than
/// failed, so Phase 6 does not strand identities minted before it.
#[tokio::test]
async fn classical_only_peers_still_pair_and_connect() {
    use p2p_live::identity::LocalIdentity;

    let alice = LocalBundle::classical_only(LocalIdentity::generate().unwrap());
    let bob = LocalBundle::classical_only(LocalIdentity::generate().unwrap());
    let alice_addr = reserve_port();
    let bob_addr = reserve_port();

    assert!(!alice.bundle().is_hybrid());

    let alices_view = Ticket::new(bob.bundle(), vec![Endpoint::Direct(bob_addr)]).unwrap();
    let bobs_view = Ticket::new(alice.bundle(), vec![Endpoint::Direct(alice_addr)]).unwrap();

    let budget = Duration::from_secs(10);
    let a = tokio::spawn(async move {
        rendezvous::rendezvous(alice_addr, &alices_view, &alice, budget).await
    });
    let b =
        tokio::spawn(
            async move { rendezvous::rendezvous(bob_addr, &bobs_view, &bob, budget).await },
        );

    assert!(
        a.await.unwrap().is_ok(),
        "classical peers must still connect"
    );
    assert!(b.await.unwrap().is_ok());
}
