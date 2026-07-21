//! Phase 5 — the transport substitution.
//!
//! The claim being tested is architectural: everything above L2 was written
//! against the `SecureSession` trait, so swapping QUIC for a Tor-carried TLS
//! stream should require **no change to the transfer protocol at all**. These
//! tests run the identical `Transfer` over both and compare.
//!
//! # What is and is not exercised
//!
//! An onion service's local side is a plain loopback TCP port that Tor forwards
//! circuits to, and that is exactly what [`OnionListener`] is — so these tests
//! drive the real listener and the real session over real sockets. The piece
//! they cannot cover is the circuit itself: `connect_onion` needs a live Tor
//! SOCKS proxy, so only its refusal paths are unit-tested. Nothing between the
//! stream and the vault differs.

use std::time::Duration;

use p2p_live::identity::LocalIdentity;
use p2p_live::pacing::Pacing;
use p2p_live::tls::TlsSession;
use p2p_live::tor::OnionListener;
use p2p_live::transfer::{EncryptedAtRest, Transfer};
use p2p_live::{Listener, SecureSession, dial};

fn shaped() -> Transfer {
    Transfer::new(EncryptedAtRest::aegis_vault())
        .chunk_len(8 * 1024)
        .checkpoint_len(16 * 1024)
        .pacing(
            Pacing::default()
                .at_rate(32 * 1024 * 1024)
                .with_bounds(16, 8),
        )
}

fn vault(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// **The Phase 5 claim.** The same transfer, byte for byte, over a TLS stream
/// instead of QUIC — with the same hybrid-PQ handshake and the same pinning.
#[tokio::test]
async fn the_same_transfer_runs_over_a_tor_style_stream() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("my_data.aegis");
    let dst = dir.path().join("received.aegis");
    let data = vault(200_000);
    std::fs::write(&src, &data).unwrap();

    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let server_pub = server_id.public_key().clone();
    let client_pub = client_id.public_key().clone();

    // The onion service's local side: a loopback port Tor forwards circuits to.
    let listener = OnionListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let receiver = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let mut session = TlsSession::accept(stream, &server_id, &client_pub)
            .await
            .unwrap();
        assert_eq!(
            session.peer(),
            &client_pub,
            "authentication is by pinned key, not by address"
        );
        let summary = shaped().recv(&mut session, &dst, &mut |_| {}).await;
        let _ = session.close().await;
        summary
    });

    // Stands in for the stream `connect_onion` returns from the SOCKS proxy.
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut session = TlsSession::connect(stream, &client_id, &server_pub)
        .await
        .unwrap();
    let sent = shaped()
        .send(&mut session, &src, &mut |_| {})
        .await
        .unwrap();
    let _ = session.close().await;

    let received = receiver.await.unwrap().unwrap();

    assert_eq!(sent.hash, received.hash, "both sides agree on the payload");
    assert_eq!(
        std::fs::read(dir.path().join("received.aegis")).unwrap(),
        data,
        "the vault must arrive byte-identical over the substituted transport"
    );
    assert!(
        sent.cover_frames > 0,
        "traffic shaping must still apply on this transport"
    );
}

/// **The strongest statement the architecture can make.** A transfer begun over
/// QUIC and interrupted resumes over *Tor* and completes correctly.
///
/// This works only because resume carries no transport state and no key
/// material — just a byte offset and a hash of the partial. A design that had
/// cached session state to resume would fail here, which is precisely why it
/// does not.
#[tokio::test]
async fn a_transfer_started_on_quic_resumes_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("my_data.aegis");
    let dst = dir.path().join("received.aegis");
    let data = vault(200_000);
    std::fs::write(&src, &data).unwrap();

    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let server_pub = server_id.public_key().clone();
    let client_pub = client_id.public_key().clone();

    // --- Attempt 1: QUIC, cancelled part-way. ------------------------------
    {
        let listener =
            Listener::bind("127.0.0.1:0".parse().unwrap(), &server_id, &client_pub).unwrap();
        let addr = listener.local_addr().unwrap();
        let src1 = src.clone();

        let sender = tokio::spawn(async move {
            let mut session = listener.accept().await.unwrap();
            let _ = shaped().send(&mut session, &src1, &mut |_| {}).await;
        });

        let mut session = dial(
            "127.0.0.1:0".parse().unwrap(),
            addr,
            &client_id,
            &server_pub,
        )
        .await
        .unwrap();

        let receiver = shaped();
        let cancel = receiver.cancel_token();
        let result = receiver
            .recv(&mut session, &dst, &mut |p| {
                if p.transferred >= 64 * 1024 {
                    cancel.cancel();
                }
            })
            .await;
        assert!(result.is_err(), "the first attempt must be interrupted");
        drop(session);
        sender.abort();
    }

    assert!(
        !dst.exists(),
        "an interrupted transfer leaves no destination"
    );
    let partial = p2p_live::transfer::partial_path(&dst);
    assert!(partial.exists(), "the partial must survive for the resume");

    // --- Attempt 2: the same transfer, over Tor-style TLS. -----------------
    let listener = OnionListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let dst2 = dst.clone();

    let receiver = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let mut session = TlsSession::accept(stream, &server_id, &client_pub)
            .await
            .unwrap();
        let summary = shaped().recv(&mut session, &dst2, &mut |_| {}).await;
        let _ = session.close().await;
        summary
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut session = TlsSession::connect(stream, &client_id, &server_pub)
        .await
        .unwrap();
    let sent = shaped()
        .send(&mut session, &src, &mut |_| {})
        .await
        .unwrap();
    let _ = session.close().await;

    let received = receiver.await.unwrap().unwrap();

    assert!(
        received.resumed_from > 0,
        "the second attempt must resume, not restart, across the transport change"
    );
    assert_eq!(sent.resumed_from, received.resumed_from);
    assert_eq!(
        std::fs::read(&dst).unwrap(),
        data,
        "a transfer resumed on a different transport must still be byte-identical"
    );
    assert_eq!(received.hash, *blake3::hash(&data).as_bytes());
}

/// A ticket offering only an onion must not be quietly dialled directly: the
/// peer chose Tor, and a fallback would hand them the exposure they avoided.
#[tokio::test]
async fn an_onion_only_ticket_is_not_dialled_directly() {
    use p2p_live::rendezvous;
    use p2p_live::ticket::{Endpoint, Ticket};
    use p2p_live::tor::OnionAddress;

    let me = LocalIdentity::generate().unwrap();
    let peer = LocalIdentity::generate().unwrap();
    let onion = OnionAddress::new(
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        4433,
    )
    .unwrap();
    let ticket = Ticket::new(peer.public_key().clone(), vec![Endpoint::Onion(onion)]).unwrap();

    let err = rendezvous::rendezvous(
        "127.0.0.1:0".parse().unwrap(),
        &ticket,
        &me,
        Duration::from_millis(50),
    )
    .await
    .unwrap_err();

    assert!(
        err.to_string().contains("Tor"),
        "the refusal must point at the Tor transport, got: {err}"
    );
}
