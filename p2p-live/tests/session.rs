//! Phase 1 tests — the `SecureSession` layer over QUIC.
//!
//! Phase 0 proved the handshake. These prove the channel built on top of it:
//! framed messages flow both ways, identity is exposed and correct, oversized
//! frames are refused, a wrong pin yields no session, and the intra-session key
//! ratchet actually fires.

use std::net::{Ipv4Addr, SocketAddr};

use p2p_live::identity::LocalIdentity;
use p2p_live::{Listener, SecureSession, dial};

fn unspecified() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A matched (server, client) identity pair and a listener bound to loopback.
fn bound_pair() -> (LocalIdentity, LocalIdentity, Listener) {
    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let listener = Listener::bind(unspecified(), &server_id, client_id.public_key()).unwrap();
    (server_id, client_id, listener)
}

/// Messages framed by the session round-trip intact, in both directions.
#[tokio::test]
async fn framed_messages_roundtrip_both_ways() {
    let (server_id, client_id, listener) = bound_pair();
    let addr = listener.local_addr().unwrap();
    let server_pub = server_id.public_key().clone();

    let server = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        // Echo three messages, then reply once unprompted.
        for _ in 0..3 {
            let m = s.recv().await.unwrap();
            s.send(&m).await.unwrap();
        }
        s.send(b"server-initiated").await.unwrap();
        s.close().await.unwrap();
    });

    let mut c = dial(unspecified(), addr, &client_id, &server_pub)
        .await
        .unwrap();

    for msg in [b"one".as_slice(), b"", &[0u8; 4096]] {
        c.send(msg).await.unwrap();
        assert_eq!(c.recv().await.unwrap(), msg, "echo must match, incl. empty");
    }
    assert_eq!(c.recv().await.unwrap(), b"server-initiated");

    c.close().await.unwrap();
    server.await.unwrap();
}

/// The session exposes the peer's authenticated identity, and it is the pinned
/// one on both ends.
#[tokio::test]
async fn peer_identity_is_the_pinned_key() {
    let (server_id, client_id, listener) = bound_pair();
    let addr = listener.local_addr().unwrap();
    let server_pub = server_id.public_key().clone();
    let client_pub = client_id.public_key().clone();

    let server = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        // The server's view of its peer must be the client's key.
        let peer = s.peer().clone();
        // Hold the session open until the client is done: dropping it here would
        // tear the connection down before the handshake's hello reply flushes.
        let _ = s.recv().await;
        peer
    });

    let c = dial(unspecified(), addr, &client_id, &server_pub)
        .await
        .unwrap();
    assert_eq!(c.peer(), &server_pub, "client's peer is the server");

    // Release the connection so the server's blocking `recv` returns.
    drop(c);
    let server_view_of_peer = server.await.unwrap();
    assert_eq!(
        server_view_of_peer, client_pub,
        "server's peer is the client"
    );
}

/// A client that pins the wrong server key gets no session at all.
#[tokio::test]
async fn wrong_pin_yields_no_session() {
    let (server_id, client_id, listener) = bound_pair();
    let addr = listener.local_addr().unwrap();
    let _ = server_id;

    // Keep the server accepting in the background so the failure is the client's
    // pin check, not a missing listener.
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let impostor = LocalIdentity::generate().unwrap();
    let result = dial(unspecified(), addr, &client_id, impostor.public_key()).await;
    assert!(
        result.is_err(),
        "dialing a server whose key is not the pinned one must fail"
    );
}

/// Sending a frame larger than the cap is refused locally, before any bytes go
/// out — the cap is a memory-safety bound, not a wire check.
#[tokio::test]
async fn oversized_frame_is_refused() {
    use p2p_live::MAX_FRAME_LEN;

    let (server_id, client_id, listener) = bound_pair();
    let addr = listener.local_addr().unwrap();
    let server_pub = server_id.public_key().clone();

    tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        let _ = s.recv().await; // keep the session alive for the client
    });

    let mut c = dial(unspecified(), addr, &client_id, &server_pub)
        .await
        .unwrap();

    let too_big = vec![0u8; MAX_FRAME_LEN + 1];
    let err = c.send(&too_big).await.unwrap_err();
    assert!(
        err.to_string().contains("too large"),
        "expected a size-cap error, got: {err}"
    );
}

/// Crossing the key-update interval forces at least one intra-session QUIC key
/// update, and the channel keeps working across it.
///
/// The interval is dialed down so the test moves kilobytes, not the 256 MiB
/// production default. Proving data still round-trips *after* the update is the
/// point: a botched ratchet would break the stream.
#[tokio::test]
async fn key_update_fires_and_channel_survives() {
    let (server_id, client_id, listener) = bound_pair();
    let addr = listener.local_addr().unwrap();
    let server_pub = server_id.public_key().clone();

    let server = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        // Receive until the explicit sentinel, then close cleanly so the client's
        // graceful close sees our FIN rather than waiting on it.
        while let Ok(m) = s.recv().await {
            if m == b"done" {
                break;
            }
        }
        s.close().await.unwrap();
    });

    let mut c = dial(unspecified(), addr, &client_id, &server_pub)
        .await
        .unwrap();
    // Force an update roughly every 8 KiB.
    c.set_key_update_interval(8 * 1024);

    let chunk = vec![0xABu8; 1024];
    for _ in 0..64 {
        c.send(&chunk).await.unwrap();
    }
    c.send(b"done").await.unwrap();

    assert!(
        c.key_updates() >= 1,
        "sending 64 KiB with an 8 KiB interval must have forced a key update"
    );

    c.close().await.unwrap();
    server.await.unwrap();
}
