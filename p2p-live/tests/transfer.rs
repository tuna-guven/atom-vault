//! Phase 2 tests — the live transfer protocol and its resume guarantees.
//!
//! These cover the testing requirements in roadmap §7 for §2.1:
//!
//! * a transfer interrupted at an arbitrary offset and resumed produces a
//!   byte-identical result to an uninterrupted one;
//! * the resumed session is a *fresh* full handshake — no reused session keys,
//!   no 0-RTT;
//! * a divergent prefix is rejected at the seam rather than stitched;
//! * a crash mid-chunk rolls the durable offset back to the last fsync'd
//!   checkpoint, so half-written bytes are never counted as received.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use p2p_live::identity::LocalIdentity;
use p2p_live::transfer::{EncryptedAtRest, Progress, Transfer};
use p2p_live::{Listener, SecureSession, dial};

const CHUNK: usize = 4 * 1024;
const CHECKPOINT: u64 = 16 * 1024;

fn unspecified() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Deterministic pseudo-random payload, so a mismatch is a real mismatch and not
/// two runs of zeros happening to agree.
fn payload(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x: u32 = 0x9e37_79b9;
    for _ in 0..len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((x >> 24) as u8);
    }
    v
}

fn configured() -> Transfer {
    Transfer::new(EncryptedAtRest::aegis_vault())
        .chunk_len(CHUNK)
        .checkpoint_len(CHECKPOINT)
}

/// A connected (server-side, client-side) session pair over loopback.
async fn connected() -> (Box<dyn SecureSession>, Box<dyn SecureSession>) {
    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let server_pub = server_id.public_key().clone();
    let listener = Listener::bind(unspecified(), &server_id, client_id.public_key()).unwrap();
    let addr = listener.local_addr().unwrap();

    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let client = dial(unspecified(), addr, &client_id, &server_pub)
        .await
        .unwrap();
    let server = accept.await.unwrap();
    (Box::new(server), Box::new(client))
}

/// Run one transfer session: the sender pushes `src`, the receiver writes `dst`.
/// Returns both sides' results so a deliberately-interrupted run can be
/// inspected rather than unwrapped.
async fn run_session(
    src: &Path,
    dst: &Path,
    receiver: Transfer,
    on_recv_progress: impl FnMut(Progress) + Send + 'static,
) -> (
    Result<p2p_live::Summary, p2p_live::Error>,
    Result<p2p_live::Summary, p2p_live::Error>,
) {
    let (mut server, mut client) = connected().await;

    let src = src.to_path_buf();
    let send = tokio::spawn(async move {
        let t = configured();
        let r = t.send(server.as_mut(), &src, &mut |_| {}).await;
        let _ = server.close().await;
        r
    });

    let mut cb = on_recv_progress;
    let recv_result = receiver.recv(client.as_mut(), dst, &mut cb).await;
    if recv_result.is_ok() {
        let _ = client.close().await;
    } else {
        // A graceful close would drain until the peer's FIN while the sender is
        // still waiting for an ACK it will never get. Aborting is what actually
        // happens when a transfer is interrupted, so model that: dropping the
        // session tears the connection down and the sender errors out.
        drop(client);
    }

    let send_result = send.await.unwrap();
    (send_result, recv_result)
}

/// The baseline: an uninterrupted transfer reproduces the source exactly, both
/// sides agree on the hash, and progress ends at the total.
#[tokio::test]
async fn transfer_round_trips_and_reports_progress() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("vault.aegis");
    let dst = dir.path().join("out.aegis");
    let data = payload(100 * 1024);
    std::fs::write(&src, &data).unwrap();

    let (seen_tx, seen_rx) = std::sync::mpsc::channel();
    let (sent, received) = run_session(&src, &dst, configured(), move |p| {
        let _ = seen_tx.send(p);
    })
    .await;

    let sent = sent.unwrap();
    let received = received.unwrap();
    assert_eq!(
        sent.hash, received.hash,
        "both sides must agree on the hash"
    );
    assert_eq!(received.total, data.len() as u64);
    assert_eq!(received.resumed_from, 0, "a fresh transfer starts at zero");
    assert_eq!(std::fs::read(&dst).unwrap(), data, "payload must be exact");

    let seen: Vec<Progress> = seen_rx.into_iter().collect();
    assert!(
        seen.windows(2)
            .all(|w| w[1].transferred >= w[0].transferred),
        "progress must be monotonic"
    );
    assert_eq!(
        seen.last().unwrap().transferred,
        data.len() as u64,
        "final progress must reach the total"
    );

    assert!(
        !p2p_live::transfer::partial_path(&dst).exists(),
        "the partial must be renamed away on success"
    );
}

/// **The core Phase 2 requirement.** A transfer cancelled part-way and then run
/// again over a *new* connection resumes from a checkpoint and yields a
/// byte-identical file.
#[tokio::test]
async fn interrupted_transfer_resumes_byte_identically() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("vault.aegis");
    let dst = dir.path().join("out.aegis");
    let data = payload(200 * 1024);
    std::fs::write(&src, &data).unwrap();

    // First attempt: cancel once a few checkpoints are durable.
    let receiver = configured();
    let cancel = receiver.cancel_token();
    let (_, first) = run_session(&src, &dst, receiver, move |p| {
        if p.transferred >= 64 * 1024 {
            cancel.cancel();
        }
    })
    .await;
    assert!(
        matches!(first, Err(p2p_live::Error::Cancelled)),
        "expected cancellation, got {first:?}"
    );
    assert!(!dst.exists(), "an incomplete transfer must not create dest");
    let partial_len = std::fs::metadata(p2p_live::transfer::partial_path(&dst))
        .unwrap()
        .len();
    assert!(partial_len > 0, "the partial must survive for resume");

    // Second attempt: a brand new connection, hence a brand new handshake.
    let (_, second) = run_session(&src, &dst, configured(), |_| {}).await;
    let second = second.unwrap();

    assert!(
        second.resumed_from > 0,
        "the second session must resume, not restart"
    );
    assert!(
        second.resumed_from % CHECKPOINT == 0,
        "resume must land on a checkpoint boundary, got {}",
        second.resumed_from
    );
    assert_eq!(
        std::fs::read(&dst).unwrap(),
        data,
        "a resumed transfer must be byte-identical to an uninterrupted one"
    );
    assert_eq!(second.hash, *blake3::hash(&data).as_bytes());
}

/// A partial whose bytes are *not* a prefix of the source must be rewound, not
/// stitched. This is what stops a good suffix landing on a bad prefix.
#[tokio::test]
async fn divergent_prefix_is_rejected_at_the_seam() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("vault.aegis");
    let dst = dir.path().join("out.aegis");
    let data = payload(100 * 1024);
    std::fs::write(&src, &data).unwrap();

    // A partial of a plausible, checkpoint-aligned length whose content differs
    // from the source in a single byte — exactly the case a naive
    // resume-by-offset would silently accept.
    let mut corrupt = data[..(2 * CHECKPOINT) as usize].to_vec();
    corrupt[1000] ^= 0x01;
    std::fs::write(p2p_live::transfer::partial_path(&dst), &corrupt).unwrap();

    let (_, received) = run_session(&src, &dst, configured(), |_| {}).await;
    let received = received.unwrap();

    assert_eq!(
        received.resumed_from, 0,
        "a divergent prefix must force a restart from zero"
    );
    assert_eq!(
        std::fs::read(&dst).unwrap(),
        data,
        "the result must still be exact after the rewind"
    );
}

/// Bytes written past the last checkpoint were never fsync'd, so after a crash
/// they may be short or zero-filled. They must be discarded, never counted as
/// received.
#[tokio::test]
async fn non_durable_tail_past_the_checkpoint_is_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("vault.aegis");
    let dst = dir.path().join("out.aegis");
    let data = payload(100 * 1024);
    std::fs::write(&src, &data).unwrap();

    // A durable prefix of exactly one checkpoint, plus a half-written tail that
    // a crash left as garbage.
    let mut partial = data[..CHECKPOINT as usize].to_vec();
    partial.extend_from_slice(&[0xFF; 3000]);
    std::fs::write(p2p_live::transfer::partial_path(&dst), &partial).unwrap();

    let (_, received) = run_session(&src, &dst, configured(), |_| {}).await;
    let received = received.unwrap();

    assert_eq!(
        received.resumed_from, CHECKPOINT,
        "resume must roll back to the last durable checkpoint, discarding the \
         non-durable tail"
    );
    assert_eq!(
        std::fs::read(&dst).unwrap(),
        data,
        "the garbage tail must not appear in the result"
    );
}

/// **PFS across a resume.** Reconnecting must be a full, fresh handshake — no
/// cached session, no 0-RTT. quinn only offers `into_0rtt` when the client has
/// usable resumption state, so its refusal on a *second* connection from the
/// same endpoint is direct evidence that nothing was cached.
#[tokio::test]
async fn resumed_connection_has_no_zero_rtt_or_cached_session() {
    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let server_pub = server_id.public_key().clone();

    // A bare endpoint rather than `Listener`: this test is about handshakes, and
    // it must accept several without waiting for any application traffic.
    let server_cfg = p2p_live::server_config(&server_id, client_id.public_key()).unwrap();
    let server_ep = quinn::Endpoint::server(server_cfg, unspecified()).unwrap();
    let addr = server_ep.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = server_ep.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });

    // One endpoint, two sequential connections: any session cache would be warm
    // by the second.
    let mut endpoint = quinn::Endpoint::client(unspecified()).unwrap();
    endpoint.set_default_client_config(p2p_live::client_config(&client_id, &server_pub).unwrap());

    for attempt in 1..=2 {
        let connecting = endpoint.connect(addr, "atom-vault").unwrap();
        match connecting.into_0rtt() {
            Ok(_) => panic!(
                "attempt {attempt}: 0-RTT was available — session state is being \
                 cached and forward secrecy is no longer strict"
            ),
            Err(connecting) => {
                let conn = connecting.await.expect("full handshake must succeed");
                conn.close(0u32.into(), b"done");
            }
        }
    }
}

/// An offer larger than the configured ceiling is refused before any bytes are
/// written to disk.
#[tokio::test]
async fn oversized_offer_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("vault.aegis");
    let dst = dir.path().join("out.aegis");
    std::fs::write(&src, payload(50 * 1024)).unwrap();

    let receiver = configured().max_total_len(1024);
    let (_, received) = run_session(&src, &dst, receiver, |_| {}).await;

    assert!(
        matches!(received, Err(p2p_live::Error::Transfer(ref m)) if m.contains("exceeds")),
        "expected a size-limit refusal, got {received:?}"
    );
    assert!(!dst.exists());
    assert!(
        !p2p_live::transfer::partial_path(&dst).exists(),
        "nothing may be written before the offer is accepted"
    );
}
