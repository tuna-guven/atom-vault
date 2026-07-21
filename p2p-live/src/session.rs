//! L2 session layer — a transport-agnostic secure channel (roadmap Phase 1).
//!
//! [`SecureSession`] is the interface the transfer protocol (Phase 2) is written
//! against: open, exchange length-framed messages, close. It says nothing about
//! *which* transport carries the bytes, so the same protocol can later run over
//! the Tor onion (Phase 5) without change.
//!
//! [`QuicSession`] is the QUIC implementation, built on the Phase 0 hybrid-PQ,
//! mutually-pinned handshake. It adds three things the raw handshake did not:
//!
//! * **Message framing** — QUIC streams are byte streams; this layer gives
//!   discrete, length-bounded messages.
//! * **Intra-session key ratcheting** — a QUIC key update is forced every
//!   [`DEFAULT_KEY_UPDATE_BYTES`], so a mid-transfer key compromise does not
//!   expose the bytes already sent (roadmap §3.3, point 3).
//! * **Establishment glue** — dialing and accepting, with identity pinning taken
//!   from the caller-supplied L0 ticket keys.
//!
//! What it deliberately does **not** add: any persistence of key material. There
//! is no session cache, no ticket, no resumption state. A dropped connection is
//! re-established by a *fresh* handshake (Phase 2 resume), never by reviving keys.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::framing::{read_frame_opt, write_frame};
use crate::identity::{LocalIdentity, PeerPublicKey};
use crate::{ALPN, Error, client_config, server_config};

pub use crate::framing::MAX_FRAME_LEN;

/// Server name presented in the TLS handshake. Authentication comes from the
/// pinned raw public key, not from this name, so it is a fixed placeholder.
pub(crate) const SERVER_NAME: &str = "atom-vault";

/// Force a QUIC key update after this many bytes have been sent on a session.
///
/// This is the intra-session ratchet. The value trades ratchet granularity
/// against key-update overhead; 256 MiB keeps updates rare on a multi-gigabyte
/// transfer while still bounding how much plaintext shares any one key.
pub const DEFAULT_KEY_UPDATE_BYTES: u64 = 256 * 1024 * 1024;

/// A transport-agnostic, mutually-authenticated, forward-secret channel carrying
/// discrete messages.
#[async_trait]
pub trait SecureSession: Send {
    /// The authenticated identity of the remote peer.
    ///
    /// Because the handshake pins this key, the value returned is exactly the one
    /// the caller expected — a mismatch would have failed the handshake, not
    /// surfaced here.
    fn peer(&self) -> &PeerPublicKey;

    /// Send one message. Framing is handled internally.
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error>;

    /// Receive one message. Returns [`Error::Session`] if the peer closed the
    /// channel or a frame exceeds [`MAX_FRAME_LEN`].
    async fn recv(&mut self) -> Result<Vec<u8>, Error>;

    /// Close the channel gracefully.
    async fn close(&mut self) -> Result<(), Error>;

    /// Export keying material bound to this specific session (RFC 5705).
    ///
    /// Two different sessions — including two legs of a man-in-the-middle —
    /// produce different values for the same label, which is what makes a
    /// signature over this output prove *which channel* the signer is on.
    /// [`crate::pq_auth`] depends on that; without it a proof could be relayed.
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), Error>;
}

/// Transport parameters shared by both ends: a keep-alive short enough that an
/// idle pause during a transfer does not trip the idle timeout.
pub(crate) fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30s is a valid idle timeout"),
    ));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(t)
}

/// A QUIC-backed [`SecureSession`].
pub struct QuicSession {
    // Held only to keep the endpoint alive for the connection's lifetime; a
    // dropped endpoint tears down its connections.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    peer: PeerPublicKey,
    key_update_bytes: u64,
    bytes_since_update: u64,
    key_updates: u64,
}

impl std::fmt::Debug for QuicSession {
    /// Shows the peer by fingerprint and the ratchet state. There is no key
    /// material in this struct, but keeping the impl explicit means a field
    /// added later cannot start printing itself by accident.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicSession")
            .field("peer", &self.peer.fingerprint())
            .field("key_updates", &self.key_updates)
            .finish_non_exhaustive()
    }
}

impl QuicSession {
    fn new(
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        peer: PeerPublicKey,
    ) -> Self {
        QuicSession {
            _endpoint: endpoint,
            conn,
            send,
            recv,
            peer,
            key_update_bytes: DEFAULT_KEY_UPDATE_BYTES,
            bytes_since_update: 0,
            key_updates: 0,
        }
    }

    /// Override the key-update interval. Primarily for tests that need to cross
    /// the threshold without moving hundreds of megabytes.
    pub fn set_key_update_interval(&mut self, bytes: u64) {
        // Guard against 0, which would force an update on every send.
        self.key_update_bytes = bytes.max(1);
    }

    /// How many intra-session key updates this side has forced so far.
    pub fn key_updates(&self) -> u64 {
        self.key_updates
    }

    /// Account for `n` sent bytes and force a key update once the interval is
    /// crossed. QUIC coalesces a second update request until the first is
    /// acknowledged, so a large interval keeps requests from overlapping.
    fn account_sent(&mut self, n: u64) {
        self.bytes_since_update = self.bytes_since_update.saturating_add(n);
        if self.bytes_since_update >= self.key_update_bytes {
            self.conn.force_key_update();
            self.bytes_since_update = 0;
            self.key_updates += 1;
        }
    }

    async fn send_frame(&mut self, msg: &[u8]) -> Result<(), Error> {
        let n = write_frame(&mut self.send, msg).await?;
        self.account_sent(n);
        Ok(())
    }

    /// Read the peer's application hello and check it names our protocol.
    async fn expect_hello(&mut self) -> Result<(), Error> {
        let hello = self
            .recv_frame_opt()
            .await?
            .ok_or_else(|| Error::Session("peer closed before sending a hello".into()))?;
        if hello != ALPN {
            return Err(Error::Session(
                "peer sent an unexpected application hello".into(),
            ));
        }
        Ok(())
    }

    /// Read one frame, or `None` at a clean end of stream.
    async fn recv_frame_opt(&mut self) -> Result<Option<Vec<u8>>, Error> {
        read_frame_opt(&mut self.recv).await
    }
}

#[async_trait]
impl SecureSession for QuicSession {
    fn peer(&self) -> &PeerPublicKey {
        &self.peer
    }

    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.send_frame(msg).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        self.recv_frame_opt()
            .await?
            .ok_or_else(|| Error::Session("channel closed by peer".into()))
    }

    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), Error> {
        self.conn
            .export_keying_material(out, label, context)
            .map_err(|e| Error::Session(format!("export keying material: {e:?}")))?;
        Ok(())
    }

    /// Graceful, race-free close.
    ///
    /// A bare `conn.close()` sends CONNECTION_CLOSE immediately, which discards
    /// any stream data the peer received but has not yet read — so a final
    /// message can be lost. Instead we do a two-way drain:
    ///
    /// 1. `finish` our send stream (no more data from us).
    /// 2. Drain our receive side until we observe the peer's own stream FIN,
    ///    proving the peer has finished sending (and therefore has read whatever
    ///    it intended to before deciding to close).
    /// 3. Wait for `stopped()` to confirm the peer acknowledged all of *our*
    ///    data.
    /// 4. Only now hard-close the connection.
    ///
    /// Both peers calling `close()` converge: neither tears the connection down
    /// until it has seen the other's FIN. This assumes the application protocol
    /// has agreed it is done — frames the peer sends after we begin closing are
    /// discarded.
    async fn close(&mut self) -> Result<(), Error> {
        let _ = self.send.finish();

        loop {
            match self.recv_frame_opt().await {
                Ok(Some(_)) => continue, // trailing frame after we began closing: discard
                Ok(None) => break,       // clean peer FIN
                Err(_) => break,         // peer/connection already gone; nothing to wait for
            }
        }

        let _ = self.send.stopped().await;
        self.conn.close(0u32.into(), b"bye");
        Ok(())
    }
}

/// Dial `remote` and establish a session, pinning `expected_peer` as the only
/// acceptable server identity.
///
/// `bind` is the local UDP address to bind (use an unspecified address with port
/// 0 for an ephemeral client port).
pub async fn dial(
    bind: SocketAddr,
    remote: SocketAddr,
    local: &LocalIdentity,
    expected_peer: &PeerPublicKey,
) -> Result<QuicSession, Error> {
    let mut cfg = client_config(local, expected_peer)?;
    cfg.transport_config(transport_config());

    let endpoint = quinn::Endpoint::client(bind)?;
    let conn = endpoint
        .connect_with(cfg, remote, SERVER_NAME)
        .map_err(|e| Error::Connect(e.to_string()))?
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;

    client_session(endpoint, conn, expected_peer).await
}

/// Finish establishing a session on the *dialing* side of an existing
/// connection.
///
/// Split out from [`dial`] so the rendezvous path, which owns a single endpoint
/// acting as both client and server, can reuse it.
///
/// The dialing side must open and write first: a QUIC bi-directional stream is
/// not visible to the peer until the opener writes, so the peer's `accept_bi`
/// cannot complete otherwise. The hello frame does that job and lets the peer
/// sanity-check the application version.
///
/// **The hello is a round trip, and that is load-bearing.** In TLS 1.3 the
/// client finishes its handshake *before* the server has processed the client's
/// certificate, so `connect().await` can resolve on a connection the peer is
/// about to reject for failing its pin check. Waiting for the peer's hello back
/// means a returned session is one where **both** sides completed
/// authentication, rather than one where only we did. Without it, a caller can
/// hold what looks like a session and only discover the rejection on its next
/// read.
pub(crate) async fn client_session(
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    peer: &PeerPublicKey,
) -> Result<QuicSession, Error> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::Session(e.to_string()))?;
    let mut session = QuicSession::new(endpoint, conn, send, recv, peer.clone());
    session.send_frame(ALPN).await?;
    session.expect_hello().await?;
    Ok(session)
}

/// Finish establishing a session on the *accepting* side of an existing
/// connection, validating the peer's hello and answering it.
///
/// The reply is what tells the dialer we accepted its identity; see
/// [`client_session`].
pub(crate) async fn server_session(
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    peer: &PeerPublicKey,
) -> Result<QuicSession, Error> {
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|e| Error::Session(e.to_string()))?;
    let mut session = QuicSession::new(endpoint, conn, send, recv, peer.clone());
    session.expect_hello().await?;
    session.send_frame(ALPN).await?;
    Ok(session)
}

/// A bound server endpoint that accepts sessions from a single pinned peer.
///
/// One listener authenticates exactly one expected client identity, matching the
/// 1:1 nature of a vault transfer. Accepting from several peers would mean
/// several pins and is out of scope here.
pub struct Listener {
    endpoint: quinn::Endpoint,
    expected_peer: PeerPublicKey,
}

impl Listener {
    /// Bind a server endpoint on `bind`, pinning `expected_peer` as the only
    /// client whose handshake will be accepted.
    pub fn bind(
        bind: SocketAddr,
        local: &LocalIdentity,
        expected_peer: &PeerPublicKey,
    ) -> Result<Self, Error> {
        let mut cfg = server_config(local, expected_peer)?;
        cfg.transport_config(transport_config());
        let endpoint = quinn::Endpoint::server(cfg, bind)?;
        Ok(Listener {
            endpoint,
            expected_peer: expected_peer.clone(),
        })
    }

    /// The actual bound address (useful when `bind` used port 0).
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.endpoint.local_addr().map_err(Error::Io)
    }

    /// Accept the next incoming session. Resolves after the handshake and the
    /// peer's hello frame have both completed and been validated.
    pub async fn accept(&self) -> Result<QuicSession, Error> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::Connect("endpoint closed".into()))?;
        let conn = incoming.await.map_err(|e| Error::Connect(e.to_string()))?;
        server_session(self.endpoint.clone(), conn, &self.expected_peer).await
    }
}
