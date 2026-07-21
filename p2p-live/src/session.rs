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

use crate::identity::{LocalIdentity, PeerPublicKey};
use crate::{ALPN, Error, client_config, server_config};

/// Server name presented in the TLS handshake. Authentication comes from the
/// pinned raw public key, not from this name, so it is a fixed placeholder.
const SERVER_NAME: &str = "atom-vault";

/// Upper bound on a single framed message. Bounds the memory a peer can make the
/// receiver allocate from one length prefix. The bulk transfer (Phase 2) streams
/// in chunks well under this; control messages are tiny.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

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
}

/// Transport parameters shared by both ends: a keep-alive short enough that an
/// idle pause during a transfer does not trip the idle timeout.
fn transport_config() -> Arc<quinn::TransportConfig> {
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
        if msg.len() > MAX_FRAME_LEN {
            return Err(Error::Session(format!(
                "outbound frame too large: {} > {MAX_FRAME_LEN}",
                msg.len()
            )));
        }
        let len = (msg.len() as u32).to_be_bytes();
        self.send
            .write_all(&len)
            .await
            .map_err(|e| Error::Session(format!("write length: {e}")))?;
        self.send
            .write_all(msg)
            .await
            .map_err(|e| Error::Session(format!("write payload: {e}")))?;
        self.account_sent(len.len() as u64 + msg.len() as u64);
        Ok(())
    }

    /// Read one frame, distinguishing a clean end-of-stream (`Ok(None)`) from a
    /// real error. A clean end is the peer having `finish`ed its stream exactly
    /// at a frame boundary.
    async fn recv_frame_opt(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let mut len_buf = [0u8; 4];
        match self.recv.read_exact(&mut len_buf).await {
            Ok(()) => {}
            // Peer finished the stream cleanly with no partial frame pending.
            Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(e) => return Err(Error::Session(format!("read length: {e}"))),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_LEN {
            // Refuse before allocating — this is the whole point of the cap.
            return Err(Error::Session(format!(
                "inbound frame too large: {len} > {MAX_FRAME_LEN}"
            )));
        }
        let mut buf = vec![0u8; len];
        self.recv
            .read_exact(&mut buf)
            .await
            .map_err(|e| Error::Session(format!("read payload: {e}")))?;
        Ok(Some(buf))
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

    // The dialing side must open and write first so the accepting side's
    // `accept_bi` can complete (a QUIC bi-stream is not visible to the peer until
    // the opener writes). The hello frame both establishes the stream and lets
    // the peer sanity-check the application version.
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::Session(e.to_string()))?;
    let mut session = QuicSession::new(endpoint, conn, send, recv, expected_peer.clone());
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
        let (send, recv) = conn
            .accept_bi()
            .await
            .map_err(|e| Error::Session(e.to_string()))?;
        let mut session = QuicSession::new(
            self.endpoint.clone(),
            conn,
            send,
            recv,
            self.expected_peer.clone(),
        );

        let hello = session
            .recv_frame_opt()
            .await?
            .ok_or_else(|| Error::Session("peer closed before sending a hello".into()))?;
        if hello != ALPN {
            return Err(Error::Session(
                "peer sent an unexpected application hello".into(),
            ));
        }
        Ok(session)
    }
}
