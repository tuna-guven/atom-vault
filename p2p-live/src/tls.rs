//! L2 over any byte stream — the second transport (roadmap Phase 5).
//!
//! [`TlsSession`] is a [`SecureSession`] carried by **any** `AsyncRead +
//! AsyncWrite`: a TCP socket, a Tor stream, a Unix socket, an in-memory pipe.
//! It exists so the metadata property that direct QUIC cannot provide — hiding
//! which two addresses are talking — can be recovered by putting the identical
//! crypto inside an onion circuit.
//!
//! # Same crypto, different pipe
//!
//! This shares [`crate::client_tls_config`] and [`crate::server_tls_config`]
//! with the QUIC path, so it is the *same* configuration object: hybrid
//! `X25519MLKEM768` as the only key-exchange group, TLS 1.3 only, RFC 7250 raw
//! public keys pinned in both directions, resumption and 0-RTT off. There is no
//! second crypto stack to keep in sync, and no second set of guarantees to
//! verify — a change to the PQ or PFS settings applies to both transports at
//! once, which is exactly why the roadmap insisted the AKE be transport-agnostic.
//!
//! # Why not QUIC over Tor
//!
//! Onion services are **TCP-only**. QUIC is UDP, so it cannot traverse a circuit
//! at all; running the same TLS 1.3 handshake directly over the TCP stream is
//! the substitution, not a workaround. Everything above L2 — the transfer
//! protocol, resume, pacing — is untouched, because it was written against the
//! trait rather than against quinn.
//!
//! # What Tor does and does not add
//!
//! It hides the peer-IP pairing, which is the one thing `CLAUDE.md` §10 says the
//! direct path cannot. It does not make the session post-quantum end to end in
//! the way the name might suggest: onion v3 identities are Ed25519 and the ntor
//! handshake is X25519, both outside our control. Our session *inside* the
//! circuit is hybrid-PQ, which is genuine defence in depth — but this must never
//! be described as a post-quantum Tor path (roadmap §8).

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::framing::{read_frame_opt, write_frame};
use crate::identity::{LocalIdentity, PeerPublicKey};
use crate::session::{DEFAULT_KEY_UPDATE_BYTES, SERVER_NAME, SecureSession};
use crate::{ALPN, Error, client_tls_config, server_tls_config};

/// A [`SecureSession`] over an arbitrary byte stream, secured by TLS 1.3.
pub struct TlsSession<S> {
    stream: TlsStream<S>,
    peer: PeerPublicKey,
    key_update_bytes: u64,
    bytes_since_update: u64,
    key_updates: u64,
}

impl<S> std::fmt::Debug for TlsSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSession")
            .field("peer", &self.peer.fingerprint())
            .field("key_updates", &self.key_updates)
            .finish_non_exhaustive()
    }
}

impl<S> TlsSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Open a session as the connecting side of `stream`, pinning
    /// `expected_peer`.
    ///
    /// `stream` is already connected — over Tor it is a stream to an onion
    /// address; this layer neither knows nor cares which.
    pub async fn connect(
        stream: S,
        local: &LocalIdentity,
        expected_peer: &PeerPublicKey,
    ) -> Result<Self, Error> {
        let config = client_tls_config(local, expected_peer)?;
        // The name is not an authentication input — the pinned raw public key
        // is. It only has to be a syntactically valid ServerName.
        let name = rustls::pki_types::ServerName::try_from(SERVER_NAME)
            .map_err(|e| Error::Connect(format!("invalid server name: {e}")))?;
        let stream = TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .map_err(|e| Error::Connect(format!("TLS handshake failed: {e}")))?;

        let mut session = Self::wrap(TlsStream::Client(stream), expected_peer.clone())?;
        // Same hello round trip as the QUIC path, for the same reason: a TLS 1.3
        // client finishes its handshake before the server has processed the
        // client certificate, so without a reply we could return a session the
        // peer is in the middle of rejecting.
        session.send_frame(ALPN).await?;
        session.expect_hello().await?;
        Ok(session)
    }

    /// Open a session as the accepting side of `stream`, pinning
    /// `expected_peer`.
    pub async fn accept(
        stream: S,
        local: &LocalIdentity,
        expected_peer: &PeerPublicKey,
    ) -> Result<Self, Error> {
        let config = server_tls_config(local, expected_peer)?;
        let stream = TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .map_err(|e| Error::Connect(format!("TLS handshake failed: {e}")))?;

        let mut session = Self::wrap(TlsStream::Server(stream), expected_peer.clone())?;
        session.expect_hello().await?;
        session.send_frame(ALPN).await?;
        Ok(session)
    }

    /// Verify the negotiated parameters, then wrap the stream.
    ///
    /// The configuration offers exactly one key-exchange group and one protocol
    /// version, so a completed handshake already implies both. Reading them back
    /// anyway turns that inference into an assertion: if a future change widens
    /// `kx_groups` for compatibility, sessions start failing here rather than
    /// silently running without post-quantum protection.
    fn wrap(stream: TlsStream<S>, peer: PeerPublicKey) -> Result<Self, Error> {
        {
            let (_, state) = stream.get_ref();

            match state.negotiated_key_exchange_group().map(|g| g.name()) {
                Some(rustls::NamedGroup::X25519MLKEM768) => {}
                other => {
                    return Err(Error::Connect(format!(
                        "negotiated key exchange group {other:?}, not the hybrid \
                         post-quantum group — refusing the session"
                    )));
                }
            }
            if state.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
                return Err(Error::Connect(format!(
                    "negotiated {:?}, not TLS 1.3",
                    state.protocol_version()
                )));
            }
            if state.alpn_protocol() != Some(ALPN) {
                return Err(Error::Connect(format!(
                    "peer negotiated ALPN {:?}, not this protocol",
                    state.alpn_protocol()
                )));
            }
        }

        Ok(TlsSession {
            stream,
            peer,
            key_update_bytes: DEFAULT_KEY_UPDATE_BYTES,
            bytes_since_update: 0,
            key_updates: 0,
        })
    }

    /// Override the key-update interval. Primarily for tests that need to cross
    /// the threshold without moving hundreds of megabytes.
    pub fn set_key_update_interval(&mut self, bytes: u64) {
        self.key_update_bytes = bytes.max(1);
    }

    /// How many intra-session key updates this side has requested so far.
    pub fn key_updates(&self) -> u64 {
        self.key_updates
    }

    /// Account for `n` sent bytes and refresh the traffic keys once the interval
    /// is crossed — the TLS-over-TCP counterpart of QUIC's key update, giving
    /// the same intra-session ratchet (roadmap §3.3 point 3).
    fn account_sent(&mut self, n: u64) -> Result<(), Error> {
        self.bytes_since_update = self.bytes_since_update.saturating_add(n);
        if self.bytes_since_update < self.key_update_bytes {
            return Ok(());
        }
        // rustls caps how many key updates a connection will perform, so a
        // refusal here is a real limit rather than a transient error.
        let result = match &mut self.stream {
            TlsStream::Client(s) => s.get_mut().1.refresh_traffic_keys(),
            TlsStream::Server(s) => s.get_mut().1.refresh_traffic_keys(),
        };
        result.map_err(|e| Error::Session(format!("key update refused: {e}")))?;
        self.bytes_since_update = 0;
        self.key_updates += 1;
        Ok(())
    }

    async fn send_frame(&mut self, msg: &[u8]) -> Result<(), Error> {
        let n = write_frame(&mut self.stream, msg).await?;
        // TLS buffers until flushed; without this a message can sit in the
        // encoder while both sides wait for each other.
        self.stream
            .flush()
            .await
            .map_err(|e| Error::Session(format!("flush: {e}")))?;
        self.account_sent(n)
    }

    async fn expect_hello(&mut self) -> Result<(), Error> {
        let hello = read_frame_opt(&mut self.stream)
            .await?
            .ok_or_else(|| Error::Session("peer closed before sending a hello".into()))?;
        if hello != ALPN {
            return Err(Error::Session(
                "peer sent an unexpected application hello".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl<S> SecureSession for TlsSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn peer(&self) -> &PeerPublicKey {
        &self.peer
    }

    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.send_frame(msg).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        read_frame_opt(&mut self.stream)
            .await?
            .ok_or_else(|| Error::Session("channel closed by peer".into()))
    }

    /// Send a TLS `close_notify` and shut the stream down.
    ///
    /// Unlike QUIC's connection close, this does not discard data the peer has
    /// already received, so no drain handshake is needed — `close_notify` is an
    /// orderly end-of-stream marker and the peer's pending reads still complete.
    ///
    /// A peer that has already closed makes the write fail, and that is not a
    /// failure to close: the session is over either way. Only errors that leave
    /// the outcome genuinely unclear are reported.
    async fn close(&mut self) -> Result<(), Error> {
        match self.stream.shutdown().await {
            Ok(()) => Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(Error::Session(format!("shutdown: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    /// A connected pair of sessions over an in-memory pipe — the transport under
    /// test is "any byte stream", so a pipe exercises it honestly.
    async fn pair() -> Result<(TlsSession<DuplexStream>, TlsSession<DuplexStream>), Error> {
        let server_id = LocalIdentity::generate()?;
        let client_id = LocalIdentity::generate()?;
        pair_with(server_id, client_id, None).await
    }

    async fn pair_with(
        server_id: LocalIdentity,
        client_id: LocalIdentity,
        client_expects: Option<PeerPublicKey>,
    ) -> Result<(TlsSession<DuplexStream>, TlsSession<DuplexStream>), Error> {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let server_pub = client_expects.unwrap_or_else(|| server_id.public_key().clone());
        let client_pub = client_id.public_key().clone();

        let accept =
            tokio::spawn(async move { TlsSession::accept(b, &server_id, &client_pub).await });
        let client = TlsSession::connect(a, &client_id, &server_pub).await?;
        let server = accept.await.map_err(|e| Error::Connect(e.to_string()))??;
        Ok((server, client))
    }

    /// The core Phase 5 claim: the same session interface, over a plain byte
    /// stream instead of QUIC.
    #[tokio::test]
    async fn messages_round_trip_both_ways() {
        let (mut server, mut client) = pair().await.unwrap();

        let echo = tokio::spawn(async move {
            for _ in 0..3 {
                let m = server.recv().await.unwrap();
                server.send(&m).await.unwrap();
            }
            server.send(b"server-initiated").await.unwrap();
            server.close().await.unwrap();
        });

        for msg in [b"one".as_slice(), b"", &[0u8; 4096]] {
            client.send(msg).await.unwrap();
            assert_eq!(client.recv().await.unwrap(), msg);
        }
        assert_eq!(client.recv().await.unwrap(), b"server-initiated");
        client.close().await.unwrap();
        echo.await.unwrap();
    }

    /// The guarantees must be the *same* ones, not merely similar: this asserts
    /// the negotiated group directly rather than trusting that the shared config
    /// was used.
    #[tokio::test]
    async fn the_handshake_is_hybrid_post_quantum_and_tls13() {
        let (server, client) = pair().await.unwrap();
        for (side, session) in [("client", &client), ("server", &server)] {
            let (_, state) = session.stream.get_ref();
            assert_eq!(
                state.negotiated_key_exchange_group().map(|g| g.name()),
                Some(rustls::NamedGroup::X25519MLKEM768),
                "{side} did not negotiate the hybrid post-quantum group"
            );
            assert_eq!(
                state.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3),
                "{side} did not negotiate TLS 1.3"
            );
            assert_eq!(state.alpn_protocol(), Some(ALPN), "{side} ALPN");
        }
    }

    #[tokio::test]
    async fn the_peer_identity_is_the_pinned_key() {
        let server_id = LocalIdentity::generate().unwrap();
        let client_id = LocalIdentity::generate().unwrap();
        let server_pub = server_id.public_key().clone();
        let client_pub = client_id.public_key().clone();

        let (server, client) = pair_with(server_id, client_id, None).await.unwrap();
        assert_eq!(client.peer(), &server_pub);
        assert_eq!(server.peer(), &client_pub);
    }

    /// Pinning must work over this transport too — a transport swap that quietly
    /// dropped authentication would be the worst possible outcome of Phase 5.
    #[tokio::test]
    async fn a_wrong_pin_yields_no_session() {
        let server_id = LocalIdentity::generate().unwrap();
        let client_id = LocalIdentity::generate().unwrap();
        let impostor = LocalIdentity::generate().unwrap();

        let result = pair_with(server_id, client_id, Some(impostor.public_key().clone())).await;
        assert!(
            result.is_err(),
            "a client pinning the wrong key must not get a session"
        );
    }

    /// The size cap applies here as well — it lives in the shared framing layer,
    /// and this proves the TLS path actually routes through it.
    #[tokio::test]
    async fn oversized_frames_are_refused() {
        let (_server, mut client) = pair().await.unwrap();
        let err = client
            .send(&vec![0u8; crate::framing::MAX_FRAME_LEN + 1])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");
    }

    /// The intra-session ratchet has parity with the QUIC path: rustls
    /// `refresh_traffic_keys` is the TLS-over-TCP counterpart of a QUIC key
    /// update, and the channel must survive it.
    #[tokio::test]
    async fn key_updates_fire_and_the_channel_survives() {
        let (mut server, mut client) = pair().await.unwrap();

        let drain = tokio::spawn(async move {
            let mut seen = 0;
            while let Ok(m) = server.recv().await {
                seen += 1;
                if m == b"done" {
                    break;
                }
            }
            server.send(b"still-here").await.unwrap();
            seen
        });

        client.set_key_update_interval(8 * 1024);
        let chunk = vec![0xABu8; 1024];
        for _ in 0..64 {
            client.send(&chunk).await.unwrap();
        }
        client.send(b"done").await.unwrap();

        assert!(
            client.key_updates() >= 1,
            "64 KiB with an 8 KiB interval must have refreshed the traffic keys"
        );
        assert_eq!(
            client.recv().await.unwrap(),
            b"still-here",
            "the channel must keep working across a key update"
        );
        assert_eq!(drain.await.unwrap(), 65);
    }
}
