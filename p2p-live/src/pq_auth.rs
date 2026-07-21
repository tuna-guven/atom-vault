//! Post-quantum authentication of an established session (roadmap Phase 6).
//!
//! # The gate finding this works around
//!
//! Roadmap Phase 6 asks for hybrid PQ **signatures** in the handshake. On the
//! current stack that is not available, and the check was worth making before
//! building anything:
//!
//! * `rustls` 0.23 defines `SignatureScheme::ML_DSA_65` as a draft code point
//!   but its `aws-lc-rs` provider implements **neither signing nor verification**
//!   for it. There is nothing to switch on.
//! * Even with an implementation, TLS 1.3's `CertificateVerify` carries exactly
//!   **one** signature. "Hybrid" would need a composite scheme
//!   (draft-ietf-lamps-pq-composite-sigs), and defining our own composite is
//!   inventing cryptography in the one area roadmap §3.1 forbids it.
//! * Using ML-DSA *instead of* Ed25519 would satisfy neither: §3.2's
//!   hybrid-never-PQ-only reasoning applies to signatures as much as to key
//!   agreement, and ML-DSA is the younger of the two.
//!
//! So the post-quantum signature moves **above** the handshake, where it needs
//! no new cryptography — only a standard construction.
//!
//! # What this does instead
//!
//! Once the session is up, each side signs a value that identifies **this exact
//! channel**, using its ML-DSA-65 key, and verifies the peer's signature. The
//! value comes from the TLS exporter (RFC 5705), which both transports expose:
//!
//! ```text
//!   exporter = export_keying_material(EXPORTER_LABEL, EXPORTER_CONTEXT)
//!   transcript = BLAKE3( DOMAIN || side || signer_id || peer_id || exporter )
//!   proof = ML-DSA-65-Sign(transcript)
//! ```
//!
//! This is channel binding, not a new key exchange: key agreement is untouched,
//! and a failure to verify simply refuses the session.
//!
//! # What it buys, precisely
//!
//! An attacker who can forge Ed25519 — the CRQC case — can complete the TLS
//! handshake impersonating a peer. They then cannot produce the ML-DSA proof, so
//! the session is refused before any payload moves. **Impersonation requires
//! breaking both Ed25519 and ML-DSA-65.** That is the Phase 6 goal.
//!
//! The binding is what stops the obvious attack. A man in the middle runs two
//! separate sessions, one to each victim, and those have *different* exporter
//! values — so a proof captured on one leg does not verify on the other. Without
//! the exporter in the transcript the whole scheme would be relayable and worth
//! nothing.
//!
//! # What it does not buy — read this before describing it to anyone
//!
//! * **The handshake signature is still Ed25519.** An attacker who forges it
//!   completes a handshake and derives session keys as an active MITM before
//!   being rejected. Nothing confidential has been sent at that point — this
//!   exchange runs before any payload — but the connection was made.
//! * **This is not a post-quantum TLS handshake**, and must never be described
//!   as one. When rustls ships ML-DSA support, the signature belongs in
//!   `CertificateVerify` and this layer becomes redundant.
//! * **Forward secrecy is unaffected.** These are long-term authentication keys;
//!   they never participate in key agreement, so compromising one cannot
//!   retroactively decrypt anything (roadmap §3.4).

use crate::Error;
use crate::bundle::{BundleId, IdentityBundle, LocalBundle};
use crate::session::SecureSession;

/// Exporter label. Unique to this use, so the value cannot collide with keying
/// material exported for any other purpose.
pub const EXPORTER_LABEL: &[u8] = b"atom-vault/live/1 pq-auth";

/// Exporter context, separating this protocol version's bindings.
const EXPORTER_CONTEXT: &[u8] = b"atom-live-pq-auth-v1";

/// Domain separator for the signed transcript.
const TRANSCRIPT_DOMAIN: &[u8] = b"atom-live-pq-auth-transcript-v1";

/// Bytes of exporter output mixed into the transcript.
const EXPORTER_LEN: usize = 32;

/// Which end of the session a proof comes from.
///
/// Both sides sign a transcript containing their own side label, so the two
/// proofs differ. Without this an attacker could reflect a peer's proof straight
/// back at them and have it verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The peer that opened the connection.
    Initiator,
    /// The peer that accepted it.
    Responder,
}

impl Side {
    fn label(self) -> &'static [u8] {
        match self {
            Side::Initiator => b"initiator",
            Side::Responder => b"responder",
        }
    }

    /// The label the *other* end signs under.
    fn peer(self) -> Side {
        match self {
            Side::Initiator => Side::Responder,
            Side::Responder => Side::Initiator,
        }
    }
}

/// Build the value a given side signs.
fn transcript(exporter: &[u8], side: Side, signer: &BundleId, peer: &BundleId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hasher.update(side.label());
    // Both identities are named explicitly. The exporter alone already pins the
    // channel; naming the parties means a proof also states *who* it is about,
    // so it cannot be reinterpreted if this transcript is ever reused elsewhere.
    hasher.update(signer.as_bytes());
    hasher.update(peer.as_bytes());
    hasher.update(exporter);
    *hasher.finalize().as_bytes()
}

/// Run the mutual post-quantum proof over an established session.
///
/// Called once, immediately after the handshake and before any payload. `peer`
/// is the **pinned** bundle from the ticket, never something the peer supplies
/// now — that is what makes the requirement undowngradeable: if the pinned
/// identity has a post-quantum key, a proof is demanded, and a peer who omits
/// it fails.
///
/// Returns `Ok(false)` when the pinned peer is classical-only and no proof was
/// required, `Ok(true)` when a proof was verified.
pub async fn authenticate(
    session: &mut dyn SecureSession,
    local: &LocalBundle,
    peer: &IdentityBundle,
    side: Side,
) -> Result<bool, Error> {
    let local_bundle = local.bundle();
    let required = peer.is_hybrid();

    if !required && !local_bundle.is_hybrid() {
        // Neither side has a post-quantum key: nothing to prove, and pretending
        // otherwise would be worse than saying so.
        return Ok(false);
    }

    let mut exporter = [0u8; EXPORTER_LEN];
    session.export_keying_material(&mut exporter, EXPORTER_LABEL, EXPORTER_CONTEXT)?;

    let local_id = local_bundle.id();
    let peer_id = peer.id();

    // Send ours first, then read theirs: each side writes before it reads, so
    // there is no ordering deadlock and no need for a role-based sequence.
    if local_bundle.is_hybrid() {
        let proof = local.sign_pq(&transcript(&exporter, side, &local_id, &peer_id))?;
        session.send(&proof).await?;
    }

    if !required {
        // We proved ourselves to a classical peer, which costs nothing and lets
        // them upgrade later. They have nothing to prove to us.
        return Ok(false);
    }

    let proof = session.recv().await?;
    let expected = transcript(&exporter, side.peer(), &peer_id, &local_id);

    peer.pq()
        .expect("checked by `required`")
        .verify(&expected, &proof)
        .map_err(|_| {
            Error::Identity(
                "the peer could not prove possession of its post-quantum key for this \
                 channel: the session is refused"
                    .into(),
            )
        })?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;
    use crate::tls::TlsSession;
    use tokio::io::DuplexStream;

    /// A connected pair of real sessions, so the exporter values are genuine.
    ///
    /// An in-memory pipe would not do here: the whole scheme rests on the
    /// exporter differing per handshake, so the sessions have to be real ones.
    async fn sessions() -> (
        TlsSession<DuplexStream>,
        TlsSession<DuplexStream>,
        LocalBundle,
        LocalBundle,
    ) {
        let server = LocalBundle::generate().unwrap();
        let client = LocalBundle::generate().unwrap();
        let server_pub = server.classical().public_key().clone();
        let client_pub = client.classical().public_key().clone();

        let (a, b) = tokio::io::duplex(256 * 1024);
        let (server_session, client_session) = tokio::join!(
            TlsSession::accept(b, server.classical(), &client_pub),
            TlsSession::connect(a, client.classical(), &server_pub),
        );

        (
            server_session.unwrap(),
            client_session.unwrap(),
            server,
            client,
        )
    }

    /// The happy path: both sides prove, both verify.
    #[tokio::test]
    async fn matching_hybrid_identities_authenticate() {
        let (mut server, mut client, server_b, client_b) = sessions().await;
        let (sb, cb) = (server_b.bundle(), client_b.bundle());

        let s = tokio::spawn(async move {
            authenticate(&mut server, &server_b, &cb, Side::Responder).await
        });
        let c = authenticate(&mut client, &client_b, &sb, Side::Initiator).await;

        assert!(c.unwrap(), "client must have verified a proof");
        assert!(
            s.await.unwrap().unwrap(),
            "server must have verified a proof"
        );
    }

    /// **The property that matters.** A proof is bound to its channel, so one
    /// captured from a different session does not verify — which is what defeats
    /// a man in the middle relaying between two legs.
    #[tokio::test]
    async fn a_proof_from_another_session_does_not_verify() {
        let (server_a, client_a, server_ba, client_ba) = sessions().await;
        let ids = (server_ba.bundle().id(), client_ba.bundle().id());

        // Capture a genuine proof from session A.
        let mut exporter_a = [0u8; EXPORTER_LEN];
        client_a
            .export_keying_material(&mut exporter_a, EXPORTER_LABEL, EXPORTER_CONTEXT)
            .unwrap();
        let captured = client_ba
            .sign_pq(&transcript(&exporter_a, Side::Initiator, &ids.1, &ids.0))
            .unwrap();
        let _ = server_a;

        // A second, independent session between the same two identities.
        let (server_b, _client_b, _sb2, _cb2) = sessions().await;
        let mut exporter_b = [0u8; EXPORTER_LEN];
        server_b
            .export_keying_material(&mut exporter_b, EXPORTER_LABEL, EXPORTER_CONTEXT)
            .unwrap();

        assert_ne!(
            exporter_a, exporter_b,
            "two sessions must not share an exporter, or binding is meaningless"
        );

        let expected = transcript(&exporter_b, Side::Initiator, &ids.1, &ids.0);
        assert!(
            client_ba
                .bundle()
                .pq()
                .unwrap()
                .verify(&expected, &captured)
                .is_err(),
            "a proof from another channel must not verify"
        );
    }

    /// A proof must not be reflectable: the two sides sign different
    /// transcripts, so bouncing one back at its author fails.
    #[test]
    fn the_two_sides_sign_different_transcripts() {
        let exporter = [7u8; EXPORTER_LEN];
        let a = LocalBundle::generate().unwrap().id();
        let b = LocalBundle::generate().unwrap().id();

        assert_ne!(
            transcript(&exporter, Side::Initiator, &a, &b),
            transcript(&exporter, Side::Responder, &a, &b),
            "side labels must separate the two proofs"
        );
        assert_ne!(
            transcript(&exporter, Side::Initiator, &a, &b),
            transcript(&exporter, Side::Initiator, &b, &a),
            "swapping the identities must change the transcript"
        );
    }

    /// An impostor's proof is refused even though the classical handshake, in
    /// this scenario, already succeeded — that is the whole point.
    #[tokio::test]
    async fn a_proof_under_the_wrong_key_is_refused() {
        let (mut server, mut client, server_b, client_b) = sessions().await;
        let impostor = LocalBundle::generate().unwrap();

        // The server is told to expect the impostor's PQ key.
        let expected_by_server = impostor.bundle();
        let sb = server_b.bundle();

        let s = tokio::spawn(async move {
            authenticate(&mut server, &server_b, &expected_by_server, Side::Responder).await
        });
        let _ = authenticate(&mut client, &client_b, &sb, Side::Initiator).await;

        assert!(
            s.await.unwrap().is_err(),
            "a proof under an unpinned key must be refused"
        );
    }

    /// Two classical identities skip the exchange rather than pretending to do
    /// it, and say so in the return value.
    #[tokio::test]
    async fn classical_peers_skip_the_proof() {
        let (mut server, mut client, _sb, _cb) = sessions().await;
        let server_c = LocalBundle::classical_only(LocalIdentity::generate().unwrap());
        let client_c = LocalBundle::classical_only(LocalIdentity::generate().unwrap());
        let (sb, cb) = (server_c.bundle(), client_c.bundle());

        let s = tokio::spawn(async move {
            authenticate(&mut server, &server_c, &cb, Side::Responder).await
        });
        let c = authenticate(&mut client, &client_c, &sb, Side::Initiator).await;

        assert!(!c.unwrap(), "no proof is required between classical peers");
        assert!(!s.await.unwrap().unwrap());
    }
}
