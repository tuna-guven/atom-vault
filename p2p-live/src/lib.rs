//! # p2p-live — strict-PFS, post-quantum live transfer for Atom Vault
//!
//! Implements the session layer from `docs/pfs-pq-roadmap.md`: a live,
//! both-peers-online transport with **strict forward secrecy** and **hybrid
//! post-quantum key agreement**.
//!
//! ## Why live, and what it removes
//!
//! Strict forward secrecy is incompatible with data at rest: a recipient who
//! fetches later must be able to decrypt later, so a key must survive until they
//! do. Transferring live removes that key entirely. There is **no bearer
//! capability and no ciphertext at rest**, so a "harvest now, decrypt later"
//! adversary has nothing to harvest.
//!
//! ## The guarantees, and how they are enforced
//!
//! | Guarantee | Mechanism |
//! |-----------|-----------|
//! | Strict PFS | TLS 1.3 ephemeral-only key agreement; resumption and 0-RTT disabled |
//! | Hybrid PQ | `X25519MLKEM768` as the **only** offered group — fails closed |
//! | Mutual auth | RFC 7250 raw public keys pinned in both directions, no CA |
//! | No downgrade | TLS 1.3 pinned; single kx group; TLS 1.2 paths refuse |
//!
//! The hybrid group is *the only one configured*, so a successful handshake is
//! itself proof that post-quantum key agreement was used. There is no
//! negotiation path to a classical-only group — a peer that cannot do
//! `X25519MLKEM768` fails to connect rather than silently downgrading.
//!
//! Long-term identity keys are used for **authentication only**, never for key
//! agreement. Their later compromise permits impersonation going forward but
//! cannot retroactively decrypt a recorded session. That separation is what
//! makes the forward secrecy strict.

pub mod identity;
mod pinned;

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::CryptoProvider;
use rustls::server::AlwaysResolvesServerRawPublicKeys;

use identity::{LocalIdentity, PeerPublicKey};
use pinned::{PinnedClientVerifier, PinnedServerVerifier};

/// ALPN identifying this protocol version. Bound into the handshake, so a peer
/// speaking a different version cannot be silently misinterpreted.
pub const ALPN: &[u8] = b"atom-vault/live/1";

/// Errors from session setup.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("identity error: {0}")]
    Identity(String),

    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("QUIC configuration error: {0}")]
    QuicConfig(String),

    #[error("connection error: {0}")]
    Connect(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// The crypto provider for this transport: aws-lc-rs restricted to the hybrid
/// post-quantum group.
///
/// Restricting `kx_groups` to a single entry is what makes the PQ guarantee
/// *strict* rather than best-effort. `rustls`'s defaults also offer classical
/// X25519/P-256, which would let a peer negotiate away the PQ protection; here
/// there is nothing to negotiate.
pub fn hybrid_pq_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider
}

/// TLS 1.3 only. QUIC requires it, and pinning it here removes any 1.2 path.
static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Build the client-side QUIC config: presents `local` as a raw public key and
/// pins `expected_peer` as the only acceptable server identity.
pub fn client_config(
    local: &LocalIdentity,
    expected_peer: &PeerPublicKey,
) -> Result<quinn::ClientConfig, Error> {
    let tls = client_tls_config(local, expected_peer)?;
    let quic = QuicClientConfig::try_from(tls).map_err(|e| Error::QuicConfig(e.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

/// The rustls half of [`client_config`], before it is wrapped for QUIC.
///
/// Split out so the negotiation guarantees can be asserted directly against the
/// same configuration the transport uses — a test that built its own config
/// would prove nothing about this one.
fn client_tls_config(
    local: &LocalIdentity,
    expected_peer: &PeerPublicKey,
) -> Result<rustls::ClientConfig, Error> {
    let provider = Arc::new(hybrid_pq_provider());
    let certified = local.certified_key(&provider)?;

    let verifier = Arc::new(PinnedServerVerifier {
        pinned: expected_peer.clone(),
        provider: provider.clone(),
    });

    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(TLS13_ONLY)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified)));

    tls.alpn_protocols = vec![ALPN.to_vec()];

    // --- Strict PFS: no resumption, no 0-RTT. ---
    // Session resumption reuses key material across connections, and 0-RTT data
    // is explicitly *not* forward secret. Both are disabled deliberately; see
    // the regression tests that assert this stays true.
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;

    Ok(tls)
}

/// Build the server-side QUIC config: presents `local` as a raw public key and
/// requires the connecting client to prove it holds `expected_peer`.
pub fn server_config(
    local: &LocalIdentity,
    expected_peer: &PeerPublicKey,
) -> Result<quinn::ServerConfig, Error> {
    let tls = server_tls_config(local, expected_peer)?;
    let quic = QuicServerConfig::try_from(tls).map_err(|e| Error::QuicConfig(e.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

/// The rustls half of [`server_config`]. See [`client_tls_config`].
fn server_tls_config(
    local: &LocalIdentity,
    expected_peer: &PeerPublicKey,
) -> Result<rustls::ServerConfig, Error> {
    let provider = Arc::new(hybrid_pq_provider());
    let certified = local.certified_key(&provider)?;

    let verifier = Arc::new(PinnedClientVerifier {
        pinned: expected_peer.clone(),
        provider: provider.clone(),
    });

    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(TLS13_ONLY)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified)));

    tls.alpn_protocols = vec![ALPN.to_vec()];

    // --- Strict PFS: issue no resumption tickets, accept no early data. ---
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;

    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};

    /// Drive a rustls client/server pair to a completed handshake purely in
    /// memory — no sockets, so the negotiated parameters can be inspected
    /// directly rather than inferred from whether a connection succeeded.
    fn handshake(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), rustls::Error> {
        // Bounded: a TLS 1.3 handshake is a few flights. If it has not settled
        // by now something is wrong, and looping forever would hide that.
        for _ in 0..16 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets()?;
            }

            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut buf.as_slice()).unwrap();
                client.process_new_packets()?;
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        panic!("handshake did not complete");
    }

    fn pinned_pair() -> (ClientConnection, ServerConnection) {
        let server_id = LocalIdentity::generate().unwrap();
        let client_id = LocalIdentity::generate().unwrap();

        let cc = client_tls_config(&client_id, server_id.public_key()).unwrap();
        let sc = server_tls_config(&server_id, client_id.public_key()).unwrap();

        // The name is not an authentication input here — the pinned raw public
        // key is. It only has to be a syntactically valid ServerName.
        let name = ServerName::try_from("atom-vault").unwrap();
        (
            ClientConnection::new(Arc::new(cc), name).unwrap(),
            ServerConnection::new(Arc::new(sc)).unwrap(),
        )
    }

    /// The direct assertion behind the whole post-quantum claim: the group that
    /// was actually negotiated is the hybrid one.
    ///
    /// The integration tests establish this indirectly (the hybrid group is the
    /// only one offered, and a classical-only peer cannot connect). This test
    /// removes the inference step and reads the negotiated group back out.
    #[test]
    fn negotiated_group_is_hybrid_pq() {
        let (mut client, mut server) = pinned_pair();
        handshake(&mut client, &mut server).expect("hybrid PQ handshake must succeed");

        for (side, conn) in [
            ("client", client.negotiated_key_exchange_group()),
            ("server", server.negotiated_key_exchange_group()),
        ] {
            let group = conn.unwrap_or_else(|| panic!("{side}: no key exchange group negotiated"));
            assert_eq!(
                group.name(),
                rustls::NamedGroup::X25519MLKEM768,
                "{side} negotiated {:?}, not the hybrid post-quantum group — \
                 the PQ guarantee has been lost",
                group.name()
            );
        }
    }

    /// TLS 1.3 must be what was negotiated. Anything else is a downgrade.
    #[test]
    fn negotiated_version_is_tls13() {
        let (mut client, mut server) = pinned_pair();
        handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
    }

    /// Regression guard for strict PFS: the settings that would reintroduce
    /// non-forward-secret key material must stay off.
    ///
    /// Resumption reuses secrets across connections and 0-RTT data is not
    /// forward secret at all. If a future change enables either for
    /// performance, this test is the thing that objects.
    #[test]
    fn resumption_and_early_data_stay_disabled() {
        let server_id = LocalIdentity::generate().unwrap();
        let client_id = LocalIdentity::generate().unwrap();

        let cc = client_tls_config(&client_id, server_id.public_key()).unwrap();
        assert!(!cc.enable_early_data, "client 0-RTT must remain disabled");

        let sc = server_tls_config(&server_id, client_id.public_key()).unwrap();
        assert_eq!(
            sc.send_tls13_tickets, 0,
            "server must issue no resumption tickets"
        );
        assert_eq!(
            sc.max_early_data_size, 0,
            "server must accept no early data"
        );
    }

    /// A server whose key is not the pinned one must be rejected at the rustls
    /// layer, independently of any QUIC-level behaviour.
    #[test]
    fn wrong_pin_fails_the_handshake() {
        let server_id = LocalIdentity::generate().unwrap();
        let client_id = LocalIdentity::generate().unwrap();
        let impostor = LocalIdentity::generate().unwrap();

        let cc = client_tls_config(&client_id, impostor.public_key()).unwrap();
        let sc = server_tls_config(&server_id, client_id.public_key()).unwrap();

        let name = ServerName::try_from("atom-vault").unwrap();
        let mut client = ClientConnection::new(Arc::new(cc), name).unwrap();
        let mut server = ServerConnection::new(Arc::new(sc)).unwrap();

        assert!(
            handshake(&mut client, &mut server).is_err(),
            "a server presenting an unpinned key must not authenticate"
        );
    }
}
