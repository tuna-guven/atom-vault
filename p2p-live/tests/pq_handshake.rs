//! Phase 0 gate tests — prove the security claims hold end-to-end over real
//! QUIC, not just that the code compiles.
//!
//! These assert the four properties `p2p-live` promises:
//!   1. A hybrid post-quantum handshake completes over real QUIC.
//!   2. Identity pinning authenticates both directions.
//!   3. A wrong pin is rejected (impersonation fails).
//!   4. There is **no downgrade path** to classical-only key agreement.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use p2p_live::identity::{LocalIdentity, PeerPublicKey};
use p2p_live::{ALPN, client_config, server_config};

/// Bind an ephemeral loopback port.
fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Spin up a server endpoint that accepts exactly one connection, echoing the
/// bytes of the first bi-directional stream back to the client.
///
/// Returns the bound address and the accept task handle.
fn spawn_echo_server(
    server_id: LocalIdentity,
    expect_client: PeerPublicKey,
) -> Result<
    (SocketAddr, tokio::task::JoinHandle<Result<Vec<u8>, String>>),
    Box<dyn std::error::Error>,
> {
    let cfg = server_config(&server_id, &expect_client)?;
    let socket = UdpSocket::bind(loopback())?;
    let addr = socket.local_addr()?;

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(cfg),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    let handle = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("no inbound connection")?;
        let conn = incoming.await.map_err(|e| format!("accept failed: {e}"))?;

        let hd = conn
            .handshake_data()
            .ok_or("no handshake data")?
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .map_err(|_| "unexpected handshake data type")?;

        // ALPN must have been negotiated to our protocol.
        //
        // quinn exposes the negotiated key exchange group only behind an
        // internal test feature, so the direct assertion that the group was
        // X25519MLKEM768 lives in the rustls-level unit test
        // `negotiated_group_is_hybrid_pq` in src/lib.rs. Here it is established
        // indirectly: the hybrid group is the only one configured, and
        // `classical_only_client_cannot_downgrade_the_server` proves there is
        // no fallback path.
        if hd.protocol.as_deref() != Some(ALPN) {
            return Err(format!("unexpected ALPN: {:?}", hd.protocol));
        }

        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| format!("accept_bi failed: {e}"))?;
        let data = recv
            .read_to_end(64 * 1024)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        send.write_all(&data)
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        send.finish().map_err(|e| format!("finish failed: {e}"))?;
        // Keep the endpoint alive until the client has drained the response.
        conn.closed().await;
        Ok(data)
    });

    Ok((addr, handle))
}

/// Connect with the given client config and round-trip `payload`.
async fn client_roundtrip(
    cfg: quinn::ClientConfig,
    addr: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut endpoint =
        quinn::Endpoint::client(loopback()).map_err(|e| format!("client bind: {e}"))?;
    endpoint.set_default_client_config(cfg);

    // The server name is irrelevant to authentication here — identity comes
    // from the pinned raw public key, not from a hostname.
    let conn = endpoint
        .connect(addr, "atom-vault")
        .map_err(|e| format!("connect setup: {e}"))?
        .await
        .map_err(|e| format!("handshake failed: {e}"))?;

    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;
    send.write_all(payload)
        .await
        .map_err(|e| format!("write: {e}"))?;
    send.finish().map_err(|e| format!("finish: {e}"))?;
    let echoed = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| format!("read: {e}"))?;
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(echoed)
}

/// **Gate 1 + 2** — a hybrid PQ, mutually-pinned handshake completes and moves
/// data over real QUIC.
///
/// Because `hybrid_pq_provider` offers `X25519MLKEM768` and nothing else, a
/// successful handshake is itself proof that post-quantum key agreement was
/// used: there is no other group either side could have negotiated.
#[tokio::test]
async fn hybrid_pq_mutually_pinned_roundtrip() {
    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let server_pub = server_id.public_key().clone();
    let client_pub = client_id.public_key().clone();

    let (addr, server) = spawn_echo_server(server_id, client_pub).unwrap();
    let cfg = client_config(&client_id, &server_pub).unwrap();

    let payload = b"vault bytes over a post-quantum, forward-secret channel";
    let echoed = client_roundtrip(cfg, addr, payload).await.unwrap();

    assert_eq!(echoed, payload, "payload must round-trip intact");
    assert_eq!(server.await.unwrap().unwrap(), payload);
}

/// **Gate 3a** — a client that pins the wrong server key must refuse to connect.
/// This is the anti-MITM property: possessing the right address is not enough.
#[tokio::test]
async fn client_rejects_unpinned_server() {
    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let client_pub = client_id.public_key().clone();

    // An unrelated identity the client will (wrongly) expect from the server.
    let impostor = LocalIdentity::generate().unwrap();

    let (addr, _server) = spawn_echo_server(server_id, client_pub).unwrap();
    let cfg = client_config(&client_id, impostor.public_key()).unwrap();

    let result = client_roundtrip(cfg, addr, b"should never arrive").await;
    assert!(
        result.is_err(),
        "connecting to a server whose key is not the pinned one must fail"
    );
}

/// **Gate 3b** — the server must reject a client whose key it has not pinned.
/// Authentication is mutual, so an unknown client cannot connect either.
#[tokio::test]
async fn server_rejects_unpinned_client() {
    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let server_pub = server_id.public_key().clone();

    // The server expects some *other* client identity.
    let expected_other = LocalIdentity::generate().unwrap();

    let (addr, _server) =
        spawn_echo_server(server_id, expected_other.public_key().clone()).unwrap();
    let cfg = client_config(&client_id, &server_pub).unwrap();

    let result = client_roundtrip(cfg, addr, b"should never arrive").await;
    assert!(
        result.is_err(),
        "server must reject a client whose raw public key is not pinned"
    );
}

/// **Gate 4 — the important one.** A client offering only classical X25519 must
/// **fail to connect**, never silently downgrade.
///
/// This is what makes the post-quantum guarantee strict rather than
/// best-effort. If someone later widens `kx_groups` for compatibility, this
/// test fails and tells them they removed the guarantee.
#[tokio::test]
async fn classical_only_client_cannot_downgrade_the_server() {
    use rustls::client::AlwaysResolvesClientRawPublicKeys;

    let server_id = LocalIdentity::generate().unwrap();
    let client_id = LocalIdentity::generate().unwrap();
    let client_pub = client_id.public_key().clone();

    let (addr, _server) = spawn_echo_server(server_id, client_pub).unwrap();

    // Build a client that is identical to the real one except that it offers
    // ONLY classical X25519 — i.e. a peer without post-quantum support.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let provider = Arc::new(provider);

    // Re-derive a certified key bound to this classical-only provider.
    let certified = client_id.certified_key(&provider).unwrap();

    #[derive(Debug)]
    struct AcceptAnyServer(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
        fn verify_server_cert(
            &self,
            _e: &rustls::pki_types::CertificateDer<'_>,
            _i: &[rustls::pki_types::CertificateDer<'_>],
            _n: &rustls::pki_types::ServerName<'_>,
            _o: &[u8],
            _t: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            // Deliberately permissive: we are testing key-exchange negotiation,
            // so certificate checks must not be what causes the failure.
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &rustls::pki_types::CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &rustls::pki_types::CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(provider)))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified)));
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let cfg = quinn::ClientConfig::new(Arc::new(quic));

    let result = client_roundtrip(cfg, addr, b"classical only").await;
    assert!(
        result.is_err(),
        "a classical-X25519-only client MUST NOT be able to connect — \
         the post-quantum guarantee would be best-effort, not strict"
    );
}
