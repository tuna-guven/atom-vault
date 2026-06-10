use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

// We use the XX pattern: both parties send their static keys to each other.
// X25519 is used for the ephemeral Diffie-Hellman key exchange.
// ChaCha20-Poly1305 is our ultra-fast, secure transport cipher.
// SHA256 is used for hashing the handshake transcript.
static NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// The resulting state of a successful handshake.
/// This contains the encrypted transport stream and the shared Master Secret
/// that we will use to derive our daily Tor addresses in `address.rs`.
pub struct VaultSession {
    pub transport: TransportState,
    pub master_secret: Zeroizing<[u8; 32]>, // SECURE: Protected against memory leaks/swap space dumps
    pub remote_static_key: VerifyingKey,
}

/// Executes the P2P cryptographic handshake over a raw async stream (like a Tor SOCKS5 TCP stream).
// FIX: Added `+ Send + Sync` to the Error return type so Tokio can safely pass it between threads
pub async fn execute_handshake<S>(
    stream: &mut S,
    is_initiator: bool,
    local_identity_key: &SigningKey,
    expected_remote_pubkey: &VerifyingKey,
) -> Result<VaultSession, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // =========================================================================
    // PHASE 1: THE NOISE HANDSHAKE (Perfect Forward Secrecy)
    // =========================================================================

    let builder = Builder::new(NOISE_PATTERN.parse()?);

    // We generate completely random, temporary X25519 keys just for this connection.
    let temp_keys = builder.generate_keypair()?;

    // Initialize the state machine
    let mut noise = if is_initiator {
        Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&temp_keys.private)
            .build_initiator()?
    } else {
        Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&temp_keys.private)
            .build_responder()?
    };

    // SECURE: Wrap the general handshake buffer in Zeroizing
    let mut buf = Zeroizing::new(vec![0u8; 65535]);

    // Execute the 3-message XX pattern exchange.
    if is_initiator {
        send_message(stream, &mut noise, &[], &mut buf).await?;
        recv_message(stream, &mut noise, &mut buf).await?;
        send_message(stream, &mut noise, &[], &mut buf).await?;
    } else {
        recv_message(stream, &mut noise, &mut buf).await?;
        send_message(stream, &mut noise, &[], &mut buf).await?;
        recv_message(stream, &mut noise, &mut buf).await?;
    }

    // =========================================================================
    // PHASE 2: CRYPTOGRAPHIC BINDING (Identity Authentication)
    // =========================================================================

    // The handshake hash is a mathematically unique fingerprint of the exchange
    let handshake_hash = noise.get_handshake_hash();

    // We sign this unique hash using our long-term Ed25519 vault identity.
    let signature = local_identity_key.sign(handshake_hash);

    // Save this hash to use as our Master Secret for address.rs later
    let mut master_secret = [0u8; 32];
    master_secret.copy_from_slice(handshake_hash);

    // SECURE: Pack our Ed25519 Public Key and Signature into a Zeroizing payload
    let mut my_auth_payload = Zeroizing::new([0u8; 96]);
    my_auth_payload[..32].copy_from_slice(local_identity_key.verifying_key().as_bytes());
    my_auth_payload[32..].copy_from_slice(&signature.to_bytes());

    // Switch the state machine from "Handshake" to "Encrypted Transport"
    let mut transport = noise.into_transport_mode()?;

    // =========================================================================
    // PHASE 3: THE ENCRYPTED PAYLOAD EXCHANGE
    // =========================================================================

    let len = transport.write_message(&*my_auth_payload, &mut buf)?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    let len = stream.read_u16().await? as usize;
    stream.read_exact(&mut buf[..len]).await?;

    // SECURE: Use Zeroizing to hold the incoming decrypted payload
    let mut plain_payload = Zeroizing::new(vec![0u8; 65535]);
    let payload_len = transport.read_message(&buf[..len], &mut plain_payload)?;

    if payload_len != 96 {
        return Err(Box::<dyn std::error::Error + Send + Sync>::from(
            "Invalid authentication payload length",
        ));
    }

    // Extract the peer's public key and signature from their payload
    let mut remote_pubkey_bytes = [0u8; 32];
    remote_pubkey_bytes.copy_from_slice(&plain_payload[..32]);

    let mut remote_sig_bytes = [0u8; 64];
    remote_sig_bytes.copy_from_slice(&plain_payload[32..96]);

    let remote_pubkey = VerifyingKey::from_bytes(&remote_pubkey_bytes)?;
    let remote_sig = Signature::from_bytes(&remote_sig_bytes);

    // =========================================================================
    // PHASE 4: VERIFICATION
    // =========================================================================

    // 1. Did we connect to the correct person from the atom:// link?
    if remote_pubkey != *expected_remote_pubkey {
        return Err(Box::<dyn std::error::Error + Send + Sync>::from(
            "Peer identity mismatch! Possible MITM attack.",
        ));
    }

    // 2. Did they actually hold the private key to sign this exact session's hash?
    if let Err(_) = remote_pubkey.verify_strict(&master_secret, &remote_sig) {
        return Err(Box::<dyn std::error::Error + Send + Sync>::from(
            "Invalid signature! The peer could not prove their identity.",
        ));
    }

    // Success! We have a perfectly forward-secret, mutually authenticated connection.
    Ok(VaultSession {
        transport,
        master_secret: Zeroizing::new(master_secret),
        remote_static_key: remote_pubkey,
    })
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Writes a Noise message over the TCP stream with a 2-byte length prefix.
// FIX: Added + Send + Sync
async fn send_message<S>(
    stream: &mut S,
    noise: &mut HandshakeState,
    payload: &[u8],
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWriteExt + Unpin,
{
    let len = noise.write_message(payload, buf)?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;
    Ok(())
}

/// Reads a length-prefixed Noise message from the TCP stream.
// FIX: Added + Send + Sync
async fn recv_message<S>(
    stream: &mut S,
    noise: &mut HandshakeState,
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncReadExt + Unpin,
{
    let len = stream.read_u16().await? as usize;
    stream.read_exact(&mut buf[..len]).await?;

    let mut payload = Zeroizing::new(vec![0u8; 65535]);
    noise.read_message(&buf[..len], &mut payload)?;
    Ok(())
}
