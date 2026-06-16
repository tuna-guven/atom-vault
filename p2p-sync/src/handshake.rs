use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

static NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

pub struct VaultSession {
    pub transport: TransportState,
    pub master_secret: Zeroizing<[u8; 32]>,
    pub remote_static_key: VerifyingKey,
}

pub async fn execute_handshake<S>(
    stream: &mut S,
    is_initiator: bool,
    local_identity_key: &SigningKey,
    authorized_peers: &[VerifyingKey], // ARCHITECTURE CHANGE: Accept a list of valid friends
) -> Result<VaultSession, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let temp_keys = builder.generate_keypair()?;

    let mut noise = if is_initiator {
        Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&temp_keys.private)
            .build_initiator()?
    } else {
        Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&temp_keys.private)
            .build_responder()?
    };

    let mut buf = Zeroizing::new(vec![0u8; 65535]);

    if is_initiator {
        send_message(stream, &mut noise, &[], &mut buf).await?;
        recv_message(stream, &mut noise, &mut buf).await?;
        send_message(stream, &mut noise, &[], &mut buf).await?;
    } else {
        recv_message(stream, &mut noise, &mut buf).await?;
        send_message(stream, &mut noise, &[], &mut buf).await?;
        recv_message(stream, &mut noise, &mut buf).await?;
    }

    let handshake_hash = noise.get_handshake_hash();
    let signature = local_identity_key.sign(handshake_hash);

    let mut master_secret = [0u8; 32];
    master_secret.copy_from_slice(handshake_hash);

    let mut my_auth_payload = Zeroizing::new([0u8; 96]);
    my_auth_payload[..32].copy_from_slice(local_identity_key.verifying_key().as_bytes());
    my_auth_payload[32..].copy_from_slice(&signature.to_bytes());

    let mut transport = noise.into_transport_mode()?;

    let len = transport.write_message(&*my_auth_payload, &mut buf)?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    let len = stream.read_u16().await? as usize;
    stream.read_exact(&mut buf[..len]).await?;

    let mut plain_payload = Zeroizing::new(vec![0u8; 65535]);
    let payload_len = transport.read_message(&buf[..len], &mut plain_payload)?;

    if payload_len != 96 {
        return Err("Invalid authentication payload length".into());
    }

    let mut remote_pubkey_bytes = [0u8; 32];
    remote_pubkey_bytes.copy_from_slice(&plain_payload[..32]);

    let mut remote_sig_bytes = [0u8; 64];
    remote_sig_bytes.copy_from_slice(&plain_payload[32..96]);

    let remote_pubkey = VerifyingKey::from_bytes(&remote_pubkey_bytes)?;
    let remote_sig = Signature::from_bytes(&remote_sig_bytes);

    // MUTUAL AUTHENTICATION ENFORCEMENT
    if !authorized_peers.contains(&remote_pubkey) {
        return Err("Peer identity mismatch! They are not in your address book. Mutual friend addition is required.".into());
    }

    if remote_pubkey
        .verify_strict(&master_secret, &remote_sig)
        .is_err()
    {
        return Err("Invalid signature! The peer could not prove their identity.".into());
    }

    Ok(VaultSession {
        transport,
        master_secret: Zeroizing::new(master_secret),
        remote_static_key: remote_pubkey,
    })
}

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
