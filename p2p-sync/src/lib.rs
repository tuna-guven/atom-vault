pub mod address;
pub mod handshake;
pub mod sync;
pub mod transport;

use arti_client::{TorClient, TorClientConfig};
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::time::{Duration, timeout};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use zeroize::Zeroizing;

pub struct AtomSyncManager {
    local_identity: SigningKey,
    client_state_dir: std::path::PathBuf,
}

impl AtomSyncManager {
    pub fn new(local_identity: SigningKey, client_state_dir: std::path::PathBuf) -> Self {
        Self {
            local_identity,
            client_state_dir,
        }
    }

    pub async fn connect_to_friend(
        &self,
        onion_address: &str,
        friend_identity: &VerifyingKey,
        _master_secret: &Zeroizing<[u8; 32]>,
    ) -> Result<
        (
            transport::Control,
            tokio::sync::mpsc::Receiver<yamux::Stream>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        println!("Dialing friend directly at: {}:80", onion_address);

        // 1. SAFE PATH PARSING (No panics on invalid OS paths)
        let state_dir_str = self
            .client_state_dir
            .to_str()
            .ok_or("Client state directory path contains invalid UTF-8")?;

        let config_json = serde_json::json!({
            "storage": {
                "state_dir": state_dir_str
            }
        });

        let default_builder = TorClientConfig::builder();
        let config_builder = serde_json::from_value(config_json).unwrap_or(default_builder);
        let config = config_builder
            .build()
            .map_err(|e| format!("Failed to build Tor config: {}", e))?;

        println!("Bootstrapping onto the Tor network...");

        // 2. DOS PREVENTION: TIMEOUT ON BOOTSTRAP
        let bootstrap_timeout = Duration::from_secs(60);
        let tor_client = timeout(bootstrap_timeout, TorClient::create_bootstrapped(config))
            .await
            .map_err(|_| "Tor bootstrap timed out after 60s. Check network connection.")??;

        // 3. DEFENSE IN DEPTH: PREVENT CLEARNET LEAKAGE
        if !onion_address.ends_with(".onion") {
            return Err(
                "Security Violation: Attempted to dial a non-onion clearnet address".into(),
            );
        }

        println!("Building circuit to hidden service...");

        // 4. DOS PREVENTION: TIMEOUT ON CONNECTION
        let connect_timeout = Duration::from_secs(45);
        let arti_stream = timeout(connect_timeout, tor_client.connect((onion_address, 80)))
            .await
            .map_err(|_| "Circuit timeout. Friend may be offline or unreachable.")??;

        let mut stream = arti_stream.compat();

        println!("Executing cryptographic handshake...");

        // 5. DOS PREVENTION: TIMEOUT ON HANDSHAKE
        // Prevents an attacker from holding the Tor socket open while refusing to speak Noise
        let handshake_timeout = Duration::from_secs(15);
        let session = timeout(
            handshake_timeout,
            handshake::execute_handshake(&mut stream, true, &self.local_identity, friend_identity),
        )
        .await
        .map_err(|_| "Noise handshake timed out. Peer may be stalling or malicious.")??;

        let (yamux_control, inbound_rx) =
            transport::start_multiplexer(stream, session.transport, true);

        Ok((yamux_control, inbound_rx))
    }
}
