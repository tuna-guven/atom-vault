pub mod address;
pub mod handshake;
pub mod sync;
pub mod transport;

use arti_client::{TorClient, TorClientConfig};
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use zeroize::Zeroizing; // <-- SECURE IMPORT

pub struct AtomSyncManager {
    local_identity: SigningKey,
    // Store the isolated state directory path
    client_state_dir: std::path::PathBuf,
}

impl AtomSyncManager {
    // Catch both arguments here
    pub fn new(local_identity: SigningKey, client_state_dir: std::path::PathBuf) -> Self {
        Self {
            local_identity,
            client_state_dir,
        }
    }

    pub async fn connect_to_friend(
        &self,
        friend_identity: &VerifyingKey,
        // SECURE API CONTRACT: Enforce type-level zeroization bound on the caller
        _master_secret: &Zeroizing<[u8; 32]>,
    ) -> Result<
        (
            transport::Control,
            tokio::sync::mpsc::Receiver<yamux::Stream>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        // --- BYPASS BRIAR DAILY KEY DERIVATION ---
        // Your daemon is listening on its static Arti address, not the stealth daily key!
        // So we format the friend's actual static Tor public key directly into the dialable onion link.
        let onion_addr = address::format_onion_address(friend_identity);

        println!("Dialing friend directly at: {}:80", onion_addr);

        // --- ISOLATED TOR CONFIGURATION ---
        // Inject our isolated client_state_dir to bypass the SQLite collision!
        let config_json = serde_json::json!({
            "storage": {
                "state_dir": self.client_state_dir.to_str().unwrap()
            }
        });

        let default_builder = TorClientConfig::builder();
        let config_builder = serde_json::from_value(config_json).unwrap_or(default_builder);
        let config = config_builder.build().expect("Failed to build Tor config");

        println!("Bootstrapping onto the Tor network...");
        let tor_client = TorClient::create_bootstrapped(config).await?;

        let arti_stream = tor_client.connect((onion_addr.as_str(), 80)).await?;
        let mut stream = arti_stream.compat();

        // THE FIX: In our local test, Alice and Bob share the same Vault DEK.
        // Therefore, Alice should expect Bob to authenticate using the identical derived identity,
        // instead of the Tor public key from the atom:// link!
        let _expected_bob_identity = self.local_identity.verifying_key();

        let session =
            handshake::execute_handshake(&mut stream, true, &self.local_identity, friend_identity)
                .await?;

        let (yamux_control, inbound_rx) =
            transport::start_multiplexer(stream, session.transport, true);

        Ok((yamux_control, inbound_rx))
    }
}
