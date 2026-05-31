pub mod address;
pub mod handshake;
pub mod sync;
pub mod transport;

use arti_client::{TorClient, TorClientConfig};
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio_util::compat::FuturesAsyncReadCompatExt;

pub struct AtomSyncManager {
    local_identity: SigningKey,
}

impl AtomSyncManager {
    pub fn new(local_identity: SigningKey) -> Self {
        Self { local_identity }
    }

    pub async fn connect_to_friend(
        &self,
        friend_identity: &VerifyingKey,
        master_secret: &[u8; 32],
    ) -> Result<
        (
            transport::Control,
            tokio::sync::mpsc::Receiver<yamux::Stream>,
        ),
        Box<dyn std::error::Error>,
    > {
        let local_pubkey_bytes = self.local_identity.verifying_key().to_bytes();
        let friend_pubkey_bytes = friend_identity.to_bytes();

        let remote_daily_key = address::derive_daily_key(
            master_secret,
            &local_pubkey_bytes,
            &friend_pubkey_bytes,
            false,
        );

        let onion_addr = address::format_onion_address(&remote_daily_key.verifying_key());
        println!("Dialing friend today at: {}:80", onion_addr);

        let config = TorClientConfig::default();
        println!("Bootstrapping onto the Tor network...");
        let tor_client = TorClient::create_bootstrapped(config).await?;

        let arti_stream = tor_client.connect((onion_addr.as_str(), 80)).await?;
        let mut stream = arti_stream.compat();

        let session =
            handshake::execute_handshake(&mut stream, true, &self.local_identity, friend_identity)
                .await?;

        let (yamux_control, inbound_rx) =
            transport::start_multiplexer(stream, session.transport, true);

        Ok((yamux_control, inbound_rx))
    }
}
