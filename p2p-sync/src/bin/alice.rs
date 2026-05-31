use arti_client::{TorClient, TorClientConfig};
use ed25519_dalek::SigningKey;
use p2p_sync::{
    handshake,
    sync::{ChunkEntry, FileIndex, SyncManager, VaultMetadata},
    transport,
};
use std::collections::HashMap;
use tokio_util::compat::FuturesAsyncReadCompatExt;

#[tokio::main]
async fn main() {
    let alice_key = SigningKey::from_bytes(&[1u8; 32]);
    let bob_pub = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

    // Your active Bob address from the logs
    let onion_addr = "rv3txodaquwo6qr4tx4upypi6qhojsof4ieshebkn7gs46dl3udlewqd.onion";

    println!("🧅 Bootstrapping Arti Tor client (this takes ~10 seconds)...");
    let mut config_builder = TorClientConfig::builder();
    config_builder.address_filter().allow_onion_addrs(true);
    let config = config_builder.build().unwrap();

    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();

    println!("🌐 Dialing {}...", onion_addr);

    // --- THE RESILIENT CONNECTION LOOP ---
    let mut arti_stream = None;
    for attempt in 1..=10 {
        println!("   Attempt {}/10 to build Tor circuit...", attempt);
        match tor_client.connect((onion_addr, 80)).await {
            Ok(stream) => {
                arti_stream = Some(stream);
                break;
            }
            Err(_e) => {
                println!("   ⚠️ Circuit timeout/failure. Retrying in 5s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }

    let arti_stream = arti_stream.expect(
        "❌ Failed to connect after 10 attempts! Check if Bob's Tor daemon is still running.",
    );
    let mut stream = arti_stream.compat();
    // -------------------------------------

    println!("🔐 Connected! Executing Noise handshake...");
    let session = handshake::execute_handshake(&mut stream, true, &alice_key, &bob_pub)
        .await
        .unwrap();

    let (control, inbound_rx) = transport::start_multiplexer(stream, session.transport, true);

    // Provide Alice with two mock chunks that Bob is missing
    let chunk1_nonce = [1u8; 24];
    let chunk2_nonce = [2u8; 24];
    let mut alice_storage = HashMap::new();
    alice_storage.insert(chunk1_nonce, b"ALICE'S ENCRYPTED CHUNK 1".to_vec());
    alice_storage.insert(chunk2_nonce, b"ALICE'S ENCRYPTED CHUNK 2".to_vec());

    let alice_metadata = VaultMetadata {
        file_table: vec![FileIndex {
            vfs_name: "alice_vacation.mp4".to_string(),
            chunks: vec![
                ChunkEntry {
                    cipher_len: 25,
                    offset: 8,
                    nonce: chunk1_nonce,
                },
                ChunkEntry {
                    cipher_len: 25,
                    offset: 33,
                    nonce: chunk2_nonce,
                },
            ],
        }],
    };

    let sync_manager = SyncManager::new(control, inbound_rx, alice_metadata, alice_storage);

    println!("🚀 Opening Yamux stream and initiating concurrent metadata sync...");
    sync_manager.synchronize().await.unwrap();

    // Keep alive briefly to serve inbound requests if Bob needs files
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
}
