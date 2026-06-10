use arti_client::{TorClient, TorClientConfig};
use ed25519_dalek::SigningKey;
use p2p_sync::{
    handshake,
    sync::{ChunkEntry, FileIndex, SyncManager, VaultMetadata},
    transport,
};
use std::collections::HashMap;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    // SECURE: Wrap the raw private key bytes in Zeroizing as they are loaded into RAM.
    // In production, these bytes would be decrypted from your local keystore.
    let key_bytes = Zeroizing::new([1u8; 32]);
    let alice_key = SigningKey::from_bytes(&*key_bytes);

    // SAFE: Bob's identity is a Public Key. It does not need memory protection.
    let bob_pub = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

    // Your active Bob address from the logs
    let onion_addr = "l7p2kxjaabxbvnmi3lwyejsdindzdldzzoo5tpupl3jgccvhkxdnbmid.onion";

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

    // SAFE: This represents encrypted Vault Ciphertext.
    // Ciphertext is mathematically safe to reside in standard OS-managed memory or swap space.
    alice_storage.insert(chunk1_nonce, b"ALICE'S ENCRYPTED CHUNK 1".to_vec());
    alice_storage.insert(chunk2_nonce, b"ALICE'S ENCRYPTED CHUNK 2".to_vec());

    let alice_metadata = VaultMetadata {
        file_table: vec![FileIndex {
            vfs_name: "alice_vacation.mp4".to_string(),
            last_modified_unix: 1700000000,
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

    let vault_path = std::path::PathBuf::from("mock_test_vault.aegis");
    let sync_manager = SyncManager::new(control, inbound_rx, alice_metadata, vault_path);

    println!("🚀 Opening Yamux stream and initiating concurrent metadata sync...");
    sync_manager.synchronize().await.unwrap();

    let sm_clone = sync_manager.clone();
    tokio::spawn(async move {
        loop {
            // Mocking a local file system change every 45 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(45)).await;

            println!("📝 Alice edited a file! Pinging Bob to synchronize...");
            let _ = sm_clone.synchronize().await;
        }
    });

    // Keep the application running so background threads can talk to each other
    tokio::signal::ctrl_c().await.unwrap();
}
