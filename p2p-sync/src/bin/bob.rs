use ed25519_dalek::SigningKey;
use p2p_sync::{
    handshake,
    sync::{ChunkEntry, FileIndex, SyncManager, VaultMetadata},
    transport,
};
use std::collections::HashMap;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    // SECURE: Wrap the raw private key bytes in Zeroizing as they are loaded into RAM.
    // In production, you would read the decrypted bytes from disk directly into this wrapper.
    let key_bytes = Zeroizing::new([2u8; 32]);
    let bob_key = SigningKey::from_bytes(&*key_bytes);

    // SAFE: Alice's identity is a Public Key. It does not need memory protection.
    let alice_pub = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("🛡️ Bob's vault is listening on 127.0.0.1:8080...");

    let (mut socket, _) = listener.accept().await.unwrap();
    println!("🔗 Connection received! Executing Noise handshake...");

    let session = handshake::execute_handshake(&mut socket, false, &bob_key, &alice_pub)
        .await
        .expect("Handshake failed");

    let (control, inbound_rx) = transport::start_multiplexer(socket, session.transport, false);

    let bob_nonce = [7u8; 24];
    let mut bob_storage = HashMap::new();

    // SAFE: This represents encrypted Vault Ciphertext.
    // Ciphertext is mathematically safe to reside in standard OS-managed memory or swap space.
    bob_storage.insert(bob_nonce, b"BOB'S EXCLUSIVE ENCRYPTED CHUNK".to_vec());

    let bob_metadata = VaultMetadata {
        file_table: vec![FileIndex {
            vfs_name: "bob_secret_notes.txt".to_string(),
            last_modified_unix: 1700000000,
            chunks: vec![ChunkEntry {
                cipher_len: 31,
                offset: 8,
                nonce: bob_nonce,
            }],
        }],
    };

    // The SyncManager starts its daemon automatically when instantiated
    let vault_path = std::path::PathBuf::from("mock_test_vault.aegis");
    let sync_manager = SyncManager::new(control, inbound_rx, bob_metadata, vault_path);

    // Bob stays alive and automatically pings Alice if he makes a local change
    let sm_clone = sync_manager.clone();
    tokio::spawn(async move {
        loop {
            // Mocking a local file system change every 30 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

            println!("📝 Local vault changed! Pinging connected friends to synchronize...");
            if let Err(e) = sm_clone.synchronize().await {
                println!("Sync failed: {}", e);
            }
        }
    });

    println!("⏳ Waiting for remote peer to initiate sync...");
    tokio::signal::ctrl_c().await.unwrap();
    println!("✅ Bob shut down.");
}
