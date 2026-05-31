use ed25519_dalek::SigningKey;
use p2p_sync::{
    handshake,
    sync::{ChunkEntry, FileIndex, SyncManager, VaultMetadata},
    transport,
};
use std::collections::HashMap;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let bob_key = SigningKey::from_bytes(&[2u8; 32]);
    let alice_pub = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("🛡️ Bob's vault is listening on 127.0.0.1:8080...");

    let (mut socket, _) = listener.accept().await.unwrap();
    println!("🔗 Connection received! Executing Noise handshake...");

    let session = handshake::execute_handshake(&mut socket, false, &bob_key, &alice_pub)
        .await
        .expect("Handshake failed");

    let (control, inbound_rx) = transport::start_multiplexer(socket, session.transport, false);

    // Provide Bob with one mock chunk that Alice is missing
    let bob_nonce = [7u8; 24];
    let mut bob_storage = HashMap::new();
    bob_storage.insert(bob_nonce, b"BOB'S EXCLUSIVE ENCRYPTED CHUNK".to_vec());

    let bob_metadata = VaultMetadata {
        file_table: vec![FileIndex {
            vfs_name: "bob_secret_notes.txt".to_string(),
            chunks: vec![ChunkEntry {
                cipher_len: 31,
                offset: 8,
                nonce: bob_nonce,
            }],
        }],
    };

    // The SyncManager starts its daemon automatically when instantiated
    let _sync_manager = SyncManager::new(control, inbound_rx, bob_metadata, bob_storage);

    println!("⏳ Waiting for remote peer to initiate sync...");
    tokio::signal::ctrl_c().await.unwrap();
    println!("✅ Bob shut down.");
}
