use ed25519_dalek::SigningKey;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};

use crate::commands::p2p_utils::{
    extract_pubkey_from_onion, load_friends, load_vault_metadata, save_vault_metadata,
    to_atom_meta, to_p2p_meta,
};
use crate::crypto;

pub fn handle_sync(
    vault_path: String,
    friend_nickname: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let friends = load_friends();
    let friend = match friends.iter().find(|f| f.nickname == friend_nickname) {
        Some(f) => f,
        None => {
            println!("❌ Friend '{}' not found.", friend_nickname);
            return Ok(());
        }
    };

    println!(
        "🚀 Initiating P2P Sync for '{}' with '{}'...",
        vault_path, friend.nickname
    );

    let friend_pubkey =
        extract_pubkey_from_onion(&friend.url).expect("Corrupted onion link in registry");

    // Re-initialize the hardcoded vault exactly as main.rs used to do
    let mut physical_vault = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&vault_path)
        .unwrap();
    let salt = [0u8; 32];
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = [42u8; 32];
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();
    let (mut metadata, _) = load_vault_metadata(&mut physical_vault, &unlocked_vault).unwrap();

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &raw_dek);
    let mut identity_bytes = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(b"atom-p2p-identity", &mut *identity_bytes)
        .unwrap();
    let local_identity = SigningKey::from_bytes(&*identity_bytes);

    let mut master_secret = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(b"atom-p2p-master-secret", &mut *master_secret)
        .unwrap();

    let physical_vault_path = std::path::PathBuf::from(&vault_path);
    let p2p_compatible_metadata = to_p2p_meta(&metadata);

    let mut client_state_dir = dirs::home_dir().expect("Could not find home directory");
    client_state_dir.push(".atom_vault/arti_client_state");
    std::fs::create_dir_all(&client_state_dir).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    let updated_p2p_metadata = rt.block_on(async {
        let atom_net = p2p_sync::AtomSyncManager::new(local_identity, client_state_dir);

        let (control, inbound_rx) = atom_net
            .connect_to_friend(&friend_pubkey, &master_secret)
            .await
            .expect("Network connection failed! Ensure friend is online.");

        println!("🔗 Tor tunnel established! Handing over to SyncManager...");
        let sync_manager = p2p_sync::sync::SyncManager::new(
            control,
            inbound_rx,
            p2p_compatible_metadata,
            physical_vault_path,
        );

        sync_manager
            .synchronize()
            .await
            .expect("Synchronization failed");

        let final_metadata = sync_manager.local_metadata.read().await;
        (*final_metadata).clone()
    });

    metadata = to_atom_meta(&updated_p2p_metadata);

    println!("💾 Sync complete! Saving updated File Allocation Table to disk...");
    let new_eof = physical_vault.seek(SeekFrom::End(0)).unwrap();
    save_vault_metadata(&mut physical_vault, &metadata, &unlocked_vault, new_eof).unwrap();

    println!("🎉 Vault successfully synchronized and saved!");
    Ok(())
}
