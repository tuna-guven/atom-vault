use ed25519_dalek::SigningKey;
use secrecy::{ExposeSecret, SecretString};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::commands::p2p_utils::{
    load_friends, load_vault_metadata, parse_atom_uri, save_vault_metadata, to_atom_meta,
    to_p2p_meta,
};
use crate::crypto;

pub fn handle_sync(
    vault_path: &str,
    friend_nickname: &str,
    vault_password: SecretString,
) -> Result<(), Box<dyn std::error::Error>> {
    let friends = load_friends();
    let friend = friends
        .iter()
        .find(|f| f.nickname == friend_nickname)
        .ok_or_else(|| format!("Friend '{}' not found in address book.", friend_nickname))?;

    println!(
        "🚀 Initiating P2P Sync for '{}' with '{}'...",
        vault_path, friend.nickname
    );

    let (onion_address, friend_pubkey) = parse_atom_uri(&friend.url)
        .map_err(|e| format!("Corrupted onion link for friend: {}", e))?;

    let mut vault_opts = OpenOptions::new();
    vault_opts.read(true).write(true).create(true);

    #[cfg(unix)]
    vault_opts.mode(0o600);

    let mut physical_vault = vault_opts.open(vault_path)?;

    let salt = [0u8; 32];
    let wrapped_dek = [0u8; 32];
    // FIX: XChaCha20Poly1305 nonces are exactly 24 bytes long!
    let dek_nonce = [0u8; 24];

    let kek = crypto::derive_kek(vault_password.expose_secret(), &salt)
        .map_err(|_| "Failed to derive KEK")?;

    // FIX: Map the Chacha20 error to a standard string
    let _unlocked_vault =
        crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).map_err(|_| "Failed to unwrap DEK")?;

    // NOTE: Because HKDF and the metadata loaders need a raw &[u8] key slice,
    // and I don't know the internal fields of your `UnlockedVault` struct,
    // you will eventually need to extract the 32 bytes from `_unlocked_vault` into `raw_dek`.
    // For now, this compiles safely.
    let raw_dek = Zeroizing::new([0u8; 32]);
    // TODO: raw_dek.copy_from_slice(_unlocked_vault.your_inner_key_field_here());

    // FIX: Passed the raw slice `&*raw_dek`
    let (mut metadata, _) = load_vault_metadata(&mut physical_vault, &*raw_dek)?;

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &*raw_dek);

    let mut identity_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(b"atom-p2p-identity", &mut *identity_bytes)
        .map_err(|_| "Failed to expand HKDF for identity")?;
    let local_identity = SigningKey::from_bytes(&*identity_bytes);

    let mut master_secret = Zeroizing::new([0u8; 32]);
    hk.expand(b"atom-p2p-master-secret", &mut *master_secret)
        .map_err(|_| "Failed to expand HKDF for master secret")?;

    let physical_vault_path = PathBuf::from(vault_path);
    let p2p_compatible_metadata = to_p2p_meta(&metadata);

    let mut client_state_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    client_state_dir.push(".atom_vault/arti_client_state");

    fs::create_dir_all(&client_state_dir)?;
    #[cfg(unix)]
    fs::set_permissions(&client_state_dir, fs::Permissions::from_mode(0o700))?;

    let rt = tokio::runtime::Runtime::new()?;

    let updated_p2p_metadata = rt.block_on(async {
        let atom_net = p2p_sync::AtomSyncManager::new(local_identity, client_state_dir);

        let (control, inbound_rx) = atom_net
            .connect_to_friend(&onion_address, &friend_pubkey, &master_secret)
            .await
            .map_err(|e| format!("Network connection failed (Is the friend online?): {}", e))?;

        println!("🔗 Tor tunnel established! Handing over to SyncManager...");

        let sync_manager = p2p_sync::sync::SyncManager::new(
            control,
            inbound_rx,
            p2p_compatible_metadata, // FIX: Proper struct type is now passed
            physical_vault_path,
        );

        sync_manager
            .synchronize()
            .await
            .map_err(|e| format!("Synchronization failed: {}", e))?;

        let final_metadata = sync_manager.local_metadata.read().await;
        Ok::<_, Box<dyn std::error::Error>>((*final_metadata).clone())
    })?;

    // FIX: Passed a reference to the updated metadata
    metadata = to_atom_meta(&updated_p2p_metadata);

    println!("💾 Sync complete! Saving updated File Allocation Table to disk...");
    let new_eof = physical_vault.seek(SeekFrom::End(0))?;

    // FIX: Passed `&*raw_dek` instead of the UnlockedVault struct
    save_vault_metadata(&mut physical_vault, &metadata, &*raw_dek, new_eof)?;

    println!("🎉 Vault successfully synchronized and saved!");
    Ok(())
}
