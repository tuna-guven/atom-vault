use secrecy::{ExposeSecret, SecretString};
use std::fs::{self, OpenOptions};
use std::path::PathBuf;

use crate::commands::daemon::get_or_create_identity;
use crate::commands::p2p_utils::{load_friends, parse_atom_uri, to_atom_meta, to_p2p_meta};
use crate::storage::{load_vault_metadata, save_vault_metadata};

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

    let (onion_address, friend_pubkey) = parse_atom_uri(&friend.url)?;

    // 1. OPEN VAULT & EXTRACT REAL METADATA
    let mut physical_vault = OpenOptions::new().read(true).write(true).open(vault_path)?;

    let (metadata, unlocked_vault, payload_offset) =
        load_vault_metadata(&mut physical_vault, vault_password.expose_secret())?;

    // 2. LOAD DECOUPLED NETWORK IDENTITY
    let local_identity = get_or_create_identity()?;

    // 3. SET UP SYNC STATE DIRECTORY
    let mut client_state_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    client_state_dir.push(".atom_vault/arti_client_state");
    fs::create_dir_all(&client_state_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&client_state_dir, fs::Permissions::from_mode(0o700))?;
    }

    let physical_vault_path = PathBuf::from(vault_path);
    let p2p_compatible_metadata = to_p2p_meta(&metadata);

    let rt = tokio::runtime::Runtime::new()?;

    // 4. EXECUTE NETWORK SYNC
    let updated_p2p_metadata = rt.block_on(async {
        let atom_net = p2p_sync::AtomSyncManager::new(local_identity, client_state_dir);

        let dummy_master_secret = zeroize::Zeroizing::new([0u8; 32]);

        let (control, inbound_rx) = atom_net
            .connect_to_friend(&onion_address, &friend_pubkey, &dummy_master_secret)
            .await
            .map_err(|e| format!("Network connection failed (Is the friend online?): {}", e))?;

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
            .map_err(|e| format!("Synchronization failed: {}", e))?;

        let final_metadata = sync_manager.local_metadata.read().await;
        Ok::<_, Box<dyn std::error::Error>>((*final_metadata).clone())
    })?;

    // 5. SECURELY SAVE METADATA
    let updated_metadata = to_atom_meta(&updated_p2p_metadata);

    println!("💾 Sync complete! Saving updated File Allocation Table to disk...");
    save_vault_metadata(
        &mut physical_vault,
        &updated_metadata,
        &unlocked_vault,
        payload_offset,
    )?;

    println!("🎉 Vault successfully synchronized and saved!");
    Ok(())
}
