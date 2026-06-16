use std::fs::{self, OpenOptions};
use std::path::PathBuf;

use crate::commands::daemon::get_or_create_identity;
use crate::commands::p2p_utils::{load_friends, parse_atom_uri, to_p2p_meta};
use crate::vfs::VaultMetadata;

pub fn handle_sync(
    vault_path: &str,
    friend_nickname: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let friends = load_friends();
    let friend = friends
        .iter()
        .find(|f| f.nickname == friend_nickname)
        .ok_or_else(|| format!("Friend '{}' not found in address book.", friend_nickname))?;

    println!(
        "🚀 Initiating Blind P2P Block Sync for '{}' with '{}'...",
        vault_path, friend.nickname
    );

    let (onion_address, friend_pubkey) = parse_atom_uri(&friend.url)?;

    // 1. OPEN VAULT AS A RAW PROTECTED FILE (NO PASSWORD/DECRYPTION)
    let mut _physical_vault = OpenOptions::new().read(true).write(true).open(vault_path)?;

    // 2. LOAD THE DECOUPLED NETWORK IDENTITY
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

    // Create a blank local metadata state and translate it to appease the SyncManager
    let empty_local_meta = VaultMetadata {
        file_table: Vec::new(),
        cdc_salt: [0u8; 32],
    };
    let p2p_compatible_metadata = to_p2p_meta(&empty_local_meta);

    let rt = tokio::runtime::Runtime::new()?;

    // 4. EXECUTE BLIND BLOCK TRANSMISSION
    rt.block_on(async {
        let atom_net = p2p_sync::AtomSyncManager::new(local_identity, client_state_dir);

        // Derive the ephemeral transport master secret
        let dummy_master_secret = zeroize::Zeroizing::new([0u8; 32]);

        let (control, inbound_rx) = atom_net
            .connect_to_friend(&onion_address, &friend_pubkey, &dummy_master_secret)
            .await
            .map_err(|e| {
                format!(
                    "Network connection failed (Is your friend's daemon online?): {}",
                    e
                )
            })?;

        println!("🔗 Tor tunnel established! Syncing encrypted data allocations blindly...");

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

        println!("⏳ Finalizing block commitment and closing stream gracefully...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    println!("🎉 Blind block layer successfully synchronized and saved!");
    Ok(())
}
