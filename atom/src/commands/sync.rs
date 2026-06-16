use std::fs::{self, OpenOptions};
use std::path::PathBuf;

use crate::commands::daemon::get_or_create_identity;
use crate::commands::p2p_utils::{load_friends, parse_atom_uri, to_p2p_meta};
use crate::vfs::VaultMetadata;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

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
    let _physical_vault = OpenOptions::new().read(true).write(true).open(vault_path)?;

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

    let _ = p2p_compatible_metadata;

    let rt = tokio::runtime::Runtime::new()?;

    // 4. EXECUTE RAW BINARY TRANSMISSION OVER TOR
    rt.block_on(async {
        let atom_net = p2p_sync::AtomSyncManager::new(local_identity, client_state_dir);
        let dummy_master_secret = zeroize::Zeroizing::new([0u8; 32]);

        let (control, _inbound_rx) = atom_net
            .connect_to_friend(&onion_address, &friend_pubkey, &dummy_master_secret)
            .await
            .map_err(|e| format!("Network connection failed: {}", e))?;

        println!("🔗 Tor tunnel established! Opening raw data stream...");

        // Open a direct Yamux multiplexed stream to Bob
        let mut data_stream = control
            .open_stream()
            .await
            .map_err(|e| format!("Failed to open Yamux stream: {}", e))?
            .compat_write();

        // Open the physical file asynchronously
        let mut file = tokio::fs::File::open(&physical_vault_path).await?;

        println!("⏳ Pumping raw ciphertext blocks over Tor...");

        // Pipe the file directly into the Tor stream
        let bytes_sent = tokio::io::copy(&mut file, &mut data_stream).await?;

        // Gracefully shut down the stream so Bob knows the file is finished
        use tokio::io::AsyncWriteExt;
        data_stream.shutdown().await?;

        println!(
            "🎉 Blind file transfer complete! Pushed {} bytes.",
            bytes_sent
        );

        // CRITICAL FIX: Ensure Arti flushes its Tor buffers before the runtime closes.
        println!("⏳ Finalizing block commitment and gracefully closing circuit...");
        drop(control);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
