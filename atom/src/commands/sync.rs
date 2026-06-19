use std::fs::{self};
use std::path::PathBuf;
use std::sync::mpsc::Sender;

use crate::commands::daemon::get_or_create_identity;
use crate::commands::p2p_utils::{SyncMessage, load_friends, parse_atom_uri};

// GUI can pass an mpsc::Sender to receive non-blocking status updates.
pub fn sync_core(
    vault_path: &str,
    friend_nickname: &str,
    status_tx: Option<Sender<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Helper closure to route logs to either the GUI channel or CLI stdout
    let log = |msg: &str| {
        if let Some(tx) = &status_tx {
            let _ = tx.send(msg.to_string());
        } else {
            println!("{}", msg);
        }
    };

    let friends = load_friends();
    let friend = friends
        .iter()
        .find(|f| f.nickname == friend_nickname)
        .ok_or_else(|| format!("Friend '{}' not found in address book.", friend_nickname))?;

    log(&format!("Initiating P2P block sync for '{}' with '{}'...", vault_path, friend.nickname));

    let (onion_address, friend_pubkey) = parse_atom_uri(&friend.url)?;

    
    let local_identity = get_or_create_identity()?;

    let mut client_state_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    client_state_dir.push(".atom_vault/arti_client_state");
    fs::create_dir_all(&client_state_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&client_state_dir, fs::Permissions::from_mode(0o700))?;
    }

    let physical_vault_path = PathBuf::from(vault_path);
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        // Evaluate the local vault metrics to construct the proposal
        let metadata = tokio::fs::metadata(&physical_vault_path).await?;
        let last_modified = metadata
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
            
        let filename = physical_vault_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        let atom_net = p2p_sync::AtomSyncManager::new(local_identity, client_state_dir);
        let dummy_master_secret = zeroize::Zeroizing::new([0u8; 32]);

        let (control, _inbound_rx) = atom_net
            .connect_to_friend(&onion_address, &friend_pubkey, &dummy_master_secret)
            .await
            .map_err(|e| format!("Network connection failed: {}", e))?;

        log("Tor tunnel established. Negotiating sync parameters...");

        // Open the multiplexed stream and wrap it for bi-directional JSON I/O
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let data_stream = control
            .open_stream()
            .await
            .map_err(|e| format!("Failed to open Yamux stream: {}", e))?
            .compat();

        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut stream_io = BufReader::new(data_stream);

        // 1. Send the consent proposal
        let proposal = SyncMessage::Proposal {
            filename,
            last_modified,
        };
        let proposal_json = format!("{}\n", serde_json::to_string(&proposal)?);
        stream_io.write_all(proposal_json.as_bytes()).await?;
        stream_io.flush().await?;

        log(&format!("Waiting for {} to accept the vault transfer...", friend_nickname));

        // 2. Await remote decision
        let mut reply_line = String::new();
        stream_io.read_line(&mut reply_line).await?;

        if let Ok(reply) = serde_json::from_str::<SyncMessage>(&reply_line) {
            match reply {
                SyncMessage::Accept { action: _ } => {
                    log(&format!("{} accepted the sync. Pumping ciphertext blocks...", friend_nickname));

                    let mut file = tokio::fs::File::open(&physical_vault_path).await?;
                    let bytes_sent = tokio::io::copy(&mut file, &mut stream_io).await?;

                    stream_io.flush().await?;
                    let mut inner_stream = stream_io.into_inner();
                    inner_stream.shutdown().await?;

                    log(&format!("Blind file transfer complete. Pushed {} bytes.", bytes_sent));
                }
                SyncMessage::Reject => {
                    log(&format!("{} rejected the sync request.", friend_nickname));
                }
                _ => {
                    log(&format!("Received an invalid protocol response from {}.", friend_nickname));
                }
            }
        } else {
            log("Connection dropped or invalid data received during negotiation.");
        }

        log("Finalizing block commitment and gracefully closing circuit...");
        drop(control);
        // Clean exit sleep allows network buffers to drain
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}


pub fn handle_sync(
    vault_path: &str,
    friend_nickname: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Pass None to route logs directly to standard output
    sync_core(vault_path, friend_nickname, None)
}