use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_stream::wrappers::ReceiverStream;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::commands::p2p_utils::{load_friends, parse_atom_uri, save_friends, SharedVault, SyncMessage};

/// Asynchronously prompts the user in the terminal using a blocking thread
/// so the main Tokio Tor event loop is never paused.
async fn ask_user(prompt: String) -> String {
    tokio::task::spawn_blocking(move || {
        use std::io::{self, Write};
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).unwrap();
        buf.trim().to_string()
    })
    .await
    .unwrap()
}

pub fn get_or_create_identity() -> Result<SigningKey, Box<dyn std::error::Error>> {
    let mut path = dirs::home_dir().ok_or("Could not find home directory")?;
    path.push(".atom_vault");
    fs::create_dir_all(&path)?;
    path.push("identity.key");

    if path.exists() {
        let bytes = fs::read(&path)?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&key));
        }
    }

    let mut new_key = [0u8; 32];
    OsRng.fill_bytes(&mut new_key);

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let mut f = opts.open(&path)?;
    use std::io::Write;
    f.write_all(&new_key)?;

    Ok(SigningKey::from_bytes(&new_key))
}

pub fn handle_daemon() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ Starting Secure Standalone P2P Daemon...");

    let local_identity = get_or_create_identity()?;

    let mut state_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    state_dir.push(".atom_vault/arti_state");
    fs::create_dir_all(&state_dir)?;

    #[cfg(unix)]
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;

    let config_json =
        serde_json::json!({ "storage": { "state_dir": state_dir.to_str().unwrap() } });
    let config = serde_json::from_value(config_json)
        .unwrap_or(arti_client::TorClientConfig::builder())
        .build()?;

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        println!("🧅 Bootstrapping embedded Arti client...");
        let client = arti_client::TorClient::create_bootstrapped(config)
            .await
            .expect("Tor bootstrap failed");

        let svc_config = tor_hsservice::config::OnionServiceConfigBuilder::default()
            .nickname("atom_vault".parse()?)
            .build()?;
        let (svc, mut stream_requests) = client.launch_onion_service(svc_config)?.unwrap();

        let onion_addr = svc.onion_address().unwrap();
        let pubkey_bytes = onion_addr.as_ref();
        use sha3::Digest;
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey_bytes);
        hasher.update(&[0x03u8]);

        let mut v3_address = Vec::with_capacity(35);
        v3_address.extend_from_slice(pubkey_bytes);
        v3_address.extend_from_slice(&hasher.finalize()[0..2]);
        v3_address.push(0x03);

        let clean_onion = format!("{}.onion", data_encoding::BASE32_NOPAD.encode(&v3_address).to_lowercase());
        let identity_b32 = data_encoding::BASE32_NOPAD.encode(local_identity.verifying_key().as_bytes()).to_lowercase();
        let final_link = format!("atom://{}/{}", clean_onion, identity_b32);

        let mut onion_file_path = dirs::home_dir().unwrap();
        onion_file_path.push(".atom_vault/onion.txt");
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        if let Ok(mut f) = opts.open(&onion_file_path) {
            use std::io::Write;
            let _ = f.write_all(final_link.as_bytes());
        }

        println!("\n✅ Daemon is online!");
        println!("🔗 Your Identity: {}\n", final_link);
        println!("🎧 Listening for incoming mutual friends...");

        while let Some(rend_request) = futures::StreamExt::next(&mut stream_requests).await {
            let friends = load_friends();
            let mut authorized_keys: Vec<VerifyingKey> = Vec::new();
            for f in &friends {
                if let Ok((_, key)) = parse_atom_uri(&f.url) {
                    authorized_keys.push(key);
                }
            }

            if let Ok(mut data_stream_requests) = rend_request.accept().await {
                if let Some(data_stream_req) = futures::StreamExt::next(&mut data_stream_requests).await {
                    if let Ok(arti_stream) = data_stream_req
                        .accept(tor_cell::relaycell::msg::Connected::new_empty())
                        .await
                    {
                        use tokio_util::compat::FuturesAsyncReadCompatExt;
                        let mut stream = arti_stream.compat();

                        match p2p_sync::handshake::execute_handshake(&mut stream, false, &local_identity, &authorized_keys).await {
                            Ok(session) => {
                                let connected_friend = friends.iter().find(|f| {
                                    parse_atom_uri(&f.url).map(|(_, k)| k == session.remote_static_key).unwrap_or(false)
                                });

                                let nick = connected_friend.map(|f| f.nickname.clone()).unwrap_or_else(|| "Unknown".to_string());
                                println!("🎉 {} is online! Secure messaging channel established.", nick);

                                let (control, inbound_rx) = p2p_sync::transport::start_multiplexer(stream, session.transport, false);
                                let mut inbound_stream = ReceiverStream::new(inbound_rx);

                                tokio::spawn(async move {
                                    let _keep_alive = control;

                                    if let Some(data_stream) = tokio_stream::StreamExt::next(&mut inbound_stream).await {
                                        use tokio_util::compat::FuturesAsyncReadCompatExt;
                                        let data_stream = data_stream.compat();
                                        
                                        // Wrap the stream in a buffered reader to intercept the JSON line
                                        let mut stream_io = tokio::io::BufReader::new(data_stream);
                                        let mut line = String::new();

                                        if let Ok(_) = stream_io.read_line(&mut line).await {
                                            if let Ok(msg) = serde_json::from_str::<SyncMessage>(&line) {
                                                if let SyncMessage::Proposal { filename, last_modified } = msg {
                                                    println!("📥 Received sync proposal for '{}' from {}", filename, nick);

                                                    let mut friends_db = load_friends();
                                                    let mut is_new = true;
                                                    let mut local_save_path = String::new();

                                                    // Check if we already know this vault
                                                    if let Some(friend) = friends_db.iter_mut().find(|f| f.nickname == nick) {
                                                        if let Some(vault) = friend.shared_vaults.iter_mut().find(|v| v.original_name == filename) {
                                                            is_new = false;
                                                            local_save_path = vault.local_path.clone();
                                                            vault.last_modified = last_modified;
                                                        }
                                                    }

                                                    let mut accepted = false;

                                                    // Request Consent and Metadata Configuration
                                                    if is_new {
                                                        let prompt = format!("{} wants to sync {} with you. Do you accept? [Y/n]: ", nick, filename);
                                                        let ans = ask_user(prompt).await;
                                                        
                                                        if ans.to_lowercase() == "y" || ans.is_empty() {
                                                            let label = ask_user("What is the label for this vault?: ".to_string()).await;

                                                            let mut default_path = dirs::home_dir().unwrap();
                                                            default_path.push(format!("Downloads/{}/{}", nick, filename));
                                                            
                                                            let path_prompt = format!("What is the folder path for the vault? [{}]: ", default_path.display());
                                                            let mut path_ans = ask_user(path_prompt).await;

                                                            if path_ans.is_empty() {
                                                                path_ans = default_path.to_string_lossy().to_string();
                                                            }

                                                            local_save_path = path_ans.clone();
                                                            accepted = true;

                                                            // Save new vault into the address book
                                                            if let Some(friend) = friends_db.iter_mut().find(|f| f.nickname == nick) {
                                                                friend.shared_vaults.push(SharedVault {
                                                                    original_name: filename.clone(),
                                                                    label,
                                                                    local_path: local_save_path.clone(),
                                                                    last_modified,
                                                                });
                                                            }
                                                            save_friends(&friends_db);
                                                        }
                                                    } else {
                                                        // Automatically accept known synchronized folders
                                                        accepted = true;
                                                    }

                                                    // Execute Data Pipeline
                                                    if accepted {
                                                        let reply = SyncMessage::Accept { action: "pull_from_you".to_string() };
                                                        let reply_json = format!("{}\n", serde_json::to_string(&reply).unwrap());
                                                        stream_io.write_all(reply_json.as_bytes()).await.unwrap();
                                                        stream_io.flush().await.unwrap();

                                                        let path = PathBuf::from(&local_save_path);
                                                        if let Some(parent) = path.parent() {
                                                            fs::create_dir_all(parent).unwrap_or_default();
                                                        }

                                                        let mut file = tokio::fs::File::create(&local_save_path).await.unwrap();
                                                        println!("⏳ Receiving encrypted payload into {}...", local_save_path);
                                                        
                                                        match tokio::io::copy(&mut stream_io, &mut file).await {
                                                            Ok(bytes) => println!("📥 Success! {} bytes written to disk.", bytes),
                                                            Err(e) => println!("❌ Transfer failed: {}", e),
                                                        }
                                                    } else {
                                                        let reply = SyncMessage::Reject;
                                                        let reply_json = format!("{}\n", serde_json::to_string(&reply).unwrap());
                                                        stream_io.write_all(reply_json.as_bytes()).await.unwrap();
                                                        stream_io.flush().await.unwrap();
                                                        println!("❌ Rejected sync proposal.");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => println!("❌ Handshake rejected: {}", e),
                        }
                    }
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
