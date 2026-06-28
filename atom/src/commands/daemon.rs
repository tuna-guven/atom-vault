use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_stream::wrappers::ReceiverStream;
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::commands::p2p_utils::{load_friends, parse_atom_uri, save_friends, SharedVault, SyncMessage};

// CROSS-THREAD COMMUNICATION FOR GUI & CLI
pub enum DaemonEvent {
    SyncRequest {
        sender_nick: String,
        filename: String,
        response_channel: tokio::sync::oneshot::Sender<SyncResponse>,
    },
    Log(String),
}

pub struct SyncResponse {
    pub accepted: bool,
    pub label: Option<String>,
    pub save_path: Option<String>,
}

static EVENT_TX: Mutex<Option<tokio::sync::mpsc::Sender<DaemonEvent>>> = Mutex::new(None);

pub fn set_event_sender(tx: tokio::sync::mpsc::Sender<DaemonEvent>) {
    let mut global_tx = EVENT_TX.lock().unwrap();
    *global_tx = Some(tx);
}

// HELPER: Routes daemon logs to the GUI channel if attached, otherwise uses terminal stdout.
pub fn send_daemon_log(msg: &str) {
    let tx_opt = EVENT_TX.lock().unwrap().clone();
    if let Some(tx) = tx_opt {
        let _ = tx.try_send(DaemonEvent::Log(msg.to_string()));
    } else {
        println!("{}", msg);
    }
}

async fn ask_user_interactive(
    sender_nick: String,
    filename: String,
) -> SyncResponse {
    let tx_opt = {
        let lock = EVENT_TX.lock().unwrap();
        lock.clone()
    };

    if let Some(tx) = tx_opt {
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(DaemonEvent::SyncRequest {
            sender_nick,
            filename,
            response_channel: resp_tx,
        }).await;

        match resp_rx.await {
            Ok(response) => response,
            Err(_) => SyncResponse { accepted: false, label: None, save_path: None },
        }
    } else {
        // FALLBACK: Blocking CLI Mode
        tokio::task::spawn_blocking(move || {
            use std::io::{self, Write};
            
            print!("{} wants to sync {} with you. Accept? [Y/n]: ", sender_nick, filename);
            io::stdout().flush().unwrap_or_default();
            let mut ans = String::new();
            io::stdin().read_line(&mut ans).unwrap_or_default();
            
            if ans.trim().to_lowercase() == "y" || ans.trim().is_empty() {
                print!("Label for this vault?: ");
                io::stdout().flush().unwrap_or_default();
                let mut label = String::new();
                io::stdin().read_line(&mut label).unwrap_or_default();
                
                let mut default_path = dirs::home_dir().unwrap_or_default();
                default_path.push(format!("Downloads/{}/{}", sender_nick, filename));
                
                print!("Folder path? [{}]: ", default_path.display());
                io::stdout().flush().unwrap_or_default();
                let mut path_ans = String::new();
                io::stdin().read_line(&mut path_ans).unwrap_or_default();
                
                let final_path = if path_ans.trim().is_empty() {
                    default_path.to_string_lossy().to_string()
                } else {
                    path_ans.trim().to_string()
                };

                SyncResponse {
                    accepted: true,
                    label: Some(label.trim().to_string()),
                    save_path: Some(final_path),
                }
            } else {
                SyncResponse { accepted: false, label: None, save_path: None }
            }
        })
        .await
        .unwrap_or(SyncResponse { accepted: false, label: None, save_path: None })
    }
}

pub fn get_or_create_identity() -> Result<SigningKey, Box<dyn std::error::Error>> {
    let mut path = dirs::home_dir().ok_or("Could not find home directory")?;
    path.push(".atom_vault");
    fs::create_dir_all(&path)?;
    path.push("identity.key");

    if path.exists() {
        let raw = fs::read(&path)?;
        let bytes = crate::config_crypto::decrypt_config(&raw)?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&key));
        }
    }

    let mut new_key = [0u8; 32];
    OsRng.fill_bytes(&mut new_key);
    let encrypted = crate::config_crypto::encrypt_config(&new_key);

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let mut f = opts.open(&path)?;
    use std::io::Write;
    f.write_all(&encrypted)?;

    Ok(SigningKey::from_bytes(&new_key))
}

pub fn handle_daemon() -> Result<(), Box<dyn std::error::Error>> {
    send_daemon_log("Starting Secure Standalone P2P Daemon...");

    let local_identity = get_or_create_identity()?;

    let mut state_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    state_dir.push(".atom_vault/arti_state");
    fs::create_dir_all(&state_dir)?;

    #[cfg(unix)]
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;

    let mut cache_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    cache_dir.push(".atom_vault/arti_cache");
    fs::create_dir_all(&cache_dir)?;

    let mut builder = arti_client::TorClientConfig::builder();
    builder.storage().state_dir(arti_client::config::CfgPath::new_literal(state_dir));
    builder.storage().cache_dir(arti_client::config::CfgPath::new_literal(cache_dir));
    let config = builder.build()?;

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        send_daemon_log("Bootstrapping embedded Arti client...");
        let client = match arti_client::TorClient::create_bootstrapped(config).await {
            Ok(c) => c,
            Err(e) => {
                send_daemon_log(&format!("[Daemon] Tor bootstrap failed: {}", e));
                return Ok(());
            }
        };

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

        let mut onion_file_path = dirs::home_dir().unwrap_or_default();
        onion_file_path.push(".atom_vault/onion.txt");
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        if let Ok(mut f) = opts.open(&onion_file_path) {
            use std::io::Write;
            let encrypted_link = crate::config_crypto::encrypt_config(final_link.as_bytes());
            let _ = f.write_all(&encrypted_link);
        }

        send_daemon_log("Daemon is online!");
        send_daemon_log(&format!("Your Identity: {}", final_link));
        send_daemon_log("Listening for incoming mutual friends...");

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
                                send_daemon_log(&format!("{} is online! Secure messaging channel established.", nick));

                                let (control, inbound_rx) = p2p_sync::transport::start_multiplexer(stream, session.transport, false);
                                let mut inbound_stream = ReceiverStream::new(inbound_rx);

                                tokio::spawn(async move {
                                    let _keep_alive = control;

                                    if let Some(data_stream) = tokio_stream::StreamExt::next(&mut inbound_stream).await {
                                        use tokio_util::compat::FuturesAsyncReadCompatExt;
                                        let data_stream = data_stream.compat();
                                        
                                        let mut stream_io = tokio::io::BufReader::new(data_stream);
                                        let mut line = String::new();

                                        if let Ok(_) = stream_io.read_line(&mut line).await {
                                            if let Ok(msg) = serde_json::from_str::<SyncMessage>(&line) {
                                                if let SyncMessage::Proposal { filename, last_modified } = msg {
                                                    send_daemon_log(&format!("Received sync proposal for '{}' from {}", filename, nick));

                                                    let mut friends_db = load_friends();
                                                    let mut is_new = true;
                                                    let mut local_save_path = String::new();

                                                    if let Some(friend) = friends_db.iter_mut().find(|f| f.nickname == nick) {
                                                        if let Some(vault) = friend.shared_vaults.iter_mut().find(|v| v.original_name == filename) {
                                                            is_new = false;
                                                            local_save_path = vault.local_path.clone();
                                                            vault.last_modified = last_modified;
                                                        }
                                                    }

                                                    let mut accepted = false;

                                                    if is_new {
                                                        let user_response = ask_user_interactive(nick.clone(), filename.clone()).await;
                                                        
                                                        if user_response.accepted {
                                                            local_save_path = user_response.save_path.unwrap_or_default();
                                                            accepted = true;

                                                            if let Some(friend) = friends_db.iter_mut().find(|f| f.nickname == nick) {
                                                                friend.shared_vaults.push(SharedVault {
                                                                    original_name: filename.clone(),
                                                                    label: user_response.label.unwrap_or_else(|| "Synced Vault".to_string()),
                                                                    local_path: local_save_path.clone(),
                                                                    last_modified,
                                                                });
                                                            }
                                                            save_friends(&friends_db);
                                                        }
                                                    } else {
                                                        accepted = true;
                                                    }

                                                    if accepted && !local_save_path.is_empty() {
                                                        let reply = SyncMessage::Accept { action: "pull_from_you".to_string() };
                                                        let reply_json = format!("{}\n", serde_json::to_string(&reply).unwrap_or_default());
                                                        
                                                        // Ağ yazma hatalarını güvenli şekilde yakala
                                                        if let Err(e) = stream_io.write_all(reply_json.as_bytes()).await {
                                                            send_daemon_log(&format!("Failed to send Accept response: {}", e));
                                                            return;
                                                        }
                                                        let _ = stream_io.flush().await;

                                                        let path = PathBuf::from(&local_save_path);
                                                        if let Some(parent) = path.parent() {
                                                            let _ = fs::create_dir_all(parent);
                                                        }

                                                        // Dosya oluşturma hatasını güvenli şekilde yakala
                                                        match tokio::fs::File::create(&local_save_path).await {
                                                            Ok(mut file) => {
                                                                send_daemon_log(&format!("Receiving encrypted payload into {}...", local_save_path));
                                                                match tokio::io::copy(&mut stream_io, &mut file).await {
                                                                    Ok(bytes) => send_daemon_log(&format!("Success! {} bytes written to disk.", bytes)),
                                                                    Err(e) => send_daemon_log(&format!("Transfer failed: {}", e)),
                                                                }
                                                            }
                                                            Err(e) => {
                                                                send_daemon_log(&format!("File System Error: Cannot write to path ({}).", e));
                                                            }
                                                        }
                                                    } else {
                                                        let reply = SyncMessage::Reject;
                                                        let reply_json = format!("{}\n", serde_json::to_string(&reply).unwrap_or_default());
                                                        let _ = stream_io.write_all(reply_json.as_bytes()).await;
                                                        let _ = stream_io.flush().await;
                                                        send_daemon_log("Rejected sync proposal.");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => send_daemon_log(&format!("Handshake rejected: {}", e)),
                        }
                    }
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}