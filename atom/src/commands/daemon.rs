use std::fs::{self, OpenOptions};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::commands::p2p_utils::{load_friends, parse_atom_uri};

/// Loads the standalone P2P Identity, or generates a new one if it doesn't exist.
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

    let config_json = serde_json::json!({ "storage": { "state_dir": state_dir.to_str().unwrap() } });
    let config = serde_json::from_value(config_json).unwrap_or(arti_client::TorClientConfig::builder()).build()?;

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        println!("🧅 Bootstrapping embedded Arti client...");
        let client = arti_client::TorClient::create_bootstrapped(config).await.expect("Tor bootstrap failed");

        let svc_config = tor_hsservice::config::OnionServiceConfigBuilder::default().nickname("atom_vault".parse()?).build()?;
        let (svc, mut stream_requests) = client.launch_onion_service(svc_config)?.unwrap();

        // Checksum generation & Tor v3 generation logic
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

        use futures::StreamExt;
        
        while let Some(rend_request) = stream_requests.next().await {
            println!("🔌 Incoming Tor circuit rendezvous request...");
            
            // Dynamically load friends right when the connection hits, so you don't need to restart 
            // the daemon if you add a friend in another terminal window!
            let friends = load_friends();
            let mut authorized_keys: Vec<VerifyingKey> = Vec::new();
            for f in &friends {
                if let Ok((_, key)) = parse_atom_uri(&f.url) {
                    authorized_keys.push(key);
                }
            }

            if let Ok(mut data_stream_requests) = rend_request.accept().await {
                if let Some(data_stream_req) = data_stream_requests.next().await {
                    if let Ok(arti_stream) = data_stream_req.accept(tor_cell::relaycell::msg::Connected::new_empty()).await {
                        
                        use tokio_util::compat::FuturesAsyncReadCompatExt;
                        let mut stream = arti_stream.compat();

                        match p2p_sync::handshake::execute_handshake(
                            &mut stream, 
                            false, 
                            &local_identity, 
                            &authorized_keys
                        ).await {
                            Ok(session) => {
                                // Match the successful key back to the nickname!
                                let connected_friend = friends.iter().find(|f| {
                                    parse_atom_uri(&f.url).map(|(_, k)| k == session.remote_static_key).unwrap_or(false)
                                });
                                
                                let nick = connected_friend.map(|f| f.nickname.as_str()).unwrap_or("Unknown Friend");
                                println!("🎉 {} is online! Handshake successful. Secure messaging channel established.", nick);
                                
                                // Spawn SyncManager here...
                                // let (control, inbound_rx) = p2p_sync::transport::start_multiplexer(stream, session.transport, false);
                                // ...
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
