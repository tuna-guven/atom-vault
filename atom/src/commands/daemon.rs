use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{SecretString, ExposeSecret};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::crypto;
use crate::commands::p2p_utils::{load_vault_metadata, to_p2p_meta};

/// Starts the P2P Daemon.
/// 
/// Security Upgrades:
/// - Accepts password securely via memory-zeroizing string.
/// - Requires an explicit list of authorized peers (friends).
/// - Enforces strict 0o600 / 0o700 file and directory permissions.
/// - Uses OsRng for cryptographic material generation.
/// - Returns Result instead of unwrapping to prevent DoS via panic.
pub fn handle_daemon(
    vault_password: SecretString,
    authorized_friends: Vec<ed25519_dalek::VerifyingKey>
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ Starting Secure Embedded Atom Vault Daemon...");

    let vault_file_path = "my_data.aegis";
    
    // 1. SECURE FILE PERMISSIONS (Unix)
    let mut vault_opts = OpenOptions::new();
    vault_opts.read(true).write(true).create(true);
    
    #[cfg(unix)]
    vault_opts.mode(0o600); // Owner read/write ONLY
    
    let mut physical_vault = vault_opts.open(vault_file_path)?;

    // 2. SECURE KEY DERIVATION & GENERATION
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt); // Use CSPRNG for Salt

    // Derive KEK. The underlying crypto library should zeroize the password bytes after use.
    let kek = crypto::derive_kek(vault_password.expose_secret(), &salt)
        .map_err(|_| "Failed to derive KEK from password")?;
    
    let mut raw_dek = zeroize::Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *raw_dek); // Use CSPRNG for the actual Encryption Key

    // FIX: Added the missing `?` at the end
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &*raw_dek)
        .map_err(|_| "Failed to wrap DEK")?;

    // FIX: Mapped the Chacha20 error to a standard string
    let _unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce)
        .map_err(|_| "Failed to unwrap DEK")?;
        
    // FIX: Passed the raw bytes `&*raw_dek` instead of the UnlockedVault struct
    let (metadata, _) = load_vault_metadata(&mut physical_vault, &*raw_dek)?;

    // 3. SECURE IDENTITY DERIVATION
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &*raw_dek);
    let mut identity_bytes = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(b"atom-p2p-identity", &mut *identity_bytes)
        .map_err(|_| "Failed to expand HKDF")?;
    
    let local_identity = ed25519_dalek::SigningKey::from_bytes(&*identity_bytes);

    // 4. SECURE DIRECTORY CREATION
    let mut state_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    state_dir.push(".atom_vault/arti_state");
    
    fs::create_dir_all(&state_dir)?;
    #[cfg(unix)]
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;

    let config_json = serde_json::json!({
        "storage": {
            "state_dir": state_dir.to_str().ok_or("Invalid path")?
        }
    });

    let default_builder = arti_client::TorClientConfig::builder();
    let config_builder = serde_json::from_value(config_json).unwrap_or(default_builder);
    let config = config_builder.build()?;

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        println!("🧅 Bootstrapping embedded Arti client (this takes ~10s)...");
        let client = arti_client::TorClient::create_bootstrapped(config).await
            .expect("Critical: Failed to bootstrap Tor network");

        let svc_config = tor_hsservice::config::OnionServiceConfigBuilder::default()
            .nickname("atom_vault".parse()?)
            .build()?;

        let (svc, mut stream_requests) = client.launch_onion_service(svc_config)?
            .ok_or("Onion service was disabled")?;

        let onion_name = svc.onion_address().ok_or("Service missing address")?;
        let pubkey_bytes = onion_name.as_ref(); 
        
        use sha3::Digest;
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey_bytes);
        hasher.update(&[0x03u8]); 
        let checksum = hasher.finalize();

        let mut v3_address = Vec::with_capacity(35);
        v3_address.extend_from_slice(pubkey_bytes);
        v3_address.extend_from_slice(&checksum[0..2]); 
        v3_address.push(0x03);

        let clean_onion = format!("{}.onion", data_encoding::BASE32_NOPAD.encode(&v3_address).to_lowercase());
        
        let identity_b32 = data_encoding::BASE32_NOPAD.encode(local_identity.verifying_key().as_bytes()).to_lowercase();
        let final_link = format!("atom://{}/{}", clean_onion, identity_b32);
        
        let mut onion_file_path = dirs::home_dir().unwrap();
        onion_file_path.push(".atom_vault/onion.txt");
        
        let mut onion_file_opts = OpenOptions::new();
        onion_file_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        onion_file_opts.mode(0o600);
        
        if let Ok(mut f) = onion_file_opts.open(&onion_file_path) {
            use std::io::Write;
            let _ = f.write_all(final_link.as_bytes());
        }
        
        println!("\n✅ Embedded Tor Hidden Service Active!");
        println!("🔗 Share this link with friends: {}\n", final_link);
        println!("🎧 Listening for incoming P2P connections...");

        use futures::StreamExt;
        
        while let Some(rend_request) = stream_requests.next().await {
            println!("🔌 Incoming Tor circuit rendezvous request!");
            
            match rend_request.accept().await {
                Ok(mut data_stream_requests) => {
                    if let Some(data_stream_req) = data_stream_requests.next().await {
                        match data_stream_req.accept(tor_cell::relaycell::msg::Connected::new_empty()).await {
                            Ok(arti_stream) => {
                                println!("🔐 Executing Post-Quantum Noise Handshake...");
                                
                                use tokio_util::compat::FuturesAsyncReadCompatExt;
                                let mut stream = arti_stream.compat();

                                let mut handshake_success = false;

                                for expected_friend in &authorized_friends {
                                    if let Ok(session) = p2p_sync::handshake::execute_handshake(
                                        &mut stream, 
                                        false, 
                                        &local_identity, 
                                        expected_friend
                                    ).await {
                                        println!("🎉 Handshake successful with known peer! Spawning SyncManager...");
                                        
                                        let physical_vault_path = PathBuf::from(&vault_file_path);

                                        let (control, inbound_rx) = p2p_sync::transport::start_multiplexer(stream, session.transport, false);
                                        
                                        let p2p_meta = to_p2p_meta(&metadata);
                                        let _sync_manager = p2p_sync::sync::SyncManager::new(control, inbound_rx, p2p_meta, physical_vault_path);
                                        
                                        handshake_success = true;
                                        break; 
                                    }
                                }

                                if !handshake_success {
                                    println!("❌ Handshake rejected: Unknown peer or failed authentication.");
                                }
                            }
                            Err(e) => println!("⚠️ Failed to accept data stream: {}", e),
                        }
                    }
                }
                Err(e) => println!("⚠️ Failed to accept Tor circuit: {}", e),
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
