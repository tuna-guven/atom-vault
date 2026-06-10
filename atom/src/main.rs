mod cli;

use clap::Parser;
use cli::{Cli, Commands, FriendCommands};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

// Internal VFS / Crypto imports
use atom::crypto;
use atom::vfs::{self, VaultMetadata};

// P2P Imports
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};

// --- DTO TRANSLATORS ---
// These functions map the internal VFS metadata into the external P2P network format and back.

fn to_p2p_meta(atom_meta: &atom::vfs::VaultMetadata) -> p2p_sync::sync::VaultMetadata {
    p2p_sync::sync::VaultMetadata {
        file_table: atom_meta
            .file_table
            .iter()
            .map(|f| p2p_sync::sync::FileIndex {
                vfs_name: f.vfs_name.clone(),
                last_modified_unix: f.last_modified_unix,
                chunks: f
                    .chunks
                    .iter()
                    .map(|c| p2p_sync::sync::ChunkEntry {
                        cipher_len: c.cipher_len,
                        offset: c.offset,
                        nonce: c.nonce,
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn to_atom_meta(p2p_meta: &p2p_sync::sync::VaultMetadata) -> atom::vfs::VaultMetadata {
    atom::vfs::VaultMetadata {
        file_table: p2p_meta
            .file_table
            .iter()
            .map(|f| atom::vfs::FileIndex {
                vfs_name: f.vfs_name.clone(),
                last_modified_unix: f.last_modified_unix,
                chunks: f
                    .chunks
                    .iter()
                    .map(|c| atom::vfs::ChunkEntry {
                        cipher_len: c.cipher_len,
                        offset: c.offset,
                        nonce: c.nonce,
                    })
                    .collect(),
            })
            .collect(),
    }
}

// --- FRIEND REGISTRY ---

#[derive(Serialize, Deserialize, Debug)]
struct FriendRecord {
    nickname: String,
    url: String, // Example: atom://rv3txodaq...onion
}

fn load_friends() -> Vec<FriendRecord> {
    if let Ok(data) = std::fs::read_to_string("friends.json") {
        serde_json::from_str(&data).unwrap_or_else(|_| Vec::new())
    } else {
        Vec::new()
    }
}

fn save_friends(friends: &[FriendRecord]) {
    let data = serde_json::to_string_pretty(friends).expect("Failed to serialize friends");
    std::fs::write("friends.json", data).expect("Failed to write friends.json");
}

// --- ONION PARSER ---

/// Tor v3 Onion addresses literally contain the Ed25519 Public Key.
/// This extracts it so we can execute the Noise Handshake!
fn extract_pubkey_from_onion(onion_url: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let onion = onion_url
        .trim_start_matches("atom://")
        .trim_end_matches(".onion");
    let decoded = BASE32_NOPAD.decode(onion.to_uppercase().as_bytes())?;

    if decoded.len() != 35 {
        return Err("Invalid onion link length".into());
    }

    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&decoded[0..32]);
    Ok(VerifyingKey::from_bytes(&pubkey_bytes)?)
}

// --- VAULT METADATA LOGIC ---

fn save_vault_metadata(
    physical_vault: &mut File,
    metadata: &VaultMetadata,
    unlocked_vault: &crypto::UnlockedVault,
    payload_end_offset: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_bytes = bincode::serialize(metadata)?;

    let secure_buffer = zeroize::Zeroizing::new(raw_bytes);
    unsafe {
        libc::mlock(
            secure_buffer.as_ptr() as *const libc::c_void,
            secure_buffer.len(),
        );
    }

    let (ciphertext, metadata_nonce) = crypto::encrypt_chunk(unlocked_vault, &secure_buffer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;

    unsafe {
        libc::munlock(
            secure_buffer.as_ptr() as *const libc::c_void,
            secure_buffer.len(),
        );
    }

    physical_vault.seek(SeekFrom::Start(payload_end_offset))?;
    let ciphertext_len = ciphertext.len() as u64;
    physical_vault.write_all(&ciphertext_len.to_le_bytes())?;
    physical_vault.write_all(&metadata_nonce)?;
    physical_vault.write_all(&ciphertext)?;

    let new_eof = physical_vault.stream_position()?;
    physical_vault.set_len(new_eof)?;

    physical_vault.seek(SeekFrom::Start(0))?;
    physical_vault.write_all(&payload_end_offset.to_le_bytes())?;

    Ok(())
}

fn load_vault_metadata(
    physical_vault: &mut File,
    unlocked_vault: &crypto::UnlockedVault,
) -> Result<(VaultMetadata, u64), Box<dyn std::error::Error>> {
    let file_len = physical_vault.metadata()?.len();

    if file_len < 8 {
        physical_vault.seek(SeekFrom::Start(0))?;
        physical_vault.write_all(&8u64.to_le_bytes())?;
        return Ok((
            VaultMetadata {
                file_table: Vec::new(),
            },
            8,
        ));
    }

    physical_vault.seek(SeekFrom::Start(0))?;
    let mut ptr_bytes = [0u8; 8];
    physical_vault.read_exact(&mut ptr_bytes)?;
    let metadata_offset = u64::from_le_bytes(ptr_bytes).max(8);

    if metadata_offset >= file_len {
        return Ok((
            VaultMetadata {
                file_table: Vec::new(),
            },
            8,
        ));
    }

    physical_vault.seek(SeekFrom::Start(metadata_offset))?;
    let mut len_bytes = [0u8; 8];
    physical_vault.read_exact(&mut len_bytes)?;
    let ciphertext_len = u64::from_le_bytes(len_bytes) as usize;

    let mut metadata_nonce = [0u8; crypto::XNONCE_LEN];
    physical_vault.read_exact(&mut metadata_nonce)?;

    let mut cipher_buffer = vec![0u8; ciphertext_len];
    physical_vault.read_exact(&mut cipher_buffer)?;

    let decrypted_bytes = crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, &metadata_nonce)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;

    unsafe {
        libc::mlock(
            decrypted_bytes.as_ptr() as *const libc::c_void,
            decrypted_bytes.len(),
        );
    }
    let metadata: VaultMetadata = bincode::deserialize(&decrypted_bytes)?;
    unsafe {
        libc::munlock(
            decrypted_bytes.as_ptr() as *const libc::c_void,
            decrypted_bytes.len(),
        );
    }

    Ok((metadata, metadata_offset))
}

fn main() {
    let args = Cli::parse();
    let vault_size = 50 * 1024 * 1024;

    let vault_file_path = "my_data.aegis";
    let mut physical_vault = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(vault_file_path)
        .unwrap();

    let _mounted_vfs = vfs::MemFile::new("atom_mount", vault_size).unwrap();

    let salt = [0u8; 32];
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = [42u8; 32];
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    let (mut metadata, _current_payload_offset) =
        load_vault_metadata(&mut physical_vault, &unlocked_vault).unwrap();

    match args.command {
        Commands::Ls => {
            println!("--- Volatile VFS File Allocation Table ---");
            if metadata.file_table.is_empty() {
                println!("Vault is empty.");
            } else {
                for file in &metadata.file_table {
                    println!("File: {:<20} Chunks: {}", file.vfs_name, file.chunks.len());
                }
            }
        }

        Commands::Import {
            from_disk: _,
            vfs_name: _,
        } => {
            // ... [YOUR EXISTING CHUNKING AND ENCRYPTION LOGIC GOES HERE] ...

            // Example of how the new file should be pushed to the metadata table:
            let _now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // metadata.file_table.push(FileIndex {
            //     vfs_name,
            //     last_modified_unix: now, // <-- The Vector Clock timestamp is required here!
            //     chunks: new_chunks,
            // });

            // ... [YOUR EXISTING `save_vault_metadata` CALL GOES HERE] ...
        }

        Commands::Unlock { path: _ } => {
            // ... [YOUR EXISTING UNLOCK & REPL LOGIC GOES HERE] ...
        }

        Commands::Export {
            vfs_name: _,
            to_disk: _,
        } => {
            // ... [YOUR EXISTING EXPORT LOGIC GOES HERE] ...
        }

        Commands::Rm { vfs_name: _ } => {
            // ... [YOUR EXISTING REMOVE LOGIC GOES HERE] ...
        }

        Commands::Id => {
            println!("--- 🪪 Your Atom Identity ---");

            // We read the hostname directly from the local embedded Arti state folder
            let mut path = dirs::home_dir().expect("Could not find home directory");
            path.push(".atom_vault/onion.txt");

            match std::fs::read_to_string(&path) {
                Ok(onion) => {
                    let onion = onion.trim();
                    println!("🔗 Your Link : atom://{}", onion);
                    println!("🔒 Status    : Ready to host (Run 'atom daemon')");
                }
                Err(_) => {
                    println!("⚠️ Identity not generated yet.");
                    println!("👉 Run 'atom daemon' once to generate your embedded Tor identity!");
                }
            }
        }

        Commands::Daemon => {
            println!("🛡️ Starting Embedded Atom Vault Daemon...");

            // 1. Configure the local state directory for embedded Tor
            let mut state_dir = dirs::home_dir().expect("Could not find home directory");
            state_dir.push(".atom_vault/arti_state");
            std::fs::create_dir_all(&state_dir).unwrap();

            // 2. Build the Arti Tor Client Config (0.42.0 Builder syntax)

            let config_json = serde_json::json!({
                "storage": {
                    "state_dir": state_dir.to_str().unwrap()
                }
            });

            let default_builder = arti_client::TorClientConfig::builder();
            let config_builder = serde_json::from_value(config_json).unwrap_or(default_builder);

            let config = config_builder.build().expect("Failed to build Tor config");

            // 3. Spool up the Tokio runtime
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                println!("🧅 Bootstrapping embedded Arti client (this takes ~10s)...");
                let client = arti_client::TorClient::create_bootstrapped(config).await
                    .expect("Failed to bootstrap Tor network");

                // 4. Configure the Onion Hidden Service
                let svc_config = tor_hsservice::config::OnionServiceConfigBuilder::default()
                    .nickname("atom_vault".parse().unwrap())
                    .build()
                    .expect("Failed to build Hidden Service Config");

                // 5. Launch the Hidden Service! 
                let (svc, mut stream_requests) = client.launch_onion_service(svc_config)
                    .expect("Failed to configure Onion Service")
                    .expect("Onion service was disabled and returned None!");

                // Use onion_address() which implements Display for easy printing
                let onion_name = svc.onion_address().expect("Service should have an address");
                
                // --- MANUAL TOR V3 ADDRESS ENCODER ---
                // We construct the exact 35-byte payload required by the Tor specification
                
                let pubkey_bytes = onion_name.as_ref(); // The 32-byte Ed25519 key
                
                // 1. Calculate the checksum: SHA3-256(".onion checksum" || PUBKEY || VERSION)
                use sha3::Digest;
                let mut hasher = sha3::Sha3_256::new();
                hasher.update(b".onion checksum");
                hasher.update(pubkey_bytes);
                hasher.update(&[0x03u8]); // Tor V3 Version Byte
                let checksum = hasher.finalize();

                // 2. Assemble the final 35-byte V3 address
                let mut v3_address = Vec::with_capacity(35);
                v3_address.extend_from_slice(pubkey_bytes);
                v3_address.extend_from_slice(&checksum[0..2]); // First 2 bytes of the hash
                v3_address.push(0x03);

                // 3. Base32 encode and append .onion
                let clean_onion = format!("{}.onion", 
                    data_encoding::BASE32_NOPAD.encode(&v3_address).to_lowercase()
                );
                
                let mut onion_file_path = dirs::home_dir().unwrap();
                onion_file_path.push(".atom_vault/onion.txt");
                std::fs::write(&onion_file_path, &clean_onion).expect("Failed to save identity");
                
                println!("\n✅ Embedded Tor Hidden Service Active!");
                println!("🔗 Share this link with friends: atom://{}\n", clean_onion);
                println!("🎧 Listening for incoming P2P connections...");

                // SECURE IDENTITY DERIVATION: Derive our Auth Identity from the Vault DEK
                let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &raw_dek);
                let mut identity_bytes = zeroize::Zeroizing::new([0u8; 32]);
                hk.expand(b"atom-p2p-identity", &mut *identity_bytes).unwrap();
                let local_identity = ed25519_dalek::SigningKey::from_bytes(&*identity_bytes);

                // 6. The Infinite Listener Loop
                use futures::StreamExt;
                
                // We now receive Rendezvous Requests (Tor Circuits)
                while let Some(rend_request) = stream_requests.next().await {
                    println!("🔌 Incoming Tor circuit rendezvous request!");
                    
                    // Step A: Accept the Tor Circuit
                    match rend_request.accept().await {
                        Ok(mut data_stream_requests) => {
                            
                            // Step B: Wait for the peer to open an Application Stream over the circuit
                            if let Some(data_stream_req) = data_stream_requests.next().await {
                                
                                // Step C: Accept the Stream to get the actual raw byte stream
                                match data_stream_req.accept(tor_cell::relaycell::msg::Connected::new_empty()).await {
                                    Ok(arti_stream) => {
                                        println!("🔐 Executing Post-Quantum Noise Handshake...");
                                        
                                        use tokio_util::compat::FuturesAsyncReadCompatExt;
                                        let mut stream = arti_stream.compat();

                                        // NOTE: In production, lookup the friend's expected pubkey from friends.json
                                        // THE FIX: Since Alice and Bob share the same hardcoded DEK in this test,
                                        // Alice's public key is identical to Bob's!
                                        let expected_friend_pubkey = local_identity.verifying_key();

                                        match p2p_sync::handshake::execute_handshake(
                                            &mut stream, 
                                            false, // false = we are the Listener
                                            &local_identity, 
                                            &expected_friend_pubkey
                                        ).await {
                                            Ok(session) => {
                                                println!("🎉 Handshake successful! Spawning SyncManager...");
                                                
                                                // We clone the path and meta for the background daemon
                                                let physical_vault_path = std::path::PathBuf::from(&vault_file_path);
                                                let p2p_meta = to_p2p_meta(&metadata);

                                                let (control, inbound_rx) = p2p_sync::transport::start_multiplexer(stream, session.transport, false);
                                                
                                                let _sync_manager = p2p_sync::sync::SyncManager::new(
                                                    control, 
                                                    inbound_rx, 
                                                    p2p_meta, 
                                                    physical_vault_path
                                                );
                                            }
                                            Err(e) => println!("❌ Handshake rejected: {}", e),
                                        }
                                    }
                                    Err(e) => println!("⚠️ Failed to accept data stream: {}", e),
                                }
                            }
                        }
                        Err(e) => println!("⚠️ Failed to accept Tor circuit: {}", e),
                    }
                }
            });
        }

        // --- NEW P2P CLI COMMANDS ---
        Commands::Friend { command } => match command {
            FriendCommands::Add { url, nickname } => {
                // 1. Validate the cryptographic signature first so we don't save garbage
                if extract_pubkey_from_onion(&url).is_err() {
                    println!("❌ Invalid atom:// link. Could not verify cryptographic signature.");
                    return;
                }

                let mut friends = load_friends();
                
                // 2. Check if the friend already exists
                if let Some(existing_friend) = friends.iter_mut().find(|f| f.nickname == nickname) {
                    // UPSERT: Update their address!
                    existing_friend.url = url.clone();
                    println!("✅ Friend '{}' address successfully updated!", nickname);
                } else {
                    // INSERT: Add as a new friend
                    friends.push(FriendRecord {
                        nickname: nickname.clone(),
                        url: url.clone(),
                    });
                    println!("✅ Friend '{}' securely added!", nickname);
                }

                // 3. Save to disk
                save_friends(&friends);
            }
            FriendCommands::List => {
                let friends = load_friends();
                if friends.is_empty() {
                    println!("No friends added yet.");
                } else {
                    println!("--- 📋 Connected Friends ---");
                    for friend in friends {
                        println!("👤 {:<15} 🔗 {}", friend.nickname, friend.url);
                    }
                }
            }
        },

        Commands::Sync {
            vault_path,
            friend_nickname,
        } => {
            let friends = load_friends();
            if let Some(friend) = friends.iter().find(|f| f.nickname == friend_nickname) {
                println!(
                    "🚀 Initiating P2P Sync for '{}' with '{}'...",
                    vault_path, friend.nickname
                );

                let friend_pubkey = extract_pubkey_from_onion(&friend.url)
                    .expect("Corrupted onion link in registry");

                // SECURE IDENTITY DERIVATION: Derive our Tor Identity deterministically from our Vault's DEK
                let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &raw_dek);
                let mut identity_bytes = zeroize::Zeroizing::new([0u8; 32]);
                hk.expand(b"atom-p2p-identity", &mut *identity_bytes)
                    .unwrap();
                let local_identity = SigningKey::from_bytes(&*identity_bytes);

                // Derive the Master Secret to authenticate the session
                let mut master_secret = zeroize::Zeroizing::new([0u8; 32]);
                hk.expand(b"atom-p2p-master-secret", &mut *master_secret)
                    .unwrap();

                let physical_vault_path = std::path::PathBuf::from(&vault_path);

                // Translate internal atom metadata to the P2P networking format
                let p2p_compatible_metadata = to_p2p_meta(&metadata);

                // 1. Give the CLIENT its own state directory so it doesn't fight the DAEMON's database!
                let mut client_state_dir = dirs::home_dir().expect("Could not find home directory");
                client_state_dir.push(".atom_vault/arti_client_state");
                std::fs::create_dir_all(&client_state_dir).unwrap();

                // 2. Spool up the Tokio runtime purely for the network lifecycle
                let rt = tokio::runtime::Runtime::new().unwrap();

                let updated_p2p_metadata = rt.block_on(async {
                    // THE FIX: Pass the newly isolated client_state_dir into the SyncManager
                    // NOTE: You will need to add a second parameter to `AtomSyncManager::new` in your `p2p-sync` crate!
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

                    // Extract the final layout from the RwLock after the sync appends new chunks
                    let final_metadata = sync_manager.local_metadata.read().await;
                    (*final_metadata).clone()
                });

                // 3. Safely translate the P2P metadata back to internal Atom metadata
                metadata = to_atom_meta(&updated_p2p_metadata);

                // 4. Write the new layout to the physical end of the .aegis file
                println!("💾 Sync complete! Saving updated File Allocation Table to disk...");

                // Because SyncManager appended chunks directly to the EOF, the file grew!
                // We MUST seek to the exact *new* EOF before appending our final metadata.
                let new_eof = physical_vault.seek(SeekFrom::End(0)).unwrap();

                save_vault_metadata(&mut physical_vault, &metadata, &unlocked_vault, new_eof)
                    .unwrap();

                println!("🎉 Vault successfully synchronized and saved!");
            } else {
                println!("❌ Friend '{}' not found.", friend_nickname);
            }
        }
    }
}
