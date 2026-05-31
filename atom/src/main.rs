mod cli;

use clap::Parser;
use cli::{Cli, Commands, FriendCommands};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

// Prevent split-brain compilation issues by importing directly from the library crate
use atom::chunker;
use atom::crypto;
use atom::vfs::{self, ChunkEntry, FileIndex, VaultMetadata};

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

// --- VAULT METADATA LOGIC ---

fn save_vault_metadata(
    physical_vault: &mut File,
    metadata: &VaultMetadata,
    unlocked_vault: &crypto::UnlockedVault,
    payload_end_offset: u64, // Boundary where file chunks end and tail metadata begins
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
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Crypto error: {:?}", e),
            )
        })?;

    unsafe {
        libc::munlock(
            secure_buffer.as_ptr() as *const libc::c_void,
            secure_buffer.len(),
        );
    }

    // 1. Append encrypted metadata payload right at the end of the existing payload data area
    physical_vault.seek(SeekFrom::Start(payload_end_offset))?;
    let ciphertext_len = ciphertext.len() as u64;
    physical_vault.write_all(&ciphertext_len.to_le_bytes())?;
    physical_vault.write_all(&metadata_nonce)?;
    physical_vault.write_all(&ciphertext)?;

    // 2. Truncate trailing garbage if the new metadata payload is smaller than the old record
    let new_eof = physical_vault.stream_position()?;
    physical_vault.set_len(new_eof)?;

    // 3. Update the 8-byte master file pointer at offset 0 to point to this new tail metadata position
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
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Metadata error: {:?}", e),
            )
        })?;

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

    let mut physical_vault = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("my_data.aegis")
        .unwrap();

    let mut mounted_vfs = vfs::MemFile::new("atom_mount", vault_size).unwrap();

    let salt = [0u8; 32];
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = [42u8; 32];
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    let (mut metadata, mut current_payload_offset) =
        load_vault_metadata(&mut physical_vault, &unlocked_vault).unwrap();

    match args.command {
        Commands::Id => {
            println!("--- 🪪 Your Atom Identity ---");

            // In a production app, this path would be relative to the user's config directory
            // (e.g., ~/.config/atom-vault/hidden_service/hostname)
            let hostname_path = "/tmp/tor_hidden_service/hostname";

            match std::fs::read_to_string(hostname_path) {
                Ok(onion) => {
                    let onion = onion.trim();
                    println!("🔗 Your Link : atom://{}", onion);
                    println!("🔒 Status    : Tor Hidden Service Active");
                    println!("\nShare your link securely with friends so they can add your vault!");
                }
                Err(_) => {
                    println!("⚠️ Could not locate your Tor Hidden Service address.");
                    println!(
                        "Make sure your Tor daemon is running and the hidden service is configured at:"
                    );
                    println!("{}", hostname_path);
                }
            }
        }

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
            from_disk,
            vfs_name,
        } => {
            println!("[Ingress] Importing '{}'...", vfs_name);
            let mut input_file = File::open(&from_disk).expect("Failed to open local file");
            let chunk_boundaries: Vec<_> = chunker::chunk_data(&mut input_file).collect();

            let mut new_chunks = Vec::new();

            physical_vault
                .seek(SeekFrom::Start(current_payload_offset))
                .unwrap();

            for chunk_result in chunk_boundaries {
                let chunk_info = chunk_result.unwrap();
                let mut secure_buffer = zeroize::Zeroizing::new(vec![0u8; chunk_info.length]);

                input_file
                    .seek(SeekFrom::Start(chunk_info.offset as u64))
                    .unwrap();
                input_file.read_exact(&mut secure_buffer).unwrap();

                unsafe {
                    libc::mlock(
                        secure_buffer.as_ptr() as *const libc::c_void,
                        chunk_info.length,
                    );
                }
                let (ciphertext, chunk_nonce) =
                    crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();
                physical_vault.write_all(&ciphertext).unwrap();
                unsafe {
                    libc::munlock(
                        secure_buffer.as_ptr() as *const libc::c_void,
                        chunk_info.length,
                    );
                }

                new_chunks.push(ChunkEntry {
                    cipher_len: ciphertext.len(),
                    offset: current_payload_offset,
                    nonce: chunk_nonce,
                });

                current_payload_offset += ciphertext.len() as u64;
            }

            metadata.file_table.push(FileIndex {
                vfs_name,
                chunks: new_chunks,
            });
            save_vault_metadata(
                &mut physical_vault,
                &metadata,
                &unlocked_vault,
                current_payload_offset,
            )
            .unwrap();
            println!("Import complete. Tail-based metadata map serialized and pointer updated.");
        }

        Commands::Unlock { path } => {
            println!("[Mount] Unlocking vault from {} into volatile RAM...", path);
            mounted_vfs.seek(SeekFrom::Start(0)).unwrap();

            for file in &metadata.file_table {
                for chunk in &file.chunks {
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    let mut cipher_buffer = vec![0u8; chunk.cipher_len];
                    physical_vault.read_exact(&mut cipher_buffer).unwrap();

                    let current_vfs_pos = mounted_vfs.seek(SeekFrom::Current(0)).unwrap();
                    mounted_vfs.write_all(&cipher_buffer).unwrap();
                    mounted_vfs.seek(SeekFrom::Start(current_vfs_pos)).unwrap();

                    let mut decrypted_chunk = Vec::new();
                    vfs::process_secure_chunk(
                        &mut mounted_vfs,
                        chunk.cipher_len,
                        &chunk.nonce,
                        &unlocked_vault,
                        |secure_plaintext| {
                            decrypted_chunk.extend_from_slice(secure_plaintext);
                        },
                    )
                    .unwrap();

                    mounted_vfs.seek(SeekFrom::Start(current_vfs_pos)).unwrap();
                    mounted_vfs.write_all(&decrypted_chunk).unwrap();
                }
            }
            println!(
                "Vault successfully unlocked. Decrypted plaintext is live on virtual RAM disk."
            );
        }

        Commands::Export { vfs_name, to_disk } => {
            println!("[Egress] Exporting '{}' to '{}'...", vfs_name, to_disk);
            let mut output_file = File::create(&to_disk).expect("Failed to create output file");

            if let Some(file_entry) = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name) {
                for chunk in &file_entry.chunks {
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    let mut cipher_buffer = vec![0u8; chunk.cipher_len];
                    physical_vault.read_exact(&mut cipher_buffer).unwrap();

                    let secure_plaintext =
                        crypto::decrypt_chunk(&unlocked_vault, &cipher_buffer, &chunk.nonce)
                            .unwrap();

                    unsafe {
                        libc::mlock(
                            secure_plaintext.as_ptr() as *const libc::c_void,
                            secure_plaintext.len(),
                        );
                    }
                    output_file.write_all(&secure_plaintext).unwrap();
                    unsafe {
                        libc::munlock(
                            secure_plaintext.as_ptr() as *const libc::c_void,
                            secure_plaintext.len(),
                        );
                    }
                }
                println!("Export complete. File safely extracted and written.");
            } else {
                println!("Error: File '{}' not found in vault index.", vfs_name);
            }
        }

        Commands::Rm { vfs_name } => {
            println!(
                "[Wiping] Commencing SSD-Safe Crypto-Shredding for '{}'...",
                vfs_name
            );
            if let Some(file_position) = metadata
                .file_table
                .iter()
                .position(|f| f.vfs_name == vfs_name)
            {
                metadata.file_table.remove(file_position);
                save_vault_metadata(
                    &mut physical_vault,
                    &metadata,
                    &unlocked_vault,
                    current_payload_offset,
                )
                .unwrap();
                println!(
                    "[Success] File '{}' crypto-shredded securely. SSD blocks abandoned.",
                    vfs_name
                );
            } else {
                println!("Error: File '{}' not found in vault index.", vfs_name);
            }
        }

        // --- NEW P2P CLI COMMANDS ---
        Commands::Friend { command } => match command {
            FriendCommands::Add { url, nickname } => {
                let mut friends = load_friends();
                if friends.iter().any(|f| f.nickname == nickname) {
                    println!(
                        "❌ A friend with the nickname '{}' already exists.",
                        nickname
                    );
                    return;
                }

                friends.push(FriendRecord {
                    nickname: nickname.clone(),
                    url: url.clone(),
                });
                save_friends(&friends);
                println!(
                    "✅ Friend '{}' successfully added with URL: {}",
                    nickname, url
                );
            }
            FriendCommands::List => {
                let friends = load_friends();
                if friends.is_empty() {
                    println!("No friends added yet. Use `atom friend add <url> <nickname>`.");
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

                // Parse the onion address out of the atom:// url
                let onion_address = friend.url.trim_start_matches("atom://");
                println!("🌐 Target Tor Hidden Service: {}", onion_address);

                // Spin up a Tokio runtime *just* for the P2P networking lifecycle
                // This keeps our main file I/O completely synchronous and blocks until sync is done!
                let rt = tokio::runtime::Runtime::new().unwrap();

                rt.block_on(async {
                    println!("🧅 Bootstrapping Arti Tor client...");

                    // TODO: Move the `arti_client::TorClient` and `SyncManager`
                    // instantiation from `alice.rs` into this block.
                    // Pass `metadata` and `physical_vault` references to it
                    // so the engine can pull real chunks off the disk!

                    println!("✅ Handing over control to the Multiplexer Daemon...");
                });

                println!("🎉 Sync sequence successfully concluded.");
            } else {
                println!(
                    "❌ Friend '{}' not found. Use `atom friend list` to see your friends.",
                    friend_nickname
                );
            }
        }
    }
}
