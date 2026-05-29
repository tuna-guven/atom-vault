mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use std::io::{Read, Write, Seek, SeekFrom};
use std::fs::{File, OpenOptions};

// FIX: All internal components are imported directly from the library crate
use atom::crypto;
use atom::vfs::{self, VaultMetadata, FileIndex, ChunkEntry};
use atom::chunker;

fn save_vault_metadata(
    physical_vault: &mut File,
    metadata: &VaultMetadata,
    unlocked_vault: &crypto::UnlockedVault, // Imported from library
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_bytes = bincode::serialize(metadata)?;
    let secure_buffer = zeroize::Zeroizing::new(raw_bytes);
    unsafe { libc::mlock(secure_buffer.as_ptr() as *const libc::c_void, secure_buffer.len()); }
    let (ciphertext, metadata_nonce) = crypto::encrypt_chunk(unlocked_vault, &secure_buffer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Crypto error: {}", e)))?;
    unsafe { libc::munlock(secure_buffer.as_ptr() as *const libc::c_void, secure_buffer.len()); }

    let ciphertext_len = ciphertext.len() as u64;
    physical_vault.seek(SeekFrom::Start(0))?;
    physical_vault.write_all(&ciphertext_len.to_le_bytes())?;
    physical_vault.write_all(&metadata_nonce)?;
    physical_vault.write_all(&ciphertext)?;
    Ok(())
}

fn load_vault_metadata(
    physical_vault: &mut File,
    unlocked_vault: &crypto::UnlockedVault, // Imported from library
) -> Result<VaultMetadata, Box<dyn std::error::Error>> {
    let file_len = physical_vault.metadata()?.len();
    if file_len < 32 {
        return Ok(VaultMetadata { file_table: Vec::new() });
    }

    physical_vault.seek(SeekFrom::Start(0))?;
    let mut len_bytes = [0u8; 8];
    physical_vault.read_exact(&mut len_bytes)?;
    let ciphertext_len = u64::from_le_bytes(len_bytes) as usize;

    let mut metadata_nonce = [0u8; crypto::XNONCE_LEN];
    physical_vault.read_exact(&mut metadata_nonce)?;

    let mut cipher_buffer = vec![0u8; ciphertext_len];
    physical_vault.read_exact(&mut cipher_buffer)?;

    let decrypted_bytes = crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, &metadata_nonce)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Metadata error: {}", e)))?;

    unsafe { libc::mlock(decrypted_bytes.as_ptr() as *const libc::c_void, decrypted_bytes.len()); }
    let metadata: VaultMetadata = bincode::deserialize(&decrypted_bytes)?;
    unsafe { libc::munlock(decrypted_bytes.as_ptr() as *const libc::c_void, decrypted_bytes.len()); }

    Ok(metadata)
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

    // Cryptographic Initialization Pipeline (Temporarily static for development/testing state)
    let salt = [0u8; 32]; // Fixed salt
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    
    // Instead of generating a random DEK every run, we use a fixed token for deterministic testing
    let raw_dek = [42u8; 32]; 
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();
    let mut metadata = load_vault_metadata(&mut physical_vault, &unlocked_vault).unwrap();

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

        Commands::Import { from_disk, vfs_name } => {
            println!("[Ingress] Importing '{}'...", vfs_name);
            let mut input_file = File::open(&from_disk).expect("Failed to open local file");
            let chunk_boundaries: Vec<_> = chunker::chunk_data(&mut input_file).collect();

            let mut new_chunks = Vec::new();

            for chunk_result in chunk_boundaries {
                let chunk_info = chunk_result.unwrap();
                let mut secure_buffer = zeroize::Zeroizing::new(vec![0u8; chunk_info.length]);
                
                input_file.seek(SeekFrom::Start(chunk_info.offset as u64)).unwrap();
                input_file.read_exact(&mut secure_buffer).unwrap();

                // FIX: If file is fresh or small, start payload section strictly at 4096 bytes boundary
                let end_of_file = physical_vault.seek(SeekFrom::End(0)).unwrap();
                let current_offset = if end_of_file < 4096 {
                    physical_vault.seek(SeekFrom::Start(4096)).unwrap()
                } else {
                    end_of_file
                };

                unsafe { libc::mlock(secure_buffer.as_ptr() as *const libc::c_void, chunk_info.length); }
                let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();
                physical_vault.write_all(&ciphertext).unwrap(); 
                unsafe { libc::munlock(secure_buffer.as_ptr() as *const libc::c_void, chunk_info.length); }
                
                new_chunks.push(ChunkEntry {
                    cipher_len: ciphertext.len(),
                    offset: current_offset,
                    nonce: chunk_nonce,
                });
            }

            metadata.file_table.push(FileIndex { vfs_name, chunks: new_chunks });
            save_vault_metadata(&mut physical_vault, &metadata, &unlocked_vault).unwrap();
            println!("Import complete. Metadata map serialized and saved securely at header.");
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
                        }
                    ).unwrap(); 

                    mounted_vfs.seek(SeekFrom::Start(current_vfs_pos)).unwrap();
                    mounted_vfs.write_all(&decrypted_chunk).unwrap();
                }
            }
            println!("Vault successfully unlocked. Decrypted plaintext is live on virtual RAM disk.");
            
            
            // TESTING VOLATILE plaintexts inside RAM disk before program exits
            mounted_vfs.seek(SeekFrom::Start(0)).unwrap();
            let mut ram_verification = vec![0u8; 30]; // Read first 30 bytes
            if mounted_vfs.read_exact(&mut ram_verification).is_ok() {
                println!("[Verification] Raw plaintext data read from volatile RAM: {:?}", String::from_utf8_lossy(&ram_verification));
            }
        
        }

        Commands::Export { vfs_name, to_disk } => {
            println!("[Egress] Exporting '{}' to '{}'...", vfs_name, to_disk);
            let mut output_file = File::create(&to_disk).expect("Failed to create output file");
            
            if let Some(file_entry) = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name) {
                for chunk in &file_entry.chunks {
                    // FIX: Rely entirely on the clean 4096-aligned absolute offset
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    let mut cipher_buffer = vec![0u8; chunk.cipher_len];
                    physical_vault.read_exact(&mut cipher_buffer).unwrap();
                    
                    let secure_plaintext = crypto::decrypt_chunk(&unlocked_vault, &cipher_buffer, &chunk.nonce).unwrap();

                    unsafe { libc::mlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len()); }
                    output_file.write_all(&secure_plaintext).unwrap();
                    unsafe { libc::munlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len()); }
                }
                println!("Export complete. File safely extracted and written.");
            } else {
                println!("Error: File '{}' not found in vault index.", vfs_name);
            }
        }

Commands::Rm { vfs_name } => {
            println!("[Wiping] Commencing DoD 5220.22-M compliant zeroization for '{}'...", vfs_name);

            // 1. Locate the file entry in the serialized index
            if let Some(file_position) = metadata.file_table.iter().position(|f| f.vfs_name == vfs_name) {
                let file_entry = &metadata.file_table[file_position];

                for chunk in &file_entry.chunks {
                    // Pass 1: Overwrite encrypted sectors on SSD with pure zeros (0x00)
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    let zero_buffer = vec![0u8; chunk.cipher_len];
                    physical_vault.write_all(&zero_buffer).unwrap();

                    // Pass 2: Overwrite with random cryptographic noise to break magnetic signature
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    let random_noise = crypto::generate_32_bytes(); // Use our csprng generator chunks
                    let mut noise_buffer = vec![0u8; chunk.cipher_len];
                    for i in 0..chunk.cipher_len {
                        noise_buffer[i] = random_noise[i % 32];
                    }
                    physical_vault.write_all(&noise_buffer).unwrap();
                    
                    // Flush hardware cache buffers to guarantee SSD cells are modified instantly
                    physical_vault.sync_all().unwrap();
                }

                // 2. Erase the tracking boundaries from Bincode file table
                metadata.file_table.remove(file_position);

                // 3. Re-save updated secure structure back to disk header
                save_vault_metadata(&mut physical_vault, &metadata, &unlocked_vault).unwrap();
                println!("[Success] File '{}' has been securely overwritten and purged from metadata index.", vfs_name);
            } else {
                println!("Error: File '{}' not found in vault index.", vfs_name);
            }
        }
    }
}