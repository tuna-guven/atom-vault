mod crypto;
mod vfs;
mod chunker;
mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use std::io::{Read, Write, Seek, SeekFrom};
use std::fs::{File, OpenOptions};

fn main() {
    let args = Cli::parse();
    let vault_size = 50 * 1024 * 1024;
    
    // 1. Persistent Storage (Encrypted container on disk)
    let mut physical_vault = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("my_data.aegis")
        .unwrap();

    // 2. Volatile Mount (RAM-backed VFS layout)
    let mut mounted_vfs = vfs::MemFile::new("atom_mount", vault_size).unwrap();

    // Crypto Initialization
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    // Track chunk metadata configurations
    let mut chunk_metadata: Vec<(String, usize, [u8; crypto::XNONCE_LEN])> = Vec::new();

    match args.command {
        Commands::Ls => {
            println!("--- Volatile VFS File Allocation Table ---");
        }

        Commands::Import { from_disk, vfs_name } => {
            println!("[Ingress] Importing '{}'...", vfs_name);
            let mut input_file = File::open(&from_disk).expect("Failed to open local file");
            let chunk_boundaries: Vec<_> = chunker::chunk_data(&mut input_file).collect();

            physical_vault.seek(SeekFrom::End(0)).unwrap();

            for chunk_result in chunk_boundaries {
                let chunk_info = chunk_result.unwrap();
                let mut secure_buffer = zeroize::Zeroizing::new(vec![0u8; chunk_info.length]);
                
                input_file.seek(SeekFrom::Start(chunk_info.offset as u64)).unwrap();
                input_file.read_exact(&mut secure_buffer).unwrap();

                unsafe { libc::mlock(secure_buffer.as_ptr() as *const libc::c_void, chunk_info.length); }
                let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();
                physical_vault.write_all(&ciphertext).unwrap(); 
                unsafe { libc::munlock(secure_buffer.as_ptr() as *const libc::c_void, chunk_info.length); }
                
                chunk_metadata.push((vfs_name.clone(), ciphertext.len(), chunk_nonce));
            }
        }

        Commands::Unlock { path } => {
            println!("[Mount] Unlocking vault from {} into volatile RAM...", path);
            physical_vault.seek(SeekFrom::Start(0)).unwrap();
            mounted_vfs.seek(SeekFrom::Start(0)).unwrap();

            for (_, cipher_len, nonce) in &chunk_metadata {
                // Temporary buffer to hold the decrypted data safely outside the first borrow
                let mut decrypted_chunk = Vec::new();

                // 1. First borrow happens here to read and decrypt
                vfs::process_secure_chunk(
                    &mut mounted_vfs, 
                    *cipher_len,
                    nonce,
                    &unlocked_vault,
                    |secure_plaintext| {
                        // Just copy the data out to our temporary buffer
                        decrypted_chunk.extend_from_slice(secure_plaintext);
                    }
                ).unwrap(); // First mutable borrow on mounted_vfs ends right HERE!

                // 2. Now it is completely safe to borrow mounted_vfs again to write the data
                mounted_vfs.write_all(&decrypted_chunk).unwrap();
            }
            println!("Vault successfully unlocked. Decrypted plaintext is live on virtual RAM disk.");
        }

        Commands::Export { vfs_name, to_disk } => {
            println!("[Egress] Exporting '{}' to '{}'...", vfs_name, to_disk);
            let mut output_file = File::create(&to_disk).expect("Failed to create output file");
            
            let file_chunks: Vec<_> = chunk_metadata.iter().filter(|(name, _, _)| name == &vfs_name).collect();
            for (_, cipher_len, nonce) in file_chunks {
                let mut cipher_buffer = vec![0u8; *cipher_len];
                physical_vault.read_exact(&mut cipher_buffer).unwrap();
                let secure_plaintext = crypto::decrypt_chunk(&unlocked_vault, &cipher_buffer, nonce).unwrap();

                unsafe { libc::mlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len()); }
                output_file.write_all(&secure_plaintext).unwrap();
                unsafe { libc::munlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len()); }
            }
        }

        Commands::Rm { vfs_name } => {
            println!("Zeroizing '{}' sectors...", vfs_name);
        }
    }
}