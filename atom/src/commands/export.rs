use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

pub fn handle_export(
    vfs_name: String,
    to_disk: String,
    metadata: &VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_entry = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name);

    let target_file = match file_entry {
        Some(file) => file,
        None => {
            println!("Error: File '{}' not found in vault.", vfs_name);
            return Ok(());
        }
    };

    let mut output_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) 
        .open(&to_disk)
        .map_err(|e| format!("Failed to create output file '{}' (it might already exist): {:?}", to_disk, e))?;

    for chunk in &target_file.chunks {
        physical_vault.seek(SeekFrom::Start(chunk.offset))?;

        let mut cipher_buffer = vec![0u8; chunk.cipher_len];
        physical_vault.read_exact(&mut cipher_buffer)?;

        let decrypted_bytes = zeroize::Zeroizing::new(
            crate::crypto::decrypt_chunk(
                unlocked_vault,
                &cipher_buffer,
                &chunk.nonce,
                chunk.offset,
            ).map_err(|e| format!("Decryption error: {:?}", e))?
        );

        output_file.write_all(&decrypted_bytes)?;
        
    }
    output_file.sync_all()?;

    println!("[Success] File '{}' successfully exported and decrypted.", vfs_name);
    Ok(())
}
