use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;

pub fn handle_export(
    vfs_name: String,
    to_disk: String,
    metadata: &VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
) -> Result<(), Box<dyn std::error::Error>> {
    
    let staging_dir_str = if let Ok(home) = std::env::var("HOME") {
        format!("{}/atom_staging", home)
    } else if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{}/atom_staging", xdg_runtime)
    } else {
        return Err("Security Error: Neither HOME nor XDG_RUNTIME_DIR environment variables are set.".into());
    };

    let safe_filename = Path::new(&to_disk)
        .file_name()
        .ok_or("Error: Invalid target file name provided.")?;

    let target_path = Path::new(&staging_dir_str).join(safe_filename);

    let file_entry = metadata
        .file_table
        .iter()
        .find(|f| f.vfs_name == vfs_name);

    let target_file = match file_entry {
        Some(file) => file,
        None => {
            return Err(format!("Error: File '{}' not found in vault.", vfs_name).into());
        }
    };

    let mut output_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) 
        .open(&target_path)
        .map_err(|e| format!("Failed to create output file at '{}' (it might already exist): {:?}", target_path.display(), e))?;

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

    println!("[Success] File '{}' successfully exported to staging area: {}", vfs_name, target_path.display());
    Ok(())
}