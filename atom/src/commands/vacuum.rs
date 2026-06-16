use crate::vfs::VaultMetadata;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

pub fn handle_vacuum(
    vault_path: &str,
    metadata: &mut VaultMetadata,
    physical_vault: &mut File,
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_path = format!("{}.tmp", vault_path);
    let mut tmp_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create vacuum temp file: {:?}", e))?;

    let header_size: u64 = 112;
    tmp_file.write_all(&header_size.to_le_bytes())?;

    physical_vault.seek(SeekFrom::Start(8))?;
    let mut header_rest = [0u8; 104];
    physical_vault.read_exact(&mut header_rest)?;
    tmp_file.write_all(&header_rest)?;

    let mut new_payload_offset = header_size;

    for file_index in &mut metadata.file_table {
        for chunk in &mut file_index.chunks {
            physical_vault.seek(SeekFrom::Start(chunk.offset))?;

            let mut cipher_buffer = vec![0u8; chunk.cipher_len];
            physical_vault.read_exact(&mut cipher_buffer)?;

            tmp_file.seek(SeekFrom::Start(new_payload_offset))?;
            tmp_file.write_all(&cipher_buffer)?;

            chunk.offset = new_payload_offset;
            new_payload_offset += chunk.cipher_len as u64;
        }
    }

    physical_vault.seek(SeekFrom::Start(0))?;
    let mut master_ptr_bytes = [0u8; 8];
    physical_vault.read_exact(&mut master_ptr_bytes)?;
    let old_master_ptr = u64::from_le_bytes(master_ptr_bytes);

    physical_vault.seek(SeekFrom::Start(old_master_ptr))?;
    let mut metadata_nonce = [0u8; crate::crypto::XNONCE_LEN];
    physical_vault.read_exact(&mut metadata_nonce)?;

    let mut encrypted_metadata = Vec::new();
    physical_vault.take(10 * 1024 * 1024).read_to_end(&mut encrypted_metadata)?;

    tmp_file.seek(SeekFrom::Start(new_payload_offset))?;
    tmp_file.write_all(&metadata_nonce)?;
    tmp_file.write_all(&encrypted_metadata)?;

    tmp_file.seek(SeekFrom::Start(0))?;
    tmp_file.write_all(&new_payload_offset.to_le_bytes())?;
    
    tmp_file.sync_all()?;
    drop(tmp_file);
    
    std::fs::rename(&tmp_path, vault_path)?;

    println!("[Vacuum] Optimization complete. Discarded dead zones and atomically defragmented storage container.");
    Ok(())
}
