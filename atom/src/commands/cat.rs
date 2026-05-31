use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use crate::crypto::UnlockedVault;
use crate::vfs::{VaultMetadata, MemFile};

pub fn handle_cat(
    vfs_name: String,
    metadata: &VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
) -> Result<(), Box<dyn std::error::Error>> {
    
    let file_entry = metadata
        .file_table
        .iter()
        .find(|f| f.vfs_name == vfs_name);

    let target_file = match file_entry {
        Some(file) => file,
        None => {
            println!("Error: File '{}' not found in vault.", vfs_name);
            return Ok(());
        }
    };

    let total_capacity: usize = target_file.chunks.iter().map(|c| c.cipher_len).sum();
    let mut memfile = MemFile::new(&vfs_name, total_capacity)?;

    for chunk in &target_file.chunks {
        physical_vault.seek(SeekFrom::Start(chunk.offset))?;

        crate::vfs::process_secure_chunk(
            physical_vault, 
            chunk.cipher_len,
            &chunk.nonce,
            unlocked_vault,
            |plaintext| {
                let _ = memfile.write_all(plaintext);
            },
        ).map_err(|e| format!("Chunk processing error: {:?}", e))?;
    }

    let final_pos = memfile.seek(SeekFrom::Current(0))?;
    memfile.seek(SeekFrom::Start(0))?;
    
    let mut buffer = vec![0u8; final_pos as usize];
    memfile.read_exact(&mut buffer)?;
    
    let output = String::from_utf8_lossy(&buffer);
    
    println!("\n--- Start of {} ---", vfs_name);
    println!("{}", output);
    println!("--- End of {} ---\n", vfs_name);

    Ok(())
}