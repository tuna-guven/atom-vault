use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use crate::crypto::{self, UnlockedVault};
use crate::vfs::{VaultMetadata, ChunkEntry, FileIndex};

pub fn handle_import(
    from_disk: String, 
    vfs_name: String, 
    physical_vault: &mut File, 
    metadata: &mut VaultMetadata, 
    unlocked_vault: &UnlockedVault, 
    current_payload_offset: &mut u64
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(from_disk)?;
    
    let chunk_boundaries: Vec<fastcdc::v2020::ChunkData> = crate::chunker::chunk_data(&mut file)
        .collect::<Result<Vec<_>, _>>()?;
        
    let mut new_chunks = Vec::new();

    physical_vault.seek(SeekFrom::Start(*current_payload_offset))?;
    
    for chunk_info in chunk_boundaries {
        let mut secure_buffer = zeroize::Zeroizing::new(vec![0u8; chunk_info.length]);
        
        file.seek(SeekFrom::Start(chunk_info.offset as u64))?;
        file.read_exact(&mut secure_buffer)?;
        
        unsafe {
            libc::mlock(
                secure_buffer.as_ptr() as *const libc::c_void,
                chunk_info.length,
            );
        }
        
        let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer)
            .map_err(|e| format!("Encryption error: {:?}", e))?;
            
        physical_vault.write_all(&ciphertext)?;
        
        unsafe {
            libc::munlock(
                secure_buffer.as_ptr() as *const libc::c_void,
                chunk_info.length,
            );
        }

        new_chunks.push(ChunkEntry {
            cipher_len: ciphertext.len(),
            offset: *current_payload_offset,
            nonce: chunk_nonce,
        });

        *current_payload_offset += ciphertext.len() as u64;
    }

    metadata.file_table.push(FileIndex {
        vfs_name,
        chunks: new_chunks,
    });
    
    crate::storage::save_vault_metadata(
        physical_vault,
        metadata,
        unlocked_vault,
        *current_payload_offset,
    )?;
    
    println!("Import completed. Tail-based metadata map serialized and pointer updated.");
    Ok(())
}