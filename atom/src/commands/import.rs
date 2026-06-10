use crate::crypto::{self, UnlockedVault};
use crate::vfs::{ChunkEntry, FileIndex, VaultMetadata};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

pub fn handle_import(
    from_disk: String,
    vfs_name: String,
    physical_vault: &mut File,
    metadata: &mut VaultMetadata,
    unlocked_vault: &UnlockedVault,
    current_payload_offset: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if metadata.file_table.iter().any(|f| f.vfs_name == vfs_name) {
        return Err(format!(
            "Error: A file named '{}' already exists in the vault.",
            vfs_name
        )
        .into());
    }

    let mut file = File::open(from_disk)?;

    let chunk_boundaries: Vec<fastcdc::v2020::ChunkData> =
        crate::chunker::chunk_data(&mut file, &metadata.cdc_salt).collect::<Result<Vec<_>, _>>()?;

    let mut new_chunks = Vec::new();

    physical_vault.seek(SeekFrom::Start(*current_payload_offset))?;

    for chunk_info in chunk_boundaries {
        let mut secure_buffer = zeroize::Zeroizing::new(vec![0u8; chunk_info.length]);

        file.seek(SeekFrom::Start(chunk_info.offset as u64))?;
        file.read_exact(&mut secure_buffer)?;

        unsafe {
            if libc::mlock(
                secure_buffer.as_ptr() as *const libc::c_void,
                chunk_info.length,
            ) != 0
            {
                return Err(Box::new(std::io::Error::last_os_error()));
            }
        }

        let encryption_result =
            crypto::encrypt_chunk(&unlocked_vault, &secure_buffer, *current_payload_offset)
                .map_err(|e| format!("Encryption error: {:?}", e));

        let (ciphertext, chunk_nonce) = match encryption_result {
            Ok(data) => data,
            Err(e) => {
                unsafe {
                    libc::munlock(
                        secure_buffer.as_ptr() as *const libc::c_void,
                        chunk_info.length,
                    );
                }
                return Err(e.into());
            }
        };

        if let Err(e) = physical_vault.write_all(&ciphertext) {
            unsafe {
                libc::munlock(
                    secure_buffer.as_ptr() as *const libc::c_void,
                    chunk_info.length,
                );
            }
            return Err(e.into());
        }

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
        last_modified_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });

    crate::storage::save_vault_metadata(
        physical_vault,
        metadata,
        unlocked_vault,
        *current_payload_offset,
    )?;

    physical_vault.sync_all()?;

    println!("Import completed. Tail-based metadata map serialized and pointer updated.");
    Ok(())
}
