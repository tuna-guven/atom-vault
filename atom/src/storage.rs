use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use crate::crypto::{UnlockedVault, XNONCE_LEN};
use crate::vfs::VaultMetadata;

pub fn load_vault_metadata(
    file: &mut File,
    password: &str,
) -> Result<(VaultMetadata, UnlockedVault, u64), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;
    let mut master_ptr_bytes = [0u8; 8];
    file.read_exact(&mut master_ptr_bytes)?;
    let master_pointer = u64::from_le_bytes(master_ptr_bytes);

    let mut salt = [0u8; 32];
    let mut dek_nonce = [0u8; XNONCE_LEN];
    let mut wrapped_dek = [0u8; 48];

    file.read_exact(&mut salt)?;
    file.read_exact(&mut dek_nonce)?;
    file.read_exact(&mut wrapped_dek)?;

    let kek = crate::crypto::derive_kek(password, &salt)
        .map_err(|e| format!("Argon2 error: {:?}", e))?;

    let unlocked_vault = crate::crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce)
        .map_err(|e| format!("DEK unwrap error: {:?}", e))?;

    let current_payload_offset = file.stream_position()?;

    file.seek(SeekFrom::Start(master_pointer))?;
    
    let mut metadata_nonce = [0u8; XNONCE_LEN];
    file.read_exact(&mut metadata_nonce)?;

    let mut encrypted_metadata = Vec::new();
    file.take(10 * 1024 * 1024).read_to_end(&mut encrypted_metadata)?;

    let decrypted_metadata_bytes = crate::crypto::decrypt_chunk(
        &unlocked_vault,
        &encrypted_metadata,
        &metadata_nonce,
        master_pointer,
    ).map_err(|e| format!("Metadata decrypt error: {:?}", e))?;

    let metadata: VaultMetadata = bincode::deserialize(&decrypted_metadata_bytes)?;

    Ok((metadata, unlocked_vault, current_payload_offset))
}

pub fn save_vault_metadata(
    file: &mut File,
    metadata: &VaultMetadata,
    unlocked_vault: &UnlockedVault,
    current_payload_offset: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized_metadata = bincode::serialize(metadata)?;

    let (encrypted_metadata, metadata_nonce) = crate::crypto::encrypt_chunk(
        unlocked_vault,
        &serialized_metadata,
        current_payload_offset,
    ).map_err(|e| format!("Metadata encrypt error: {:?}", e))?;

    file.seek(SeekFrom::Start(current_payload_offset))?;
    
    file.write_all(&metadata_nonce)?;
    file.write_all(&encrypted_metadata)?;

    file.sync_data()?;
    
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&current_payload_offset.to_le_bytes())?;
    file.sync_all()?;
    
    Ok(())
}