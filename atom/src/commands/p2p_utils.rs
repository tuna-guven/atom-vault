use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::crypto;
use crate::vfs::VaultMetadata;

// --- FRIEND REGISTRY ---

#[derive(Serialize, Deserialize, Debug)]
pub struct FriendRecord {
    pub nickname: String,
    pub url: String,
}

pub fn load_friends() -> Vec<FriendRecord> {
    if let Ok(data) = std::fs::read_to_string("friends.json") {
        serde_json::from_str(&data).unwrap_or_else(|_| Vec::new())
    } else {
        Vec::new()
    }
}

pub fn save_friends(friends: &[FriendRecord]) {
    let data = serde_json::to_string_pretty(friends).expect("Failed to serialize friends");
    std::fs::write("friends.json", data).expect("Failed to write friends.json");
}

pub fn extract_pubkey_from_onion(
    onion_url: &str,
) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let onion = onion_url
        .trim_start_matches("atom://")
        .trim_end_matches(".onion");
    let decoded = BASE32_NOPAD.decode(onion.to_uppercase().as_bytes())?;
    if decoded.len() != 35 {
        return Err("Invalid onion link length".into());
    }
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&decoded[0..32]);
    Ok(VerifyingKey::from_bytes(&pubkey_bytes)?)
}

// --- METADATA TRANSLATORS ---

pub fn to_p2p_meta(atom_meta: &VaultMetadata) -> p2p_sync::sync::VaultMetadata {
    p2p_sync::sync::VaultMetadata {
        file_table: atom_meta
            .file_table
            .iter()
            .map(|f| p2p_sync::sync::FileIndex {
                vfs_name: f.vfs_name.clone(),
                last_modified_unix: f.last_modified_unix,
                chunks: f
                    .chunks
                    .iter()
                    .map(|c| p2p_sync::sync::ChunkEntry {
                        cipher_len: c.cipher_len,
                        offset: c.offset,
                        nonce: c.nonce,
                    })
                    .collect(),
            })
            .collect(),
        // Map the salt to the network struct
        cdc_salt: atom_meta.cdc_salt,
    }
}

pub fn to_atom_meta(p2p_meta: &p2p_sync::sync::VaultMetadata) -> VaultMetadata {
    VaultMetadata {
        file_table: p2p_meta
            .file_table
            .iter()
            .map(|f| crate::vfs::FileIndex {
                vfs_name: f.vfs_name.clone(),
                last_modified_unix: f.last_modified_unix,
                chunks: f
                    .chunks
                    .iter()
                    .map(|c| crate::vfs::ChunkEntry {
                        cipher_len: c.cipher_len,
                        offset: c.offset,
                        nonce: c.nonce,
                    })
                    .collect(),
            })
            .collect(),
        // Map the salt from the network struct back to the VFS
        cdc_salt: p2p_meta.cdc_salt,
    }
}

// --- VAULT METADATA IO ---

pub fn load_vault_metadata(
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
                // Generate a secure salt for the brand new vault
                cdc_salt: crypto::generate_32_bytes(),
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
                // Generate a secure salt for the brand new vault
                cdc_salt: crypto::generate_32_bytes(),
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

    // FIX: Pass `metadata_offset` as the AAD offset to prevent the compiler error
    let decrypted_bytes = crypto::decrypt_chunk(
        unlocked_vault,
        &cipher_buffer,
        &metadata_nonce,
        metadata_offset,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;

    let metadata: VaultMetadata = bincode::deserialize(&decrypted_bytes)?;
    Ok((metadata, metadata_offset))
}

pub fn save_vault_metadata(
    physical_vault: &mut File,
    metadata: &VaultMetadata,
    unlocked_vault: &crypto::UnlockedVault,
    payload_end_offset: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_bytes = bincode::serialize(metadata)?;
    let secure_buffer = zeroize::Zeroizing::new(raw_bytes);

    // FIX: Pass `payload_end_offset` as the AAD offset to prevent the compiler error
    let (ciphertext, metadata_nonce) =
        crypto::encrypt_chunk(unlocked_vault, &secure_buffer, payload_end_offset).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e))
        })?;

    physical_vault.seek(SeekFrom::Start(payload_end_offset))?;
    let ciphertext_len = ciphertext.len() as u64;
    physical_vault.write_all(&ciphertext_len.to_le_bytes())?;
    physical_vault.write_all(&metadata_nonce)?;
    physical_vault.write_all(&ciphertext)?;

    let new_eof = physical_vault.stream_position()?;
    physical_vault.set_len(new_eof)?;

    physical_vault.seek(SeekFrom::Start(0))?;
    physical_vault.write_all(&payload_end_offset.to_le_bytes())?;

    Ok(())
}
