use std::fs::File;
use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;

pub fn handle_rm(
    vfs_name: String, 
    metadata: &mut VaultMetadata, 
    physical_vault: &mut File, 
    unlocked_vault: &UnlockedVault, 
    current_payload_offset: &mut u64
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "[Wiping] Commencing SSD-Safe Crypto-Shredding for '{}'...",
        vfs_name
    );
    
    let to_be_removed_file_position = metadata.file_table.iter().position(|f| f.vfs_name == vfs_name);
    if let Some(index) = to_be_removed_file_position {
        metadata.file_table.remove(index);
        
        crate::storage::save_vault_metadata(
            physical_vault,
            metadata,
            unlocked_vault,
            *current_payload_offset,
        )?;

        physical_vault.sync_all()?;
    } else {
        println!("Error: File not found.")
    }

    Ok(())
}