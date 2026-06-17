use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write}; 

pub fn handle_rm(
    vfs_name: String,
    metadata: &mut VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
    current_payload_offset: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[Wiping] Commencing Crypto-Shredding for '{}'...", vfs_name);
    
    let to_be_removed_file_position = metadata.file_table.iter().position(|f| f.vfs_name == vfs_name);
    
    if let Some(index) = to_be_removed_file_position {
        // 1. Borrow checker çakışmalarını önlemek için chunk verisini kopyala
        let chunks_to_wipe = metadata.file_table[index].chunks.clone();

        // 2. GERÇEK GÜVENLİ SİLME (Zeroization)
        for chunk in chunks_to_wipe {
            let zero_buffer = vec![0u8; chunk.cipher_len]; 
            
            physical_vault.seek(SeekFrom::Start(chunk.offset))?;
            physical_vault.write_all(&zero_buffer)?;
        }
        
        physical_vault.flush()?;
        println!("[Wiping] Physical data blocks successfully zeroized.");

        // 3. Artık veriler yok edildi, metadata'dan kaydı uçur
        metadata.file_table.remove(index);
        
        // --- KRİTİK İŞLETİM SİSTEMİ YAMALARI ---
        
        // YAMA A: İmleci (Cursor) kesin olarak metadata'nın başlaması gereken yere çek
        physical_vault.seek(SeekFrom::Start(*current_payload_offset))?;

        // YAMA B: Trailing Garbage (Artık Çöp) Temizliği
        // Dosyayı payload'ın bittiği yerden itibaren tamamen kırp (Truncate).
        // Böylece eski, daha uzun metadata'nın artıkları şifre çözücüyü patlatamaz.
        physical_vault.set_len(*current_payload_offset)?;

        crate::storage::save_vault_metadata(
            physical_vault,
            metadata,
            unlocked_vault,
            *current_payload_offset,
        )?;

        physical_vault.sync_all()?;
        println!("[Wiping] Metadata securely updated and file truncated.");
    } else {
        println!("Error: File not found.");
        return Err("File not found in metadata".into()); 
    }

    Ok(())
}