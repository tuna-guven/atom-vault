use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

pub fn handle_vacuum(
    vault_path: &str,
    metadata: &mut VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault, // KRİTİK: Metadata'yı yeniden şifrelemek için eklendi
) -> Result<u64, Box<dyn std::error::Error>> {
    // Güncel offset'i döndürür
    let tmp_path = format!("{}.tmp", vault_path);
    let mut tmp_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create vacuum temp file: {:?}", e))?;

    // Header size comes from the shared constant rather than a literal. This
    // used to be a hardcoded 112 — the pre-KdfSettings value — which copied only
    // 112 of the 125 header bytes and then started writing chunk data at offset
    // 112, overwriting the last 13 bytes of the wrapped DEK. The vault became
    // permanently unopenable on the next unwrap.
    let header_size: u64 = crate::crypto::VAULT_HEADER_SIZE;

    // Geçici olarak Master Pointer alanını (8 bayt) 0 ile doldur, sonra güncelleyeceğiz
    tmp_file.write_all(&[0u8; 8])?;

    // Header'ın geri kalanını kopyala (Master Salt, KDF parametreleri vs.)
    physical_vault.seek(SeekFrom::Start(8))?;
    let mut header_rest = vec![0u8; (header_size - 8) as usize];
    physical_vault.read_exact(&mut header_rest)?;
    tmp_file.write_all(&header_rest)?;

    let mut new_payload_offset = header_size;

    // Sadece silinmemiş, aktif chunk'ları yeni dosyaya sıkıştırarak yaz.
    //
    // Relocation is a pure byte-copy: a chunk's key derives from its random
    // file_salt and file_id, and its AAD binds the file_id — never the physical
    // offset. Moving a blob therefore cannot invalidate its tag. (Before the v1
    // format the offset was the AAD, so this loop silently broke every chunk it
    // moved.)
    for file_index in &mut metadata.file_table {
        for chunk in &mut file_index.chunks {
            physical_vault.seek(SeekFrom::Start(chunk.offset))?;

            let mut cipher_buffer = vec![0u8; chunk.cipher_len];
            physical_vault.read_exact(&mut cipher_buffer)?;

            tmp_file.seek(SeekFrom::Start(new_payload_offset))?;
            tmp_file.write_all(&cipher_buffer)?;

            // Bellekteki metadata'nın offset'ini YENİ konuma göre güncelle
            chunk.offset = new_payload_offset;
            new_payload_offset += chunk.cipher_len as u64;
        }
    }

    // KRİTİK YAMA: Eski metadata'yı kopyalamak yerine, offset'leri güncellenmiş
    // yeni metadata'yı şifreleyerek dosyanın sonuna yaz.
    crate::storage::save_vault_metadata(
        &mut tmp_file,
        metadata,
        unlocked_vault,
        new_payload_offset,
    )?;

    tmp_file.sync_all()?;
    drop(tmp_file); // Yeniden adlandırma (rename) yapabilmek için dosya kilidini (FD) serbest bırak

    std::fs::rename(&tmp_path, vault_path)?;

    println!(
        "[Vacuum] Optimization complete. Discarded dead zones and atomically defragmented storage container."
    );

    // Yeni payload offset'ini döndür ki shell.rs bunu güncelleyebilsin
    Ok(new_payload_offset)
}
