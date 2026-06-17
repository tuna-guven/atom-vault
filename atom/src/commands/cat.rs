use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use crate::crypto::UnlockedVault;
use crate::vfs::{VaultMetadata, MemFile};

pub fn handle_cat(
    vfs_name: String,
    metadata: &VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_entry = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name);

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
            chunk.offset,
            |plaintext| {
                if let Err(e) = memfile.write_all(plaintext) {
                    eprintln!("[ERROR] Memory write failed during decryption: {:?}", e);
                }
            },
        ).map_err(|e| format!("Chunk processing error: {:?}", e))?;
    }

    let final_pos = memfile.seek(SeekFrom::Current(0))?;
    memfile.seek(SeekFrom::Start(0))?;

    let mut buffer = zeroize::Zeroizing::new(vec![0u8; final_pos as usize]);
    memfile.read_exact(&mut *buffer)?;

    println!("\n--- Start of {} ---", vfs_name);
    let mut stdout = io::stdout().lock();

    let control_chars_count = buffer
        .iter()
        .filter(|&&b| b < 32 && b != b'\n' && b != b'\t' && b != b'\r')
        .count();
    let is_probably_binary = control_chars_count > (buffer.len() / 100); // %1 eşiği

    if is_probably_binary {
        // Kullanıcı dostu bilgilendirme mesajı
        let preview_len = std::cmp::min(buffer.len(), 64);
        writeln!(stdout, "[Note: Binary or Null-padded data detected. Suppressing automated terminal flood.]")?;
        write!(stdout, "First {} bytes (HEX Preview): ", preview_len)?;
        for byte in &buffer[..preview_len] {
            write!(stdout, "{:02X} ", byte)?;
        }
        writeln!(stdout)?;
    } else if let Ok(text) = std::str::from_utf8(&buffer) {
        // Eğer temiz bir metin dosyasıysa normal şekilde ve güvenle yazdır
        for c in text.chars() {
            if c.is_ascii_control() && c != '\n' && c != '\t' && c != '\r' {
                let _ = write!(stdout, "\\x{:02X}", c as u8);
            } else {
                let _ = write!(stdout, "{}", c);
            }
        }
    } else {
        writeln!(stdout, "[Note: Non-UTF8 Binary file detected. Displaying sanitized HEX layout]")?;
        for chunk in buffer.chunks(16) {
            for byte in chunk {
                let _ = write!(stdout, "{:02X} ", byte);
            }
            let _ = writeln!(stdout);
        }
    }

    let _ = stdout.flush();
    println!("\n--- End of {} ---\n", vfs_name);

    Ok(())
}
