use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

// RAII Guard using raw pointers to securely pin memory and prevent OS swap leaks
struct MlockGuard {
    ptr: *const libc::c_void,
    len: usize,
}

impl MlockGuard {
    fn new(slice: &[u8]) -> std::io::Result<Self> {
        let ptr = slice.as_ptr() as *const libc::c_void;
        let len = slice.len();
        unsafe {
            if libc::mlock(ptr, len) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(Self { ptr, len })
    }
}

impl Drop for MlockGuard {
    fn drop(&mut self) {
        unsafe {
            libc::munlock(self.ptr, self.len);
        }
    }
}

/// Decrypt all chunks of `vfs_name` into a single buffer.  Used by the GUI
/// broker flow: the caller sends the returned bytes to the broker for writing.
pub fn decrypt_to_bytes(
    vfs_name: &str,
    metadata: &VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file_entry = metadata
        .file_table
        .iter()
        .find(|f| f.vfs_name == vfs_name)
        .ok_or_else(|| format!("Error: File '{}' not found in vault.", vfs_name))?;

    let mut output: Vec<u8> = Vec::new();

    for chunk in &file_entry.chunks {
        physical_vault.seek(SeekFrom::Start(chunk.offset))?;
        let mut cipher_buffer = vec![0u8; chunk.cipher_len];
        physical_vault.read_exact(&mut cipher_buffer)?;

        let decrypted = zeroize::Zeroizing::new(
            crate::crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, &chunk.file_id)
                .map_err(|e| format!("Decryption error: {:?}", e))?,
        );
        let _mlock_guard = MlockGuard::new(&decrypted)?;
        let content = if chunk.plain_len > 0 {
            &decrypted[..chunk.plain_len]
        } else {
            &decrypted[..]
        };
        output.extend_from_slice(content);
    }

    Ok(output)
}

pub fn handle_export(
    vfs_name: String,
    to_disk: String,
    metadata: &VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
    force_overwrite: bool, // YENİ PARAMETRE: Shell'den veya GUI'den gelen onay
) -> Result<(), Box<dyn std::error::Error>> {
    let staging_dir_str = if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{}/atom_staging", xdg_runtime)
    } else if let Ok(home) = std::env::var("HOME") {
        format!("{}/.atom_vault/staging", home)
    } else {
        return Err(
            "Security Error: Neither XDG_RUNTIME_DIR nor HOME environment variables are set."
                .into(),
        );
    };

    let safe_filename = Path::new(&to_disk)
        .file_name()
        .ok_or("Error: Invalid target file name provided.")?;

    let target_path = Path::new(&staging_dir_str).join(safe_filename);

    // YENİ KONTROL: Eğer dosya varsa ve overwrite false ise özel hata dön
    if target_path.exists() && !force_overwrite {
        return Err("ALREADY_EXISTS".into());
    }

    let file_entry = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name);

    let target_file = match file_entry {
        Some(file) => file,
        None => {
            return Err(format!("Error: File '{}' not found in vault.", vfs_name).into());
        }
    };

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true);

    // GÜVENLİ YAZMA MODU
    if force_overwrite {
        open_opts.create(true).truncate(true); // Dosya varsa içini tamamen ez ve sıfırdan yaz
    } else {
        open_opts.create_new(true); // Sadece yeni oluştur (Zaten üstte yakaladık ama kernel savunması)
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600); // Owner Read/Write ONLY
    }

    let mut output_file = open_opts.open(&target_path).map_err(|e| {
        format!(
            "Failed to create secure output file at '{}': {:?}",
            target_path.display(),
            e
        )
    })?;

    for chunk in &target_file.chunks {
        physical_vault.seek(SeekFrom::Start(chunk.offset))?;

        let mut cipher_buffer = vec![0u8; chunk.cipher_len];
        physical_vault.read_exact(&mut cipher_buffer)?;

        let decrypted_bytes = zeroize::Zeroizing::new(
            crate::crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, &chunk.file_id)
                .map_err(|e| format!("Decryption error: {:?}", e))?,
        );

        let _mlock_guard = MlockGuard::new(&decrypted_bytes)?;
        let content = if chunk.plain_len > 0 {
            &decrypted_bytes[..chunk.plain_len]
        } else {
            &decrypted_bytes[..]
        };
        output_file.write_all(content)?;
    }

    output_file.sync_all()?;

    println!(
        "[Success] File '{}' successfully exported to secure staging area: {}",
        vfs_name,
        target_path.display()
    );
    Ok(())
}
