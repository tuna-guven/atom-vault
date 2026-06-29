use crate::chunker::MAX_CHUNK_SIZE;
use crate::crypto::{self, UnlockedVault};
use crate::vfs::{ChunkEntry, FileIndex, VaultMetadata};
use rand::RngCore;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

// RAII Guard using raw pointers to handle alignment cleanly and avoid borrow checker conflicts
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

/// Import pre-read bytes into the vault.  Used by the GUI broker flow where
/// the file has already been read in a sandboxed sub-thread; the caller is
/// responsible for zeroing `data` after this returns.
pub fn handle_import_from_bytes(
    data: Vec<u8>,
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

    let chunk_boundaries: Vec<fastcdc::v2020::ChunkData> =
        crate::chunker::chunk_data(std::io::Cursor::new(&data))
            .collect::<Result<Vec<_>, _>>()?;

    let mut new_chunks = Vec::new();
    physical_vault.seek(SeekFrom::Start(*current_payload_offset))?;

    for chunk_info in chunk_boundaries {
        let start = chunk_info.offset as usize;
        let plain_len = chunk_info.length;

        // Pad plaintext to MAX_CHUNK_SIZE with random bytes to hide chunk size.
        let mut padded = zeroize::Zeroizing::new(vec![0u8; MAX_CHUNK_SIZE]);
        padded[..plain_len].copy_from_slice(&data[start..start + plain_len]);
        rand::rngs::OsRng.fill_bytes(&mut padded[plain_len..]);

        let _mlock_guard = MlockGuard::new(&padded)?;
        let (ciphertext, chunk_nonce) =
            crypto::encrypt_chunk(unlocked_vault, &padded, *current_payload_offset)
                .map_err(|e| format!("Encryption error: {:?}", e))?;

        physical_vault.write_all(&ciphertext)?;
        new_chunks.push(ChunkEntry {
            cipher_len: ciphertext.len(),
            offset: *current_payload_offset,
            nonce: chunk_nonce,
            plain_len,
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
    Ok(())
}

pub fn handle_import(
    from_disk: String,
    vfs_name: String,
    physical_vault: &mut File,
    metadata: &mut VaultMetadata,
    unlocked_vault: &UnlockedVault,
    current_payload_offset: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Sync staging path determination logic with main.rs
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

    let allowed_path = Path::new(&staging_dir_str)
        .canonicalize()
        .map_err(|_| "Fatal: Could not resolve staging directory path.")?;

    let target_path = Path::new(&from_disk).canonicalize().map_err(|_| {
        format!(
            "Error: The file '{}' does not exist or cannot be resolved.",
            from_disk
        )
    })?;

    // Validate path confinement
    if !target_path.starts_with(&allowed_path) {
        return Err(format!(
            "Security Violation: Imports are strictly limited to the staging area.\n\
             Please move your file to: {}\n\
             Attempted to access: {}",
            staging_dir_str,
            target_path.display()
        )
        .into());
    }

    if metadata.file_table.iter().any(|f| f.vfs_name == vfs_name) {
        return Err(format!(
            "Error: A file named '{}' already exists in the vault.",
            vfs_name
        )
        .into());
    }

    // 2. Open the canonicalized target_path directly to eliminate TOCTOU race conditions.
    // Open with write capability to allow in-place zero-shredding on cleanup.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target_path)?;

    let chunk_boundaries: Vec<fastcdc::v2020::ChunkData> =
        crate::chunker::chunk_data(&mut file).collect::<Result<Vec<_>, _>>()?;

    let mut new_chunks = Vec::new();

    physical_vault.seek(SeekFrom::Start(*current_payload_offset))?;

    for chunk_info in chunk_boundaries {
        let plain_len = chunk_info.length;

        // Pad plaintext to MAX_CHUNK_SIZE with random bytes to hide chunk size.
        let mut padded = zeroize::Zeroizing::new(vec![0u8; MAX_CHUNK_SIZE]);
        file.seek(SeekFrom::Start(chunk_info.offset as u64))?;
        file.read_exact(&mut padded[..plain_len])?;
        rand::rngs::OsRng.fill_bytes(&mut padded[plain_len..]);

        // 3. Bind the buffer to the raw pointer-based MlockGuard
        let _mlock_guard = MlockGuard::new(&padded)?;

        // Pass immutable reference safely without triggering an exclusive borrow checker conflict
        let (ciphertext, chunk_nonce) =
            crypto::encrypt_chunk(&unlocked_vault, &padded, *current_payload_offset)
                .map_err(|e| format!("Encryption error: {:?}", e))?;

        if let Err(e) = physical_vault.write_all(&ciphertext) {
            return Err(e.into());
        }

        new_chunks.push(ChunkEntry {
            cipher_len: ciphertext.len(),
            offset: *current_payload_offset,
            nonce: chunk_nonce,
            plain_len,
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

    // 4. Anti-Forensics Shredder: Secure overwriting of physical contents on disk/tmpfs
    println!("Shredding plaintext file from staging area...");
    if let Ok(file_meta) = file.metadata() {
        let size = file_meta.len();
        let _ = file.seek(SeekFrom::Start(0));

        let mut zero_page = vec![0u8; 4096];
        let mut written = 0;

        while written < size {
            let to_write = std::cmp::min(4096, size - written) as usize;
            if file.write_all(&zero_page[..to_write]).is_err() {
                break;
            }
            written += to_write as u64;
        }
        let _ = file.sync_all();
        zeroize::Zeroize::zeroize(&mut zero_page);
    }

    // Explicitly drop file handles to avoid resource lockups before unlinking
    drop(file);
    if let Err(e) = std::fs::remove_file(&target_path) {
        eprintln!(
            "Warning: Failed to delete staged file '{}': {}",
            target_path.display(),
            e
        );
    } else {
        println!("Staged file safely wiped and unlinked.");
    }

    Ok(())
}
