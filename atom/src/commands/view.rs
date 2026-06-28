use memfd::MemfdOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use zeroize::Zeroize;

use crate::crypto::UnlockedVault;
use crate::sandbox;
use crate::vfs::{FileIndex, process_secure_chunk};

/// Decrypt `file_index` chunks into a sealed, anonymous memfd.
///
/// Returns the memfd `File`; the caller is responsible for spawning the viewer
/// and shredding the file when done.  Used by the GUI path so that the bwrap
/// spawn can happen on the pre-sandbox broker thread rather than the
/// Landlock-restricted main thread.
pub fn prepare_decrypted_memfd(
    physical_vault: &mut std::fs::File,
    file_index: &FileIndex,
    unlocked_vault: &UnlockedVault,
) -> Result<std::fs::File, Box<dyn std::error::Error + Send + Sync>> {
    let memfd_name = format!("atom_vault_memfd_{}", file_index.vfs_name);
    let mut memfd_file = MemfdOptions::default()
        .close_on_exec(true)
        .allow_sealing(true)
        .create(&memfd_name)?
        .into_file();

    for chunk in &file_index.chunks {
        process_secure_chunk(
            physical_vault,
            chunk.cipher_len,
            &chunk.nonce,
            unlocked_vault,
            chunk.offset,
            |secure_plaintext| {
                memfd_file
                    .write_all(secure_plaintext)
                    .expect("Fatal: Failed to write to RAM disk");
            },
        )?;
    }

    memfd_file.flush()?;
    memfd_file.seek(SeekFrom::Start(0))?;

    // Seal against external writes/grows so the viewer app cannot modify the
    // in-RAM copy.  F_SEAL_SEAL prevents further seal changes.
    unsafe {
        libc::fcntl(
            memfd_file.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL,
        );
    }

    Ok(memfd_file)
}

/// Attempt to zero the memfd content and then drop the file (closing the fd).
///
/// The seals applied by `prepare_decrypted_memfd` prevent writes, so the
/// zero-write will fail silently.  The real erasure happens when the last fd
/// referencing the anonymous memfd is closed: the kernel releases the backing
/// pages.  This function makes the intent explicit and drops the file handle.
pub fn shred_memfd(mut memfd_file: std::fs::File) {
    let size = memfd_file.seek(SeekFrom::End(0)).unwrap_or(0);
    if size > 0 {
        let _ = memfd_file.seek(SeekFrom::Start(0));
        let mut zero_page = [0u8; 4096];
        let mut written = 0u64;
        while written < size {
            let to_write = std::cmp::min(4096, size - written) as usize;
            if memfd_file.write_all(&zero_page[..to_write]).is_err() {
                break;
            }
            written += to_write as u64;
        }
        let _ = memfd_file.flush();
        zero_page.zeroize();
    }
    let _ = memfd_file.set_len(0);
    // memfd_file is dropped here, closing the last fd and freeing the pages.
    println!("Traces successfully removed.");
}

/// CLI entry point: decrypt, spawn bwrap directly, wait and shred.
///
/// Used by the interactive shell `view` command where there is no GUI broker.
/// Note: if Landlock is active (CLI `enter` path), bwrap inherits the domain
/// and may fail namespace creation — run `cargo run -- enter` outside Landlock
/// for full viewer support.
pub fn execute<F>(
    physical_vault: &mut std::fs::File,
    file_index: &FileIndex,
    unlocked_vault: &UnlockedVault,
    on_close: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnOnce() + Send + 'static,
{
    let memfd_file = prepare_decrypted_memfd(physical_vault, file_index, unlocked_vault)?;
    let raw_fd = memfd_file.as_raw_fd();

    println!("Starting secure sandbox mode...");
    let pid = sandbox::spawn_in_bwrap_sandbox(raw_fd)?;

    std::thread::spawn(move || {
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        println!("Sandbox closed. Initiating memory shredding...");
        shred_memfd(memfd_file);
        on_close();
    });

    Ok(())
}
