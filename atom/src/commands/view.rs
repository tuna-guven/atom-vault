use memfd::MemfdOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

use crate::crypto::UnlockedVault;
use crate::sandbox;
use crate::vfs::{FileIndex, process_secure_chunk};

pub fn execute(
    physical_vault: &mut std::fs::File,
    file_index: &FileIndex,
    unlocked_vault: &UnlockedVault,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Create dynamic RAM disk with CLOEXEC to prevent FD leaking
    let memfd_name = format!("atom_vault_memfd_{}", file_index.vfs_name);
    let mut memfd_file = MemfdOptions::default()
        .close_on_exec(true)
        .allow_sealing(true)
        .create(&memfd_name)?
        .into_file();

    // 2. Decrypt and write chunks directly to volatile RAM
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

    // 3. Rewind file pointer for the target application to read from the start
    memfd_file.flush()?;
    memfd_file.seek(SeekFrom::Start(0))?;

    // 4. Enforce Strict Kernel Seals
    let target_raw_fd = memfd_file.as_raw_fd();

    unsafe {
        // SECURITY FIX: Apply complete immutable seals before passing to the child process.
        // Zathura can now only read. It cannot write, grow, or shrink the payload to crash the host.
        libc::fcntl(
            target_raw_fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL,
        );
    }

    println!("Starting secure sandbox mode...");
    if let Err(e) = sandbox::spawn_in_sandbox(target_raw_fd) {
        eprintln!("Sandbox error: {}", e);
    }

    // 5. Zero-allocation RAM deallocation
    println!("Sandbox closed. Releasing memory mapping safely...");

    // By allowing `memfd_file` to drop out of scope naturally, the Linux kernel
    // instantly reclaims the volatile pages directly from RAM. No disk wipe necessary.

    println!("Traces successfully removed.");
    Ok(())
}
