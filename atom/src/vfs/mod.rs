use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::unistd::{Whence, ftruncate, lseek};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::io::{Error, ErrorKind, Read, Result as IoResult, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkEntry {
    /// Length of the complete on-disk v1 blob, including the magic prefix,
    /// per-chunk salt, nonce and AEAD tag.
    pub cipher_len: usize,
    pub offset: u64,
    /// Random per-chunk identifier. Feeds both the HKDF `info` and the AEAD's
    /// AAD, binding the blob to this specific chunk.
    ///
    /// The former `nonce` field is gone: the nonce now travels inside the blob
    /// itself (§7), alongside the per-chunk salt.
    pub file_id: [u8; crate::crypto::FILE_ID_LEN],
    /// Actual plaintext length before uniform padding.  Zero means "no padding"
    /// (legacy vaults written before uniform-padding was introduced).
    #[serde(default)]
    pub plain_len: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileIndex {
    pub vfs_name: String,
    pub chunks: Vec<ChunkEntry>,
    // KEPT FROM P2P BRANCH: Required for Briar-style vector clock syncing
    pub last_modified_unix: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMetadata {
    pub file_table: Vec<FileIndex>,
    pub cdc_salt: [u8; 32],
}

/// Decrypts a chunk directly into memory, locks it to prevent swapping,
/// executes the provided closure, and guarantees memory zeroing even on panic.
///
/// `plain_len` is the byte count of actual content before uniform padding.
/// Pass `0` for legacy chunks that were written without padding.
pub fn process_secure_chunk<F>(
    physical_vault: &mut std::fs::File,
    cipher_len: usize,
    file_id: &[u8; crate::crypto::FILE_ID_LEN],
    unlocked_vault: &crate::crypto::UnlockedVault,
    chunk_offset: u64,
    plain_len: usize,
    action: F,
) -> std::io::Result<()>
where
    F: FnOnce(&[u8]),
{
    physical_vault.seek(SeekFrom::Start(chunk_offset))?;

    let mut cipher_buffer = vec![0u8; cipher_len];
    physical_vault.read_exact(&mut cipher_buffer)?;

    let mut secure_plaintext =
        crate::crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, file_id).map_err(|e| {
            Error::new(ErrorKind::InvalidData, format!("Decryption error: {:?}", e))
        })?;

    // Lock memory page to prevent OS from swapping plaintext to disk
    let mlock_result = unsafe {
        libc::mlock(
            secure_plaintext.as_ptr() as *const libc::c_void,
            secure_plaintext.len(),
        )
    };
    if mlock_result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Strip uniform padding: use plain_len when set, otherwise pass the full slice (legacy).
    let content = if plain_len > 0 {
        &secure_plaintext[..plain_len]
    } else {
        &secure_plaintext[..]
    };

    // Isolate execution to ensure sensitive data is wiped even if the action panics
    let action_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        action(content);
    }));

    // Securely overwrite the plaintext in RAM
    secure_plaintext.zeroize();

    unsafe {
        libc::munlock(
            secure_plaintext.as_ptr() as *const libc::c_void,
            secure_plaintext.len(),
        );
    }

    // Resume the panic if the closure failed
    if let Err(err) = action_result {
        std::panic::resume_unwind(err);
    }

    Ok(())
}

/// A highly secure, memory-backed file representation using Linux memfd and mmap.
pub struct MemFile {
    fd: OwnedFd,
    fixed_size: usize,
    memory_ptr: std::ptr::NonNull<libc::c_void>,
}

impl MemFile {
    pub fn new(vault_name: &str, vault_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let vault_name = CString::new(vault_name)?;

        // Enforce CLOEXEC to prevent file descriptor leaking to child processes
        let flags = MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING;
        let fd = memfd_create(vault_name.as_c_str(), flags)?;

        // Allocate strict file size
        ftruncate(&fd, vault_size as i64)?;

        let raw_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),               // OS shall pick an address which is empty
                vault_size,                         // Memory size to be mapped
                libc::PROT_READ | libc::PROT_WRITE, // both write and read permissions
                libc::MAP_SHARED,                   // changes shall affect the file
                fd.as_raw_fd(),                     // our ram file's ID
                0,                                  // offset from the doc header
            )
        };

        if raw_ptr == libc::MAP_FAILED {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        // Seal the file to prevent unauthorized resizing
        unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
            );
        }

        Ok(Self {
            fd,
            fixed_size: vault_size,
            memory_ptr: std::ptr::NonNull::new(raw_ptr).unwrap(),
        })
    }
}

// Extract raw FD for Landlock isolation bindings
impl std::os::fd::AsRawFd for MemFile {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

// Anti-forensics: Force overwrite mapped memory with zeros before unmapping
impl Drop for MemFile {
    fn drop(&mut self) {
        unsafe {
            // Explicitly wipe the mapped memory with 0s before unmapping
            self.memory_ptr.as_ptr().write_bytes(0, self.fixed_size);
            libc::munmap(self.memory_ptr.as_ptr(), self.fixed_size);
        }
    }
}

impl Write for MemFile {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        nix::unistd::write(&self.fd, buf).map_err(|e| Error::new(ErrorKind::Other, e))
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl Read for MemFile {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        nix::unistd::read(&self.fd, buf).map_err(|e| Error::new(ErrorKind::Other, e))
    }
}

impl Seek for MemFile {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (n as i64, Whence::SeekSet),
            SeekFrom::Current(n) => (n, Whence::SeekCur),
            SeekFrom::End(n) => (n, Whence::SeekEnd),
        };

        let new_pos =
            lseek(&self.fd, offset, whence).map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(new_pos as u64)
    }
}
