use nix::sys::memfd::{MemFdCreateFlag, memfd_create};
use nix::unistd::{Whence, ftruncate, lseek};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::io::{Error, ErrorKind, Read, Result as IoResult, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkEntry {
    pub cipher_len: usize,
    pub offset: u64,
    // with merkle tree we would get deterministic nonce here instead of creating totally random bytes
    pub nonce: [u8; crate::crypto::XNONCE_LEN],
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

pub fn process_secure_chunk<F>(
    physical_vault: &mut std::fs::File, // Bypass RAM disk and read straight from SSD
    cipher_len: usize,
    nonce: &[u8; crate::crypto::XNONCE_LEN],
    unlocked_vault: &crate::crypto::UnlockedVault,
    chunk_offset: u64, // Required for the new AAD chunk reordering protection
    action: F,
) -> std::io::Result<()>
where
    F: FnOnce(&[u8]),
{
    let mut cipher_buffer = vec![0u8; cipher_len];
    physical_vault.read_exact(&mut cipher_buffer)?;

    let mut secure_plaintext =
        crate::crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, nonce, chunk_offset).map_err(
            |e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Decryption error: {:?}", e),
                )
            },
        )?;

    // Lock on ram to prevent swap leakage
    let mlock_result = unsafe {
        libc::mlock(
            secure_plaintext.as_ptr() as *const libc::c_void,
            secure_plaintext.len(),
        )
    };
    if mlock_result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Execute closure with panic-catching to guarantee zeroization even on crash
    let action_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        action(&secure_plaintext);
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

    if let Err(err) = action_result {
        std::panic::resume_unwind(err);
    }

    Ok(())
}


pub struct MemFile {
    fd: OwnedFd,
    fixed_size: usize,
    memory_ptr: std::ptr::NonNull<libc::c_void>,
}

impl MemFile {
    pub fn new(vault_name: &str, vault_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let vault_name = CString::new(vault_name)?;

        // we want from linux to create an empty file for us
        let flags = MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING;
        let fd = memfd_create(&vault_name, flags)?;

        // we want vault to be fixed size
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

        // Apply OS-level seals to prevent the file from being resized or swapped
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

impl Drop for MemFile {
    fn drop(&mut self) {
        unsafe {
            // Explicitly wipe the mapped memory with 0s before unmapping
            self.memory_ptr.as_ptr().write_bytes(0, self.fixed_size);
            libc::munmap(self.memory_ptr.as_ptr(), self.fixed_size);
        }
    }
}

// Implement standard I/O traits
impl Write for MemFile {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let written_size =
            nix::unistd::write(&self.fd, buf).map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(written_size)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl Read for MemFile {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let read_size = nix::unistd::read(self.fd.as_raw_fd(), buf)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(read_size)
    }
}

impl Seek for MemFile {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (n as i64, Whence::SeekSet),
            SeekFrom::Current(n) => (n, Whence::SeekCur),
            SeekFrom::End(n) => (n, Whence::SeekEnd),
        };

        let new_pos = lseek(self.fd.as_raw_fd(), offset, whence)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(new_pos as u64)
    }
}
