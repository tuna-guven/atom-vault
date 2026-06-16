use std::os::fd::{OwnedFd, AsRawFd}; 
use std::ffi::CString;
use std::io::{Write, Read, Seek, SeekFrom, Result as IoResult, Error, ErrorKind};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::unistd::{ftruncate, lseek, Whence};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkEntry {
    pub cipher_len: usize,
    pub offset: u64,
    // TODO: Replace random bytes with deterministic nonce generation using a Merkle tree approach
    pub nonce: [u8; crate::crypto::XNONCE_LEN],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileIndex {
    pub vfs_name: String,
    pub chunks: Vec<ChunkEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMetadata {
    pub file_table: Vec<FileIndex>,
    pub cdc_salt: [u8; 32],
}

/// Decrypts a chunk directly into memory, locks it to prevent swapping, 
/// executes the provided closure, and guarantees memory zeroing even on panic.
pub fn process_secure_chunk<F>(
    physical_vault: &mut std::fs::File,
    cipher_len: usize,
    nonce: &[u8; crate::crypto::XNONCE_LEN],
    unlocked_vault: &crate::crypto::UnlockedVault,
    chunk_offset: u64,
    action: F,   
) -> std::io::Result<()> where F: FnOnce(&[u8]), {

    physical_vault.seek(SeekFrom::Start(chunk_offset))?;

    let mut cipher_buffer = vec![0u8; cipher_len];
    physical_vault.read_exact(&mut cipher_buffer)?;

    let mut secure_plaintext = crate::crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, nonce, chunk_offset)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Decryption error: {:?}", e)))?;
    
    // Lock memory page to prevent OS from swapping plaintext to disk
    let mlock_result = unsafe {
        libc::mlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len())
    };
    if mlock_result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Isolate execution to ensure sensitive data is wiped even if the action panics
    let action_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        action(&secure_plaintext);
    }));

    // Zero-out the buffer immediately after use
    secure_plaintext.zeroize();

    unsafe {
        libc::munlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len());
    }

    // Resume panic if the action failed, maintaining safety guarantees
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
        let flags = MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING;
        let fd = memfd_create(&vault_name, flags)?;

        // Allocate strict file size
        ftruncate(&fd, vault_size as i64)?;

        let raw_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),                 
                vault_size,                           
                libc::PROT_READ | libc::PROT_WRITE,   
                libc::MAP_SHARED,                     
                fd.as_raw_fd(),                       
                0                                     
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
                libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL
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
        nix::unistd::read(self.fd.as_raw_fd(), buf).map_err(|e| Error::new(ErrorKind::Other, e))
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