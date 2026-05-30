use std::os::fd::{OwnedFd, AsRawFd}; 
use std::ffi::CString;
use std::io::{self, Write, Read, Seek, SeekFrom, Result as IoResult, Error, ErrorKind};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::unistd::{ftruncate, lseek, Whence};
use crate::crypto::{self, UnlockedVault, XNONCE_LEN};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkEntry {
    pub cipher_len: usize,
    pub offset: u64,
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
    pub max_capacity: Option<u64>,
}

pub fn process_secure_chunk<F>(
    vault: &mut MemFile,
    cipher_len: usize,
    nonce: &[u8; XNONCE_LEN],
    unlocked_vault: &UnlockedVault,
    action: F,   
) -> io::Result<()> where F: FnOnce(&[u8]), {
    // read the encrypted data from vfs into the buffer
    let mut cipher_buffer = vec![0u8; cipher_len];
    vault.read_exact(&mut cipher_buffer)?;

    // decrypt the file
    let secure_plaintext = crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, nonce)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Decryption error: {:?}", e)))?;
    
    // lock on ram to prevent swap leakage
    unsafe {
        libc::mlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len());
    }

    // execute closure with the locked plaintext
    action(&secure_plaintext);

    // unpin memory
    unsafe {
        libc::munlock(secure_plaintext.as_ptr() as *const libc::c_void, secure_plaintext.len());
    }

    Ok(())
}

pub struct MemFile {
    fd: OwnedFd,
    fixed_size: usize,
    memory_ptr: std::ptr::NonNull<libc::c_void>,
    // FIX: files ve current_write_offset alanları Bincode mimarisinde gereksiz olduğu için kaldırıldı.
}

impl MemFile {
    pub fn new(vault_name: &str, vault_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let vault_name = CString::new(vault_name)?;

        // we want from linux to create an empty file for us
        let fd = memfd_create(&vault_name, MemFdCreateFlag::MFD_CLOEXEC)?;
        
        // we want vault to be fixed size
        ftruncate(&fd, vault_size as i64)?;

        let raw_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),                 // OS shall pick an address which is empty
                vault_size,                           // Memory size to be mapped
                libc::PROT_READ | libc::PROT_WRITE,   // both write and read permissions
                libc::MAP_SHARED,                     // changes shall affect the file
                fd.as_raw_fd(),                       // our ram file's ID
                0                                     // offset from the doc header
            )
        };

        if raw_ptr == libc::MAP_FAILED {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        // FIX: Struct'tan sildiğimiz alanları constructor'dan da temizledik
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
            libc::munmap(self.memory_ptr.as_ptr(), self.fixed_size);
        }
    }
}

// we are making a contract with the trait of std::io::write so that our file is not just any file but can write 
impl Write for MemFile {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let written_size = nix::unistd::write(&self.fd, buf)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
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