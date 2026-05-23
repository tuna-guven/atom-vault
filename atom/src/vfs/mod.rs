use std::os::fd::{OwnedFd, AsRawFd}; 
use std::ffi::CString;
use std::io::{Write, Read, Seek, SeekFrom, Result as IoResult, Error, ErrorKind};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::unistd::{ftruncate, lseek, Whence};

pub struct MemFile {
    fd: OwnedFd,
    fixed_size: usize,
}

impl MemFile {
    pub fn new(vault_name: &str, vault_size: usize) -> Result<Self, Box<dyn std::error::Error>>{
        let vault_name = CString::new(vault_name)?;

        // we want from linux to create an empty file for us
        let fd = memfd_create(&vault_name, MemFdCreateFlag::MFD_CLOEXEC)?;
        
        // we want vault to be fixed size
        ftruncate(&fd, vault_size as i64)?;

        Ok(Self { 
            fd, 
            fixed_size: vault_size
        })        
    }
}

// we are making a contract with the trait of std::io::write so that our file is not just any file but can write 
impl Write for MemFile {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize>{
        let written_size = nix::unistd::write(&self.fd, buf)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(written_size)     
    }

    fn flush(&mut self) -> IoResult<()>{
        Ok(())
    }
}

impl Read for MemFile {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize>{
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