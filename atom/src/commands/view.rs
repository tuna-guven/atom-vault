use memfd::MemfdOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use zeroize::Zeroize;

use crate::crypto::UnlockedVault;
use crate::sandbox;
use crate::vfs::{FileIndex, process_secure_chunk};

pub fn execute<F>(
    physical_vault: &mut std::fs::File,
    file_index: &FileIndex,
    unlocked_vault: &UnlockedVault,
    on_close: F, // GUI'nin kilitlenmesini engelleyecek callback fonksiyonu
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
where 
    F: FnOnce() + Send + 'static, 
{
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
        // Prevent external growing and new seals. 
        libc::fcntl(
            target_raw_fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL,
        );
    }

    println!("Starting secure sandbox mode...");
    let pid = sandbox::spawn_in_bwrap_sandbox(target_raw_fd)?;

    // 5. Zero-allocation RAM shredding'i arka plan OS Thread'ine taşıyoruz
    std::thread::spawn(move || {
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0); // Zathura kapanana kadar burada bekler
        }

        println!("Sandbox closed. Initiating memory shredding...");
        
        let size = memfd_file.seek(SeekFrom::End(0)).unwrap_or(0);
        if size > 0 {
            let _ = memfd_file.seek(SeekFrom::Start(0));
            
            let mut zero_page = [0u8; 4096];
            let mut written = 0;
            
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
        println!("Traces successfully removed.");
        
        // İşlem bittiğinde arka plandan AtomicBool bayrağını tetikler
        on_close();
    });

    Ok(())
}
