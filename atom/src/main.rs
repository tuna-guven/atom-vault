mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use std::io::{Read, Write, Seek, SeekFrom};
use std::fs::{File, OpenOptions, rename};
use std::os::unix::net::UnixListener;
use std::fs::remove_file as rm_fs;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;

// Prevent split-brain compilation issues by importing directly from the library crate
use atom::chunker;
use atom::crypto;
use atom::vfs::{self, ChunkEntry, FileIndex, VaultMetadata};

fn save_vault_metadata(
    physical_vault: &mut File,
    metadata: &VaultMetadata,
    unlocked_vault: &crypto::UnlockedVault,
    payload_end_offset: u64, // Boundary where file chunks end and tail metadata begins
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_bytes = bincode::serialize(metadata)?;

    let secure_buffer = zeroize::Zeroizing::new(raw_bytes);
    unsafe {
        libc::mlock(
            secure_buffer.as_ptr() as *const libc::c_void,
            secure_buffer.len(),
        );
    }

    // Format authenticated AEAD errors using Debug formatting {:?}
    let (ciphertext, metadata_nonce) = crypto::encrypt_chunk(unlocked_vault, &secure_buffer)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Crypto error: {:?}", e),
            )
        })?;

    unsafe {
        libc::munlock(
            secure_buffer.as_ptr() as *const libc::c_void,
            secure_buffer.len(),
        );
    }

    // 1. Append encrypted metadata payload right at the end of the existing payload data area
    physical_vault.seek(SeekFrom::Start(payload_end_offset))?;
    let ciphertext_len = ciphertext.len() as u64;
    physical_vault.write_all(&ciphertext_len.to_le_bytes())?;
    physical_vault.write_all(&metadata_nonce)?;
    physical_vault.write_all(&ciphertext)?;

    // 2. Truncate trailing garbage ONLY if the container is running in dynamic expansion mode
    let new_eof = physical_vault.stream_position()?;
    if metadata.max_capacity.is_none() {
        physical_vault.set_len(new_eof)?;
    }

    // 3. Update the 8-byte master file pointer at offset 0 to point to this new tail metadata position
    physical_vault.seek(SeekFrom::Start(0))?;
    physical_vault.write_all(&payload_end_offset.to_le_bytes())?;

    Ok(())
}

fn load_vault_metadata(
    physical_vault: &mut File,
    unlocked_vault: &crypto::UnlockedVault,
) -> Result<(VaultMetadata, u64), Box<dyn std::error::Error>> {
    let file_len = physical_vault.metadata()?.len();

    // VFS GROUNDWORK: If completely fresh container file, initialize pointer right past offset 40 (8 bytes ptr + 32 bytes salt space)
    if file_len < 40 {
        physical_vault.seek(SeekFrom::Start(0))?;
        physical_vault.write_all(&40u64.to_le_bytes())?;
        
        // Fill the 32-byte salt space with dummy bytes for now (Tuna will overwrite this later)
        physical_vault.seek(SeekFrom::Start(8))?;
        physical_vault.write_all(&[0u8; 32])?;
        
        return Ok((VaultMetadata { file_table: Vec::new(), max_capacity: None }, 40));
    }

    // Read the 8-byte pointer to locate tail-based metadata
    physical_vault.seek(SeekFrom::Start(0))?;
    let mut ptr_bytes = [0u8; 8];
    physical_vault.read_exact(&mut ptr_bytes)?;
    let metadata_offset = u64::from_le_bytes(ptr_bytes).max(40);

    // Return empty table if the master pointer references space beyond current EOF bounds
    if metadata_offset >= file_len {
        return Ok((VaultMetadata { file_table: Vec::new(), max_capacity: None }, 40));
    }

    // Seek directly to the tail partition and parse out the layout structure
    physical_vault.seek(SeekFrom::Start(metadata_offset))?;
    let mut len_bytes = [0u8; 8];
    physical_vault.read_exact(&mut len_bytes)?;
    let read_cipher_len = u64::from_le_bytes(len_bytes) as usize;

    let mut metadata_nonce = [0u8; crypto::XNONCE_LEN];
    physical_vault.read_exact(&mut metadata_nonce)?;

    let mut cipher_buffer = vec![0u8; read_cipher_len];
    physical_vault.read_exact(&mut cipher_buffer)?;

    let decrypted_bytes = crypto::decrypt_chunk(unlocked_vault, &cipher_buffer, &metadata_nonce)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Metadata error: {:?}", e),
            )
        })?;

    unsafe {
        libc::mlock(
            decrypted_bytes.as_ptr() as *const libc::c_void,
            decrypted_bytes.len(),
        );
    }
    let metadata: VaultMetadata = bincode::deserialize(&decrypted_bytes)?;
    unsafe {
        libc::munlock(
            decrypted_bytes.as_ptr() as *const libc::c_void,
            decrypted_bytes.len(),
        );
    }

    // Return current structural layout and the exact offset where new chunks can be safely appended
    Ok((metadata, metadata_offset))
}

fn main() {
    let args = Cli::parse();
    let vault_size = 50 * 1024 * 1024;
    let vault_path = "my_data.aegis";
    let tmp_vault_path = "my_data.aegis.tmp";
    let pid_path = "vault.pid";

    // Handle LOCK command early before checking physical vault existence
    if let Commands::Lock = args.command {
        println!("[Wiping] Intercepting background mount daemon...");
        if let Ok(mut pid_file) = File::open(pid_path) {
            let mut pid_str = String::new();
            pid_file.read_to_string(&mut pid_str).unwrap();
            if let Ok(pid) = pid_str.trim().parse::<libc::pid_t>() {
                unsafe {
                    // Send SIGTERM to safely terminate the daemon process and unmap RAM pages
                    libc::kill(pid, libc::SIGTERM);
                }
                let _ = rm_fs(pid_path);
                let _ = rm_fs("/tmp/atom_vault.sock");
                println!("[Success] Vault memory space locked. Foreground mount daemon reaped.");
                return;
            }
        }
        println!("Notification: No active mount daemon process detected.");
        return;
    }

    let salt = [0u8; 32];
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = [42u8; 32];
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    // CRITICAL FIX: Handle CREATE command before loading existing metadata from disk
    if let Commands::Create { size } = args.command {
        println!("[Factory] Initializing a new secure vault container...");
        
        let mut physical_vault = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true) // Force overwrite any broken old files cleanly
            .open(vault_path)
            .unwrap();

        let max_capacity = match size {
            Some(mb) => {
                let bytes = mb * 1024 * 1024;
                println!("[Pre-allocation] Reserving fixed size: {} MB ({} bytes)", mb, bytes);
                
                // Force allocate physical zeros across host sectors immediately
                physical_vault.set_len(bytes).expect("Failed to allocate physical fixed disk size");
                Some(bytes)
            }
            None => {
                println!("[Dynamic-Mode] No explicit size provided. Container will expand dynamically.");
                None
            }
        };

        // Write base structure layout boundaries (offset 0 and offset 8)
        physical_vault.seek(SeekFrom::Start(0)).unwrap();
        physical_vault.write_all(&40u64.to_le_bytes()).unwrap();
        physical_vault.write_all(&[0u8; 32]).unwrap();

        // Build fresh clean container layout memory map state
        let fresh_metadata = VaultMetadata {
            file_table: Vec::new(),
            max_capacity,
        };

        // VFS GROUNDWORK: Initial configuration commits at offset 40 to leave safe vacuum for the crypto module salt bytes
        save_vault_metadata(&mut physical_vault, &fresh_metadata, &unlocked_vault, 40).unwrap();
        println!("[Success] Vault layout successfully initialized. State table mended.");
        return; // Creation complete, terminate early
    }
    
    // For all other commands, open the vault in strict read/write mode (do NOT automatically truncate or corrupt)
    let mut physical_vault = OpenOptions::new()
        .read(true)
        .write(true)
        .open(vault_path)
        .expect("Error: Vault file 'my_data.aegis' not found. Run the 'create' command first.");

    let mut mounted_vfs = vfs::MemFile::new("atom_mount", vault_size).unwrap();

    // Safely load existing data maps
    let (mut metadata, mut current_payload_offset) = load_vault_metadata(&mut physical_vault, &unlocked_vault).unwrap();

    match args.command {
        Commands::Create { .. } => unreachable!(), // Handled early above

        Commands::Ls => {
            println!("--- Volatile VFS File Allocation Table ---");
            if metadata.file_table.is_empty() {
                println!("Vault is empty.");
            } else {
                for file in &metadata.file_table {
                    println!("File: {:<20} Chunks: {}", file.vfs_name, file.chunks.len());
                }
            }
        }

        Commands::Import {
            from_disk,
            vfs_name,
        } => {
            println!("[Ingress] Importing '{}'...", vfs_name);
            let mut input_file = File::open(&from_disk).expect("Failed to open local file");
            let chunk_boundaries: Vec<_> = chunker::chunk_data(&mut input_file).collect();

            let mut new_chunks = Vec::new();

            // Guard rails: If fixed size option is armed, check bounds before pushing raw strings
            if let Some(max_bytes) = metadata.max_capacity {
                let incoming_file_len = input_file.metadata().unwrap().len();
                // Estimate space requirements roughly: offset pointer + upcoming payload file size + safe padding
                if current_payload_offset + incoming_file_len + 10240 > max_bytes {
                    panic!("Critical Error: Out of pre-allocated storage bounds. Fixed size envelope limit reached.");
                }
            }

            // Seek directly to current payload end boundary to write fresh chunks over the old metadata location
            physical_vault
                .seek(SeekFrom::Start(current_payload_offset))
                .unwrap();

            for chunk_result in chunk_boundaries {
                let chunk_info = chunk_result.unwrap();
                let mut secure_buffer = zeroize::Zeroizing::new(vec![0u8; chunk_info.length]);

                input_file
                    .seek(SeekFrom::Start(chunk_info.offset as u64))
                    .unwrap();
                input_file.read_exact(&mut secure_buffer).unwrap();

                unsafe {
                    libc::mlock(
                        secure_buffer.as_ptr() as *const libc::c_void,
                        chunk_info.length,
                    );
                }
                let (ciphertext, chunk_nonce) =
                    crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();
                physical_vault.write_all(&ciphertext).unwrap();
                unsafe {
                    libc::munlock(
                        secure_buffer.as_ptr() as *const libc::c_void,
                        chunk_info.length,
                    );
                }

                new_chunks.push(ChunkEntry {
                    cipher_len: ciphertext.len(),
                    offset: current_payload_offset,
                    nonce: chunk_nonce,
                });

                // Advance track offset point linearly past the written encrypted block length
                current_payload_offset += ciphertext.len() as u64;
            }

            metadata.file_table.push(FileIndex {
                vfs_name,
                chunks: new_chunks,
            });
            save_vault_metadata(
                &mut physical_vault,
                &metadata,
                &unlocked_vault,
                current_payload_offset,
            )
            .unwrap();
            println!("Import complete. Tail-based metadata map serialized and pointer updated.");
        }

        Commands::Unlock { path } => {
            println!("[Mount] Unlocking vault from {} into volatile RAM...", path);
            mounted_vfs.seek(SeekFrom::Start(0)).unwrap();

            for file in &metadata.file_table {
                for chunk in &file.chunks {
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    let mut cipher_buffer = vec![0u8; chunk.cipher_len];
                    physical_vault.read_exact(&mut cipher_buffer).unwrap();

                    let current_vfs_pos = mounted_vfs.seek(SeekFrom::Current(0)).unwrap();
                    mounted_vfs.write_all(&cipher_buffer).unwrap();
                    mounted_vfs.seek(SeekFrom::Start(current_vfs_pos)).unwrap();

                    // SANITATION FIX: Plaintext accumulation wrapped inside secure zeroizing structure (Issue #10)
                    let mut decrypted_chunk = zeroize::Zeroizing::new(Vec::new());
                    vfs::process_secure_chunk(
                        &mut mounted_vfs,
                        chunk.cipher_len,
                        &chunk.nonce,
                        &unlocked_vault,
                        |secure_plaintext| {
                            decrypted_chunk.extend_from_slice(secure_plaintext);
                        },
                    )
                    .unwrap();

                    mounted_vfs.seek(SeekFrom::Start(current_vfs_pos)).unwrap();
                    mounted_vfs.write_all(&decrypted_chunk).unwrap();
                }
            }
            
            println!(
                "Vault successfully unlocked. Decrypted plaintext is live on virtual RAM disk."
            );

            // Validate volatile mapping context inside active RAM pages
            mounted_vfs.seek(SeekFrom::Start(0)).unwrap();
            let mut ram_verification = vec![0u8; 30];
            if mounted_vfs.read_exact(&mut ram_verification).is_ok() {
                println!(
                    "[Verification] Raw plaintext data read from volatile RAM: {:?}",
                    String::from_utf8_lossy(&ram_verification)
                );
            }

            // VFS DAEMONIZATION: Fork process to persist the memfd descriptor context in active memory pages
            println!("[Daemon] Forking execution into low-level Unix background page... ");
            unsafe {
                let pid = libc::fork();
                if pid < 0 {
                    panic!("Critical Error: Failed to spawn background VFS persistence daemon.");
                }
                if pid > 0 {
                    // Parent Process: Write the child's PID into tracking file and exit gracefully to host terminal
                    let mut pid_file = File::create(pid_path).unwrap();
                    write!(pid_file, "{}", pid).unwrap();
                    println!("[Success] Background daemon spawned under PID: {}. Ramdisk is persistent.", pid);
                    return;
                }
                // Child Process: Dissociate completely from host session controlling terminal context
                libc::setsid();
            }

            // VFS DAEMON IPC PIPELINE: Bind to a Unix Domain Socket for local inter-process communication
            let socket_path = "/tmp/atom_vault.sock";
            let _ = rm_fs(socket_path);

            let listener = UnixListener::bind(socket_path).expect("Critical Error: Failed to bind IPC Unix socket.");

            // Security Hardening: register signal hooks to intercept SIGTERM/SIGINT
            let mut signals = Signals::new(&[SIGTERM, SIGINT]).unwrap();

            std::thread::spawn(move || {
                for signal in signals.forever() {
                    match signal {
                        SIGTERM | SIGINT => {
                            println!("[Daemon] Shutdown signal received. Commencing memory sanitation...");
                            let _ = rm_fs("/tmp/atom_vault.sock");
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                }
            });

            listener.set_nonblocking(true).unwrap();

            // Background daemon incoming connections loop
            loop {
                match listener.accept() {
                    Ok((mut _stream, _addr)) => {
                        // tomorrow we can handle read/write requests over this stream
                        println!("[Daemon IPC] Connection received from virtual client context.");
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        }

        Commands::Lock => unreachable!(), // Handled early above

        Commands::Vacuum => {
            println!("[Compaction] Commencing optimized Zero-Crypto sequential repack...");
            
            let mut tmp_vault = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(tmp_vault_path)
                .unwrap();

            // Set up host structure limits if pre-allocated boundary mode is active
            if let Some(max_bytes) = metadata.max_capacity {
                tmp_vault.set_len(max_bytes).expect("Failed to pre-allocate temp file size");
            }

            // Initialize baseline structure points on temp container file
            tmp_vault.seek(SeekFrom::Start(0)).unwrap();
            tmp_vault.write_all(&40u64.to_le_bytes()).unwrap();
            tmp_vault.write_all(&[0u8; 32]).unwrap(); // Empty reserved salt container space

            let mut fresh_compacted_offset = 40u64;

            // Sequential Copy Loop: Pull out raw ciphertext blocks without cycle decryption overhead
            for file_entry in &mut metadata.file_table {
                for chunk in &mut file_entry.chunks {
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    
                    let mut cipher_buffer = vec![0u8; chunk.cipher_len];
                    physical_vault.read_exact(&mut cipher_buffer).unwrap();

                    tmp_vault.seek(SeekFrom::Start(fresh_compacted_offset)).unwrap();
                    tmp_vault.write_all(&cipher_buffer).unwrap();

                    // Re-bind the table schema offset attributes onto the dynamic temp target linear track
                    chunk.offset = fresh_compacted_offset;
                    fresh_compacted_offset += chunk.cipher_len as u64;
                }
            }

            // Serialize updated metadata map straight onto the tail of the temp file container
            save_vault_metadata(&mut tmp_vault, &metadata, &unlocked_vault, fresh_compacted_offset).unwrap();

            // Atomic Replacement: Safely swap files instantly at OS level
            drop(physical_vault);
            drop(tmp_vault);
            rename(tmp_vault_path, vault_path).expect("Failed to atomically replace container file context");
            println!("[Success] Vacuum complete. Discarded noise blocks reaped and footprint minimized.");
        }

        Commands::Export { vfs_name, to_disk } => {
            println!("[Egress] Exporting '{}' to '{}'...", vfs_name, to_disk);
            let mut output_file = File::create(&to_disk).expect("Failed to create output file");

            if let Some(file_entry) = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name) {
                for chunk in &file_entry.chunks {
                    physical_vault.seek(SeekFrom::Start(chunk.offset)).unwrap();
                    let mut cipher_buffer = vec![0u8; chunk.cipher_len];
                    physical_vault.read_exact(&mut cipher_buffer).unwrap();
                    
                    // SANITATION FIX: Plaintext vector securely isolated to clear on drop state (Issue #10)
                    let secure_plaintext = zeroize::Zeroizing::new(
                        crypto::decrypt_chunk(&unlocked_vault, &cipher_buffer, &chunk.nonce).unwrap()
                    );

                    unsafe {
                        libc::mlock(
                            secure_plaintext.as_ptr() as *const libc::c_void,
                            secure_plaintext.len(),
                        );
                    }
                    output_file.write_all(&secure_plaintext).unwrap();
                    unsafe {
                        libc::munlock(
                            secure_plaintext.as_ptr() as *const libc::c_void,
                            secure_plaintext.len(),
                        );
                    }
                }
                println!("Export complete. File safely extracted and written.");
            } else {
                println!("Error: File '{}' not found in vault index.", vfs_name);
            }
        }

        Commands::Rm { vfs_name } => {
            println!(
                "[Wiping] Commencing SSD-Safe Crypto-Shredding for '{}'...",
                vfs_name
            );

            // Purge the file entry and corresponding nonces out of the Bincode allocation layout.
            // Abandoned disk blocks become instant cryptographic noise, neutralizing FTL wear leveling vulnerabilities.
            if let Some(file_position) = metadata
                .file_table
                .iter()
                .position(|f| f.vfs_name == vfs_name)
            {
                metadata.file_table.remove(file_position);
                save_vault_metadata(
                    &mut physical_vault,
                    &metadata,
                    &unlocked_vault,
                    current_payload_offset,
                )
                .unwrap();
                println!(
                    "[Success] File '{}' crypto-shredded securely. SSD blocks abandoned.",
                    vfs_name
                );
            } else {
                println!("Error: File '{}' not found in vault index.", vfs_name);
            }
        }
    }
}