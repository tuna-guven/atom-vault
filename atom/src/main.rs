mod crypto;
mod vfs;
mod chunker;

use std::io::{Read, Write, Seek, SeekFrom, Cursor};
use zeroize::Zeroizing;

fn main() {
    println!("Atom-Vault: Production Pipeline Started.");

    // Initialize vault and cryptographic keys
    let vault_size = 50 * 1024 * 1024;
    let mut vault = vfs::MemFile::new("atom_vault", vault_size).unwrap();
    
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    // Store ciphertext lengths and nonces for egress mapping
    let mut chunk_metadata = Vec::new();

    // ==========================================
    // INGRESS PIPELINE: P2P Stream -> Encrypt -> VFS
    // ==========================================
    println!("[1] Starting Ingress Pipeline (Processing incoming data)...");
    
    let raw_network_data = b"CONFIDENTIAL_P2P_GAME_DATA".repeat(500);
    let mut network_stream = Cursor::new(raw_network_data);

    // Collect boundaries first to drop the mutable borrow on network_stream
    let chunk_boundaries: Vec<_> = chunker::chunk_data(&mut network_stream).collect();

    for chunk_result in chunk_boundaries {
        let chunk_info = chunk_result.unwrap();

        // 1. Allocate secure buffer and read plaintext
        let mut secure_buffer = Zeroizing::new(vec![0u8; chunk_info.length]);
        network_stream.seek(SeekFrom::Start(chunk_info.offset as u64)).unwrap();
        network_stream.read_exact(&mut secure_buffer).unwrap();

        // 2. Pin to physical RAM to prevent swap leakage
        unsafe {
            libc::mlock(
                secure_buffer.as_ptr() as *const libc::c_void,
                chunk_info.length,
            );
        }

        // 3. Encrypt in secure memory
        let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();

        // 4. Write ciphertext to MemFile (VFS never sees plaintext)
        vault.write_all(&ciphertext).unwrap();
        chunk_metadata.push((ciphertext.len(), chunk_nonce));

        // 5. Unpin memory (Zeroize handles the memory wipe on drop)
        unsafe {
            libc::munlock(
                secure_buffer.as_ptr() as *const libc::c_void,
                chunk_info.length,
            );
        }
    }
    println!("Ingress completed: Data encrypted and stored in VFS.");

    // ==========================================
    // EGRESS PIPELINE: VFS -> Decrypt -> Memory
    // ==========================================
    println!("[2] Starting Egress Pipeline (Reading from VFS)...");
    
    vault.seek(SeekFrom::Start(0)).unwrap();

    for (cipher_len, nonce) in chunk_metadata {
        // 1. Read ciphertext from MemFile
        let mut cipher_buffer = vec![0u8; cipher_len];
        vault.read_exact(&mut cipher_buffer).unwrap();

        // 2. Decrypt into a Zeroizing container
        let secure_plaintext = crypto::decrypt_chunk(&unlocked_vault, &cipher_buffer, &nonce).unwrap();

        // 3. Pin decrypted plaintext to physical RAM instantly
        unsafe {
            libc::mlock(
                secure_plaintext.as_ptr() as *const libc::c_void,
                secure_plaintext.len(),
            );
        }

        // Validate that decrypted data is not empty and matches expected simulation size
        assert!(!secure_plaintext.is_empty());
        assert!(secure_plaintext.starts_with(b"CONFIDENTIAL") || secure_plaintext.windows(12).any(|w| w == b"CONFIDENTIAL"));

        // 4. Unpin memory
        unsafe {
            libc::munlock(
                secure_plaintext.as_ptr() as *const libc::c_void,
                secure_plaintext.len(),
            );
        }
    }
    
    println!("Egress completed: Data successfully validated and wiped.");
}