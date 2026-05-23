mod crypto;
mod vfs;
mod chunker;

use std::io::{Write, Seek, SeekFrom};

fn main() {
    println!("Atom-Vault is starting...");

    let mut vault = vfs::MemFile::new("atom_vault", 50 * 1024 * 1024).unwrap();

    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    vault.write_all(&b"SYSTEM_DATA".repeat(500)).unwrap();
    vault.seek(SeekFrom::Start(0)).unwrap();

    let chunks = chunker::chunk_data(&mut vault).unwrap();

    if let Some(first_chunk) = chunks.first() {
        let (_ciphertext, _chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &first_chunk.data).unwrap();
    }
}