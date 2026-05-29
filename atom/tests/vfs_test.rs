use atom::vfs::{MemFile, process_secure_chunk, VaultMetadata, FileIndex, ChunkEntry};
use atom::crypto;
use zeroize::Zeroizing;
use std::io::{Write, Read, Seek, SeekFrom};
use std::fs::OpenOptions;

#[test]
fn test_memfile_creation_and_basic_io() {
    let mut file = MemFile::new("basic_io_test", 1024 * 1024).unwrap();
    let test_data = b"ATOM_VOLATILE_STORAGE_TEST";
    
    let written = file.write(test_data).unwrap();
    assert_eq!(written, test_data.len());

    file.seek(SeekFrom::Start(0)).unwrap();
    let mut buffer = vec![0u8; test_data.len()];
    file.read_exact(&mut buffer).unwrap();
    assert_eq!(buffer, test_data);
}

#[test]
fn test_bincode_vault_metadata_serialization_loop() {
    let test_file_path = "test_metadata_io.aegis";
    
    // Crypto Setup
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("test_password", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(test_file_path)
        .unwrap();

    // 1. Create mock structured Bincode metadata layouts with offset attributes
    let chunk_1 = ChunkEntry { cipher_len: 128, offset: 0, nonce: [1u8; crypto::XNONCE_LEN] };
    let chunk_2 = ChunkEntry { cipher_len: 256, offset: 0, nonce: [2u8; crypto::XNONCE_LEN] };
    let file_index = FileIndex {
        vfs_name: "secure_payload.bin".to_string(),
        chunks: vec![chunk_1, chunk_2],
    };
    let original_metadata = VaultMetadata { file_table: vec![file_index] };

    // 2. Serialize and encrypt to disk layout
    let raw_bytes = bincode::serialize(&original_metadata).unwrap();
    let secure_buffer = Zeroizing::new(raw_bytes);
    let (ciphertext, metadata_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();
    let ciphertext_len = ciphertext.len() as u64;

    file.write_all(&ciphertext_len.to_le_bytes()).unwrap();
    file.write_all(&metadata_nonce).unwrap();
    file.write_all(&ciphertext).unwrap();

    // 3. Simulating app restart: read back, decrypt and deserialize
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut len_bytes = [0u8; 8];
    file.read_exact(&mut len_bytes).unwrap();
    let read_cipher_len = u64::from_le_bytes(len_bytes) as usize;

    let mut read_nonce = [0u8; crypto::XNONCE_LEN];
    file.read_exact(&mut read_nonce).unwrap();

    let mut read_cipher_buffer = vec![0u8; read_cipher_len];
    file.read_exact(&mut read_cipher_buffer).unwrap();

    let decrypted_bytes = crypto::decrypt_chunk(&unlocked_vault, &read_cipher_buffer, &read_nonce).unwrap();
    let parsed_metadata: VaultMetadata = bincode::deserialize(&decrypted_bytes).unwrap();

    // 4. Structural Verification
    assert_eq!(parsed_metadata.file_table.len(), 1);
    assert_eq!(parsed_metadata.file_table[0].vfs_name, "secure_payload.bin");
    assert_eq!(parsed_metadata.file_table[0].chunks.len(), 2);
    assert_eq!(parsed_metadata.file_table[0].chunks[0].cipher_len, 128);

    let _ = std::fs::remove_file(test_file_path);
}

#[test]
fn test_process_secure_chunk_callback_execution() {
    let mut mem_file = MemFile::new("secure_chunk_test", 1024 * 1024).unwrap();
    
    // Crypto Setup
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("test_pass", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    // 1. Write encrypted dummy data to simulated RAM disk
    let raw_payload = b"SECRET_CHUNK_DATA";
    let secure_buffer = Zeroizing::new(raw_payload.to_vec());
    let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();
    
    mem_file.write_all(&ciphertext).unwrap();
    mem_file.seek(SeekFrom::Start(0)).unwrap();

    // 2. Execute process_secure_chunk and capture decrypted plaintext inside closure
    let mut validated_data = Vec::new();
    process_secure_chunk(
        &mut mem_file,
        ciphertext.len(),
        &chunk_nonce,
        &unlocked_vault,
        |plaintext| {
            validated_data.extend_from_slice(plaintext);
        }
    ).unwrap();

    // 3. Assert callback executed successfully with correct context match
    assert_eq!(validated_data, raw_payload);
}