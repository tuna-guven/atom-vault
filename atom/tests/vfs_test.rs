use atom::vfs::{MemFile, process_secure_chunk, VaultMetadata, FileIndex, ChunkEntry};
use atom::crypto;
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

    // Create mock structured metadata layout
    let chunk_1 = ChunkEntry { cipher_len: 128, offset: 112, nonce: [1u8; crypto::XNONCE_LEN] };
    let chunk_2 = ChunkEntry { cipher_len: 256, offset: 240, nonce: [2u8; crypto::XNONCE_LEN] };
    let file_index = FileIndex {
        vfs_name: "secure_payload.bin".to_string(),
        chunks: vec![chunk_1, chunk_2],
    };
    
    // Instantiate metadata with the newly introduced cdc_salt field
    let original_metadata = VaultMetadata { 
        file_table: vec![file_index],
        cdc_salt: [0u8; 32], 
    };

    // Header layout configuration offset
    let payload_end_offset = 112u64; 

    // Serialize and encrypt metadata using offset as AAD
    let raw_bytes = bincode::serialize(&original_metadata).unwrap();
    let (ciphertext, metadata_nonce) = crypto::encrypt_chunk(
        &unlocked_vault, 
        &raw_bytes, 
        payload_end_offset
    ).unwrap();
    
    // Write 8-byte master pointer at offset 0
    file.write_all(&payload_end_offset.to_le_bytes()).unwrap();

    // Write encrypted metadata payload at target offset
    file.seek(SeekFrom::Start(payload_end_offset)).unwrap();
    file.write_all(&metadata_nonce).unwrap();
    file.write_all(&ciphertext).unwrap();

    // Parse the 8-byte master pointer
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut ptr_bytes = [0u8; 8];
    file.read_exact(&mut ptr_bytes).unwrap();
    let read_metadata_offset = u64::from_le_bytes(ptr_bytes);
    assert_eq!(read_metadata_offset, payload_end_offset);

    // Read metadata nonce and ciphertext
    file.seek(SeekFrom::Start(read_metadata_offset)).unwrap();
    let mut read_nonce = [0u8; crypto::XNONCE_LEN];
    file.read_exact(&mut read_nonce).unwrap();

    let mut read_cipher_buffer = Vec::new();
    file.read_to_end(&mut read_cipher_buffer).unwrap();

    // Decrypt metadata validating against its offset (AAD)
    let decrypted_bytes = crypto::decrypt_chunk(
        &unlocked_vault, 
        &read_cipher_buffer, 
        &read_nonce, 
        read_metadata_offset
    ).unwrap();
    
    let parsed_metadata: VaultMetadata = bincode::deserialize(&decrypted_bytes).unwrap();

    // Structural Verification
    assert_eq!(parsed_metadata.file_table.len(), 1);
    assert_eq!(parsed_metadata.file_table[0].vfs_name, "secure_payload.bin");
    assert_eq!(parsed_metadata.file_table[0].chunks.len(), 2);
    assert_eq!(parsed_metadata.file_table[0].chunks[0].cipher_len, 128);

    let _ = std::fs::remove_file(test_file_path);
}

#[test]
fn test_process_secure_chunk_callback_execution() {
    let test_file_path = "test_secure_chunk_io.bin";
    
    // Crypto Setup
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("test_pass", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    let mock_chunk_offset = 112u64;
    let raw_payload = b"SECRET_CHUNK_DATA";
    
    // Encrypt chunk bound to its destination offset
    let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(
        &unlocked_vault, 
        raw_payload, 
        mock_chunk_offset
    ).unwrap();
    
    let mut physical_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(test_file_path)
        .unwrap();

    // Persist payload at mock offset
    physical_file.seek(SeekFrom::Start(mock_chunk_offset)).unwrap();
    physical_file.write_all(&ciphertext).unwrap();
    
    physical_file.seek(SeekFrom::Start(mock_chunk_offset)).unwrap();

    // Execute safe pipeline and capture plaintext via callback enclosure
    let mut validated_data = Vec::new();
    process_secure_chunk(
        &mut physical_file,
        ciphertext.len(),
        &chunk_nonce,
        &unlocked_vault,
        mock_chunk_offset,
        |plaintext| {
            validated_data.extend_from_slice(plaintext);
        }
    ).unwrap();

    assert_eq!(validated_data, raw_payload);

    let _ = std::fs::remove_file(test_file_path);
}