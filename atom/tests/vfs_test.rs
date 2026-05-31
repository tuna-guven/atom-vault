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

    // 1. Create mock structured Bincode metadata layouts with offset attributes
    let chunk_1 = ChunkEntry { cipher_len: 128, offset: 112, nonce: [1u8; crypto::XNONCE_LEN] };
    let chunk_2 = ChunkEntry { cipher_len: 256, offset: 240, nonce: [2u8; crypto::XNONCE_LEN] };
    let file_index = FileIndex {
        vfs_name: "secure_payload.bin".to_string(),
        chunks: vec![chunk_1, chunk_2],
    };
    let original_metadata = VaultMetadata { file_table: vec![file_index] };

    // 2. Serialize and encrypt metadata
    let raw_bytes = bincode::serialize(&original_metadata).unwrap();
    let (ciphertext, metadata_nonce) = crypto::encrypt_chunk(&unlocked_vault, &raw_bytes).unwrap();

    // Simulate Tail-Based Architecture layout: 
    // Header size (8+32+24+48 = 112). Payload starts at 112. 
    // In this mock, assume payload is empty and metadata starts right after header.
    let payload_end_offset = 112u64; 
    
    // Write the 8-byte master pointer at offset 0 pointing to metadata position
    file.write_all(&payload_end_offset.to_le_bytes()).unwrap();

    // Write the encrypted metadata payload at the specified dynamic offset
    file.seek(SeekFrom::Start(payload_end_offset)).unwrap();
    
    // YENİ MİMARİ: Artık uzunluk byte'ı yazmıyoruz, doğrudan Nonce ve Ciphertext basıyoruz
    file.write_all(&metadata_nonce).unwrap();
    file.write_all(&ciphertext).unwrap();

    // 3. Simulating app restart: read the 8-byte master pointer first
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut ptr_bytes = [0u8; 8];
    file.read_exact(&mut ptr_bytes).unwrap();
    let read_metadata_offset = u64::from_le_bytes(ptr_bytes);
    assert_eq!(read_metadata_offset, payload_end_offset);

    // Seek directly to the dynamic tail location using the parsed pointer
    file.seek(SeekFrom::Start(read_metadata_offset)).unwrap();
    
    let mut read_nonce = [0u8; crypto::XNONCE_LEN];
    file.read_exact(&mut read_nonce).unwrap();

    // YENİ MİMARİ: Uzunluk okumak yerine EOF (End Of File) gelene kadar tampona çekiyoruz
    let mut read_cipher_buffer = Vec::new();
    file.read_to_end(&mut read_cipher_buffer).unwrap();

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
    let test_file_path = "test_secure_chunk_io.bin";
    
    // Crypto Setup
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("test_pass", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    // 1. Write encrypted dummy data to a PHYSICAL mock file 
    // (Because process_secure_chunk now demands &mut std::fs::File for security boundaries)
    let raw_payload = b"SECRET_CHUNK_DATA";
    let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, raw_payload).unwrap();
    
    let mut physical_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(test_file_path)
        .unwrap();

    physical_file.write_all(&ciphertext).unwrap();
    physical_file.seek(SeekFrom::Start(0)).unwrap();

    // 2. Execute process_secure_chunk and capture decrypted plaintext inside closure
    let mut validated_data = Vec::new();
    process_secure_chunk(
        &mut physical_file,
        ciphertext.len(),
        &chunk_nonce,
        &unlocked_vault,
        |plaintext| {
            validated_data.extend_from_slice(plaintext);
        }
    ).unwrap();

    // 3. Assert callback executed successfully with correct context match
    assert_eq!(validated_data, raw_payload);

    let _ = std::fs::remove_file(test_file_path);
}