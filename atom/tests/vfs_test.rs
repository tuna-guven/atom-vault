use atom::vfs::{MemFile, process_secure_chunk};
use atom::crypto;
use zeroize::Zeroizing;
use std::io::{Write, Read, Seek, SeekFrom};
use std::fs::OpenOptions;

#[test]
fn test_memfile_creation_and_basic_io() {
    // RAM diskin başarıyla oluşturulup veri kabul edip etmediği testi
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
fn test_vfs_architecture_ingress_and_mount() {
    let vault_size = 5 * 1024 * 1024;
    let test_file_path = "test_run_tuna_architecture.aegis";
    
    // 1. Cryptographic Setup
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("test_password", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    // 2. Ingress Simulation (Write ciphertext to physical disk)
    let mut physical_vault = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(test_file_path)
        .unwrap();

    let original_plaintext = b"CONFIDENTIAL_ENGINEERING_DATA".repeat(100);
    
    let mut secure_buffer = Zeroizing::new(original_plaintext.clone());
    unsafe { libc::mlock(secure_buffer.as_ptr() as *const libc::c_void, secure_buffer.len()); }
    let (ciphertext, chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();
    physical_vault.write_all(&ciphertext).unwrap();
    unsafe { libc::munlock(secure_buffer.as_ptr() as *const libc::c_void, secure_buffer.len()); }

    let cipher_len = ciphertext.len();

    // 3. Mount/Unlock Simulation 
    let mut mounted_vfs = MemFile::new("mount_test_vault", vault_size).unwrap();
    
    // CRITICAL FIX: Önce şifreli veriyi tam olarak SSD'den (physical_vault) RAM diskimize (mounted_vfs) yazıyoruz.
    // Böylece process_secure_chunk RAM diskten okuma yaptığında şifreli doğru veriyi bulacak!
    physical_vault.seek(SeekFrom::Start(0)).unwrap();
    mounted_vfs.seek(SeekFrom::Start(0)).unwrap();
    
    let mut cipher_disk_buffer = vec![0u8; cipher_len];
    physical_vault.read_exact(&mut cipher_disk_buffer).unwrap();
    mounted_vfs.write_all(&cipher_disk_buffer).unwrap();

    // RAM diski tekrar başa sar ki process_secure_chunk sıfırıncı adresten şifreli veriyi okuyabilsin
    mounted_vfs.seek(SeekFrom::Start(0)).unwrap();

    let mut decrypted_payload = Vec::new();

    // process_secure_chunk artık aradığı şifreli veriyi mounted_vfs içinde bulacak, 
    // çözecek, mlock ile koruma altına alıp closure'a teslim edecek!
    process_secure_chunk(
        &mut mounted_vfs,
        cipher_len,
        &chunk_nonce,
        &unlocked_vault,
        |secure_plaintext| {
            decrypted_payload.extend_from_slice(secure_plaintext);
        }
    ).unwrap(); 

    // RAM diskimizi tamamen temizleyip deşifre edilmiş gerçek veriyi üzerine yazıyoruz
    mounted_vfs.seek(SeekFrom::Start(0)).unwrap();
    mounted_vfs.write_all(&decrypted_payload).unwrap();

    // 4. Verification
    mounted_vfs.seek(SeekFrom::Start(0)).unwrap();
    let mut final_check_buffer = vec![0u8; original_plaintext.len()];
    mounted_vfs.read_exact(&mut final_check_buffer).unwrap();
    
    assert_eq!(final_check_buffer, original_plaintext, "Mounted RAM disk data must match original plaintext!");

    // 5. Cleanup
    let _ = std::fs::remove_file(test_file_path);
}