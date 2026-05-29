use atom::vfs::MemFile; // Kendi crate adını (atom) buraya yazıyorsun
use std::io::{Write, Read, Seek, SeekFrom};

#[test]
fn test_memfile_creation_and_io() {
    // Sudo gerektirmeden 1 MB'lık güvenli RAM disk oluşturabiliyor muyuz?
    let mut file = MemFile::new("test_vault", 1024 * 1024).unwrap();
    
    // İçine veri yazmayı dene
    let test_data = b"HELLO_ATOM_VAULT";
    let written = file.write(test_data).unwrap();
    assert_eq!(written, test_data.len(), "Written size must match data length");

    // İmleci başa sar ve geri okumayı dene
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut buffer = vec![0u8; test_data.len()];
    file.read_exact(&mut buffer).unwrap();

    assert_eq!(buffer, test_data, "Read plaintext must match written data");
}