use atom::vfs::MemFile;
use atom::chunker;
use std::io::{Write, Seek, SeekFrom};

#[test]
fn test_streaming_chunker_boundaries() {
    let mut file = MemFile::new("chunker_test_vault", 2 * 1024 * 1024).unwrap();
    
    // Chunker'ın sınırları bulabilmesi için tekrarlayan veri yazıyoruz
    let dummy_data = b"SECURE_DATA_BLOCK_ATOM".repeat(500);
    file.write_all(&dummy_data).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();

    // Akış motorunu tetikle
    let mut chunk_stream = chunker::chunk_data(&mut file);

    // En azından ilk parçanın başarıyla üretildiğini doğrula
    let first_chunk_result = chunk_stream.next();
    assert!(first_chunk_result.is_some(), "Chunk stream should yield at least one chunk");

    let chunk_info = first_chunk_result.unwrap().unwrap();
    assert!(chunk_info.length > 0, "Chunk length must be greater than 0");
    assert_eq!(chunk_info.offset, 0, "First chunk offset must start at 0");
}