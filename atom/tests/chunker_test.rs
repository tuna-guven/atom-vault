use atom::chunker;
use std::io::Cursor;

#[test]
fn test_streaming_chunker_boundaries() {
    // Simulate incoming network data stream
    let dummy_data = b"SECURE_DATA_BLOCK_ATOM".repeat(500);
    let mut network_stream = Cursor::new(dummy_data);

    // Collect boundaries into a static vector (Architecture B approach)
    let chunk_boundaries: Vec<_> = chunker::chunk_data(&mut network_stream).collect();

    // Verify stream processing
    assert!(!chunk_boundaries.is_empty(), "Chunk stream should yield boundaries");
    
    let first_chunk_info = chunk_boundaries[0].as_ref().unwrap();
    assert!(first_chunk_info.length > 0, "Chunk length must be greater than 0");
    assert_eq!(first_chunk_info.offset, 0, "First chunk offset must start at 0");
}