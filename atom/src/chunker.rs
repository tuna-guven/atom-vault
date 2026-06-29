use fastcdc::v2020::StreamCDC;
use std::io::{BufReader, Read};

pub const MAX_CHUNK_SIZE: usize = 8192;

/// Chunks the data stream using content-defined chunking (FastCDC v2020).
/// Raw plaintext is fed directly into the chunker; fingerprinting resistance
/// is achieved by uniform-size padding before per-chunk AEAD encryption
/// rather than a broken repeating-key XOR pre-mask.
pub fn chunk_data<R: Read>(
    source: R,
) -> impl Iterator<Item = Result<fastcdc::v2020::ChunkData, std::io::Error>> {
    let min_size = 2048;
    let avg_size = 4096;

    let reader = BufReader::with_capacity(64 * 1024, source);
    let chunker = StreamCDC::new(reader, min_size, avg_size, MAX_CHUNK_SIZE as u32);

    chunker.map(|result| result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
}
