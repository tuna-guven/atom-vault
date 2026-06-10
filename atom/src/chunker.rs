use fastcdc::v2020::StreamCDC;
use std::io::{BufReader, Read};

/*
pub struct Chunk{
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
}
*/

pub fn chunk_data<R: Read>(
    source: R,
) -> impl Iterator<Item = Result<fastcdc::v2020::ChunkData, std::io::Error>> {
    let min_size = 2048;
    let avg_size = 4096;
    let max_size = 8192;

    // making streamCDC more performatic
    let reader = BufReader::new(source);

    let chunker = StreamCDC::new(reader, min_size, avg_size, max_size);

    // turning fastcdc::Error -> std::io::Error
    chunker.map(|result| result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
}
