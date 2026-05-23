use std::io::Read;
use fastcdc::v2020::FastCDC;

pub struct Chunk{
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
}

pub fn chunk_data<R: Read>(mut source: R) -> Result<Vec<Chunk>, std::io::Error>{
    let mut buffer = Vec::new();
    source.read_to_end(&mut buffer)?;

    let min_size = 2048;
    let avg_size = 4096;
    let max_size = 8192;
    let chunker = FastCDC::new(&buffer, min_size, avg_size, max_size);
    
    let mut chunks: Vec<Chunk> = Vec::new();
    for entry in chunker{
        let start = entry.offset;
        let end = start + entry.length;

        let chunk_data = buffer[start..end].to_vec();
        chunks.push(Chunk { 
            offset: entry.offset as u64, 
            length: entry.length, 
            data: chunk_data 
        });
    }
    Ok(chunks)
}