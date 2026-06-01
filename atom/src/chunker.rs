use std::io::{Read, BufReader};
use fastcdc::v2020::StreamCDC;

pub struct MaskedReader<R: Read> {
    inner: R,
    salt: [u8; 32],
    salt_index: usize,
}

impl<R: Read> MaskedReader<R> {
    pub fn new(inner: R, salt: &[u8; 32]) -> Self {
        Self {
            inner,
            salt: *salt,
            salt_index: 0,
        }
    }
}

impl<R: Read> Read for MaskedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.inner.read(buf)?;
        
        for byte in buf[..bytes_read].iter_mut() {
            *byte ^= self.salt[self.salt_index];
            self.salt_index = (self.salt_index + 1) % 32;
        }
        
        Ok(bytes_read)
    }
}

pub fn chunk_data<R: Read>(
    source: R, 
    cdc_salt: &[u8; 32]
) -> impl Iterator<Item = Result<fastcdc::v2020::ChunkData, std::io::Error>> {
    let min_size = 2048;
    let avg_size = 4096;
    let max_size = 8192;

    let masked_reader = MaskedReader::new(source, cdc_salt);

    // making streamCDC more performatic
    let reader = BufReader::with_capacity(64 * 1024, masked_reader);

    let chunker = StreamCDC::new(reader, min_size, avg_size, max_size);

    // turning fastcdc::Error -> std::io::Error
    chunker.map(|result| {
        result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    })
}