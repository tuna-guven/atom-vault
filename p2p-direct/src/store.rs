//! L1 / Mode A — the blind store and the upload/download orchestration.
//!
//! A [`BlindStore`] is a dumb, content-only key/value blob store: it maps an
//! opaque 32-byte object ID to bytes and back, and learns nothing else — no
//! plaintext, no filenames, no true size, no peer relationship. Upload and
//! download are decoupled in time, so the two peers never co-occur on the wire.
//!
//! [`upload`] runs L3→L2→L1: frame the stream, seal each block, PUT it under a
//! random ID, pad the count with random decoys, seal+PUT the manifest, and
//! return the [`ReadCap`] to be delivered over L4. [`download`] reverses it.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{self, AEAD_TAG_LEN};
use crate::encode::{self, BlockRef, EncodeParams, Manifest, MANIFEST_VERSION};
use crate::{Error, ReadCap, RootKey};

/// A content-only blob store. Implementations must treat IDs and bytes as
/// opaque and MUST NOT record who wrote or read them (that linkage is exactly
/// what Mode A exists to avoid).
#[async_trait]
pub trait BlindStore: Send + Sync {
    /// Store `data` under `id`. Overwriting an existing ID should be an error or
    /// a no-op; random 32-byte IDs make collisions negligible.
    async fn put(&self, id: &[u8; 32], data: &[u8]) -> Result<(), Error>;

    /// Fetch the bytes previously stored under `id`.
    async fn get(&self, id: &[u8; 32]) -> Result<Vec<u8>, Error>;
}

/// An in-memory [`BlindStore`] for tests and local round-trips.
#[derive(Default)]
pub struct InMemoryStore {
    objects: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of objects currently held — used by tests to assert the on-store
    /// block count (decoys included).
    pub fn len(&self) -> usize {
        self.objects.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lengths of every stored object. Used by tests to assert that all blocks
    /// (real and decoy) are byte-for-byte the same size — the store must not be
    /// able to fingerprint by length.
    pub fn object_lengths(&self) -> Vec<usize> {
        self.objects
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .collect()
    }
}

#[async_trait]
impl BlindStore for InMemoryStore {
    async fn put(&self, id: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        self.objects
            .lock()
            .unwrap()
            .insert(*id, data.to_vec());
        Ok(())
    }

    async fn get(&self, id: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.objects
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::Store("object not found".into()))
    }
}

/// An HTTP(S) [`BlindStore`]: `PUT`/`GET` `<base>/<hex-id>`. The endpoint only
/// needs to serve opaque IDs; it performs no auth of its own, so it cannot link
/// uploader to downloader.
#[cfg(feature = "http-store")]
pub struct HttpStore {
    base_url: String,
    client: reqwest::Client,
}

#[cfg(feature = "http-store")]
impl HttpStore {
    /// `base_url` is the object namespace, e.g. `https://store.example/blobs`.
    pub fn new(base_url: impl Into<String>) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(HttpStore {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        })
    }

    fn url(&self, id: &[u8; 32]) -> String {
        format!("{}/{}", self.base_url, hex::encode(id))
    }
}

#[cfg(feature = "http-store")]
#[async_trait]
impl BlindStore for HttpStore {
    async fn put(&self, id: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let resp = self
            .client
            .put(self.url(id))
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Store(format!("PUT returned {}", resp.status())));
        }
        Ok(())
    }

    async fn get(&self, id: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let resp = self
            .client
            .get(self.url(id))
            .send()
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Store(format!("GET returned {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| Error::Store(e.to_string()))
    }
}

/// Encode, encrypt, and upload `reader`'s full contents to `store` under a fresh
/// random `root`. Returns the [`ReadCap`] to deliver over L4.
///
/// Streams block-by-block: at most one block (plus its ciphertext) is held in
/// memory at a time, so a multi-GB vault does not need multi-GB of RAM.
pub async fn upload<R, S>(
    reader: &mut R,
    params: &EncodeParams,
    root: &RootKey,
    store: &S,
) -> Result<ReadCap, Error>
where
    R: AsyncRead + Unpin,
    S: BlindStore,
{
    let block_size = params.block_size;
    let ciphertext_len = block_size + AEAD_TAG_LEN;

    // --- L3→L2→L1: frame, seal, and PUT the real blocks as we read. ---
    let mut blocks: Vec<BlockRef> = Vec::new();
    let mut real_len: u64 = 0;
    let mut index: u32 = 0;

    loop {
        let Some((padded, filled)) = read_padded_block(reader, block_size).await? else {
            break;
        };
        real_len += filled as u64;

        let key = crypto::derive_block_key(root, index);
        let nonce = crypto::random_nonce();
        let ciphertext = crypto::seal(&key, &nonce, &padded)?;
        let object_id = crypto::random_object_id();

        store.put(&object_id, &ciphertext).await?;
        blocks.push(BlockRef {
            object_id,
            nonce,
            index: Some(index),
        });

        index = index
            .checked_add(1)
            .ok_or_else(|| Error::Malformed("stream exceeds 2^32 blocks".into()))?;
    }

    let real_blocks = blocks.len();
    let total_blocks = params.ladder.total_blocks(real_blocks);

    // --- Decoys: indistinguishable random blocks of the same ciphertext size. ---
    for _ in real_blocks..total_blocks {
        let mut decoy = vec![0u8; ciphertext_len];
        crypto::random_fill(&mut decoy);
        let object_id = crypto::random_object_id();
        store.put(&object_id, &decoy).await?;
        blocks.push(BlockRef {
            object_id,
            nonce: crypto::random_nonce(),
            index: None,
        });
    }

    // Shuffle so the store cannot tell real blocks from decoys by order.
    shuffle(&mut blocks);

    // --- Seal and PUT the manifest under its own random ID. ---
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        block_size: block_size as u32,
        real_len,
        blocks,
    };
    let manifest_bytes = bincode::serialize(&manifest)
        .map_err(|e| Error::Serialize(e.to_string()))?;
    let manifest_key = crypto::derive_manifest_key(root);
    let manifest_nonce = crypto::random_nonce();
    let sealed_manifest = crypto::seal(&manifest_key, &manifest_nonce, &manifest_bytes)?;

    // Store `nonce || ciphertext` so the recipient (who derives manifest_key
    // from the root) can open it.
    let mut manifest_object = Vec::with_capacity(manifest_nonce.len() + sealed_manifest.len());
    manifest_object.extend_from_slice(&manifest_nonce);
    manifest_object.extend_from_slice(&sealed_manifest);

    let manifest_id = crypto::random_object_id();
    store.put(&manifest_id, &manifest_object).await?;

    Ok(ReadCap {
        root_key: root.clone(),
        manifest_id,
    })
}

/// Fetch and decode a transfer described by `cap` from `store`, writing the
/// reconstructed plaintext stream to `writer`.
///
/// Verifies each block's AEAD tag (via decryption) and reassembles by block
/// index, truncating the final block to the manifest's `real_len`.
pub async fn download<W, S>(cap: &ReadCap, store: &S, writer: &mut W) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
    S: BlindStore,
{
    let root = &cap.root_key;

    // --- Fetch and open the manifest. ---
    let manifest_object = store.get(&cap.manifest_id).await?;
    if manifest_object.len() < crypto::NONCE_LEN {
        return Err(Error::Malformed("manifest object too short".into()));
    }
    let (nonce_bytes, sealed) = manifest_object.split_at(crypto::NONCE_LEN);
    let mut manifest_nonce = [0u8; crypto::NONCE_LEN];
    manifest_nonce.copy_from_slice(nonce_bytes);

    let manifest_key = crypto::derive_manifest_key(root);
    let manifest_bytes = crypto::open(&manifest_key, &manifest_nonce, sealed)?;
    let manifest: Manifest =
        bincode::deserialize(&manifest_bytes).map_err(|e| Error::Serialize(e.to_string()))?;

    if manifest.version != MANIFEST_VERSION {
        return Err(Error::Malformed(format!(
            "unsupported manifest version {}",
            manifest.version
        )));
    }
    let block_size = manifest.block_size as usize;

    // --- Reassemble real blocks in index order, ignoring decoys entirely. ---
    let ordered = manifest.real_blocks_ordered();
    let expected_blocks = encode::plan(
        manifest.real_len,
        &EncodeParams {
            block_size,
            ladder: encode::Ladder::Exact,
        },
    )
    .real_blocks;
    if ordered.len() != expected_blocks {
        return Err(Error::Malformed(format!(
            "manifest lists {} real blocks but real_len implies {}",
            ordered.len(),
            expected_blocks
        )));
    }

    let mut written: u64 = 0;
    for (expected_index, block) in ordered.iter().enumerate() {
        let idx = block.index.expect("real block has an index");
        if idx as usize != expected_index {
            return Err(Error::Malformed("real block indices are not contiguous".into()));
        }

        let ciphertext = store.get(&block.object_id).await?;
        let key = crypto::derive_block_key(root, idx);
        let plaintext = crypto::open(&key, &block.nonce, &ciphertext)?;
        if plaintext.len() != block_size {
            return Err(Error::Malformed("block plaintext has wrong length".into()));
        }

        // Trim the final block's zero-padding using the true length.
        let remaining = manifest.real_len - written;
        let take = (block_size as u64).min(remaining) as usize;
        writer.write_all(&plaintext[..take]).await?;
        written += take as u64;
    }

    writer.flush().await?;

    if written != manifest.real_len {
        return Err(Error::Malformed("reassembled length mismatch".into()));
    }
    Ok(())
}

/// Read up to `block_size` bytes, returning them zero-padded to `block_size`
/// along with the count of real bytes. `Ok(None)` at clean EOF.
async fn read_padded_block<R: AsyncRead + Unpin>(
    reader: &mut R,
    block_size: usize,
) -> Result<Option<(Vec<u8>, usize)>, Error> {
    let mut buf = vec![0u8; block_size];
    let mut filled = 0;
    while filled < block_size {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    if filled == 0 {
        Ok(None)
    } else {
        Ok(Some((buf, filled)))
    }
}

/// In-place Fisher–Yates shuffle using the OS RNG.
fn shuffle<T>(items: &mut [T]) {
    let n = items.len();
    if n <= 1 {
        return;
    }
    for i in (1..n).rev() {
        let j = random_below(i + 1);
        items.swap(i, j);
    }
}

/// Uniform random `usize` in `[0, bound)` via rejection sampling. `bound > 0`.
fn random_below(bound: usize) -> usize {
    debug_assert!(bound > 0);
    let bound_u = bound as u64;
    // Largest multiple of bound that fits in u64; reject above it to stay uniform.
    let zone = u64::MAX - (u64::MAX % bound_u);
    loop {
        let x = u64::from_le_bytes(crypto::random_array());
        if x < zone {
            return (x % bound_u) as usize;
        }
    }
}
