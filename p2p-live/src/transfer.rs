//! L3 live transfer protocol — chunked, resumable, integrity-checked
//! (roadmap Phase 2 / §2.1).
//!
//! Runs over any [`SecureSession`], so it is transport-agnostic: the same
//! protocol works over direct QUIC today and over the Tor onion (Phase 5)
//! unchanged.
//!
//! # Resume without loss
//!
//! The hard rule from the roadmap: **resume never persists key material.** Every
//! reconnection is a full, fresh hybrid-PQ handshake with new ephemeral keys.
//! What survives an outage is only *plaintext-payload progress* — a byte offset
//! and the partial file — never a key. A segment recorded before the drop was
//! encrypted under ephemeral keys that no longer exist, so resuming grants an
//! adversary no new decryption power.
//!
//! The exchange, repeated identically on every session (initial or resumed):
//!
//! ```text
//!   sender                                       receiver
//!     |------------------ OFFER(total) ------------->|
//!     |<--------- RESUME(have, prefix_hash) ---------|
//!     |  verify BLAKE3(source[0..have]) == prefix_hash
//!     |------------------ START(offset) ------------>|  truncate to offset
//!     |------------------ DATA(chunk) -------------->|  write, hash, fsync at
//!     |                     ...                      |  checkpoints
//!     |----------------- DONE(full_hash) ----------->|  verify, rename into place
//!     |<---------------------- ACK ------------------|
//! ```
//!
//! `START(offset)` means "truncate to this offset and append from here". The
//! sender chooses `offset = have` when the receiver's prefix verifies, and `0`
//! when it does not — which is what stops a good suffix being stitched onto a bad
//! prefix. "No loss" has to mean "no corruption at the seam" too.
//!
//! # Why BLAKE3 and not a Merkle tree
//!
//! The channel is already mutually authenticated and AEAD-protected, so wire
//! tampering is not the threat this hashing addresses — that is closed. What it
//! catches is *our own* reassembly, resume-seam and disk-write bugs, plus
//! corruption at the sender before the bytes entered the channel. A streaming
//! hash covers that, and the same hash doubles as the resume commitment. BLAKE3
//! is internally a Merkle tree, so if random-access or prefix proofs are ever
//! needed, adopt `bao` verified streaming rather than hand-rolling a tree.
//!
//! # Determinism requirements
//!
//! * The offset counts **logical payload bytes**, never wire bytes. Pacing and
//!   cover traffic (Phase 4) and the per-session encryption are non-deterministic
//!   and must stay outside the resumable stream.
//! * The source must be byte-stable for the transfer's duration. A source that
//!   changes underneath a resume is correctly rejected by the seam check.
//!
//! # Cost of resume
//!
//! Both sides re-hash the prefix on reconnect: the receiver to produce
//! `prefix_hash`, the sender to verify it. Resuming a 4 GiB prefix therefore
//! costs a 4 GiB read on each side (BLAKE3 is fast enough that this is
//! disk-bound). The alternative — persisting hasher state — would mean
//! serialising internal hash state across a crash, which is both unsupported by
//! the crate and exactly the kind of "trust what we wrote down" that the seam
//! check exists to avoid.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::Error;
use crate::session::{MAX_FRAME_LEN, SecureSession};

/// Payload bytes per `DATA` frame. Matches the 1 MiB block size the encoder
/// already uses elsewhere in the workspace.
///
/// Every frame is exactly this size except the last, so the on-wire frame
/// sequence reveals the payload length only to within one chunk. Removing even
/// that residue — and the fact that the stream stops when the data does — is
/// Phase 4's job (constant-rate pacing, cover traffic, randomized ramp-down).
pub const DEFAULT_CHUNK_LEN: usize = 1 << 20;

/// How often the receiver makes progress durable: `fsync` the partial file and
/// treat everything before this boundary as recoverable.
///
/// A crash costs at most one checkpoint of re-transfer. Smaller is more durable
/// and more expensive; 16 MiB keeps `fsync` calls to a few hundred over a
/// multi-gigabyte vault.
pub const DEFAULT_CHECKPOINT_LEN: u64 = 16 * DEFAULT_CHUNK_LEN as u64;

/// Suffix of the in-progress file. The partial lives beside the destination so
/// the final rename is atomic (same filesystem).
const PARTIAL_SUFFIX: &str = ".part";

/// Witness that the bytes being streamed are **already encrypted at rest**.
///
/// Resume checkpoints the partial payload to disk, which normally reintroduces
/// the "data at rest" that transferring live exists to eliminate. It is
/// acceptable here *only* because the payload is the `.aegis` vault file, itself
/// encrypted under the vault's own password: the on-disk partial is ciphertext,
/// strictly less exposure than the completed transfer the recipient already
/// opted into.
///
/// This type is the guard the roadmap asks for. Constructing it is the point
/// where a future change that streams a *decrypted* tree instead must stop: the
/// on-disk partial would then be plaintext at rest and the design decision has
/// to be revisited rather than inherited.
#[derive(Debug)]
pub struct EncryptedAtRest(());

impl EncryptedAtRest {
    /// The payload is an `.aegis` vault file — ciphertext under the vault's own
    /// password. This is the only sanctioned way to obtain the witness.
    pub fn aegis_vault() -> Self {
        EncryptedAtRest(())
    }
}

/// Cooperative cancellation shared between a transfer and whatever wants to stop
/// it.
///
/// Cancelling is safe at any point: the receiver's partial file stays on disk and
/// a later transfer resumes from the last checkpoint. Cancellation is observed at
/// chunk boundaries, so it takes effect promptly while data is flowing; a fully
/// stalled connection is ended by the QUIC idle timeout instead.
#[derive(Clone, Debug, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Cancel::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), Error> {
        if self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
}

/// A progress observation, reported at chunk boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Payload bytes confirmed so far, counting any resumed prefix.
    pub transferred: u64,
    /// Total payload bytes in the transfer.
    pub total: u64,
    /// Offset this session started from; `0` for a fresh transfer.
    pub resumed_from: u64,
}

/// Callback type for progress reporting. `&mut |_| {}` opts out.
pub type ProgressFn<'a> = &'a mut (dyn FnMut(Progress) + Send);

/// What a completed transfer moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Total payload length.
    pub total: u64,
    /// Offset this session resumed from; `0` if it ran from the start.
    pub resumed_from: u64,
    /// BLAKE3 of the complete payload, verified by both sides.
    pub hash: [u8; 32],
}

/// A configured transfer. Build once, then drive either end.
#[derive(Debug)]
pub struct Transfer {
    chunk_len: usize,
    checkpoint_len: u64,
    max_total_len: Option<u64>,
    cancel: Cancel,
}

impl Transfer {
    /// Create a transfer for an already-encrypted payload.
    ///
    /// The [`EncryptedAtRest`] witness is not stored — it exists to make the
    /// at-rest assumption explicit at every call site.
    pub fn new(_: EncryptedAtRest) -> Self {
        Transfer {
            chunk_len: DEFAULT_CHUNK_LEN,
            checkpoint_len: DEFAULT_CHECKPOINT_LEN,
            max_total_len: None,
            cancel: Cancel::new(),
        }
    }

    /// Override the payload bytes per frame. Clamped to leave room for the
    /// one-byte tag inside [`MAX_FRAME_LEN`].
    pub fn chunk_len(mut self, bytes: usize) -> Self {
        self.chunk_len = bytes.clamp(1, MAX_FRAME_LEN - 1);
        self
    }

    /// Override the durability checkpoint interval.
    pub fn checkpoint_len(mut self, bytes: u64) -> Self {
        self.checkpoint_len = bytes.max(1);
        self
    }

    /// Refuse an offer larger than `bytes`.
    ///
    /// Unset by default: the sender is a peer whose key the user pinned
    /// deliberately, and a cap set too low silently breaks legitimate
    /// multi-gigabyte vaults. Set it where a bound on disk consumption by a
    /// compromised-but-authenticated sender is wanted.
    pub fn max_total_len(mut self, bytes: u64) -> Self {
        self.max_total_len = Some(bytes);
        self
    }

    /// A handle that can cancel this transfer from another task.
    pub fn cancel_token(&self) -> Cancel {
        self.cancel.clone()
    }

    /// Send `source` over `session`, resuming from wherever the receiver is.
    pub async fn send(
        &self,
        session: &mut dyn SecureSession,
        source: &Path,
        progress: ProgressFn<'_>,
    ) -> Result<Summary, Error> {
        let mut file = File::open(source)
            .await
            .map_err(|e| Error::Transfer(format!("open {}: {e}", source.display())))?;
        let total = file
            .metadata()
            .await
            .map_err(|e| Error::Transfer(format!("stat {}: {e}", source.display())))?
            .len();

        session.send(&encode_offer(total)).await?;
        let (have, prefix_hash) = decode_resume(&session.recv().await?)?;

        // Verify the receiver's partial really is a prefix of what we are about
        // to send. A divergence means their bytes are not ours: start over
        // rather than stitch a good suffix onto a bad prefix.
        let mut buf = vec![0u8; self.chunk_len];
        let (offset, mut hasher) = if have > 0 && have <= total {
            let hasher = hash_prefix(&mut file, have, &mut buf).await?;
            if *hasher.finalize().as_bytes() == prefix_hash {
                (have, hasher)
            } else {
                (0, blake3::Hasher::new())
            }
        } else {
            (0, blake3::Hasher::new())
        };

        session.send(&encode_start(offset)).await?;

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| Error::Transfer(format!("seek to {offset}: {e}")))?;

        let mut sent = offset;
        progress(Progress {
            transferred: sent,
            total,
            resumed_from: offset,
        });

        while sent < total {
            self.cancel.check()?;

            let want = ((total - sent) as usize).min(self.chunk_len);
            file.read_exact(&mut buf[..want])
                .await
                .map_err(|e| Error::Transfer(format!("read at {sent}: {e}")))?;

            hasher.update(&buf[..want]);
            session.send(&encode_data(&buf[..want])).await?;
            sent += want as u64;

            progress(Progress {
                transferred: sent,
                total,
                resumed_from: offset,
            });
        }

        let hash = *hasher.finalize().as_bytes();
        session.send(&encode_done(&hash)).await?;

        // The ACK is what makes the sender's success claim honest: it means the
        // receiver verified the full-payload hash and put the file in place, not
        // merely that our last write left this process.
        let ack = session.recv().await?;
        if ack.first().copied() != Some(tag::ACK) {
            return Err(Error::Transfer(format!(
                "expected ACK, got tag {:?}",
                ack.first()
            )));
        }

        Ok(Summary {
            total,
            resumed_from: offset,
            hash,
        })
    }

    /// Receive into `dest`, resuming from any partial left by an earlier attempt.
    ///
    /// Data lands in `<dest>.part` and is renamed into place only after the
    /// full-payload hash verifies, so `dest` never exists in a half-written or
    /// unverified state.
    pub async fn recv(
        &self,
        session: &mut dyn SecureSession,
        dest: &Path,
        progress: ProgressFn<'_>,
    ) -> Result<Summary, Error> {
        let total = decode_offer(&session.recv().await?)?;
        if let Some(max) = self.max_total_len
            && total > max
        {
            return Err(Error::Transfer(format!(
                "offered payload of {total} bytes exceeds the {max}-byte limit"
            )));
        }

        let partial = partial_path(dest);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&partial)
            .await
            .map_err(|e| Error::Transfer(format!("open {}: {e}", partial.display())))?;

        // Roll back to the last checkpoint boundary. Bytes past it were written
        // but never fsync'd, so after a crash they may be short, zero-filled, or
        // absent — treating the file length as authoritative would count
        // half-written bytes as received. The file's own length *is* the durable
        // offset once rounded down this way, which is why no sidecar metadata
        // file is needed; the prefix hash below is what proves it.
        let on_disk = file
            .metadata()
            .await
            .map_err(|e| Error::Transfer(format!("stat {}: {e}", partial.display())))?
            .len();
        let have = (on_disk / self.checkpoint_len) * self.checkpoint_len;
        let have = have.min(total);
        file.set_len(have)
            .await
            .map_err(|e| Error::Transfer(format!("truncate to {have}: {e}")))?;

        let mut buf = vec![0u8; self.chunk_len];
        let mut hasher = hash_prefix(&mut file, have, &mut buf).await?;
        session
            .send(&encode_resume(have, hasher.finalize().as_bytes()))
            .await?;

        let offset = decode_start(&session.recv().await?)?;
        if offset > have {
            // Would leave a hole: the sender must never ask us to start beyond
            // what we told it we have.
            return Err(Error::Transfer(format!(
                "sender asked to start at {offset} but we only have {have} bytes"
            )));
        }
        if offset != have {
            // Our prefix diverged; the sender rewound us. Discard the bad tail
            // and re-derive the hash over what is left.
            file.set_len(offset)
                .await
                .map_err(|e| Error::Transfer(format!("truncate to {offset}: {e}")))?;
            hasher = hash_prefix(&mut file, offset, &mut buf).await?;
        }

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| Error::Transfer(format!("seek to {offset}: {e}")))?;

        let mut received = offset;
        let mut last_checkpoint = offset;
        progress(Progress {
            transferred: received,
            total,
            resumed_from: offset,
        });

        let sender_hash = loop {
            self.cancel.check()?;
            let frame = session.recv().await?;
            match frame.first().copied() {
                Some(tag::DATA) => {
                    let chunk = &frame[1..];
                    if received + chunk.len() as u64 > total {
                        return Err(Error::Transfer(
                            "sender sent more data than it offered".into(),
                        ));
                    }
                    file.write_all(chunk)
                        .await
                        .map_err(|e| Error::Transfer(format!("write at {received}: {e}")))?;
                    hasher.update(chunk);
                    received += chunk.len() as u64;

                    if received - last_checkpoint >= self.checkpoint_len {
                        // Make the data durable *before* the length that
                        // advertises it becomes visible as recovered progress.
                        file.sync_data()
                            .await
                            .map_err(|e| Error::Transfer(format!("fsync at {received}: {e}")))?;
                        last_checkpoint = received;
                    }

                    progress(Progress {
                        transferred: received,
                        total,
                        resumed_from: offset,
                    });
                }
                Some(tag::DONE) => break decode_done(&frame)?,
                other => {
                    return Err(Error::Transfer(format!(
                        "unexpected frame tag {other:?} during transfer"
                    )));
                }
            }
        };

        if received != total {
            return Err(Error::Transfer(format!(
                "stream ended at {received} of {total} bytes"
            )));
        }

        let hash = *hasher.finalize().as_bytes();
        if hash != sender_hash {
            // Leave the partial in place: a retry re-verifies the prefix and
            // will rewind to wherever the two sides actually diverge.
            return Err(Error::Integrity(format!(
                "payload hash mismatch: computed {}, sender claimed {}",
                hex(&hash),
                hex(&sender_hash)
            )));
        }

        file.sync_all()
            .await
            .map_err(|e| Error::Transfer(format!("final fsync: {e}")))?;
        drop(file);
        tokio::fs::rename(&partial, dest)
            .await
            .map_err(|e| Error::Transfer(format!("rename into {}: {e}", dest.display())))?;
        sync_parent_dir(dest).await;

        session.send(&[tag::ACK]).await?;

        Ok(Summary {
            total,
            resumed_from: offset,
            hash,
        })
    }
}

/// Where the in-progress copy of `dest` lives.
pub fn partial_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(PARTIAL_SUFFIX);
    PathBuf::from(name)
}

/// Hash `file[0..len]`, leaving the cursor wherever the read ended.
async fn hash_prefix(file: &mut File, len: u64, buf: &mut [u8]) -> Result<blake3::Hasher, Error> {
    let mut hasher = blake3::Hasher::new();
    file.seek(SeekFrom::Start(0))
        .await
        .map_err(|e| Error::Transfer(format!("seek to 0: {e}")))?;
    let mut read = 0u64;
    while read < len {
        let want = ((len - read) as usize).min(buf.len());
        file.read_exact(&mut buf[..want])
            .await
            .map_err(|e| Error::Transfer(format!("read prefix at {read}: {e}")))?;
        hasher.update(&buf[..want]);
        read += want as u64;
    }
    Ok(hasher)
}

/// Best-effort `fsync` of the directory so the rename itself is durable.
///
/// Not fatal if it fails: some filesystems refuse a directory fsync, and the
/// only cost is that a power cut immediately after a completed transfer might
/// require repeating it.
async fn sync_parent_dir(dest: &Path) {
    if let Some(dir) = dest.parent()
        && let Ok(handle) = File::open(dir).await
    {
        let _ = handle.sync_all().await;
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// --- Wire format -----------------------------------------------------------
//
// Every message is one `SecureSession` frame: a tag byte followed by fixed-width
// big-endian fields. Deliberately hand-rolled and tiny — a transfer protocol
// inside an authenticated channel needs no general-purpose serialisation
// format, and every decoder here checks its length before indexing.

mod tag {
    pub const OFFER: u8 = 0x01;
    pub const RESUME: u8 = 0x02;
    pub const START: u8 = 0x03;
    pub const DATA: u8 = 0x04;
    pub const DONE: u8 = 0x05;
    pub const ACK: u8 = 0x06;
}

fn expect(frame: &[u8], want: u8, len: usize, what: &str) -> Result<(), Error> {
    if frame.first().copied() != Some(want) {
        return Err(Error::Transfer(format!(
            "expected {what} (tag {want:#04x}), got tag {:?}",
            frame.first()
        )));
    }
    if frame.len() != len {
        return Err(Error::Transfer(format!(
            "malformed {what}: {} bytes, expected {len}",
            frame.len()
        )));
    }
    Ok(())
}

fn be64(bytes: &[u8]) -> u64 {
    let mut n = [0u8; 8];
    n.copy_from_slice(bytes);
    u64::from_be_bytes(n)
}

fn encode_offer(total: u64) -> Vec<u8> {
    let mut v = vec![tag::OFFER];
    v.extend_from_slice(&total.to_be_bytes());
    v
}

fn decode_offer(frame: &[u8]) -> Result<u64, Error> {
    expect(frame, tag::OFFER, 9, "OFFER")?;
    Ok(be64(&frame[1..9]))
}

fn encode_resume(have: u64, prefix_hash: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![tag::RESUME];
    v.extend_from_slice(&have.to_be_bytes());
    v.extend_from_slice(prefix_hash);
    v
}

fn decode_resume(frame: &[u8]) -> Result<(u64, [u8; 32]), Error> {
    expect(frame, tag::RESUME, 41, "RESUME")?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&frame[9..41]);
    Ok((be64(&frame[1..9]), hash))
}

fn encode_start(offset: u64) -> Vec<u8> {
    let mut v = vec![tag::START];
    v.extend_from_slice(&offset.to_be_bytes());
    v
}

fn decode_start(frame: &[u8]) -> Result<u64, Error> {
    expect(frame, tag::START, 9, "START")?;
    Ok(be64(&frame[1..9]))
}

fn encode_data(chunk: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(chunk.len() + 1);
    v.push(tag::DATA);
    v.extend_from_slice(chunk);
    v
}

fn encode_done(hash: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![tag::DONE];
    v.extend_from_slice(hash);
    v
}

fn decode_done(frame: &[u8]) -> Result<[u8; 32], Error> {
    expect(frame, tag::DONE, 33, "DONE")?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&frame[1..33]);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_messages_round_trip() {
        assert_eq!(
            decode_offer(&encode_offer(5_368_709_120)).unwrap(),
            5_368_709_120
        );
        assert_eq!(decode_start(&encode_start(42)).unwrap(), 42);
        let hash = [7u8; 32];
        assert_eq!(decode_done(&encode_done(&hash)).unwrap(), hash);
        assert_eq!(decode_resume(&encode_resume(9, &hash)).unwrap(), (9, hash));
    }

    /// Decoders must reject a frame of the wrong tag or length rather than
    /// indexing past the end.
    #[test]
    fn decoders_reject_malformed_frames() {
        assert!(decode_offer(&[]).is_err(), "empty frame");
        assert!(decode_offer(&[tag::OFFER]).is_err(), "truncated OFFER");
        assert!(decode_offer(&encode_start(1)).is_err(), "wrong tag");
        assert!(decode_resume(&encode_resume(1, &[0; 32])[..40]).is_err());
        assert!(decode_done(&[tag::DONE; 32]).is_err(), "short DONE");
    }

    #[test]
    fn partial_path_sits_beside_the_destination() {
        let p = partial_path(Path::new("/vaults/my_data.aegis"));
        assert_eq!(p, Path::new("/vaults/my_data.aegis.part"));
        assert_eq!(p.parent(), Path::new("/vaults/my_data.aegis").parent());
    }

    /// The chunk length must always leave room for the tag byte inside a frame.
    #[test]
    fn chunk_len_is_clamped_into_the_frame_budget() {
        let t = Transfer::new(EncryptedAtRest::aegis_vault()).chunk_len(usize::MAX);
        assert!(t.chunk_len < MAX_FRAME_LEN);
        let t = Transfer::new(EncryptedAtRest::aegis_vault()).chunk_len(0);
        assert_eq!(t.chunk_len, 1, "a zero chunk would never make progress");
    }
}
