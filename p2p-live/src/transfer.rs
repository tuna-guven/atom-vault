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
//! The exchange, repeated identically on every session (initial or resumed).
//! Every frame is the same size on the wire and leaves on a fixed schedule; see
//! [`crate::pacing`].
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
//!     |------------------ COVER ... ---------------->|  discard (ramp-down)
//!     |------------------ FINISH ------------------->|
//!     |<---------------------- ACK ------------------|
//! ```
//!
//! The receiver deliberately does **not** acknowledge at `DONE`, even though it
//! holds the whole payload by then: a reply at that moment would mark the true
//! end of data with a packet in the reverse direction, undoing the ramp-down.
//! The `ACK` waits for `FINISH`, at the randomised end.
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
use crate::pacing::Pacing;
use crate::session::{MAX_FRAME_LEN, SecureSession};

/// Payload bytes per `DATA` frame. Matches the 1 MiB block size the encoder
/// already uses elsewhere in the workspace.
///
/// Every frame on the wire is padded to exactly this size plus [`HEADER_LEN`],
/// including control messages and the short final chunk, so no frame is
/// distinguishable by length. See [`crate::pacing`] for the rest of the
/// traffic-analysis story.
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
    /// Cover frames sent or received. The bandwidth traffic-analysis
    /// hardening cost, exposed so a caller can report it honestly.
    pub cover_frames: u64,
}

/// A configured transfer. Build once, then drive either end.
#[derive(Debug)]
pub struct Transfer {
    chunk_len: usize,
    checkpoint_len: u64,
    max_total_len: Option<u64>,
    pacing: Pacing,
    cancel: Cancel,
}

impl Transfer {
    /// Create a transfer for an already-encrypted payload.
    ///
    /// Traffic shaping is **on by default** ([`Pacing::default`]): the stream is
    /// paced, padded and quantised. Turning it off is a deliberate act — see
    /// [`Transfer::pacing`].
    ///
    /// The [`EncryptedAtRest`] witness is not stored — it exists to make the
    /// at-rest assumption explicit at every call site.
    pub fn new(_: EncryptedAtRest) -> Self {
        Transfer {
            chunk_len: DEFAULT_CHUNK_LEN,
            checkpoint_len: DEFAULT_CHECKPOINT_LEN,
            max_total_len: None,
            pacing: Pacing::default(),
            cancel: Cancel::new(),
        }
    }

    /// Override the payload bytes per frame. Clamped to leave room for the frame
    /// header inside [`MAX_FRAME_LEN`].
    pub fn chunk_len(mut self, bytes: usize) -> Self {
        self.chunk_len = bytes.clamp(1, MAX_FRAME_LEN - HEADER_LEN);
        self
    }

    /// Override the durability checkpoint interval.
    pub fn checkpoint_len(mut self, bytes: u64) -> Self {
        self.checkpoint_len = bytes.max(1);
        self
    }

    /// Override the traffic-shaping configuration.
    ///
    /// Passing [`Pacing::disabled`] makes the transfer as fast as the link
    /// allows and lets its shape reveal the payload size, duration and end time.
    /// Frames stay uniformly padded either way — that costs almost nothing and
    /// removes a leak no rate setting can.
    pub fn pacing(mut self, pacing: Pacing) -> Self {
        self.pacing = pacing;
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

    /// Total padded size of one frame on the wire.
    fn frame_len(&self) -> usize {
        self.chunk_len + HEADER_LEN
    }

    /// Send `source` over `session`, resuming from wherever the receiver is.
    pub async fn send(
        &self,
        session: &mut dyn SecureSession,
        source: &Path,
        progress: ProgressFn<'_>,
    ) -> Result<Summary, Error> {
        let frame_len = self.frame_len();
        let mut file = File::open(source)
            .await
            .map_err(|e| Error::Transfer(format!("open {}: {e}", source.display())))?;
        let total = file
            .metadata()
            .await
            .map_err(|e| Error::Transfer(format!("stat {}: {e}", source.display())))?
            .len();

        session
            .send(&frame(tag::OFFER, &total.to_be_bytes(), frame_len))
            .await?;
        let (have, prefix_hash) = decode_resume(&expect(session, tag::RESUME).await?)?;

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

        session
            .send(&frame(tag::START, &offset.to_be_bytes(), frame_len))
            .await?;

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| Error::Transfer(format!("seek to {offset}: {e}")))?;

        // How many data frames remain, and how many frames we will actually emit
        // once the count is padded up the ladder. The plan is drawn once, before
        // any data moves, so the emitted length cannot depend on how the
        // transfer goes.
        let real_frames = (total - offset).div_ceil(self.chunk_len as u64);
        let planned_frames = self.pacing.plan(real_frames)?;
        let mut pacer = self.pacing.pacer(frame_len);

        let mut sent = offset;
        let mut emitted = 0u64;
        progress(Progress {
            transferred: sent,
            total,
            resumed_from: offset,
        });

        while sent < total {
            self.cancel.check()?;
            pacer.tick().await;

            let want = ((total - sent) as usize).min(self.chunk_len);
            file.read_exact(&mut buf[..want])
                .await
                .map_err(|e| Error::Transfer(format!("read at {sent}: {e}")))?;

            hasher.update(&buf[..want]);
            session
                .send(&frame(tag::DATA, &buf[..want], frame_len))
                .await?;
            sent += want as u64;
            emitted += 1;

            progress(Progress {
                transferred: sent,
                total,
                resumed_from: offset,
            });
        }

        let hash = *hasher.finalize().as_bytes();
        pacer.tick().await;
        session.send(&frame(tag::DONE, &hash, frame_len)).await?;

        // The ramp-down. The receiver already has everything it needs; these
        // frames exist so the flow's volume and stop time carry no information
        // about when the real data ran out.
        let cover = vec![0u8; 0];
        let mut cover_frames = 0u64;
        while emitted < planned_frames {
            // Cancelling here forfeits the ramp-down — the true end time becomes
            // visible again — but a user asking to stop outranks a property that
            // has already done its job for the payload itself.
            if self.cancel.is_cancelled() {
                break;
            }
            pacer.tick().await;
            session.send(&frame(tag::COVER, &cover, frame_len)).await?;
            emitted += 1;
            cover_frames += 1;
        }

        pacer.tick().await;
        session.send(&frame(tag::FINISH, &cover, frame_len)).await?;

        // The ACK is what makes the sender's success claim honest: it means the
        // receiver verified the full-payload hash and put the file in place, not
        // merely that our last write left this process. It arrives after the
        // randomised tail, so its timing does not mark the true end of data
        // either.
        expect(session, tag::ACK).await?;

        Ok(Summary {
            total,
            resumed_from: offset,
            hash,
            cover_frames,
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
        // Adopt the sender's frame size for our own replies, so both directions
        // look identical on the wire even if the two ends are configured with
        // different chunk sizes.
        let offer = session.recv().await?;
        let frame_len = offer.len();
        if !(HEADER_LEN..=MAX_FRAME_LEN).contains(&frame_len) {
            return Err(Error::Transfer(format!(
                "peer's frame size {frame_len} is out of range"
            )));
        }
        let total = decode_offer(&offer)?;
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
        let mut resume = Vec::with_capacity(40);
        resume.extend_from_slice(&have.to_be_bytes());
        resume.extend_from_slice(hasher.finalize().as_bytes());
        session
            .send(&frame(tag::RESUME, &resume, frame_len))
            .await?;

        let offset = decode_start(&expect(session, tag::START).await?)?;
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
        let mut cover_frames = 0u64;
        let mut hash = None;
        progress(Progress {
            transferred: received,
            total,
            resumed_from: offset,
        });

        loop {
            self.cancel.check()?;
            let raw = session.recv().await?;
            // Every frame must be the same size. A peer that started varying
            // frame sizes would be leaking the payload length through framing,
            // whatever else it claimed to be doing.
            if raw.len() != frame_len {
                return Err(Error::Transfer(format!(
                    "peer changed frame size from {frame_len} to {} mid-stream",
                    raw.len()
                )));
            }
            let (tag, content) = parse(&raw)?;

            match tag {
                tag::DATA => {
                    if hash.is_some() {
                        return Err(Error::Transfer("data frame after DONE".into()));
                    }
                    if received + content.len() as u64 > total {
                        return Err(Error::Transfer(
                            "sender sent more data than it offered".into(),
                        ));
                    }
                    file.write_all(content)
                        .await
                        .map_err(|e| Error::Transfer(format!("write at {received}: {e}")))?;
                    hasher.update(content);
                    received += content.len() as u64;

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

                // Cover traffic. Discarded without touching the disk or the
                // hash: it exists only to occupy the wire.
                tag::COVER => cover_frames += 1,

                tag::DONE => {
                    if hash.is_some() {
                        return Err(Error::Transfer("duplicate DONE frame".into()));
                    }
                    let claimed = decode_done(content)?;
                    hash = Some(
                        self.finish_payload(
                            &mut file, &partial, dest, received, total, &hasher, claimed,
                        )
                        .await?,
                    );
                    // Deliberately keep reading: the sender's ramp-down is still
                    // in flight and acknowledging now would mark the true end of
                    // data with a reply packet.
                }

                tag::FINISH => match hash {
                    Some(hash) => {
                        session.send(&frame(tag::ACK, &[], frame_len)).await?;
                        return Ok(Summary {
                            total,
                            resumed_from: offset,
                            hash,
                            cover_frames,
                        });
                    }
                    None => {
                        return Err(Error::Transfer(format!(
                            "stream ended at {received} of {total} bytes"
                        )));
                    }
                },

                other => {
                    return Err(Error::Transfer(format!(
                        "unexpected frame tag {other:#04x} during transfer"
                    )));
                }
            }
        }
    }

    /// Verify the completed payload and move it into place.
    #[allow(clippy::too_many_arguments)]
    async fn finish_payload(
        &self,
        file: &mut File,
        partial: &Path,
        dest: &Path,
        received: u64,
        total: u64,
        hasher: &blake3::Hasher,
        claimed: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        if received != total {
            return Err(Error::Transfer(format!(
                "sender finished at {received} of {total} bytes"
            )));
        }

        let hash = *hasher.clone().finalize().as_bytes();
        if hash != claimed {
            // Leave the partial in place: a retry re-verifies the prefix and
            // will rewind to wherever the two sides actually diverge.
            return Err(Error::Integrity(format!(
                "payload hash mismatch: computed {}, sender claimed {}",
                hex(&hash),
                hex(&claimed)
            )));
        }

        file.sync_all()
            .await
            .map_err(|e| Error::Transfer(format!("final fsync: {e}")))?;
        tokio::fs::rename(partial, dest)
            .await
            .map_err(|e| Error::Transfer(format!("rename into {}: {e}", dest.display())))?;
        sync_parent_dir(dest).await;
        Ok(hash)
    }
}

/// Where the in-progress copy of `dest` lives.
pub fn partial_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(PARTIAL_SUFFIX);
    PathBuf::from(name)
}

/// Receive one frame and require it to carry `want`, returning its content.
async fn expect(session: &mut dyn SecureSession, want: u8) -> Result<Vec<u8>, Error> {
    let raw = session.recv().await?;
    let (tag, content) = parse(&raw)?;
    if tag != want {
        return Err(Error::Transfer(format!(
            "expected frame tag {want:#04x}, got {tag:#04x}"
        )));
    }
    Ok(content.to_vec())
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
// Every message is one `SecureSession` frame of **exactly the same length**:
//
//     [tag u8][content_len u32 BE][content ...][zero padding to frame_len]
//
// Uniform length is a security property, not tidiness: without it the short
// final data frame reveals the payload length modulo the chunk size, and the
// control messages are identifiable by their distinctive small sizes.
//
// The padding is zeros rather than random bytes. Everything here is inside the
// session's AEAD, so an observer sees ciphertext either way and random padding
// would buy nothing for the cost of drawing megabytes from the CSPRNG.
//
// Deliberately hand-rolled and tiny — a transfer protocol inside an
// authenticated channel needs no general-purpose serialisation format, and
// every decoder checks its length before indexing.

/// Bytes of framing overhead ahead of the content.
pub(crate) const HEADER_LEN: usize = 5;

mod tag {
    pub const OFFER: u8 = 0x01;
    pub const RESUME: u8 = 0x02;
    pub const START: u8 = 0x03;
    pub const DATA: u8 = 0x04;
    pub const DONE: u8 = 0x05;
    pub const ACK: u8 = 0x06;
    /// Padding traffic. Carries nothing and is discarded on receipt.
    pub const COVER: u8 = 0x07;
    /// End of the ramp-down: the sender will send no more frames.
    pub const FINISH: u8 = 0x08;
}

/// Build one padded frame.
fn frame(tag: u8, content: &[u8], frame_len: usize) -> Vec<u8> {
    debug_assert!(content.len() + HEADER_LEN <= frame_len);
    let mut v = vec![0u8; frame_len.max(content.len() + HEADER_LEN)];
    v[0] = tag;
    v[1..5].copy_from_slice(&(content.len() as u32).to_be_bytes());
    v[HEADER_LEN..HEADER_LEN + content.len()].copy_from_slice(content);
    v
}

/// Split a padded frame into its tag and content, discarding the padding.
fn parse(raw: &[u8]) -> Result<(u8, &[u8]), Error> {
    if raw.len() < HEADER_LEN {
        return Err(Error::Transfer(format!(
            "frame of {} bytes is too short to hold a header",
            raw.len()
        )));
    }
    let tag = raw[0];
    let len = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
    let content = raw
        .get(HEADER_LEN..HEADER_LEN + len)
        .ok_or_else(|| Error::Transfer(format!("frame claims {len} content bytes it lacks")))?;
    Ok((tag, content))
}

fn be64(bytes: &[u8]) -> u64 {
    let mut n = [0u8; 8];
    n.copy_from_slice(bytes);
    u64::from_be_bytes(n)
}

fn fixed(content: &[u8], len: usize, what: &str) -> Result<(), Error> {
    if content.len() != len {
        return Err(Error::Transfer(format!(
            "malformed {what}: {} content bytes, expected {len}",
            content.len()
        )));
    }
    Ok(())
}

fn decode_offer(raw: &[u8]) -> Result<u64, Error> {
    let (tag, content) = parse(raw)?;
    if tag != tag::OFFER {
        return Err(Error::Transfer(format!(
            "expected OFFER, got tag {tag:#04x}"
        )));
    }
    fixed(content, 8, "OFFER")?;
    Ok(be64(content))
}

fn decode_resume(content: &[u8]) -> Result<(u64, [u8; 32]), Error> {
    fixed(content, 40, "RESUME")?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&content[8..40]);
    Ok((be64(&content[..8]), hash))
}

fn decode_start(content: &[u8]) -> Result<u64, Error> {
    fixed(content, 8, "START")?;
    Ok(be64(content))
}

fn decode_done(content: &[u8]) -> Result<[u8; 32], Error> {
    fixed(content, 32, "DONE")?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(content);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{LocalIdentity, PeerPublicKey};
    use crate::pacing::Ladder;
    use async_trait::async_trait;
    use tokio::sync::mpsc;

    /// An in-memory [`SecureSession`] that records the exact size of every frame
    /// it sends.
    ///
    /// The traffic-analysis properties are claims about **what an observer sees
    /// on the wire**, so they have to be asserted against the actual byte
    /// stream. A test that only checked the file arrived intact would pass
    /// whether or not any of this worked.
    struct MockSession {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        peer: PeerPublicKey,
        /// Length of every frame we sent, in order.
        sent_sizes: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
        /// Tag of every frame we sent, in order.
        sent_tags: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    type Log = std::sync::Arc<std::sync::Mutex<Vec<usize>>>;
    type TagLog = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

    fn mock_pair() -> (MockSession, MockSession, Log, TagLog) {
        let (a_tx, b_rx) = mpsc::unbounded_channel();
        let (b_tx, a_rx) = mpsc::unbounded_channel();
        let peer = LocalIdentity::generate().unwrap().public_key().clone();
        let sizes: Log = Default::default();
        let tags: TagLog = Default::default();
        let a = MockSession {
            tx: a_tx,
            rx: a_rx,
            peer: peer.clone(),
            sent_sizes: sizes.clone(),
            sent_tags: tags.clone(),
        };
        let b = MockSession {
            tx: b_tx,
            rx: b_rx,
            peer,
            sent_sizes: Default::default(),
            sent_tags: Default::default(),
        };
        (a, b, sizes, tags)
    }

    #[async_trait]
    impl SecureSession for MockSession {
        fn peer(&self) -> &PeerPublicKey {
            &self.peer
        }
        async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
            self.sent_sizes.lock().unwrap().push(msg.len());
            self.sent_tags.lock().unwrap().push(msg[0]);
            self.tx
                .send(msg.to_vec())
                .map_err(|_| Error::Session("mock peer went away".into()))
        }
        async fn recv(&mut self) -> Result<Vec<u8>, Error> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| Error::Session("mock peer went away".into()))
        }
        async fn close(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn export_keying_material(
            &self,
            _out: &mut [u8],
            _label: &[u8],
            _context: &[u8],
        ) -> Result<(), Error> {
            // Deliberately unavailable: an in-memory pipe has no handshake to
            // bind to, and returning arbitrary bytes would let a test "pass"
            // channel binding that the real transports would have to earn.
            Err(Error::Session(
                "the mock session has no channel binding".into(),
            ))
        }
    }

    /// Run a whole transfer over the mock pair, returning the sender's frame
    /// sizes and tags alongside both summaries.
    async fn run(
        payload_len: usize,
        pacing: Pacing,
        chunk_len: usize,
    ) -> (Summary, Summary, Vec<usize>, Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("v.aegis");
        let dst = dir.path().join("out.aegis");
        let data: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let (mut a, mut b, sizes, tags) = mock_pair();
        let cfg = move || {
            Transfer::new(EncryptedAtRest::aegis_vault())
                .chunk_len(chunk_len)
                .checkpoint_len(1024)
                .pacing(pacing)
        };

        let send = tokio::spawn(async move { cfg().send(&mut a, &src, &mut |_| {}).await });
        let received = cfg().recv(&mut b, &dst, &mut |_| {}).await.unwrap();
        let sent = send.await.unwrap().unwrap();

        let out = std::fs::read(&dst).unwrap();
        let sizes = sizes.lock().unwrap().clone();
        let tags = tags.lock().unwrap().clone();
        (sent, received, sizes, tags, out)
    }

    /// **The core anti-fingerprinting claim.** Every frame on the wire is the
    /// same size — control messages, full data chunks, the short final chunk and
    /// cover alike. If any frame differed, its size would identify it.
    #[tokio::test]
    async fn every_frame_on_the_wire_is_identical_in_size() {
        // A payload deliberately not a multiple of the chunk size, so the final
        // data frame is a partial one.
        let (_, _, sizes, _, out) = run(1000 + 37, Pacing::default().at_rate(u64::MAX), 1000).await;
        assert_eq!(out.len(), 1037);
        assert!(sizes.len() > 4, "expected several frames, got {sizes:?}");
        assert!(
            sizes.iter().all(|n| *n == sizes[0]),
            "frame sizes vary: {sizes:?}"
        );
        assert_eq!(sizes[0], 1000 + HEADER_LEN);
    }

    /// The stream must not stop when the data does: cover frames follow DONE,
    /// so the moment transmission ends is not the moment the vault finished
    /// arriving.
    #[tokio::test]
    async fn the_stream_keeps_running_after_the_data_ends() {
        let pacing = Pacing::default().at_rate(u64::MAX).with_bounds(32, 0);
        let (sent, received, _, tags, _) = run(2000, pacing, 1000).await;

        assert!(sent.cover_frames > 0, "no cover traffic was emitted");
        assert_eq!(sent.cover_frames, received.cover_frames);

        let done = tags
            .iter()
            .position(|t| *t == tag::DONE)
            .expect("DONE sent");
        let finish = tags
            .iter()
            .position(|t| *t == tag::FINISH)
            .expect("FINISH sent");
        assert!(
            finish > done + 1,
            "nothing was sent between DONE and FINISH"
        );
        assert!(
            tags[done + 1..finish].iter().all(|t| *t == tag::COVER),
            "expected only cover between DONE and FINISH: {:?}",
            &tags[done + 1..finish]
        );
    }

    /// Payload sizes that differ must present the same number of frames once
    /// quantised — a 5.0 GB and a 6.3 GB vault look alike, in miniature.
    #[tokio::test]
    async fn different_payloads_present_the_same_frame_count() {
        let pacing = Pacing::default()
            .at_rate(u64::MAX)
            .with_ladder(Ladder::PowerOfTwo)
            .with_bounds(0, 0);

        let (_, _, a_sizes, _, _) = run(5 * 100, pacing, 100).await; // 5 frames
        let (_, _, b_sizes, _, _) = run(7 * 100, pacing, 100).await; // 7 frames
        assert_eq!(
            a_sizes.len(),
            b_sizes.len(),
            "a 5-frame and a 7-frame payload must both round up to 8"
        );
    }

    /// Cover must never displace data: the payload still arrives byte-perfect
    /// with the stream full of frames that mean nothing.
    #[tokio::test]
    async fn cover_traffic_does_not_corrupt_the_payload() {
        let pacing = Pacing::default().at_rate(u64::MAX).with_bounds(64, 16);
        let (sent, received, _, _, out) = run(3333, pacing, 256).await;

        assert_eq!(sent.hash, received.hash);
        assert_eq!(out.len(), 3333);
        assert_eq!(out, (0..3333).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
        assert!(received.cover_frames > 0);
    }

    /// Pacing must actually bound the rate. Without it the mock channel would
    /// finish in microseconds.
    #[tokio::test]
    async fn pacing_holds_the_stream_to_the_configured_rate() {
        // 100-byte frames at ~10 KiB/s is ~10 ms per frame; 16 frames ≈ 160 ms.
        let pacing = Pacing::default()
            .at_rate(10 * 1024)
            .with_ladder(Ladder::None)
            .with_bounds(16, 0);

        let started = std::time::Instant::now();
        let (_, _, sizes, _, _) = run(400, pacing, 95).await;
        let elapsed = started.elapsed();

        assert!(sizes.len() >= 16);
        assert!(
            elapsed >= std::time::Duration::from_millis(100),
            "16 paced frames finished in {elapsed:?} — the rate limit did nothing"
        );
    }

    /// With shaping off the stream is minimal: no cover, no ladder. Frames stay
    /// uniformly padded, because that costs almost nothing and removes a leak
    /// no rate setting can.
    #[tokio::test]
    async fn disabled_pacing_emits_no_cover_but_still_pads() {
        let (sent, received, sizes, _, out) = run(250, Pacing::disabled(), 100).await;
        assert_eq!(sent.cover_frames, 0);
        assert_eq!(received.cover_frames, 0);
        assert_eq!(out.len(), 250);
        assert!(sizes.iter().all(|n| *n == 100 + HEADER_LEN));
    }

    #[test]
    fn frames_round_trip_and_discard_padding() {
        let f = frame(tag::DONE, &[9u8; 32], 1024);
        assert_eq!(f.len(), 1024);
        let (t, c) = parse(&f).unwrap();
        assert_eq!(t, tag::DONE);
        assert_eq!(c, &[9u8; 32]);

        let empty = frame(tag::COVER, &[], 512);
        assert_eq!(empty.len(), 512);
        assert_eq!(parse(&empty).unwrap(), (tag::COVER, &[][..]));
    }

    /// Decoders must reject a frame of the wrong tag or length rather than
    /// indexing past the end.
    #[test]
    fn decoders_reject_malformed_frames() {
        assert!(parse(&[]).is_err(), "empty frame");
        assert!(parse(&[tag::OFFER, 0, 0]).is_err(), "truncated header");
        // Claims more content than the frame holds.
        assert!(parse(&[tag::DATA, 0, 0, 0xFF, 0xFF, 1, 2]).is_err());

        assert!(
            decode_offer(&frame(tag::START, &[0; 8], 64)).is_err(),
            "tag"
        );
        assert!(
            decode_offer(&frame(tag::OFFER, &[0; 7], 64)).is_err(),
            "len"
        );
        assert!(decode_resume(&[0; 39]).is_err());
        assert!(decode_start(&[0; 9]).is_err());
        assert!(decode_done(&[0; 31]).is_err());
    }

    #[test]
    fn partial_path_sits_beside_the_destination() {
        let p = partial_path(Path::new("/vaults/my_data.aegis"));
        assert_eq!(p, Path::new("/vaults/my_data.aegis.part"));
        assert_eq!(p.parent(), Path::new("/vaults/my_data.aegis").parent());
    }

    /// The chunk length must always leave room for the frame header.
    #[test]
    fn chunk_len_is_clamped_into_the_frame_budget() {
        let t = Transfer::new(EncryptedAtRest::aegis_vault()).chunk_len(usize::MAX);
        assert!(t.frame_len() <= MAX_FRAME_LEN);
        let t = Transfer::new(EncryptedAtRest::aegis_vault()).chunk_len(0);
        assert_eq!(t.chunk_len, 1, "a zero chunk would never make progress");
    }

    /// Shaping is on unless it is turned off by name.
    #[test]
    fn traffic_shaping_is_the_default() {
        let t = Transfer::new(EncryptedAtRest::aegis_vault());
        assert!(t.pacing.is_shaped(), "a default transfer must be shaped");
    }
}
