//! # p2p-direct — non-Tor sync for Atom Vault (Mode A: blind store)
//!
//! This crate implements the non-Tor transfer mechanism specified in the
//! project `CLAUDE.md`. It is the sibling of the Tor-based `p2p-sync` crate.
//!
//! The layered design (see the spec) is realised here as:
//!
//! * [`encode`] — **L3**: serialize a stream, split it into fixed-size blocks,
//!   pad the block *count* up a quantized ladder with random decoys, and emit a
//!   manifest. Kills structure- and size-fingerprinting.
//! * [`crypto`] — **L2**: per-block XChaCha20-Poly1305 with convergence-free,
//!   HKDF-derived block keys; the per-vault `root_key`; and the cap commitment.
//! * [`pake`] — **L4**: expand a short out-of-band secret via SPAKE2 and deliver
//!   the read-cap ([`ReadCap`]) over the resulting channel.
//! * [`store`] — **L1 / Mode A**: a [`store::BlindStore`] that holds only
//!   padded ciphertext under opaque IDs, plus the [`store::upload`] /
//!   [`store::download`] orchestration that ties the layers together.
//!
//! The single canonical bug this crate must never introduce (per the spec): the
//! `root_key` / full read-cap must never travel L1 (the store). Only opaque
//! ciphertext, random object IDs, and — at most — the commitment hash may go
//! near the store. The cap itself travels L4 ([`pake`]).

pub mod crypto;
pub mod encode;
pub mod pake;
pub mod store;

pub use crypto::RootKey;
pub use encode::{EncodeParams, Ladder, Manifest};

/// Errors produced anywhere in the non-Tor pipeline.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An AEAD open/seal or key-derivation step failed. Intentionally opaque —
    /// callers must not be able to distinguish *why* a decryption failed.
    #[error("cryptographic operation failed")]
    Crypto,

    /// The SPAKE2 handshake failed (wrong short secret, or a malformed peer
    /// message). Also intentionally opaque to avoid an online guessing oracle.
    #[error("PAKE handshake failed")]
    Pake,

    /// (De)serialization of a manifest or capability failed.
    #[error("serialization error: {0}")]
    Serialize(String),

    /// The underlying blind store failed to PUT or GET an object.
    #[error("blind store error: {0}")]
    Store(String),

    /// A local I/O error while reading the source stream or writing output.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Data read back from the store did not match the shape the manifest
    /// promised (truncated object, wrong length, unknown version, …).
    #[error("malformed data: {0}")]
    Malformed(String),

    /// `H(root_key)` did not match the commitment carried out-of-band — the
    /// payload the store served does not correspond to the cap we were given.
    #[error("commitment mismatch: downloaded payload does not match the capability")]
    CommitmentMismatch,
}

/// A bearer read-capability for a Mode-A transfer.
///
/// Knowledge of `root_key` (which derives every per-block key and the manifest
/// key) plus `manifest_id` (the opaque store object holding the encrypted
/// manifest) is sufficient to fetch and decrypt the whole vault. This is the
/// secret that travels **L4** via [`pake`] and must never touch the store.
pub struct ReadCap {
    /// Per-vault random root key. All block/manifest keys derive from it.
    pub root_key: RootKey,
    /// Opaque store object ID under which the encrypted manifest lives.
    pub manifest_id: [u8; 32],
}

impl ReadCap {
    /// Fixed wire layout for sealing over L4: `root_key(32) || manifest_id(32)`.
    pub(crate) const SERIALIZED_LEN: usize = 64;

    pub(crate) fn to_bytes(&self) -> zeroize::Zeroizing<[u8; Self::SERIALIZED_LEN]> {
        let mut out = zeroize::Zeroizing::new([0u8; Self::SERIALIZED_LEN]);
        out[..32].copy_from_slice(self.root_key.as_bytes());
        out[32..].copy_from_slice(&self.manifest_id);
        out
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(Error::Malformed("read-cap has wrong length".into()));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[..32]);
        let mut manifest_id = [0u8; 32];
        manifest_id.copy_from_slice(&bytes[32..]);
        Ok(ReadCap {
            root_key: RootKey::from_bytes(root),
            manifest_id,
        })
    }

    /// The commitment a sender publishes out-of-band so a recipient can verify
    /// that the payload the store served matches this cap. `H(root_key)`.
    pub fn commitment(&self) -> [u8; 32] {
        crypto::commitment(&self.root_key)
    }
}
