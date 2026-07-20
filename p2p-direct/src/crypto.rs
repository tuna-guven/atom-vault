//! L2 — object encryption primitives.
//!
//! Every per-block key is derived from a single per-vault random `root_key` via
//! HKDF-SHA256. This is deliberately **convergence-free**: keys depend only on
//! the root and a block index, never on block *content*, so an adversary who
//! guesses a block's plaintext cannot confirm its presence (the attack that
//! rules out convergent/content-derived keys per the spec §5).
//!
//! Manifest and block payloads use distinct HKDF labels so a manifest-cap and a
//! block-read-cap could be separated later (Tahoe-LAFS style), even though v1
//! grants a single root.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

/// Plaintext size of one block before AEAD (the last real block is zero-padded
/// up to this). Ciphertext is this plus [`AEAD_TAG_LEN`].
pub const DEFAULT_BLOCK_SIZE: usize = 1 << 20; // 1 MiB

/// XChaCha20-Poly1305 authentication tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length (extended-nonce: 24 bytes, safe to pick at
/// random across a very large block count with no counter-reuse risk).
pub const NONCE_LEN: usize = 24;

/// HKDF `info` label prefix for per-block keys. The block index (LE u32) is
/// appended to derive `block_key_i`.
const LABEL_BLOCK: &[u8] = b"atom-block-v1|";

/// HKDF `info` label for the manifest encryption key.
const LABEL_MANIFEST: &[u8] = b"atom-manifest-v1";

/// Domain separator for the cap commitment `H(root_key)`.
const LABEL_COMMITMENT: &[u8] = b"atom-cap-commitment-v1";

/// The per-vault random root key. Zeroized on drop.
#[derive(Clone)]
pub struct RootKey(Zeroizing<[u8; 32]>);

impl RootKey {
    /// Draw a fresh root key from the OS RNG.
    pub fn generate() -> Self {
        RootKey(Zeroizing::new(random_array()))
    }

    /// Wrap known bytes (e.g. a cap received over L4).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        RootKey(Zeroizing::new(bytes))
    }

    /// Borrow the raw key bytes. Handle with care — never let these reach L1.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive the key for real block `index` from the root: convergence-free,
/// content-independent. `block_key_i = HKDF(root_key, "atom-block-v1|" || i)`.
pub fn derive_block_key(root: &RootKey, index: u32) -> Zeroizing<[u8; 32]> {
    let mut info = [0u8; LABEL_BLOCK.len() + 4];
    info[..LABEL_BLOCK.len()].copy_from_slice(LABEL_BLOCK);
    info[LABEL_BLOCK.len()..].copy_from_slice(&index.to_le_bytes());
    hkdf_expand(root.as_bytes(), &info)
}

/// Derive the manifest encryption key from the root (distinct label from blocks).
pub fn derive_manifest_key(root: &RootKey) -> Zeroizing<[u8; 32]> {
    hkdf_expand(root.as_bytes(), LABEL_MANIFEST)
}

/// The cap commitment `H(root_key)` (domain-separated SHA-256). Published
/// out-of-band so a recipient can bind received blocks to the cap they hold.
pub fn commitment(root: &RootKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_COMMITMENT);
    hasher.update(root.as_bytes());
    hasher.finalize().into()
}

/// AEAD-seal `plaintext` under `key`+`nonce`. Returns `ciphertext || tag`.
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Crypto)?;
    cipher
        .encrypt(&XNonce::from(*nonce), plaintext)
        .map_err(|_| Error::Crypto)
}

/// AEAD-open `ciphertext` (which includes the tag) under `key`+`nonce`.
pub fn open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Crypto)?;
    cipher
        .decrypt(&XNonce::from(*nonce), ciphertext)
        .map_err(|_| Error::Crypto)
}

/// A fresh random 24-byte nonce from the OS RNG.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    random_array()
}

/// A fresh random opaque object ID from the OS RNG.
pub fn random_object_id() -> [u8; 32] {
    random_array()
}

/// Fill `buf` with cryptographically secure random bytes. Panics only if the
/// OS RNG is unavailable, which is unrecoverable for a security tool.
pub fn random_fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS random number generator is unavailable");
}

/// A fresh random fixed-size array.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    random_fill(&mut out);
    out
}

fn hkdf_expand(ikm: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut okm[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vector: derivation is deterministic in root+index and
    // convergence-free (independent of any plaintext). The `EXPECTED_BLOCK0`
    // value is the real HKDF-SHA256 output for ikm=0x11*32, info=LABEL_BLOCK||0.
    // Locks the KDF wiring so a dependency bump that silently changes the
    // labels/derivation is caught. (Value filled in from a first test run.)
    #[test]
    fn block_key_kat() {
        let root = RootKey::from_bytes([0x11; 32]);
        let k0 = derive_block_key(&root, 0);
        let k0_again = derive_block_key(&root, 0);
        let k1 = derive_block_key(&root, 1);
        assert_eq!(&*k0, &*k0_again, "derivation must be deterministic");
        assert_ne!(&*k0, &*k1, "distinct indices yield distinct keys");
        assert_eq!(&*k0, &EXPECTED_BLOCK0, "block-0 KDF wiring changed");
    }

    // Real HKDF-SHA256(ikm=[0x11;32], info=b"atom-block-v1|"||0u32le) output.
    const EXPECTED_BLOCK0: [u8; 32] = [
        0x05, 0x99, 0x49, 0xb1, 0x9e, 0xa9, 0x84, 0xd6, 0x28, 0x54, 0xa4, 0x51, 0x1a, 0xba, 0x93,
        0x7a, 0xfe, 0x14, 0x4e, 0xdb, 0xd4, 0xe9, 0x0c, 0x3d, 0xe6, 0xee, 0x51, 0x58, 0xc9, 0xca,
        0x29, 0x78,
    ];

    #[test]
    fn manifest_key_differs_from_block_key() {
        let root = RootKey::from_bytes([0x22; 32]);
        let mk = derive_manifest_key(&root);
        let bk0 = derive_block_key(&root, 0);
        assert_ne!(&*mk, &*bk0, "label separation must hold");
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x33u8; 32];
        let nonce = random_nonce();
        let pt = b"attack at dawn, but only if the vault says so";
        let ct = seal(&key, &nonce, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + AEAD_TAG_LEN);
        let back = open(&key, &nonce, &ct).unwrap();
        assert_eq!(&back, pt);
    }

    #[test]
    fn open_rejects_tamper() {
        let key = [0x44u8; 32];
        let nonce = random_nonce();
        let mut ct = seal(&key, &nonce, b"hello").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&key, &nonce, &ct).is_err(), "AEAD must reject tampering");
    }

    #[test]
    fn commitment_binds_root() {
        let a = RootKey::from_bytes([0x55; 32]);
        let b = RootKey::from_bytes([0x56; 32]);
        assert_ne!(commitment(&a), commitment(&b));
        assert_eq!(commitment(&a), commitment(&RootKey::from_bytes([0x55; 32])));
    }
}
