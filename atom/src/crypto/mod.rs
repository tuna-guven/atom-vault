// atom/src/crypto/mod.rs
#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use scrypt::{Params as ScryptParams, scrypt};
use sha2::Sha256;
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Cryptographic Constants
pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;

/// Length of the wrapped DEK on disk (32-byte key + 16-byte Poly1305 tag).
pub const WRAPPED_DEK_LEN: usize = KEY_LEN + 16;

/// Per-chunk random HKDF salt (§4).
pub const FILE_SALT_LEN: usize = 16;

/// Per-chunk random identifier, stored in the chunk's `ChunkEntry` (§4).
///
/// Deliberately random rather than a content address: `file_id` is stored in
/// cleartext metadata, so deriving it from plaintext would let an observer link
/// identical chunks — the equality leak that rules out convergent encryption.
pub const FILE_ID_LEN: usize = 16;

/// Magic + version prefix on every v1 chunk blob (§7).
pub const CHUNK_MAGIC_V1: &[u8; 3] = b"AV\x01";

/// HKDF context string for per-chunk key derivation (§4).
const CHUNK_KEY_INFO: &[u8] = b"atom-vault v1 file-key";

/// Fixed `file_id` for the vault metadata block.
///
/// The metadata block is the root of the vault, so there is nowhere to store a
/// random id for it — it must be derivable from nothing. A fixed value is safe
/// here because the per-write random `file_salt` still yields a distinct key on
/// every save; the constant only provides domain separation from data chunks,
/// whose ids are random 16-byte values that will not collide with this pattern.
pub const METADATA_FILE_ID: [u8; FILE_ID_LEN] = *b"atom-vault-meta1";

/// Fixed size of the vault header written by `create` and preserved by `vacuum`:
/// master pointer (8) + KDF params (13) + salt (32) + DEK nonce (24) +
/// wrapped DEK (48) = 125 bytes.
///
/// Defined once here because `vacuum` previously hardcoded a stale `112` — the
/// value from before `KdfSettings` joined the header — and truncated the last
/// 13 bytes of the wrapped DEK, permanently bricking the vault.
pub const VAULT_HEADER_SIZE: u64 = 8
    + KdfSettings::SIZE as u64
    + SALT_LEN as u64
    + XNONCE_LEN as u64
    + WRAPPED_DEK_LEN as u64;

/// Byte overhead a v1 blob adds on top of the padded plaintext:
/// magic (3) + file_salt (16) + nonce (24) + Poly1305 tag (16).
pub const CHUNK_OVERHEAD: usize = CHUNK_MAGIC_V1.len() + FILE_SALT_LEN + XNONCE_LEN + 16;

/// Errors surfaced by the chunk encryption layer.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Blob is truncated, or its magic/version prefix is not `CHUNK_MAGIC_V1`.
    BadFormat,
    /// HKDF expansion failed (only possible on an invalid output length).
    Kdf,
    /// AEAD sealing failed.
    Seal,
    /// AEAD authentication failed. No plaintext is produced.
    Open,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            CryptoError::BadFormat => "chunk blob is truncated or not a v1 blob",
            CryptoError::Kdf => "per-chunk key derivation failed",
            CryptoError::Seal => "chunk encryption failed",
            CryptoError::Open => "chunk authentication failed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CryptoError {}

// Type aliases for clarity
pub type Salt = [u8; SALT_LEN];
pub type VaultKey = [u8; KEY_LEN]; // Used for both KEK and DEK
pub type WrappedKey = Vec<u8>; // The DEK after it's encrypted (Ciphertext + 16-byte Tag)

/// Available Key Derivation Functions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfChoice {
    Argon2id,
    Scrypt,
}

/// Settings supplied by CLI flags or read from the .aegis header
#[derive(Debug, Clone, Copy)]
pub struct KdfSettings {
    pub choice: KdfChoice,
    pub memory_kib: u32,
    pub iterations: u32, // Maps to t_cost for Argon2, 'r' (block size) for Scrypt
    pub parallelism: u32,
}

// Keep the default exactly as your current implementation so nothing breaks
impl Default for KdfSettings {
    fn default() -> Self {
        Self {
            choice: KdfChoice::Argon2id,
            memory_kib: 65536, // 64 MiB
            iterations: 3,     // 3 transform rounds
            parallelism: 4,    // 4 threads
        }
    }
}

impl KdfSettings {
    pub const SIZE: usize = 13;

    /// Serializes the settings into exactly 13 bytes for the vault header
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        // Using spaces to prevent markdown parsing errors
        buf[0] = match self.choice {
            KdfChoice::Argon2id => 0,
            KdfChoice::Scrypt => 1,
        };

        buf[1..5].copy_from_slice(&self.memory_kib.to_le_bytes());
        buf[5..9].copy_from_slice(&self.iterations.to_le_bytes());
        buf[9..13].copy_from_slice(&self.parallelism.to_le_bytes());

        buf
    }

    /// Deserializes the settings from the vault header when opening a file
    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, &'static str> {
        // Using spaces to prevent markdown parsing errors
        let choice = match buf[0] {
            0 => KdfChoice::Argon2id,
            1 => KdfChoice::Scrypt,
            _ => return Err("Unknown KDF algorithm byte in vault header"),
        };

        Ok(Self {
            choice,
            memory_kib: u32::from_le_bytes(buf[1..5].try_into().unwrap()),
            iterations: u32::from_le_bytes(buf[5..9].try_into().unwrap()),
            parallelism: u32::from_le_bytes(buf[9..13].try_into().unwrap()),
        })
    }
}

/// The structure that holds the raw Data Encryption Key (DEK) in memory...
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockedVault {
    pub dek: VaultKey, // Made public so encrypt/decrypt chunk can access it, or you can use a getter.
}

/// Derives a 32-byte Key Encryption Key (KEK) from a password, salt, and chosen settings.
pub fn derive_kek(password: &str, salt: &Salt, settings: &KdfSettings) -> Result<VaultKey, String> {
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);

    match settings.choice {
        KdfChoice::Argon2id => {
            let params = Argon2Params::new(
                settings.memory_kib,
                settings.iterations,
                settings.parallelism,
                Some(KEY_LEN),
            )
            .map_err(|e| format!("Invalid Argon2 params: {:?}", e))?;

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(password.as_bytes(), salt, &mut kek[..])
                .map_err(|e| format!("Argon2 hashing failed: {:?}", e))?;
        }
        KdfChoice::Scrypt => {
            // Scrypt uses log2(N) for memory cost.
            let mut log_n = (settings.memory_kib as f64).log2() as u8;
            log_n = log_n.clamp(10, 20); // Keep within safe, standard Scrypt bounds

            let params = ScryptParams::new(
                log_n,
                settings.iterations.max(1),  // 'r' block size parameter
                settings.parallelism.max(1), // 'p' parallelization parameter
            )
            .map_err(|e| format!("Invalid Scrypt params: {:?}", e))?;

            scrypt(password.as_bytes(), salt, &params, &mut kek[..])
                .map_err(|e| format!("Scrypt hashing failed: {:?}", e))?;
        }
    }

    let mut final_kek = [0u8; KEY_LEN];
    final_kek.copy_from_slice(&kek[..]);

    Ok(final_kek)
}

/// Benchmarks the system to find the optimal transform rounds for a target time
pub fn calibrate_kdf(target_ms: u32, choice: KdfChoice, memory_kib: u32, parallelism: u32) -> u32 {
    let salt = generate_32_bytes();
    let password = "benchmark_password";

    let settings = KdfSettings {
        choice,
        memory_kib,
        iterations: 1, // Run a single baseline iteration
        parallelism,
    };

    let start = Instant::now();
    let _ = derive_kek(password, &salt, &settings);
    let elapsed_ms = start.elapsed().as_millis() as u32;

    // Prevent divide-by-zero on extremely fast systems
    let elapsed_ms = elapsed_ms.max(1);

    // Calculate required rounds (linear scaling)
    let calculated_rounds = target_ms / elapsed_ms;

    // Apply safe minimum bounds
    match choice {
        KdfChoice::Argon2id => calculated_rounds.max(3),
        KdfChoice::Scrypt => calculated_rounds.max(8),
    }
}

/// Helper to generate 32 bytes of secure random data (for DEK and Salt)
pub fn generate_32_bytes() -> [u8; 32] {
    let mut data = [0u8; 32];
    OsRng.fill_bytes(&mut data);
    data
}

/// Helper to generate a 24-byte random Nonce for XChaCha20
pub fn generate_xnonce() -> [u8; XNONCE_LEN] {
    let mut data = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut data);
    data
}

/// Encrypts the raw DEK using the KEK and a random Nonce.
pub fn wrap_dek(
    kek: &VaultKey,
    dek: &VaultKey,
) -> Result<(WrappedKey, [u8; XNONCE_LEN]), chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*kek));
    let nonce_bytes = generate_xnonce();
    let nonce = XNonce::from(nonce_bytes);
    let wrapped_dek = cipher.encrypt(&nonce, dek.as_ref())?;
    Ok((wrapped_dek, nonce_bytes))
}

/// Decrypts the wrapped DEK.
pub fn unwrap_dek(
    kek: &VaultKey,
    wrapped_dek: &[u8],
    nonce_bytes: &[u8; XNONCE_LEN],
) -> Result<UnlockedVault, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*kek));
    let nonce = XNonce::from(*nonce_bytes);
    let decrypted_dek_vec = Zeroizing::new(cipher.decrypt(&nonce, wrapped_dek)?);

    if decrypted_dek_vec.len() != KEY_LEN {
        return Err(chacha20poly1305::Error);
    }

    let mut raw_dek = [0u8; KEY_LEN];
    raw_dek.copy_from_slice(&decrypted_dek_vec[..]);
    Ok(UnlockedVault { dek: raw_dek })
}

/// Generates a fresh random per-chunk identifier.
pub fn generate_file_id() -> [u8; FILE_ID_LEN] {
    let mut id = [0u8; FILE_ID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

/// Derives the per-chunk encryption key (§4).
///
/// `chunk_key = HKDF-SHA256(ikm = DEK, salt = file_salt, info = ctx || file_id)`
///
/// Every chunk gets a fresh random `file_salt` **and** a unique `file_id`, so no
/// two chunks are ever encrypted under the same key. A nonce collision *across*
/// chunks is therefore structurally impossible rather than merely improbable,
/// and the 24-byte random nonce covers reuse *within* a key's lifetime (which
/// here is a single message anyway).
///
/// Note the derivation depends only on the DEK, the salt and the id — never on
/// chunk content or on the chunk's physical offset in the vault file. Content
/// independence keeps the scheme convergence-free; offset independence is what
/// lets `vacuum` relocate a chunk as a pure byte-copy.
fn derive_chunk_key(
    dek: &VaultKey,
    file_salt: &[u8; FILE_SALT_LEN],
    file_id: &[u8; FILE_ID_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let mut info = [0u8; CHUNK_KEY_INFO.len() + FILE_ID_LEN];
    info[..CHUNK_KEY_INFO.len()].copy_from_slice(CHUNK_KEY_INFO);
    info[CHUNK_KEY_INFO.len()..].copy_from_slice(file_id);

    let hk = Hkdf::<Sha256>::new(Some(file_salt), dek);
    let mut chunk_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info, &mut chunk_key[..])
        .map_err(|_| CryptoError::Kdf)?;

    Ok(chunk_key)
}

/// Additional authenticated data binding a chunk to its version and identity,
/// so a blob cannot be relabelled or replayed as a different chunk.
///
/// The offset is deliberately *not* bound: chunks move during `vacuum`, and
/// binding a mutable physical position would invalidate the tag on every
/// relocated chunk.
fn chunk_aad(file_id: &[u8; FILE_ID_LEN]) -> [u8; 3 + FILE_ID_LEN] {
    let mut aad = [0u8; 3 + FILE_ID_LEN];
    aad[..3].copy_from_slice(CHUNK_MAGIC_V1);
    aad[3..].copy_from_slice(file_id);
    aad
}

/// Encrypts a single chunk of file data under a freshly derived per-chunk key.
///
/// Returns the complete v1 blob (§7):
/// `magic(3) || file_salt(16) || nonce(24) || ciphertext || tag(16)`
pub fn encrypt_chunk(
    unlocked_vault: &UnlockedVault,
    chunk_plaintext: &[u8],
    file_id: &[u8; FILE_ID_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let mut file_salt = [0u8; FILE_SALT_LEN];
    OsRng.fill_bytes(&mut file_salt);

    let chunk_key = derive_chunk_key(&unlocked_vault.dek, &file_salt, file_id)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*chunk_key));

    let nonce_bytes = generate_xnonce();
    let aad = chunk_aad(file_id);

    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: chunk_plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Seal)?;

    let mut blob = Vec::with_capacity(CHUNK_OVERHEAD + chunk_plaintext.len());
    blob.extend_from_slice(CHUNK_MAGIC_V1);
    blob.extend_from_slice(&file_salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// Decrypts a v1 chunk blob produced by [`encrypt_chunk`].
///
/// On authentication failure this returns `CryptoError::Open` and emits no
/// plaintext whatsoever; the AEAD verifies the tag in constant time before
/// releasing any bytes.
pub fn decrypt_chunk(
    unlocked_vault: &UnlockedVault,
    blob: &[u8],
    file_id: &[u8; FILE_ID_LEN],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Parse: magic || file_salt || nonce || ciphertext||tag
    let rest = blob
        .strip_prefix(CHUNK_MAGIC_V1)
        .ok_or(CryptoError::BadFormat)?;
    if rest.len() < FILE_SALT_LEN + XNONCE_LEN + 16 {
        return Err(CryptoError::BadFormat);
    }
    let (file_salt, rest) = rest.split_at(FILE_SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(XNONCE_LEN);

    let file_salt: &[u8; FILE_SALT_LEN] = file_salt.try_into().expect("split_at guarantees length");
    let nonce_bytes: [u8; XNONCE_LEN] = nonce_bytes.try_into().expect("split_at guarantees length");

    let chunk_key = derive_chunk_key(&unlocked_vault.dek, file_salt, file_id)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*chunk_key));

    let aad = chunk_aad(file_id);

    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Open)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_CHUNK_SIZE: usize = 64 * 1024;

    fn vault() -> UnlockedVault {
        UnlockedVault { dek: [0x42; KEY_LEN] }
    }

    /// Header arithmetic must agree with what `create` writes. `vacuum` used a
    /// stale literal that drifted from this and destroyed the wrapped DEK.
    #[test]
    fn vault_header_size_matches_layout() {
        assert_eq!(VAULT_HEADER_SIZE, 125);
        assert_eq!(
            VAULT_HEADER_SIZE,
            8 + KdfSettings::SIZE as u64 + 32 + 24 + 48
        );
    }

    #[test]
    fn roundtrip_across_sizes() {
        let v = vault();
        for len in [0usize, 1, 63, MAX_CHUNK_SIZE - 1, MAX_CHUNK_SIZE, MAX_CHUNK_SIZE + 1, 300_000] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let id = generate_file_id();
            let blob = encrypt_chunk(&v, &pt, &id).unwrap();
            assert_eq!(blob.len(), pt.len() + CHUNK_OVERHEAD, "len {}", len);
            assert!(blob.starts_with(CHUNK_MAGIC_V1));
            let back = decrypt_chunk(&v, &blob, &id).unwrap();
            assert_eq!(&back[..], &pt[..], "roundtrip failed at len {}", len);
        }
    }

    /// Flipping any single bit anywhere in the blob — magic, salt, nonce,
    /// ciphertext or tag — must cause a hard rejection.
    #[test]
    fn tamper_anywhere_is_rejected() {
        let v = vault();
        let id = generate_file_id();
        let blob = encrypt_chunk(&v, b"the quick brown fox jumps", &id).unwrap();

        for byte in 0..blob.len() {
            let mut bad = blob.clone();
            bad[byte] ^= 0x01;
            assert!(
                decrypt_chunk(&v, &bad, &id).is_err(),
                "tampered byte {} was accepted",
                byte
            );
        }
    }

    #[test]
    fn truncation_is_rejected() {
        let v = vault();
        let id = generate_file_id();
        let blob = encrypt_chunk(&v, b"payload", &id).unwrap();
        for cut in 0..blob.len() {
            assert!(decrypt_chunk(&v, &blob[..cut], &id).is_err(), "prefix {} accepted", cut);
        }
    }

    /// The AAD binds file_id, so a blob cannot be replayed as a different chunk.
    #[test]
    fn wrong_file_id_is_rejected() {
        let v = vault();
        let id = generate_file_id();
        let blob = encrypt_chunk(&v, b"secret contents", &id).unwrap();

        let mut other = id;
        other[0] ^= 0xff;
        assert_eq!(decrypt_chunk(&v, &blob, &other).unwrap_err(), CryptoError::Open);
    }

    #[test]
    fn wrong_dek_is_rejected() {
        let id = generate_file_id();
        let blob = encrypt_chunk(&vault(), b"secret contents", &id).unwrap();
        let other = UnlockedVault { dek: [0x43; KEY_LEN] };
        assert_eq!(decrypt_chunk(&other, &blob, &id).unwrap_err(), CryptoError::Open);
    }

    #[test]
    fn non_v1_blob_is_rejected() {
        let v = vault();
        let id = generate_file_id();
        let mut blob = encrypt_chunk(&v, b"x", &id).unwrap();
        blob[2] = 0x00; // version byte
        assert_eq!(decrypt_chunk(&v, &blob, &id).unwrap_err(), CryptoError::BadFormat);
    }

    /// No deterministic leak: identical plaintext under identical key and id
    /// must still produce distinct blobs (fresh salt + fresh nonce). This is
    /// what separates the design from a convergent/SIV-style scheme.
    #[test]
    fn identical_plaintext_yields_distinct_blobs() {
        let v = vault();
        let id = generate_file_id();
        let pt = b"identical plaintext";

        let a = encrypt_chunk(&v, pt, &id).unwrap();
        let b = encrypt_chunk(&v, pt, &id).unwrap();

        assert_ne!(a, b, "same plaintext produced identical blobs");
        // salt and nonce regions must both differ
        let sr = CHUNK_MAGIC_V1.len()..CHUNK_MAGIC_V1.len() + FILE_SALT_LEN;
        let nr = sr.end..sr.end + XNONCE_LEN;
        assert_ne!(a[sr.clone()], b[sr], "file_salt was reused");
        assert_ne!(a[nr.clone()], b[nr.clone()], "nonce was reused");
        // and therefore the ciphertext bodies differ
        assert_ne!(a[nr.end..], b[nr.end..]);
    }

    /// Distinct salts or distinct ids must both yield distinct keys, so no two
    /// chunks ever share one.
    #[test]
    fn derivation_separates_on_salt_and_id() {
        let dek = [0x42u8; KEY_LEN];
        let s1 = [0x01u8; FILE_SALT_LEN];
        let s2 = [0x02u8; FILE_SALT_LEN];
        let i1 = [0x0au8; FILE_ID_LEN];
        let i2 = [0x0bu8; FILE_ID_LEN];

        let k11 = derive_chunk_key(&dek, &s1, &i1).unwrap();
        let k12 = derive_chunk_key(&dek, &s1, &i2).unwrap();
        let k21 = derive_chunk_key(&dek, &s2, &i1).unwrap();

        assert_ne!(&*k11, &*k12, "distinct file_id must separate keys");
        assert_ne!(&*k11, &*k21, "distinct file_salt must separate keys");
        assert_eq!(&*k11, &*derive_chunk_key(&dek, &s1, &i1).unwrap(), "must be deterministic");
    }

    #[test]
    fn metadata_id_differs_from_random_ids() {
        let dek = [0x42u8; KEY_LEN];
        let salt = [0x07u8; FILE_SALT_LEN];
        let meta = derive_chunk_key(&dek, &salt, &METADATA_FILE_ID).unwrap();
        let data = derive_chunk_key(&dek, &salt, &[0u8; FILE_ID_LEN]).unwrap();
        assert_ne!(&*meta, &*data, "metadata key must be domain-separated");
    }

    /// Known-answer test pinning the HKDF wiring (ikm/salt/info construction) so
    /// a refactor or dependency bump cannot silently change derived keys and
    /// render every existing vault unreadable.
    #[test]
    fn derivation_kat() {
        let key = derive_chunk_key(&[0x11; KEY_LEN], &[0x22; FILE_SALT_LEN], &[0x33; FILE_ID_LEN]).unwrap();
        assert_eq!(&*key, &EXPECTED_KAT, "per-chunk KDF wiring changed");
    }

    /// HKDF-SHA256(ikm = [0x11;32], salt = [0x22;16],
    ///             info = b"atom-vault v1 file-key" || [0x33;16]), L = 32.
    ///
    /// Cross-checked against an independent RFC 5869 implementation, so this
    /// pins the standard, not merely this crate's behaviour.
    const EXPECTED_KAT: [u8; 32] = [
        11, 138, 127, 181, 212, 85, 215, 133, 10, 76, 42, 128, 37, 172, 34, 106, 230, 49, 246,
        21, 115, 59, 86, 192, 228, 44, 232, 124, 200, 207, 94, 119,
    ];
}
