// atom/src/crypto/mod.rs

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use scrypt::{Params as ScryptParams, scrypt};
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Cryptographic Constants
pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;

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

/// Encrypts a single chunk of file data.
pub fn encrypt_chunk(
    unlocked_vault: &UnlockedVault,
    chunk_plaintext: &[u8],
    chunk_offset: u64,
) -> Result<(Vec<u8>, [u8; XNONCE_LEN]), chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(&Key::from(unlocked_vault.dek));
    let nonce_bytes = generate_xnonce();
    let nonce = XNonce::from(nonce_bytes);

    let offset_bytes = chunk_offset.to_le_bytes();
    let payload = Payload {
        msg: chunk_plaintext,
        aad: &offset_bytes,
    };

    let ciphertext = cipher.encrypt(&nonce, payload)?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypts a single chunk of file data.
pub fn decrypt_chunk(
    unlocked_vault: &UnlockedVault,
    chunk_ciphertext: &[u8],
    nonce_bytes: &[u8; XNONCE_LEN],
    chunk_offset: u64,
) -> Result<Zeroizing<Vec<u8>>, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(&Key::from(unlocked_vault.dek));
    let nonce = XNonce::from(*nonce_bytes);

    let offset_bytes = chunk_offset.to_le_bytes();
    let payload = Payload {
        msg: chunk_ciphertext,
        aad: &offset_bytes,
    };

    let plaintext_vec = cipher.decrypt(&nonce, payload)?;
    Ok(Zeroizing::new(plaintext_vec))
}
