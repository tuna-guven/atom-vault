use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Cryptographic Constants
pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;

// Type aliases for clarity
pub type Salt = [u8; SALT_LEN];
pub type VaultKey = [u8; KEY_LEN]; // Used for both KEK and DEK
pub type WrappedKey = Vec<u8>; // The DEK after it's encrypted (Ciphertext + 16-byte Tag)

/// The structure that holds the raw Data Encryption Key (DEK) in memory while the vault is open.
/// We use ZeroizeOnDrop so that when this struct goes out of scope, Rust automatically overwrites
/// the DEK in RAM with zeros, preventing memory-scraping malware from finding it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockedVault {
    dek: VaultKey,
}

/// Derives a 32-byte Key Encryption Key (KEK) from a password and a salt.
pub fn derive_kek(password: &str, salt: &Salt) -> Result<VaultKey, argon2::Error> {
    // 1. Define your Argon2id parameters directly (m_cost, t_cost, p_cost, output_len)
    let params = Params::new(65536, 3, 4, Some(KEY_LEN))?;

    // 2. Initialize the Argon2 context
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // 3. Hash the password into a 32-byte array
    // Zafiyet Düzeltmesi: Hata durumunda KEK'in RAM'de kalmaması için Zeroizing ile sarmalandı.
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon2.hash_password_into(password.as_bytes(), salt, &mut kek[..])?;

    // 4. Return the resulting KEK
    let mut final_kek = [0u8; KEY_LEN];
    final_kek.copy_from_slice(&kek[..]);

    Ok(final_kek)
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
/// Returns a tuple containing the (Wrapped DEK Ciphertext, The Nonce Used).
pub fn wrap_dek(
    kek: &VaultKey,
    dek: &VaultKey,
) -> Result<(WrappedKey, [u8; XNONCE_LEN]), chacha20poly1305::Error> {
    // 1. Initialize the cipher with the KEK
    let cipher = XChaCha20Poly1305::new(kek.into());

    // 2. Generate a random 24-byte nonce
    let nonce_bytes = generate_xnonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    // 3. Encrypt the DEK.
    let wrapped_dek = cipher.encrypt(nonce, dek.as_ref())?;

    // Return the ciphertext and the nonce so your friend can save them to the .aeigs file header
    Ok((wrapped_dek, nonce_bytes))
}

/// Decrypts the wrapped DEK. If the KEK is wrong or the data was tampered with, this fails.
pub fn unwrap_dek(
    kek: &VaultKey,
    wrapped_dek: &[u8],
    nonce_bytes: &[u8; XNONCE_LEN],
) -> Result<UnlockedVault, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(kek.into());
    let nonce = XNonce::from_slice(nonce_bytes);

    // Attempt to decrypt and verify the Auth Tag simultaneously
    let decrypted_dek_vec = Zeroizing::new(cipher.decrypt(nonce, wrapped_dek)?);

    // Güvenlik: Eksik veya bozuk veri kopyalamasını engellemek için tam boyut kontrolü
    if decrypted_dek_vec.len() != KEY_LEN {
        return Err(chacha20poly1305::Error);
    }

    // Convert the Vec<u8> back into our strict 32-byte VaultKey array
    let mut raw_dek = [0u8; KEY_LEN];
    raw_dek.copy_from_slice(&decrypted_dek_vec[..]);

    Ok(UnlockedVault { dek: raw_dek })
}

/// Encrypts a single chunk of file data.
/// Binds the chunk's offset as Additional Authenticated Data (AAD) to prevent reordering attacks.
pub fn encrypt_chunk(
    unlocked_vault: &UnlockedVault,
    chunk_plaintext: &[u8],
    chunk_offset: u64,
) -> Result<(Vec<u8>, [u8; XNONCE_LEN]), chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(unlocked_vault.dek.as_ref().into());
    let nonce_bytes = generate_xnonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Bind the offset cryptographically to this specific chunk
    let offset_bytes = chunk_offset.to_le_bytes();
    let payload = Payload {
        msg: chunk_plaintext,
        aad: &offset_bytes,
    };

    let ciphertext = cipher.encrypt(nonce, payload)?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypts a single chunk of file data.
/// Verifies the chunk_offset AAD to ensure the chunk wasn't moved.
pub fn decrypt_chunk(
    unlocked_vault: &UnlockedVault,
    chunk_ciphertext: &[u8],
    nonce_bytes: &[u8; XNONCE_LEN],
    chunk_offset: u64,
) -> Result<Zeroizing<Vec<u8>>, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(unlocked_vault.dek.as_ref().into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let offset_bytes = chunk_offset.to_le_bytes();
    let payload = Payload {
        msg: chunk_ciphertext,
        aad: &offset_bytes,
    };

    let plaintext_vec = cipher.decrypt(nonce, payload)?;
    Ok(Zeroizing::new(plaintext_vec))
}