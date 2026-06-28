//! At-rest encryption for Atom Vault config files via GNOME Keyring.
//!
//! A random 32-byte key is generated on first launch and persisted in the
//! user's Secret Service (GNOME Keyring or compatible).  All config files are
//! wrapped with XChaCha20-Poly1305.  **If the keyring is unreachable the app
//! refuses to start** — plaintext config is never acceptable.
//!
//! # File format
//! ```text
//! [5-byte magic "ATOM\x01"][24-byte XChaCha20 nonce][ciphertext + 16-byte tag]
//! ```
//! Files written before this feature was added lack the magic header; they are
//! passed through on read so they can be transparently re-encrypted on the next
//! write (one-time migration).

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::sync::OnceLock;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"ATOM\x01";
const SERVICE: &str = "io.atom_vault.AtomVault";
const ACCOUNT: &str = "config-encryption-key";

static CONFIG_KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

/// Load (or generate) the config-file encryption key from the Secret Service.
///
/// Returns an error if the keyring is unreachable or if storing the key fails.
/// The caller **must** treat this as fatal — call `std::process::exit(1)` on
/// failure rather than continuing without encryption.
pub fn init_config_key() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Could not create runtime for keyring init: {e}"))?;
    let key = rt.block_on(fetch_or_create_key())
        .map_err(|e| -> Box<dyn std::error::Error> { format!("{e}").into() })?;
    let _ = CONFIG_KEY.set(key);
    Ok(())
}

async fn fetch_or_create_key(
) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    use secret_service::{EncryptionType, SecretService};

    let ss = SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| format!("Secret Service connect: {e}"))?;

    let collection = ss
        .get_default_collection()
        .await
        .map_err(|e| format!("Get default collection: {e}"))?;

    collection
        .unlock()
        .await
        .map_err(|e| format!("Unlock collection: {e}"))?;

    let attrs: HashMap<&str, &str> = [("application", SERVICE), ("purpose", ACCOUNT)]
        .into_iter()
        .collect();

    let items = collection
        .search_items(attrs.clone())
        .await
        .map_err(|e| format!("Search items: {e}"))?;

    if let Some(item) = items.into_iter().next() {
        let secret = item
            .get_secret()
            .await
            .map_err(|e| format!("Get secret: {e}"))?;
        if secret.len() == 32 {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&secret);
            return Ok(key);
        }
        // Wrong length — fall through to regenerate and overwrite
    }

    // First launch: generate a fresh key and persist it.
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let key = Zeroizing::new(raw);

    collection
        .create_item(
            "Atom Vault Config Encryption Key",
            attrs,
            key.as_ref(),
            true, // replace any corrupt/stale entry
            "application/octet-stream",
        )
        .await
        .map_err(|e| format!("Create keyring item: {e}"))?;

    Ok(key)
}

/// Encrypt `plaintext` with the config key.
///
/// # Panics
/// Panics if called before a successful [`init_config_key`].  This is a
/// programming error — init must always precede any config I/O.
pub fn encrypt_config(plaintext: &[u8]) -> Vec<u8> {
    let key = CONFIG_KEY
        .get()
        .expect("[FATAL] encrypt_config called before init_config_key succeeded");

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption must not fail for a valid key");

    let mut out = Vec::with_capacity(MAGIC.len() + 24 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt config data produced by [`encrypt_config`].
///
/// Files lacking the ATOM magic header are returned as-is so that files
/// written before encryption was introduced can be read once and then
/// re-encrypted on the next write (migration path only).
///
/// Returns an error if the ciphertext is truncated or the authentication tag
/// does not verify — both indicate corruption or a key mismatch.
pub fn decrypt_config(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !data.starts_with(MAGIC) {
        return Ok(data.to_vec());
    }
    let key = CONFIG_KEY
        .get()
        .expect("[FATAL] decrypt_config called before init_config_key succeeded");

    let payload = &data[MAGIC.len()..];
    if payload.len() < 24 {
        return Err("Encrypted config file is truncated — possible data corruption".into());
    }
    let (nonce_bytes, ciphertext) = payload.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Config decryption failed — corrupted file or keyring key mismatch".into())
}
