use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// A Tor v3 Onion address string (e.g., "pg6mm...pscryd.onion")
pub type OnionAddress = String;

/// Core mathematical derivation for the daily Tor key.
/// Both peers execute this independently. The `is_local_host` flag determines
/// which peer's daily address is being generated.
pub fn derive_daily_key(
    master_secret: &[u8; 32],
    local_identity_pubkey: &[u8; 32],
    remote_identity_pubkey: &[u8; 32],
    is_local_host: bool,
) -> SigningKey {
    // 1. Calculate the current 24-hour epoch
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let epoch = now / 86400;

    // 2. Deterministic role assignment to prevent key collisions
    // We sort the permanent public keys. The smaller key is Peer A.
    let is_peer_a = local_identity_pubkey < remote_identity_pubkey;

    // 3. Determine the prefix based on whose key we are deriving
    let role_prefix = match (is_peer_a, is_local_host) {
        (true, true) => b"host-A",   // I am A, deriving my hosting key
        (false, true) => b"host-B",  // I am B, deriving my hosting key
        (true, false) => b"host-B",  // I am A, deriving B's address to connect
        (false, false) => b"host-A", // I am B, deriving A's address to connect
    };

    // 4. Construct the contextual binding
    let mut info = Vec::new();
    info.extend_from_slice(b"atom-vault-hs-v1|");
    info.extend_from_slice(role_prefix);
    info.extend_from_slice(b"|epoch|");
    info.extend_from_slice(&epoch.to_le_bytes());

    // 5. Expand the secret via HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(None, master_secret);

    // SECURE: Wrap the Output Keying Material (OKM) in Zeroizing.
    // This array holds the raw Tor private key bytes before they are loaded into the SigningKey struct.
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("Valid length for SHA256");

    SigningKey::from_bytes(&*okm)
}

/// Converts a raw Ed25519 public key into a Tor v3 Onion address.
/// Format: base32( PUBKEY | SHA3_256(".onion checksum" | PUBKEY | VERSION)[0..2] | VERSION ) + ".onion"
pub fn format_onion_address(pubkey: &VerifyingKey) -> OnionAddress {
    // Tor v3 uses 0x03 as the version byte
    let version = 0x03u8;

    // 1. Calculate the Tor checksum using SHA3-256 (not SHA2)
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey.as_bytes());
    hasher.update(&[version]);
    let checksum = hasher.finalize();

    // 2. Construct the raw byte payload
    // (Note: No zeroizing needed here because public keys and onion addresses are public data)
    let mut raw_bytes = Vec::with_capacity(35); // 32 (pubkey) + 2 (checksum) + 1 (version)
    raw_bytes.extend_from_slice(pubkey.as_bytes());
    raw_bytes.extend_from_slice(&checksum[0..2]);
    raw_bytes.push(version);

    // 3. Base32 encode without padding, lowercased
    let base32_encoded = BASE32_NOPAD.encode(&raw_bytes).to_lowercase();

    format!("{}.onion", base32_encoded)
}
