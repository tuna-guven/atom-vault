use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SignatureError, VerifyingKey};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

// ============================================================================
// 1. ATOM URI PARSING
// ============================================================================

#[derive(Debug)]
pub enum AtomUriError {
    InvalidPrefix,
    InvalidFormat,
    InvalidOnionLength,
    InvalidKeyLength,
    Base32DecodeError(data_encoding::DecodeError),
    InvalidEd25519Key(SignatureError),
}

impl fmt::Display for AtomUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtomUriError::InvalidPrefix => write!(f, "URI must start with 'atom://'"),
            AtomUriError::InvalidFormat => write!(
                f,
                "URI must contain Tor address and Identity Key separated by '/'"
            ),
            AtomUriError::InvalidOnionLength => write!(f, "Invalid Tor V3 address length"),
            AtomUriError::InvalidKeyLength => write!(f, "Invalid Base32 identity key length"),
            AtomUriError::Base32DecodeError(e) => write!(f, "Base32 decode error: {}", e),
            AtomUriError::InvalidEd25519Key(e) => write!(f, "Invalid Ed25519 key: {}", e),
        }
    }
}

impl std::error::Error for AtomUriError {}

pub fn parse_atom_uri(onion_url: &str) -> Result<(String, VerifyingKey), AtomUriError> {
    let stripped = onion_url
        .strip_prefix("atom://")
        .ok_or(AtomUriError::InvalidPrefix)?;

    let (onion_address, pubkey_b32) = stripped
        .split_once('/')
        .ok_or(AtomUriError::InvalidFormat)?;

    if onion_address.len() != 62 || !onion_address.ends_with(".onion") {
        return Err(AtomUriError::InvalidOnionLength);
    }

    if pubkey_b32.len() != 52 {
        return Err(AtomUriError::InvalidKeyLength);
    }

    let pubkey_b32_upper = pubkey_b32.to_uppercase();
    let decoded_pubkey = BASE32_NOPAD
        .decode(pubkey_b32_upper.as_bytes())
        .map_err(AtomUriError::Base32DecodeError)?;

    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&decoded_pubkey);

    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(AtomUriError::InvalidEd25519Key)?;

    Ok((onion_address.to_string(), verifying_key))
}

// ============================================================================
// 2. PEER ADDRESS BOOK (FRIENDS)
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FriendRecord {
    pub nickname: String,
    pub url: String,
}

fn get_friends_path() -> PathBuf {
    let mut path = dirs::home_dir().expect("Could not find home directory");
    path.push(".atom_vault");
    fs::create_dir_all(&path).ok();
    path.push("friends.json");
    path
}

pub fn load_friends() -> Vec<FriendRecord> {
    let path = get_friends_path();
    if let Ok(mut file) = std::fs::File::open(path) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            if let Ok(friends) = serde_json::from_str(&contents) {
                return friends;
            }
        }
    }
    vec![] // Return empty list if file doesn't exist or is corrupted
}

pub fn save_friends(friends: &[FriendRecord]) {
    let path = get_friends_path();
    let json = serde_json::to_string_pretty(friends).expect("Failed to serialize friends list");

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    opts.mode(0o600); // Secure permissions: only owner can read/write address book

    if let Ok(mut file) = opts.open(path) {
        let _ = file.write_all(json.as_bytes());
    }
}

// ============================================================================
// 3. VAULT METADATA TRANSLATION
// ============================================================================

use crate::vfs::VaultMetadata;

pub type P2PMetadata = p2p_sync::sync::VaultMetadata;

/// Translates local vault metadata into the P2P networking format.
pub fn to_p2p_meta(local_meta: &VaultMetadata) -> P2PMetadata {
    P2PMetadata {
        // Map the salt bytes directly
        cdc_salt: local_meta.cdc_salt,
        // Since we are doing a blind sync, we pass an empty vector.
        // Rust's type inference will automatically cast this empty vector
        // to whatever FileEntry type the p2p_sync crate expects!
        file_table: Vec::new(),
    }
}
