//! Non-Tor **Mode A** (blind store) transfer — the app-side driver for the
//! `p2p-direct` crate.
//!
//! Mirrors the structure of [`crate::commands::sync`]: pure core functions that
//! take an optional status channel, so both the CLI and the GUI can drive them.
//!
//! ## Why the handshake is copy/paste
//!
//! Mode A is *async*: the two peers are never online together, so there is no
//! live channel for the SPAKE2 round trip. Per the spec (§7), the read-cap must
//! never be sent directly — it is sealed under a key both sides derive from a
//! short, single-use secret shared out-of-band. That means three small blobs
//! travel the users' own secure channel (Signal, in person, …):
//!
//! ```text
//!   1. sender    -> recipient : handshake message A
//!   2. recipient -> sender    : handshake message B
//!   3. sender    -> recipient : sealed capability
//! ```
//!
//! An eavesdropper on that channel who does not know the short secret learns
//! nothing, and online guessing is limited to one attempt per handshake.

use std::path::PathBuf;
use std::sync::mpsc::Sender;

use data_encoding::BASE32_NOPAD;
use p2p_direct::encode::{EncodeParams, Ladder};
use p2p_direct::pake::{self, SessionKey, SpakeState};
use p2p_direct::store::{download, upload, HttpStore};
use p2p_direct::RootKey;

type DirectResult<T> = Result<T, Box<dyn std::error::Error>>;

/// How aggressively the on-store block count is padded with decoys.
///
/// Padding is what prevents the store from fingerprinting a vault by its size
/// (spec §4). Turning it off is faster and cheaper but leaks the true size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaddingProfile {
    /// Round up to the next power of two. Coarsest buckets, ≤2× upload overhead.
    Maximum,
    /// Round up to the next multiple of 1024 blocks (1 GiB at the default size).
    Balanced,
    /// No decoys. The store learns the vault's true size — use only when the
    /// store is trusted and the recipient is not specifically targeted.
    None,
}

impl PaddingProfile {
    pub fn ladder(self) -> Ladder {
        match self {
            PaddingProfile::Maximum => Ladder::NextPowerOfTwo,
            PaddingProfile::Balanced => Ladder::MultipleOf(1024),
            PaddingProfile::None => Ladder::Exact,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PaddingProfile::Maximum => "Maximum (next power of two)",
            PaddingProfile::Balanced => "Balanced (multiple of 1024 blocks)",
            PaddingProfile::None => "None — leaks true size",
        }
    }

    pub const ALL: [PaddingProfile; 3] = [
        PaddingProfile::Maximum,
        PaddingProfile::Balanced,
        PaddingProfile::None,
    ];

    /// Parse the `--padding` CLI value. Validated again here so the mapping
    /// lives next to the profiles rather than only in the arg parser.
    pub fn from_cli(s: &str) -> DirectResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "maximum" => Ok(PaddingProfile::Maximum),
            "balanced" => Ok(PaddingProfile::Balanced),
            "none" => Ok(PaddingProfile::None),
            other => Err(format!(
                "Unknown padding profile '{}'. Expected maximum, balanced, or none.",
                other
            )
            .into()),
        }
    }
}

/// Encode a handshake/capability blob for the out-of-band channel.
pub fn encode_blob(bytes: &[u8]) -> String {
    BASE32_NOPAD.encode(bytes).to_lowercase()
}

/// Decode a blob pasted by the user. Tolerates case, whitespace, and newlines
/// introduced by copy/paste through chat clients.
pub fn decode_blob(text: &str) -> DirectResult<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err("Blob is empty.".into());
    }
    BASE32_NOPAD
        .decode(cleaned.to_uppercase().as_bytes())
        .map_err(|e| format!("Malformed blob: {}", e).into())
}

/// Step 1 — start a SPAKE2 handshake from the short secret. Returns the state to
/// hold onto and the blob to hand the peer over the out-of-band channel.
pub fn begin_handshake(short_secret: &str) -> DirectResult<(SpakeState, String)> {
    let secret = short_secret.trim();
    if secret.is_empty() {
        return Err("Short secret cannot be empty.".into());
    }
    let (state, msg) = pake::start(secret.as_bytes());
    Ok((state, encode_blob(&msg)))
}

/// Step 2 — complete the handshake with the peer's blob, yielding the shared
/// session key. A wrong short secret does not fail here; it fails later when the
/// sealed capability cannot be opened (this is deliberate — no guessing oracle).
pub fn complete_handshake(state: SpakeState, peer_blob: &str) -> DirectResult<SessionKey> {
    let peer_msg = decode_blob(peer_blob)?;
    state
        .finish(&peer_msg)
        .map_err(|_| "Handshake failed. Check the peer's handshake message.".into())
}

/// Step 3 (sender) — encode, encrypt, and upload `vault_path` to the blind
/// store, then seal the resulting read-cap under `session`.
///
/// Returns the sealed-capability blob to send over the out-of-band channel.
pub fn send_core(
    vault_path: &str,
    store_url: &str,
    session: &SessionKey,
    padding: PaddingProfile,
    status_tx: Option<Sender<String>>,
) -> DirectResult<String> {
    let log = |msg: &str| {
        if let Some(tx) = &status_tx {
            let _ = tx.send(msg.to_string());
        } else {
            println!("{}", msg);
        }
    };

    let store_url = store_url.trim();
    if store_url.is_empty() {
        return Err("Blind store URL is required.".into());
    }
    if !store_url.starts_with("https://") {
        return Err(
            "Refusing to upload over a non-HTTPS store URL. Use https:// so the \
             store cannot be trivially observed or tampered with in transit."
                .into(),
        );
    }

    let path = PathBuf::from(vault_path);
    if !path.exists() {
        return Err(format!("Vault not found: {}", vault_path).into());
    }

    let params = EncodeParams {
        ladder: padding.ladder(),
        ..EncodeParams::default()
    };
    let root = RootKey::generate();
    let store = HttpStore::new(store_url).map_err(|e| format!("Store error: {}", e))?;

    log("Encoding vault into padded blocks and uploading...");

    let rt = tokio::runtime::Runtime::new()?;
    let cap = rt.block_on(async {
        let mut file = tokio::fs::File::open(&path).await?;
        upload(&mut file, &params, &root, &store)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { format!("Upload failed: {}", e).into() })
    })?;

    log("Upload complete. Sealing capability for out-of-band delivery...");

    let sealed = pake::seal_cap(session, &cap)
        .map_err(|e| format!("Failed to seal capability: {}", e))?;

    log("Capability sealed. Send the blob to your recipient.");
    Ok(encode_blob(&sealed))
}

/// Step 3 (recipient) — open the sealed capability, then fetch and decode the
/// vault from the blind store into `save_path`.
///
/// Returns the number of plaintext bytes written.
pub fn receive_core(
    save_path: &str,
    store_url: &str,
    session: &SessionKey,
    sealed_cap_blob: &str,
    status_tx: Option<Sender<String>>,
) -> DirectResult<u64> {
    let log = |msg: &str| {
        if let Some(tx) = &status_tx {
            let _ = tx.send(msg.to_string());
        } else {
            println!("{}", msg);
        }
    };

    let store_url = store_url.trim();
    if store_url.is_empty() {
        return Err("Blind store URL is required.".into());
    }
    if save_path.trim().is_empty() {
        return Err("Destination path is required.".into());
    }

    let sealed = decode_blob(sealed_cap_blob)?;
    let cap = pake::open_cap(session, &sealed).map_err(|_| {
        "Could not open the capability. The short secret or handshake messages \
         do not match, or the blob was altered."
    })?;

    log(&format!(
        "Capability verified (commitment {}). Downloading blocks...",
        hex_prefix(&cap.commitment())
    ));

    let store = HttpStore::new(store_url).map_err(|e| format!("Store error: {}", e))?;
    let dest = PathBuf::from(save_path.trim());
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut file = tokio::fs::File::create(&dest).await?;
        download(&cap, &store, &mut file)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> {
                format!("Download failed: {}", e).into()
            })
    })?;

    let written = std::fs::metadata(&dest)?.len();
    log(&format!(
        "Received {} bytes into {}",
        written,
        dest.display()
    ));
    Ok(written)
}

/// Short hex prefix of a commitment, for display.
fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

// ── CLI entry points ──────────────────────────────────────────────────────────

/// Read one line from stdin, trimmed. Errors on EOF so a piped/closed stdin
/// fails loudly instead of silently proceeding with an empty blob.
fn prompt_line(prompt: &str) -> DirectResult<String> {
    use std::io::{self, BufRead, Write};
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        return Err("Unexpected end of input.".into());
    }
    Ok(line.trim().to_string())
}

/// Prompt for the shared short secret without echoing it to the terminal (and
/// therefore not into shell scrollback).
///
/// Deliberately does **not** fall back to reading an echoed line from a piped
/// stdin: the short secret is the root of trust for the whole transfer, and
/// silently echoing it (or accepting it from a scriptable source that lands in
/// shell history or `/proc`) would be a real downgrade. Requiring a terminal is
/// the safer failure.
fn prompt_secret() -> DirectResult<String> {
    let secret = rpassword::prompt_password("Shared short secret (input hidden): ").map_err(
        |e| -> Box<dyn std::error::Error> {
            format!(
                "Could not read the short secret from a terminal ({}). Run this \
                 command in an interactive terminal — the secret is deliberately \
                 not accepted from a pipe, environment variable, or argument, \
                 where it would leak into history or /proc.",
                e
            )
            .into()
        },
    )?;
    if secret.trim().is_empty() {
        return Err("Short secret cannot be empty.".into());
    }
    Ok(secret)
}

fn print_banner() {
    println!(
        "\nNon-Tor transfer (Mode A — blind store)\n\
         The store sees only equal-sized opaque ciphertext under random IDs.\n\
         Your ISP and the store still see that you connected to the store.\n\
         Share the short secret in person or over Signal — never alongside the blobs.\n"
    );
}

/// Drive the two handshake steps interactively, returning the session key.
///
/// `our_label` / `their_label` only affect the prompts, so `send` and `receive`
/// can describe the exchange from each side's point of view.
fn run_interactive_handshake(our_label: &str, their_label: &str) -> DirectResult<SessionKey> {
    let secret = prompt_secret()?;
    let (state, our_blob) = begin_handshake(&secret)?;

    println!("\n── Step 1: send {} to your peer ──\n", our_label);
    println!("{}\n", our_blob);

    let peer_blob = prompt_line(&format!("Paste {} here, then press Enter:\n> ", their_label))?;
    let session = complete_handshake(state, &peer_blob)?;
    println!("\nSession key derived.\n");
    Ok(session)
}

/// `atom direct send` — upload a vault and print the sealed capability.
pub fn handle_direct_send(
    vault_path: &str,
    store_url: &str,
    padding: &str,
) -> DirectResult<()> {
    let padding = PaddingProfile::from_cli(padding)?;
    print_banner();
    println!("Padding profile: {}\n", padding.label());

    let session = run_interactive_handshake(
        "YOUR handshake message",
        "your peer's handshake message",
    )?;

    let sealed = send_core(vault_path, store_url, &session, padding, None)?;

    println!("\n── Step 3: send this sealed capability to your recipient ──\n");
    println!("{}\n", sealed);
    println!(
        "The capability is useless without the short secret, but treat it as \
         sensitive anyway — it is a bearer token for the uploaded vault."
    );
    Ok(())
}

/// `atom direct receive` — fetch and decrypt a vault into `save_path`.
pub fn handle_direct_receive(save_path: &str, store_url: &str) -> DirectResult<()> {
    print_banner();

    let session = run_interactive_handshake(
        "YOUR handshake message",
        "your peer's handshake message",
    )?;

    let sealed = prompt_line("Paste the sealed capability, then press Enter:\n> ")?;
    let written = receive_core(save_path, store_url, &session, &sealed, None)?;

    println!("\nDone. {} bytes written to {}", written, save_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_roundtrip() {
        let data = vec![0u8, 1, 2, 250, 255, 128];
        let encoded = encode_blob(&data);
        assert_eq!(decode_blob(&encoded).unwrap(), data);
    }

    #[test]
    fn blob_decode_tolerates_whitespace_and_case() {
        let data = vec![9u8; 40];
        let encoded = encode_blob(&data);
        // Simulate a paste that picked up newlines and got upper-cased.
        let mangled = format!(
            "{}\n  {}",
            &encoded[..10].to_uppercase(),
            &encoded[10..]
        );
        assert_eq!(decode_blob(&mangled).unwrap(), data);
    }

    #[test]
    fn blob_decode_rejects_empty_and_garbage() {
        assert!(decode_blob("").is_err());
        assert!(decode_blob("   \n ").is_err());
        assert!(decode_blob("not!valid!base32").is_err());
    }

    #[test]
    fn empty_secret_rejected() {
        assert!(begin_handshake("   ").is_err());
    }

    #[test]
    fn handshake_roundtrip_matching_secret() {
        let (s_state, s_blob) = begin_handshake("shared words here").unwrap();
        let (r_state, r_blob) = begin_handshake("shared words here").unwrap();
        assert!(complete_handshake(s_state, &r_blob).is_ok());
        assert!(complete_handshake(r_state, &s_blob).is_ok());
    }

    #[test]
    fn padding_from_cli_accepts_known_values_any_case() {
        assert_eq!(
            PaddingProfile::from_cli("maximum").unwrap(),
            PaddingProfile::Maximum
        );
        assert_eq!(
            PaddingProfile::from_cli("BALANCED").unwrap(),
            PaddingProfile::Balanced
        );
        assert_eq!(
            PaddingProfile::from_cli("None").unwrap(),
            PaddingProfile::None
        );
    }

    #[test]
    fn padding_from_cli_rejects_unknown() {
        let err = PaddingProfile::from_cli("aggressive").unwrap_err();
        assert!(err.to_string().contains("aggressive"));
    }

    #[test]
    fn padding_profiles_map_to_ladders() {
        assert_eq!(PaddingProfile::Maximum.ladder(), Ladder::NextPowerOfTwo);
        assert_eq!(PaddingProfile::Balanced.ladder(), Ladder::MultipleOf(1024));
        assert_eq!(PaddingProfile::None.ladder(), Ladder::Exact);
    }

    #[test]
    fn send_rejects_non_https_store() {
        let (state, peer) = begin_handshake("x").unwrap();
        let (state2, _) = begin_handshake("x").unwrap();
        let _ = state2;
        let session = complete_handshake(state, &peer).unwrap();
        let err = send_core(
            "/nonexistent.aegis",
            "http://insecure.example/blobs",
            &session,
            PaddingProfile::Maximum,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-HTTPS"));
    }
}
