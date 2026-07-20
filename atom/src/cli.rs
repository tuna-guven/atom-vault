// atom/src/cli.rs

use clap::{
    Parser, Subcommand,
    builder::styling::{AnsiColor, Effects, Styles},
};

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
}

#[derive(Parser, Debug)]
#[command(
    name = "atom",
    about = "Atom Vault: Secure Application-Level Virtual File System",
    version,
    styles = cli_styles()
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new, cryptographically secure Atom Vault
    #[command(
        long_about = "Initialize a new, cryptographically secure Atom Vault.\n\n\
        This command creates a new .aegis container file to safely store your encrypted data. \
        You can customize the underlying Key Derivation Function (KDF) using the available flags, \
        or stick to the highly secure defaults (Argon2id). For maximum security, use the \
        --generate-passphrase flag to create a 10-word diceware master password."
    )]
    Create {
        /// Directory where the .aegis file will be saved
        #[arg(long, value_parser = parse_vault_path, default_value = ".")]
        vault_path: String,

        /// Name of the vault. The .aegis extension is added automatically
        #[arg(long, value_parser = parse_vault_name)]
        vault_name: String,

        /// The Key Derivation Function to use ("argon2id" or "scrypt")
        #[arg(long, default_value = "argon2id")]
        kdf: String,

        /// Memory limit for the KDF in KiB (Default: 64MiB for Argon2id, 256MiB for Scrypt)
        #[arg(long)]
        memory: Option<u32>,

        /// Overrides auto-calibration and manually sets the number of transform rounds
        #[arg(long)]
        transform_rounds: Option<u32>,

        /// Target decryption delay in milliseconds for auto-tuning rounds (Default: 1000)
        #[arg(long, default_value_t = 1000)]
        decryption_time: u32,

        /// Number of CPU threads to use for hashing (Defaults to all available logical cores)
        #[arg(long)]
        parallelism: Option<u32>,

        /// Automatically generate a highly secure, 10-word EFF diceware master passphrase
        #[arg(long, default_value_t = false)]
        generate_passphrase: bool,
    },

    /// Unlock a vault and enter its cryptographically isolated interactive shell
    Enter {
        #[arg(long, default_value = "my_data.aegis", value_parser = parse_vault_path)]
        vault_path: String,
    },

    // --- P2P PROTOCOL COMMANDS ---
    /// Show your own Atom ID and connection link to share with friends
    Id,

    /// Start the embedded Tor background daemon
    Daemon,

    /// Manage P2P connections and friends
    Friend {
        #[command(subcommand)]
        command: FriendCommands,
    },

    /// Synchronize your vault with a connected friend
    Sync {
        /// Path to the .aegis vault file to sync
        #[arg(
            value_name = "VAULT_PATH",
            required = true,
            index = 1,
            default_value = "my_data.aegis",
            value_parser = parse_vault_path
        )]
        vault_path: String,

        /// The nickname of the friend you want to sync with
        #[arg(value_name = "FRIEND_NICKNAME", required = true, index = 2)]
        friend_nickname: String,
    },

    /// Transfer a vault without Tor, via a blind object store (async Mode A)
    #[command(
        long_about = "Transfer a vault without Tor, via a blind object store (Mode A).\n\n\
        The store only ever sees equal-sized, opaque ciphertext under random IDs — never \
        your vault, its true size, or who downloads it. Sender and recipient never appear \
        on the wire at the same time.\n\n\
        Because the two peers are never online together, the capability is delivered by a \
        SPAKE2 handshake driven from a short secret you agree on out-of-band. Three short \
        blobs travel your own secure channel (in person, Signal, ...):\n\
        \x20 1. sender    -> recipient : handshake message A\n\
        \x20 2. recipient -> sender    : handshake message B\n\
        \x20 3. sender    -> recipient : sealed capability\n\n\
        Keep the short secret OFF that channel. Your ISP and the store still see that you \
        connected to the store — upload from behind a VPN if that matters."
    )]
    Direct {
        #[command(subcommand)]
        command: DirectCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum DirectCommands {
    /// Encode, encrypt, and upload a vault to a blind store
    Send {
        /// Path to the .aegis vault file to send
        #[arg(long, value_parser = parse_vault_path)]
        vault_path: String,

        /// HTTPS base URL of the blind object store
        #[arg(long, value_parser = parse_store_url)]
        store_url: String,

        /// Decoy padding for the on-store block count. More padding hides the
        /// vault's true size better, at the cost of extra upload.
        #[arg(long, default_value = "maximum", value_parser = parse_padding)]
        padding: String,
    },

    /// Fetch and decrypt a vault from a blind store
    Receive {
        /// Where to write the decoded vault
        #[arg(long, value_parser = parse_vault_path)]
        save_path: String,

        /// HTTPS base URL of the blind object store
        #[arg(long, value_parser = parse_store_url)]
        store_url: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum FriendCommands {
    /// Add or update a friend using their atom:// link
    Add {
        /// The connection link provided by your friend (must start with atom://)
        #[arg(value_parser = parse_atom_url)]
        url: String,

        /// A local nickname to easily identify this friend
        nickname: String,
    },

    /// List all connected friends and their Tor .onion routing status
    List,
}

// --- Validators ---

fn parse_vault_name(s: &str) -> Result<String, String> {
    if s.trim().is_empty() {
        return Err("Vault name cannot be empty or whitespace only".to_string());
    }
    if s.len() > 32 {
        return Err("Vault name cannot exceed 32 characters".to_string());
    }
    if !s.is_ascii() {
        return Err("Vault name must contain only ASCII".to_string());
    }
    if s.chars().any(|c| !c.is_alphanumeric() && c != '_' && c != '-') {
        return Err("Vault name can only contain alphanumeric characters, _, or -".to_string());
    }
    Ok(s.to_string())
}

fn parse_vault_path(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("Vault path cannot be empty".to_string());
    }
    if s.len() > 4096 {
        return Err("Vault path is too long".to_string());
    }
    Ok(s.to_string())
}

fn parse_store_url(s: &str) -> Result<String, String> {
    // Refuse plaintext HTTP up front rather than after a long upload. The store
    // is untrusted, but the transport to it should still not be trivially
    // observable or tamperable.
    if !s.starts_with("https://") {
        return Err("Store URL must start with 'https://'".to_string());
    }
    Ok(s.to_string())
}

fn parse_padding(s: &str) -> Result<String, String> {
    match s.to_ascii_lowercase().as_str() {
        "maximum" | "balanced" | "none" => Ok(s.to_ascii_lowercase()),
        _ => Err("Padding must be one of: maximum, balanced, none".to_string()),
    }
}

fn parse_atom_url(s: &str) -> Result<String, String> {
    if !s.starts_with("atom://") {
        return Err("Invalid format: Friend links must start with 'atom://'".to_string());
    }
    Ok(s.to_string())
}
