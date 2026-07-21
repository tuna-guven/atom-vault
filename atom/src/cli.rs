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

    /// Live transfer: strict forward secrecy, post-quantum, no broker
    #[command(long_about = "Transfer a vault live, while both peers are online.\n\n\
        Nothing is stored anywhere in between: there is no server, no relay, and no \
        capability that could later be stolen or compelled. Key agreement is hybrid \
        post-quantum (X25519 + ML-KEM-768) and every session uses fresh ephemeral keys, \
        so recording the traffic today gains an attacker nothing tomorrow.\n\n\
        Pair once with 'atom live pair', then both of you run 'send' and 'receive' at the \
        same time. The pairing code is the root of trust for everything else: say it out \
        loud, in person or on a call, and NEVER send it through the same channel as the \
        pairing blobs.\n\n\
        Your ISP and your peer's ISP can see that the two of you exchanged packets. If \
        that must stay hidden, pair with an .onion address so the transfer runs over Tor.")]
    Live {
        #[command(subcommand)]
        command: LiveCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum LiveCommands {
    /// Show your live identity and the address peers will reach you on
    Id,

    /// Set the address peers should use to reach you (ip:port or onion:port)
    Address {
        /// e.g. 203.0.113.7:4433, or <56-char>.onion:4433 to transfer over Tor
        #[arg(value_name = "ADDRESS", required = true)]
        address: String,
    },

    /// Pair with a peer by exchanging tickets, authenticated by a short secret
    Pair {
        /// What to call this peer locally
        #[arg(long, required = true)]
        nickname: String,

        /// The pairing code your peer read out. Omit to generate one to read to them.
        #[arg(long)]
        code: Option<String>,
    },

    /// List the peers you have paired with
    Peers,

    /// Send a vault to a paired peer (they must run 'receive' at the same time)
    Send {
        /// Path to the .aegis vault file to send
        #[arg(long, value_parser = parse_vault_path)]
        vault_path: String,

        /// Nickname of the paired peer
        #[arg(long, required = true)]
        peer: String,
    },

    /// Receive a vault from a paired peer (they must run 'send' at the same time)
    Receive {
        /// Where to write the received vault
        #[arg(long, value_parser = parse_vault_path)]
        save_path: String,

        /// Nickname of the paired peer
        #[arg(long, required = true)]
        peer: String,
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
    if s.chars()
        .any(|c| !c.is_alphanumeric() && c != '_' && c != '-')
    {
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

fn parse_atom_url(s: &str) -> Result<String, String> {
    if !s.starts_with("atom://") {
        return Err("Invalid format: Friend links must start with 'atom://'".to_string());
    }
    Ok(s.to_string())
}
