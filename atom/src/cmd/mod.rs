use clap::{
    Parser, Subcommand,
    builder::styling::{AnsiColor, Effects, Styles},
};

// This matches Cargo's color scheme
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
    about = "Atom Vault: Secure, P2P-synced encrypted containers",
    version,
    styles = cli_styles()
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new encrypted Atom vault
    Create {
        /// Name of the vault (ASCII only, max 32 chars)
        #[arg(long, value_parser = parse_vault_name)]
        name: String,

        /// Key Derivation Function to use
        #[arg(long, default_value = "argon2id")]
        kdf: String,

        /// Authenticated Encryption algorithm to use
        #[arg(long, default_value = "XChaCha20-Poly1305")]
        aead: String,

        /// Path to an external key file
        #[arg(long)]
        key_file: Option<String>,

        /// [NOT IMPLEMENTED] Use YubiKey for hardware-backed authentication
        #[arg(long)]
        yk: bool,
    },

    /// Manage P2P connected friends
    Friends {
        #[command(subcommand)]
        cmd: FriendsCommands,
    },

    /// Unlock a vault
    Unlock,

    /// Lock an active vault
    Lock,

    /// Open a secure shell into a vault
    Shell,
}

#[derive(Subcommand, Debug)]
pub enum FriendsCommands {
    /// List connected friends via p2p-sync
    List,
    /// Add a new friend using an atom:// link
    New {
        /// The atom:// invite link
        link: String,
    },
}

// Custom validator for the --name flag
fn parse_vault_name(s: &str) -> Result<String, String> {
    if s.len() > 32 {
        return Err("Vault name cannot exceed 32 characters".to_string());
    }
    if !s.is_ascii() {
        return Err("Vault name must contain only ASCII characters".to_string());
    }
    Ok(s.to_string())
}
