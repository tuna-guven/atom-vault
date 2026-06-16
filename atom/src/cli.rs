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
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new, empty secure vault container file
    Create {
        #[arg(long, default_value = ".")]
        vault_path: String,

        #[arg(long, value_parser = parse_vault_name)]
        vault_name: String,
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
    if s.chars()
        .any(|c| !c.is_alphanumeric() && c != '_' && c != '-')
    {
        return Err(
            "Vault name can only contain alphanumeric characters, underscores, or dashes"
                .to_string(),
        );
    }
    Ok(s.to_string())
}

fn parse_atom_url(s: &str) -> Result<String, String> {
    if !s.starts_with("atom://") {
        return Err("Invalid format: Friend links must start with 'atom://'".to_string());
    }
    Ok(s.to_string())
}
