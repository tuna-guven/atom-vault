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
    /// Show your own Atom ID and connection link to share with friends
    Id,

    /// List all files currently mounted inside the vault
    Ls,

    /// Import a physical file from hard disk into the secure vault (Ingress)
    Import {
        /// Path to the local file on your hard disk
        #[arg(long)]
        from_disk: String,

        /// Target name inside the secure VFS
        #[arg(long, value_parser = parse_vault_name)]
        vfs_name: String,
    },

    /// Unlock a vault and mount it to volatile memory layout
    Unlock {
        /// Path to the .aegis vault file on disk
        #[arg(long, default_value = "my_data.aegis")]
        path: String,
    },

    /// Export a file from the secure vault back to the local hard disk (Egress)
    Export {
        /// Name of the file inside the VFS
        #[arg(long)]
        vfs_name: String,

        /// Target path on the local hard disk
        #[arg(long)]
        to_disk: String,
    },

    /// Securely wipe a file from the vault
    Rm { vfs_name: String },

    /// Manage P2P connections and friends
    Friend {
        #[command(subcommand)]
        command: FriendCommands,
    },

    /// Synchronize your vault with a connected friend
    Sync {
        /// Path to the .aegis vault file to sync
        #[arg(default_value = "my_data.aegis")]
        vault_path: String,

        /// The nickname of the friend you want to sync with
        friend_nickname: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum FriendCommands {
    /// Add a new friend using their atom:// link
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
    if s.len() > 32 {
        return Err("Vault name cannot exceed 32 characters".to_string());
    }
    if !s.is_ascii() {
        return Err("Vault name must contain only ASCII characters".to_string());
    }
    Ok(s.to_string())
}

fn parse_atom_url(s: &str) -> Result<String, String> {
    if !s.starts_with("atom://") {
        return Err("Invalid format: Friend links must start with 'atom://'".to_string());
    }
    Ok(s.to_string())
}
