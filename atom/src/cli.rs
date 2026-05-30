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
    Create {
        /// Optional fixed size in Megabytes (MB). If not provided, vault expands dynamically.
        #[arg(short, long)]
        size: Option<u64>,
    },
    Ls,
    Import {
        /// Path to the local file on your hard disk
        #[arg(long)]
        from_disk: String,
        
        /// Target name inside the secure VFS
        #[arg(long, value_parser = parse_vault_name)]
        vfs_name: String,
    },
    Unlock {
        /// Path to the .aegis vault file on disk
        #[arg(long, default_value = "my_data.aegis")]
        path: String,
    },
    // Securely wipe volatile ram disk and terminate the background mount daemon
    Lock,
    /// Repack the vault, discard abandoned noise blocks, and shrink container size
    Vacuum,
    Export {
        /// Name of the file inside the VFS
        #[arg(long)]
        vfs_name: String,
        
        /// Target path on the local hard disk
        #[arg(long)]
        to_disk: String,
    },
    Rm {
        vfs_name: String,
    },
}

fn parse_vault_name(s: &str) -> Result<String, String> {
    if s.len() > 32 {
        return Err("Vault name cannot exceed 32 characters".to_string());
    }
    if !s.is_ascii() {
        return Err("Vault name must contain only ASCII characters".to_string());
    }
    Ok(s.to_string())
}