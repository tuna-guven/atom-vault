mod cmd;
mod crypto;

use clap::Parser;
use cmd::{Cli, Commands, FriendsCommands};

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Create {
            name,
            kdf,
            aead,
            key_file,
            yk,
        } => {
            println!("Creating vault '{}'...", name);
            println!("Using KDF: {}", kdf);
            println!("Using AEAD: {}", aead);

            if *yk {
                println!("YubiKey integration is not implemented yet!");
            }
            // TODO: Route to your core vault creation logic
        }
        Commands::Friends { cmd } => match cmd {
            FriendsCommands::List => {
                println!("Fetching connected friends via p2p-sync...");
                // TODO: Call p2p-sync logic
            }
            FriendsCommands::New { link } => {
                println!("Adding new friend from link: {}", link);
                // TODO: Handle atom:// link parsing
            }
        },
        Commands::Unlock | Commands::Lock | Commands::Shell => {
            // ANSI escape codes for yellow text
            println!("\x1b[33mWe are working on this feature, hold tight!\x1b[0m");
        }
    }
}
