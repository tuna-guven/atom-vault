mod chunker;
mod cli;
mod commands;
mod crypto;
mod storage;
mod vfs;

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n[FATAL] Atom Vault encountered a critical runtime failure.");
        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Reason: {}", s);
        }
        eprintln!("Purging volatile process memory and enforcing immediate emergency exit.");
    }));

    let args = Cli::parse();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match args.command {
            Commands::Create {
                vault_path,
                vault_name,
            } => commands::create::handle_create(vault_path, vault_name),
            Commands::Enter { vault_path } => commands::enter::handle_enter(vault_path),

            // --- NEW P2P ROUTING ---
            Commands::Daemon => commands::daemon::handle_daemon(),
            Commands::Id => commands::id::handle_id(),
            Commands::Friend { command } => commands::friend::handle_friend(command),
            Commands::Sync {
                vault_path,
                friend_nickname,
            } => commands::sync::handle_sync(vault_path, friend_nickname),
        }
    }));

    match result {
        Ok(sub_command_result) => {
            sub_command_result?;
        }
        Err(_) => {
            eprintln!(
                "[FATAL] Process memory safely purged via unwinding. Emergency exit enforced."
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
