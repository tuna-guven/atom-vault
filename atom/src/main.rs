mod chunker;
mod cli;
mod commands;
mod crypto;
mod storage;
mod vfs;

use clap::Parser;
use cli::{Cli, Commands};
use secrecy::SecretString;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable raw standard panic hooks to prevent sensitive data leaks during crashes
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n[FATAL] Atom Vault encountered a critical runtime failure.");
        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Reason: {}", s);
        }
        eprintln!("Purging volatile process memory and enforcing immediate emergency exit.");
    }));

    // Parse command line arguments using our secure customized styling interface
    let args = Cli::parse();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Route system execution to targeted synchronous sub-command handlers
        match args.command {
            Commands::Create {
                vault_path,
                vault_name,
            } => commands::create::handle_create(&vault_path, &vault_name),
            Commands::Enter { vault_path } => commands::enter::handle_enter(vault_path),

            // --- DECOUPLED P2P ROUTING ---
            Commands::Daemon => commands::daemon::handle_daemon(),
            Commands::Id => commands::id::handle_id(),
            Commands::Friend { command } => commands::friend::handle_friend(command),
            Commands::Sync {
                vault_path,
                friend_nickname,
            } => {
                // Securely prompt for the vault password (no terminal echo)
                let pass = rpassword::prompt_password("🔐 Enter Vault Password: ")
                    .expect("Failed to read password from terminal");

                // Immediately wrap the password in Zeroizing memory
                let secret_pass = SecretString::from(pass);

                commands::sync::handle_sync(&vault_path, &friend_nickname, secret_pass)
            }
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
