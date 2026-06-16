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
    // SECURITY: Global panic hook to intercept unexpected crashes and ensure
    // we don't leave sensitive traces on standard output if something fails deep inside.
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

            // --- SECURE P2P ROUTING ---
            Commands::Daemon => {
                // Securely prompt for password (no terminal echo)
                let pass = rpassword::prompt_password("🔐 Enter Vault Password: ")
                    .expect("Failed to read password from terminal");

                // Immediately wrap the password in Zeroizing memory
                let secret_pass = SecretString::from(pass);

                // Load the address book and parse all friend URIs to extract their Ed25519 Public Keys.
                // If a URI is corrupted, we simply skip it during the filter_map phase.
                let friends = commands::p2p_utils::load_friends();
                let auth_keys: Vec<ed25519_dalek::VerifyingKey> = friends
                    .into_iter()
                    .filter_map(|f| {
                        commands::p2p_utils::parse_atom_uri(&f.url)
                            .ok()
                            .map(|(_, key)| key)
                    })
                    .collect();

                commands::daemon::handle_daemon(secret_pass, auth_keys)
            }

            Commands::Id => commands::id::handle_id(),

            Commands::Friend { command } => commands::friend::handle_friend(command),

            Commands::Sync {
                vault_path,
                friend_nickname,
            } => {
                // Securely prompt for password (no terminal echo)
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
            // Unpack the actual Result returned by the command handlers
            sub_command_result?;
        }
        Err(_) => {
            eprintln!(
                "\n[FATAL] Process memory safely purged via unwinding. Emergency exit enforced."
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
