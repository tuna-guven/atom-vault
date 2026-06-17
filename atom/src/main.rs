mod chunker;
mod cli;
mod commands;
mod crypto;
pub mod sandbox;
mod storage;
mod vfs;

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable raw standard panic hooks to prevent sensitive data leaks during crashes
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n[FATAL] Atom Vault encountered a critical runtime failure.");

        // FIX 1: Catch both static string slices (&str) and dynamically allocated Strings
        let payload = panic_info.payload();
        if let Some(s) = payload.downcast_ref::<&str>() {
            eprintln!("Reason: {}", s);
        } else if let Some(s) = payload.downcast_ref::<String>() {
            eprintln!("Reason: {}", s);
        } else {
            eprintln!("Reason: Unknown error payload.");
        }

        eprintln!("Purging volatile process memory and enforcing immediate emergency exit.");
    }));

    // Parse command line arguments using our secure customized styling interface
    let args = Cli::parse();

    // FIX 2: Prioritize XDG_RUNTIME_DIR (RAM/tmpfs) over HOME (Disk) for staging
    let staging_dir_str = if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{}/atom_staging", xdg_runtime)
    } else if let Ok(home) = std::env::var("HOME") {
        format!("{}/.atom_vault/staging", home) // Hidden fallback directory
    } else {
        return Err(
            "Security Error: Neither XDG_RUNTIME_DIR nor HOME environment variables are set."
                .into(),
        );
    };

    // FIX 3: Enforce strict 0700 permissions on the staging directory
    let mut dir_builder = std::fs::DirBuilder::new();
    dir_builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dir_builder.mode(0o700);
    }

    if let Err(e) = dir_builder.create(&staging_dir_str) {
        eprintln!(
            "Warning: Failed to safely create staging directory at {}: {}",
            staging_dir_str, e
        );
    }

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
            } => commands::sync::handle_sync(&vault_path, &friend_nickname),
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
