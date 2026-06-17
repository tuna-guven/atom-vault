mod cli;
mod commands;
mod crypto;
mod vfs;
mod storage;
mod chunker;
pub mod sandbox;

use clap::Parser;
use cli::{Cli, Commands};

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

    let staging_dir_str = if let Ok(home) = std::env::var("HOME") {
        format!("{}/atom_staging", home)
    } else if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{}/atom_staging", xdg_runtime)
    } else {
        return Err("Security Error: Neither HOME nor XDG_RUNTIME_DIR environment variables are set.".into());
    };

    if let Err(e) = std::fs::create_dir_all(&staging_dir_str) {
        eprintln!("Warning: Failed to create staging directory at {}: {}", staging_dir_str, e);
    }
    // --------------------------------------------------------------------

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Route system execution to targeted synchronous sub-command handlers
        match args.command {
            Commands::Create { vault_path, vault_name } => {
                commands::create::handle_create(vault_path, vault_name)
            }
            Commands::Enter { vault_path } => {
                commands::enter::handle_enter(vault_path)
            }
        }
    }));

    match result {
        Ok(sub_command_result) => {
            sub_command_result?;
        }
        Err(_) => {
            eprintln!("[FATAL] Process memory safely purged via unwinding. Emergency exit enforced.");
            std::process::exit(1);
        }
    }

    Ok(())
}