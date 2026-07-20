mod chunker;
mod cli;
mod commands;
pub mod config_crypto;
mod crypto;
pub mod gui;
pub mod sandbox;
pub mod secure_input;
mod storage;
mod vfs;

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Zero-Trust Panic Hook: Herhangi bir çökme anında bellek sızıntısını önler
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n[FATAL] Atom Vault encountered a critical runtime failure.");
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

    // Raise the soft RLIMIT_MEMLOCK to the hard limit so viewers can pin as much
    // plaintext in RAM as the system allows.  Before the bwrap re-exec so the
    // raised limit is inherited.
    crate::commands::view::raise_memlock_limit();

    // Load (or generate) the config-file encryption key from GNOME Keyring.
    // Must run before any config I/O and before the bwrap exec so the key is
    // available in both the original and re-exec'd process.
    if let Err(e) = crate::config_crypto::init_config_key() {
        eprintln!("[FATAL] Cannot access GNOME Keyring: {e}");
        eprintln!("Atom Vault requires the Secret Service (GNOME Keyring or compatible) to protect config files.");
        eprintln!("Ensure the Secret Service daemon is running and your session keyring is unlocked.");
        std::process::exit(1);
    }

    // Attempt to re-exec inside a bwrap outer cage before any threads spawn.
    // Skipped automatically when: already sandboxed, running inside a Flatpak
    // app, or namespace creation is blocked (SELinux, nested Flatpak terminal).
    // In all fallback cases Landlock still applies once a vault is selected.
    crate::sandbox::try_bwrap_self_sandbox();

    let args = Cli::parse();

    // Güvenli Staging Dizini (Geçici Dosya Çıkarma Alanı) Belirleme
    let staging_dir_str = if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{}/atom_staging", xdg_runtime)
    } else if let Ok(home) = std::env::var("HOME") {
        format!("{}/.atom_vault/staging", home)
    } else {
        return Err(
            "Security Error: Neither XDG_RUNTIME_DIR nor HOME environment variables are set."
                .into(),
        );
    };

    let mut dir_builder = std::fs::DirBuilder::new();
    dir_builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Sadece sahibinin okuyup/yazabileceği katı izinler (0700)
        dir_builder.mode(0o700);
    }

    if let Err(e) = dir_builder.create(&staging_dir_str) {
        eprintln!(
            "Warning: Failed to safely create staging directory at {}: {}",
            staging_dir_str, e
        );
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match args.command {
        Some(Commands::Create {
            vault_path,
            vault_name,
            kdf,
            memory,
            transform_rounds,
            parallelism,
            generate_passphrase,
            decryption_time,
        }) => commands::create::handle_create(
            &vault_path,
            &vault_name,
            &kdf,
            memory,
            transform_rounds,
            parallelism,
            decryption_time,
            generate_passphrase,
            None, // TTY tabanlı CLI için GUI şifresi 'None' geçilir
        ),
        Some(Commands::Enter { vault_path }) => commands::enter::handle_enter(vault_path),
        Some(Commands::Daemon) => commands::daemon::handle_daemon(),
        Some(Commands::Id) => commands::id::handle_id(),
        Some(Commands::Friend { command }) => commands::friend::handle_friend(command),
        Some(Commands::Sync {
            vault_path,
            friend_nickname,
        }) => commands::sync::handle_sync(&vault_path, &friend_nickname),
        Some(Commands::Direct { command }) => match command {
            cli::DirectCommands::Send {
                vault_path,
                store_url,
                padding,
            } => commands::direct::handle_direct_send(&vault_path, &store_url, &padding),
            cli::DirectCommands::Receive {
                save_path,
                store_url,
            } => commands::direct::handle_direct_receive(&save_path, &store_url),
        },
        None => {
            // Argüman yoksa varsayılan olarak GUI'yi ve arka plan P2P dinleyicisini başlat
            println!("[INFO] No CLI arguments provided. Launching Graphical Interface...");
            crate::gui::run_gui()
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