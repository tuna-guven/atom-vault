// atom/src/commands/create.rs

use eff_wordlist::large::random_word;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use sysinfo::System;
use zeroize::Zeroizing;

use crate::crypto::{KdfChoice, KdfSettings, calibrate_kdf};

pub fn handle_create(
    vault_path: &str,
    vault_name: &str,
    kdf_choice: &str,
    memory_arg: Option<u32>,
    rounds_arg: Option<u32>,
    parallelism_arg: Option<u32>,
    decryption_time: u32,
    generate_passphrase: bool,
    gui_password: Option<Zeroizing<String>>
) -> Result<(), Box<dyn std::error::Error>> {

    // 1. Build the path and ensure the parent directories exist
    let mut actual_file_path = PathBuf::from(vault_path);
    fs::create_dir_all(&actual_file_path)?;
    actual_file_path.push(format!("{}.aegis", vault_name));

    println!(
        "[Create] Creating a secure vault at '{}' ...",
        actual_file_path.display()
    );

    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_usage();

    let total_mem_gb = sys.total_memory() / (1024 * 1024 * 1024);
    let total_threads = sys.cpus().len() as u32;

    let mut settings = KdfSettings::default();
    if kdf_choice.eq_ignore_ascii_case("scrypt") {
        settings.choice = KdfChoice::Scrypt;
        settings.memory_kib = memory_arg.unwrap_or(262144);
        settings.parallelism = parallelism_arg.unwrap_or(1);
    } else {
        settings.choice = KdfChoice::Argon2id;
        settings.memory_kib = memory_arg.unwrap_or(65536);
        settings.parallelism = parallelism_arg.unwrap_or(total_threads.max(1));
    std::io::stdout().flush()?;

    // YENİ: Şifre GUI'den verilmişse onu kullan, verilmemişse CLI TTY'den (pinentry) iste
    let password = match gui_password {
        Some(pw) => pw,
        None => crate::secure_input::read_password_pinentry()?,
    };

    if password.trim().is_empty() {
        return Err("Password cannot be empty or contain only spaces.".into());
    }

    settings.iterations = if let Some(explicit_rounds) = rounds_arg {
        explicit_rounds
    } else {
        calibrate_kdf(
            decryption_time,
            settings.choice,
            settings.memory_kib,
            settings.parallelism,
        )
    };

    println!(
        "[System] Total Memory: {} GB | Total Threads: {}",
        total_mem_gb, total_threads
    );
    println!(
        "[Crypto] Calibrated transform rounds to {} to achieve ~{:.1}s decryption delay.",
        settings.iterations,
        decryption_time as f64 / 1000.0
    );

    let password = if generate_passphrase {
        let mut words = Vec::with_capacity(10);
        for _ in 0..10 {
            words.push(random_word());
        }
        let pass = words.join(" ");
        println!("\n[SECURE PASSPHRASE GENERATED]");
        println!(">>> {} <<<", pass);
        println!("Please save this immediately. You will need it to unlock your vault.\n");
        Zeroizing::new(pass)
    } else {
        print!("Enter a password: ");
        std::io::stdout().flush()?;
        let pass = Zeroizing::new(rpassword::read_password()?);
        if pass.trim().is_empty() {
            return Err("Password cannot be empty or contain only spaces.".into());
        }

        print!("Confirm password: ");
        std::io::stdout().flush()?;
        let confirm_pass = Zeroizing::new(rpassword::read_password()?);

        if pass != confirm_pass {
            return Err("Security Error: Passwords do not match. Aborting creation.".into());
        }
        pass
    };

    let salt = crate::crypto::generate_32_bytes();
    let dek = Zeroizing::new(crate::crypto::generate_32_bytes());

    let kek = crate::crypto::derive_kek(&password, &salt, &settings)
        .map_err(|e| format!("KDF error: {:?}", e))?;

    let (wrapped_dek, dek_nonce) =
        crate::crypto::wrap_dek(&kek, &dek).map_err(|e| format!("Encryption error: {:?}", e))?;

    let unlocked_vault = crate::crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce)
        .map_err(|e| format!("DEK unwrap error: {:?}", e))?;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&actual_file_path)
        .map_err(|e| {
            format!(
                "Failed to create vault file (it might already exist): {:?}",
                e
            )
        })?;

    let kdf_bytes = settings.to_bytes();
    let payload_offset: u64 = 112 + KdfSettings::SIZE as u64;

    file.write_all(&payload_offset.to_le_bytes())?;
    file.write_all(&kdf_bytes)?;
    file.write_all(&salt)?;
    file.write_all(&dek_nonce)?;
    file.write_all(&wrapped_dek)?;

    use rand::RngCore;
    let mut cdc_salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cdc_salt);

    let metadata = crate::vfs::VaultMetadata {
        file_table: Vec::new(),
        cdc_salt,
    };

    crate::storage::save_vault_metadata(&mut file, &metadata, &unlocked_vault, payload_offset)?;
    file.sync_all()?;

    println!(
        "[Success] Vault successfully initialized with {:?}.",
        settings.choice
    );
    Ok(())
}