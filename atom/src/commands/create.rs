use std::fs;
use std::io::Write;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn handle_create(
    vault_path: &str, 
    vault_name: &str,
    gui_password: Option<Zeroizing<String>> // YENİ: GUI'den gelirse şifreyi buradan al
) -> Result<(), Box<dyn std::error::Error>> {
    
    // 1. Build the path and ensure the parent directories exist
    let mut actual_file_path = PathBuf::from(vault_path);
    fs::create_dir_all(&actual_file_path)?;

    // 2. Append the target filename
    actual_file_path.push(format!("{}.aegis", vault_name));

    println!(
        "[Create] Creating a secure vault at '{}' ...",
        actual_file_path.display()
    );

    std::io::stdout().flush()?;

    // YENİ: Şifre GUI'den verilmişse onu kullan, verilmemişse CLI TTY'den (pinentry) iste
    let password = match gui_password {
        Some(pw) => pw,
        None => crate::secure_input::read_password_pinentry()?,
    };

    if password.trim().is_empty() {
        return Err("Password cannot be empty or contain only spaces.".into());
    }

    let salt = crate::crypto::generate_32_bytes();
    let dek = Zeroizing::new(crate::crypto::generate_32_bytes());
    
    let kek = crate::crypto::derive_kek(&password, &salt)
        .map_err(|e| format!("Argon2 error: {:?}", e))?;
        
    let (wrapped_dek, dek_nonce) = crate::crypto::wrap_dek(&kek, &dek)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let unlocked_vault = crate::crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce)
        .map_err(|e| format!("DEK unwrap error: {:?}", e))?;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&actual_file_path)
        .map_err(|e| format!("Failed to create vault file (it might already exist): {:?}", e))?;
    
    let payload_offset: u64 = 112; 
    
    file.write_all(&payload_offset.to_le_bytes())?;
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

    println!("[Success] Vault successfully initialized.");
    Ok(())
}