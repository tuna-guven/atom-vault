use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

pub fn handle_create(vault_path: String, vault_name: String) -> Result<(), Box<dyn std::error::Error>> {
    let actual_file_path = Path::new(&vault_path).join(format!("{}.aegis", vault_name));

    println!("[Create] Creating a secure vault at '{}' ...", actual_file_path.display());

    print!("Enter a password: ");
    std::io::stdout().flush()?;

    let password = Zeroizing::new(rpassword::read_password()?);
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
        .create_new(true) // Dosya halihazırda varsa hata döndürür
        .open(&actual_file_path)
        .map_err(|e| format!("Failed to create vault file (it might already exist): {:?}", e))?;
    
    let payload_offset: u64 = 112; 
    
    file.write_all(&payload_offset.to_le_bytes())?;
    file.write_all(&salt)?;
    file.write_all(&dek_nonce)?;
    file.write_all(&wrapped_dek)?;

    // Tunanin buna uygun fonksiyonu olabilirrr
    use rand::RngCore;
    let mut cdc_salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cdc_salt);
    // .......................

    let metadata = crate::vfs::VaultMetadata { 
        file_table: Vec::new() ,
        cdc_salt,
    };
    
    crate::storage::save_vault_metadata(&mut file, &metadata, &unlocked_vault, payload_offset)?;

    file.sync_all()?; 

    println!("[Success] Vault successfully initialized.");
    Ok(())
}