use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn handle_create(vault_path: String, vault_name: String) -> Result<(), Box<dyn std::error::Error>> {
    let actual_file_path = Path::new(&vault_path).join(format!("{}.aegis", vault_name));

    println!("[Create] Creating a secure vault at '{}' ...", actual_file_path.display());

    print!("Enter a password: ");
    std::io::stdout().flush()?;

    let password = rpassword::read_password()?;

    let salt = crate::crypto::generate_32_bytes();
    let dek = crate::crypto::generate_32_bytes();
    
    let kek = crate::crypto::derive_kek(&password, &salt)
        .map_err(|e| format!("Argon2 error: {:?}", e))?;
        
    let (wrapped_dek, dek_nonce) = crate::crypto::wrap_dek(&kek, &dek)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let unlocked_vault = crate::crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce)
        .map_err(|e| format!("DEK unwrap error: {:?}", e))?;

    let mut file = File::create(&actual_file_path)?;
    
    let payload_offset: u64 = 112; 
    
    file.write_all(&payload_offset.to_le_bytes())?;
    file.write_all(&salt)?;
    file.write_all(&dek_nonce)?;
    file.write_all(&wrapped_dek)?;

    let metadata = crate::vfs::VaultMetadata { 
        file_table: Vec::new() 
    };
    
    crate::storage::save_vault_metadata(&mut file, &metadata, &unlocked_vault, payload_offset)?;

    println!("[Success] Vault successfully initialized.");
    Ok(())
}