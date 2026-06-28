use std::fs;

pub fn get_id_string() -> Result<String, Box<dyn std::error::Error>> {
    let mut path = dirs::home_dir().ok_or("Could not find home directory")?;
    path.push(".atom_vault/onion.txt");

    let raw = fs::read(&path).map_err(|_| -> Box<dyn std::error::Error> {
        "Identity not generated yet. Run 'atom daemon' first.".into()
    })?;
    let decrypted = crate::config_crypto::decrypt_config(&raw)?;
    let text = String::from_utf8(decrypted)?;
    Ok(text.trim().to_string())
}

pub fn handle_id() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- 🪪 Your Atom Identity ---");
    
    match get_id_string() {
        Ok(onion) => {
            println!("🔗 Your Link : atom://{}", onion);
            println!("🔒 Status    : Ready to host (Run 'atom daemon')");
        }
        Err(e) => {
            println!("⚠️ {}", e);
            println!("👉 Run 'atom daemon' once to generate your embedded Tor identity!");
        }
    }

    Ok(())
}