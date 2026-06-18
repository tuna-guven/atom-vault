use std::fs;

pub fn get_id_string() -> Result<String, Box<dyn std::error::Error>> {
    let mut path = dirs::home_dir().ok_or("Could not find home directory")?;
    path.push(".atom_vault/onion.txt");

    match fs::read_to_string(&path) {
        Ok(onion) => Ok(onion.trim().to_string()),
        Err(_) => Err("Identity not generated yet. Run 'atom daemon' first.".into()),
    }
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