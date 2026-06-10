pub fn handle_id() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- 🪪 Your Atom Identity ---");

    let mut path = dirs::home_dir().expect("Could not find home directory");
    path.push(".atom_vault/onion.txt");

    match std::fs::read_to_string(&path) {
        Ok(onion) => {
            let onion = onion.trim();
            println!("🔗 Your Link : atom://{}", onion);
            println!("🔒 Status    : Ready to host (Run 'atom daemon')");
        }
        Err(_) => {
            println!("⚠️ Identity not generated yet.");
            println!("👉 Run 'atom daemon' once to generate your embedded Tor identity!");
        }
    }

    Ok(())
}
