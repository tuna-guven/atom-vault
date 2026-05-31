use std::fs::OpenOptions;
use std::io::{self, Write};

pub fn handle_enter(vault_path: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(vault_path)?;

    print!("Enter the password for vault: ");
    io::stdout().flush()?;
    let password = rpassword::read_password()?;

    let (mut metadata, unlocked_vault, current_payload_offset) = 
        crate::storage::load_vault_metadata(&mut file, &password)?;

    crate::commands::shell::start_interactive_shell(
        &mut metadata,
        &mut file,
        &unlocked_vault,
        current_payload_offset,
    )?;

    Ok(())
}