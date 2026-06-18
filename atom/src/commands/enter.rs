use std::fs::OpenOptions;
use std::io::{self, Write};
//use zeroize::Zeroizing;

pub fn handle_enter(vault_path: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&vault_path)
        .map_err(|e| format!("Failed to open vault file '{}': {:?}", vault_path, e))?;

    io::stdout().flush()?;
    let password = crate::secure_input::read_password_pinentry()?;
    if password.trim().is_empty() {
        return Err("Password cannot be empty or contain only spaces.".into());
    }

    let (mut metadata, unlocked_vault, current_payload_offset) =
        crate::storage::load_vault_metadata(&mut file, &password)?;

    crate::commands::shell::start_interactive_shell(
        &mut metadata,
        &mut file,
        &unlocked_vault,
        current_payload_offset,
        vault_path,
    )?;

    file.sync_all()?;

    Ok(())
}
