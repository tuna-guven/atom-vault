use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

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

    // ── Cryptographic initialisation ──────────────────────────────────────────
    // load_vault_metadata performs Argon2id / Scrypt KDF and decrypts the DEK.
    // The Landlock sandbox is applied immediately after this line so the
    // cryptographic keys are already in memory and no further key material
    // needs to be read from arbitrary filesystem locations.
    let (mut metadata, unlocked_vault, current_payload_offset) =
        crate::storage::load_vault_metadata(&mut file, &password)?;

    // ── Inner Landlock sandbox (CLI path) ─────────────────────────────────────
    //
    // The vault file FD opened above is already held; Landlock only restricts
    // future open() calls, so existing FDs (including `file`) are unaffected.
    //
    // Allowed read-only paths:
    //   /usr  — binaries and shared libraries needed by shell helpers (bwrap,
    //           flatpak) spawned by the `view` command
    //   /etc  — locale, fontconfig, TLS certs used by helper processes
    //
    // Allowed read-write paths:
    //   vault_path    — vacuum command must reopen the vault after compaction
    //   staging_dir   — export command writes decrypted files here
    //
    // Security note: the `import` shell command reads host files by path.
    // Under this sandbox it can only import from the staging directory.
    // This is intentional: stage files there before importing them.
    {
        let staging_dir = std::env::var("XDG_RUNTIME_DIR")
            .map(|r| format!("{}/atom_staging", r))
            .unwrap_or_else(|_| {
                std::env::var("HOME")
                    .map(|h| format!("{}/.atom_vault/staging", h))
                    .unwrap_or_else(|_| "/tmp/atom_staging".into())
            });

        let vault_path_ref = Path::new(vault_path.as_str());
        let staging_path_ref = Path::new(staging_dir.as_str());

        let ro: &[&Path] = &[Path::new("/usr"), Path::new("/etc")];
        let rw: &[&Path] = &[vault_path_ref, staging_path_ref];

        crate::sandbox::apply_process_sandbox(ro, rw)?;
    }

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
