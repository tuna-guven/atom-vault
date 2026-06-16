use crate::cli::FriendCommands;
use crate::commands::p2p_utils::{FriendRecord, load_friends, parse_atom_uri, save_friends};
use std::fs;

pub fn handle_friend(command: FriendCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        FriendCommands::Add { url, nickname } => {
            // 1. Cryptographic Validation & Extraction
            // We immediately parse the input to ensure it is perfectly well-formed.
            let (_new_onion, new_pubkey) = match parse_atom_uri(&url) {
                Ok(parsed) => parsed,
                Err(e) => return Err(format!("Invalid atom:// link: {}", e).into()),
            };

            // 2. Robust Self-Add Prevention via Cryptographic Match
            if let Some(mut my_onion_path) = dirs::home_dir() {
                my_onion_path.push(".atom_vault/onion.txt");

                if let Ok(my_url) = fs::read_to_string(&my_onion_path) {
                    if let Ok((_, my_pubkey)) = parse_atom_uri(my_url.trim()) {
                        // Compare the underlying public keys, not the raw strings
                        if new_pubkey == my_pubkey {
                            return Err("You cannot add your own identity as a friend.".into());
                        }
                    }
                }
            } else {
                return Err("System error: Could not determine user home directory.".into());
            }

            // 3. Cryptographically Secure Address Book Upsert
            let mut friends = load_friends();

            // Check A: Prevent identity collision (Same public key saved under two different nicknames)
            if let Some(existing_by_key) = friends.iter().find(|f| {
                parse_atom_uri(&f.url)
                    .map(|(_, k)| k == new_pubkey)
                    .unwrap_or(false)
            }) {
                if existing_by_key.nickname != nickname {
                    return Err(format!(
                        "This identity is already saved under the nickname '{}'.",
                        existing_by_key.nickname
                    )
                    .into());
                }
            }

            // Check B: Prevent nickname impersonation (Overwriting a known friend with an unknown key)
            if let Some(existing_friend) = friends.iter_mut().find(|f| f.nickname == nickname) {
                let (_, existing_pubkey) = parse_atom_uri(&existing_friend.url)?;

                // If the user is trying to change the routing address (.onion) for a known key, allow it.
                // If the key is DIFFERENT, they are being attacked or made a mistake.
                if existing_pubkey != new_pubkey {
                    return Err(format!(
                        "SECURITY ALERT: Nickname '{}' is already associated with a DIFFERENT identity key! To overwrite, manually remove the old friend first.", 
                        nickname
                    ).into());
                }

                existing_friend.url = url.clone();
                println!(
                    "✅ Friend '{}' routing address successfully updated!",
                    nickname
                );
            } else {
                // If it passes all checks, it's a completely new, valid friend.
                friends.push(FriendRecord {
                    nickname: nickname.clone(),
                    url: url.clone(),
                });
                println!("✅ Friend '{}' securely added!", nickname);
                println!(
                    "⚠️ Make sure {} adds your atom link too before you can start messaging.",
                    nickname
                );
            }
            // Note: Ensure `save_friends` writes the file with 0o600 permissions
            save_friends(&friends);
        }
        FriendCommands::List => {
            let friends = load_friends();
            if friends.is_empty() {
                println!("No friends added yet.");
            } else {
                println!("--- 📋 Connected Friends ---");
                for friend in friends {
                    // Truncate URL for cleaner terminal display if desired, or show full
                    println!("👤 {:<15} 🔗 {}", friend.nickname, friend.url);
                }
            }
        }
    }
    Ok(())
}
