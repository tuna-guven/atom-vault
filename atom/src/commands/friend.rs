use crate::cli::FriendCommands;
use crate::commands::p2p_utils::{FriendRecord, load_friends, parse_atom_uri, save_friends};
use std::fs;

pub fn add_friend_core(url: &str, nickname: &str) -> Result<String, Box<dyn std::error::Error>> {
    let (_new_onion, new_pubkey) =
        parse_atom_uri(url).map_err(|e| format!("Invalid atom:// link: {}", e))?;

    if let Some(mut my_onion_path) = dirs::home_dir() {
        my_onion_path.push(".atom_vault/onion.txt");

        if let Ok(my_url) = fs::read_to_string(&my_onion_path) {
            if let Ok((_, my_pubkey)) = parse_atom_uri(my_url.trim()) {
                if new_pubkey == my_pubkey {
                    return Err("You cannot add your own identity as a friend.".into());
                }
            }
        }
    } else {
        return Err("System error: Could not determine user home directory.".into());
    }

    let mut friends = load_friends();

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

    if let Some(existing_friend) = friends.iter_mut().find(|f| f.nickname == nickname) {
        let (_, existing_pubkey) = parse_atom_uri(&existing_friend.url)?;

        if existing_pubkey != new_pubkey {
            return Err(format!(
                "SECURITY ALERT: Nickname '{}' is already associated with a DIFFERENT identity key! To overwrite, manually remove the old friend first.", 
                nickname
            ).into());
        }

        existing_friend.url = url.to_string();
        save_friends(&friends);
        return Ok(format!(
            "Friend '{}' routing address successfully updated!",
            nickname
        ));
    }

    friends.push(FriendRecord {
        nickname: nickname.to_string(),
        url: url.to_string(),
        shared_vaults: Vec::new(),
        last_seen: None,
    });

    save_friends(&friends);
    Ok(format!(
        "Friend '{}' securely added! Make sure they add your atom link too.",
        nickname
    ))
}

pub fn handle_friend(command: FriendCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        FriendCommands::Add { url, nickname } => match add_friend_core(&url, &nickname) {
            Ok(msg) => println!("✅ {}", msg),
            Err(e) => return Err(e),
        },
        FriendCommands::List => {
            let friends = load_friends();
            if friends.is_empty() {
                println!("No friends added yet.");
            } else {
                println!("--- 📋 Connected Friends ---");
                for friend in friends {
                    println!("👤 {:<15} 🔗 {}", friend.nickname, friend.url);
                }
            }
        }
    }
    Ok(())
}
