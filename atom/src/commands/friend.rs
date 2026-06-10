use crate::cli::FriendCommands;
use crate::commands::p2p_utils::{
    FriendRecord, extract_pubkey_from_onion, load_friends, save_friends,
};

pub fn handle_friend(command: FriendCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        FriendCommands::Add { url, nickname } => {
            if extract_pubkey_from_onion(&url).is_err() {
                println!("❌ Invalid atom:// link. Could not verify cryptographic signature.");
                return Ok(());
            }

            let mut friends = load_friends();
            if let Some(existing_friend) = friends.iter_mut().find(|f| f.nickname == nickname) {
                existing_friend.url = url.clone();
                println!("✅ Friend '{}' address successfully updated!", nickname);
            } else {
                friends.push(FriendRecord {
                    nickname: nickname.clone(),
                    url: url.clone(),
                });
                println!("✅ Friend '{}' securely added!", nickname);
            }
            save_friends(&friends);
        }
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
