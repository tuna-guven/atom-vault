use std::fs::File;
use std::io::{self, Write};
use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;

pub fn start_interactive_shell(
    metadata: &mut VaultMetadata,
    physical_vault: &mut File,
    unlocked_vault: &UnlockedVault,
    mut current_payload_offset: u64,
    vault_path: String, 
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("\n==================================================");
    println!("      Welcome to Atom Vault Secure Shell!         ");
    println!("  Your cryptographically isolated workspace is ready. ");
    println!("==================================================\n");

    loop { 
        print!("atom-vault> ");
        io::stdout().flush()?;
        
        let mut input = zeroize::Zeroizing::new(String::new());
        io::stdin().read_line(&mut input)?;
        
        let trimmed_input = input.trim();
        let parts: Vec<&str> = trimmed_input.split_whitespace().collect();
        
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "ls" => {
                crate::commands::ls::handle_ls(metadata);
            }
            
            "import" => {
                if parts.len() < 3 {
                    println!("Error: Missing arguments.");
                    println!("Usage: import <from_disk_path> <target_vfs_name>");
                } else {
                    let from_disk = parts[1].to_string();
                    let vfs_name = parts[2].to_string();
                    
                    crate::commands::import::handle_import(
                        from_disk,
                        vfs_name,
                        physical_vault,
                        metadata,
                        unlocked_vault,
                        &mut current_payload_offset,
                    )?;
                }
            }
            
            "rm" => {
                if parts.len() < 2 {
                    println!("Error: Missing argument.");
                    println!("Usage: rm <vfs_name>");
                } else {
                    let vfs_name = parts[1].to_string();
                    
                    crate::commands::rm::handle_rm(
                        vfs_name,
                        metadata,
                        physical_vault,
                        unlocked_vault,
                        &mut current_payload_offset,
                    )?;
                }
            }
            
            "export" => {
                if parts.len() < 3 {
                    println!("Error: Missing arguments.");
                    println!("Usage: export <vfs_name> <to_disk_path>");
                } else {
                    let vfs_name = parts[1].to_string();
                    let to_disk = parts[2].to_string();
                    
                    crate::commands::export::handle_export(
                        vfs_name,
                        to_disk,
                        metadata,
                        physical_vault,
                        unlocked_vault,
                    )?;
                }
            }

            "cat" => {
                if parts.len() < 2 {
                    println!("Error: Missing argument.");
                    println!("Usage: cat <vfs_name>");
                } else {
                    let vfs_name = parts[1].to_string();
                    
                    crate::commands::cat::handle_cat(
                        vfs_name,
                        metadata,
                        physical_vault,
                        unlocked_vault,
                    )?;
                }
            }
            "vacuum" => {
                crate::commands::vacuum::handle_vacuum(
                    &vault_path,
                    metadata,
                    physical_vault,
                )?;
                *physical_vault = File::options().read(true).write(true).open(&vault_path)?;
                current_payload_offset = physical_vault.metadata()?.len();
            }
            
            "help" => {
                println!("\nAvailable Commands inside the Secure Shell:");
                println!("  ls                                  - List all files inside the vault");
                println!("  cat <vfs_name>                      - Read and display a file securely in RAM");
                println!("  import <from_disk> <vfs_name>       - Encrypt and import a host file into the vault");
                println!("  export <vfs_name> <to_disk>         - Decrypt and export a file back to the host disk");
                println!("  rm <vfs_name>                       - Cryptographically shred a file reference from metadata");
                println!("  vacuum                              - Defragment and shrink the physical .aegis container");
                println!("  help                                - Show this help menu");
                println!("  exit                                - Lock vault, purge cryptographic keys, and exit\n");
            }
            
            "exit" => {
                println!("[Wiping] Purging ephemeral keys from RAM...");
                println!("Locking vault and exiting secure shell. Goodbye!");
                break; 
            }
            
            _ => {
                let sanitized_name: String = parts[0]
                    .chars()
                    .map(|c| if c.is_ascii_control() { '?' } else { c })
                    .collect();
                println!("Unknown command: '{}'. Type 'help' for available commands.", sanitized_name);
            }
        }
    }

    Ok(())
}