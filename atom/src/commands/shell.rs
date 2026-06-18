use crate::crypto::UnlockedVault;
use crate::vfs::VaultMetadata;
use std::fs::File;
use std::io::{self, Write};
use std::sync::mpsc; // CLI'yi bloke etmek ve thread senkronizasyonu için gerekli
use zeroize::Zeroizing;

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

        let mut input = Zeroizing::new(String::new());
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
                    
                    if let Err(e) = crate::commands::import::handle_import(
                        from_disk,
                        vfs_name,
                        physical_vault,
                        metadata,
                        unlocked_vault,
                        &mut current_payload_offset,
                    ) {
                        eprintln!("{}", e);
                    }
                }
            }

            "rm" => {
                if parts.len() < 2 {
                    println!("Error: Missing argument.");
                    println!("Usage: rm <vfs_name>");
                } else {
                    let vfs_name = parts[1].to_string();

                    if let Err(e) = crate::commands::rm::handle_rm(
                        vfs_name,
                        metadata,
                        physical_vault,
                        unlocked_vault,
                        &mut current_payload_offset,
                    ) {
                        eprintln!("{}", e);
                    }
                }
            }

            "export" => {
                if parts.len() < 3 {
                    println!("Error: Missing arguments.");
                    println!("Usage: export <vfs_name> <target_filename>");
                } else {
                    let vfs_name = parts[1].to_string();
                    let to_disk = parts[2].to_string();
                    
                    print!("\n[WARNING] You are about to extract decrypted data to the physical disk (Staging Area).\nAre you sure you want to proceed? [y/N]: ");
                    std::io::stdout().flush().unwrap_or_default();
                    
                    // Girdi tamponunu temiz tutmak için Zeroizing
                    let mut input = Zeroizing::new(String::new());
                    std::io::stdin().read_line(&mut input).unwrap_or_default();
                    
                    if input.trim().eq_ignore_ascii_case("y") {
                        
                        // 1. ADIM: Normal deneme (force_overwrite: false)
                        match crate::commands::export::handle_export(
                            vfs_name.clone(),
                            to_disk.clone(),
                            metadata,
                            physical_vault,
                            unlocked_vault,
                            false 
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                // 2. ADIM: Dosya zaten varsa uyarı ver ve sor
                                if e.to_string() == "ALREADY_EXISTS" {
                                    print!("Warning: The file already exists in the staging area. Do you want to overwrite it? [y/N]: ");
                                    std::io::stdout().flush().unwrap_or_default();
                                    
                                    let mut ow_input = Zeroizing::new(String::new());
                                    std::io::stdin().read_line(&mut ow_input).unwrap_or_default();
                                    
                                    if ow_input.trim().eq_ignore_ascii_case("y") {
                                        // Kullanıcı zorla yaz dedi, parametreyi true gönder
                                        if let Err(err2) = crate::commands::export::handle_export(
                                            vfs_name,
                                            to_disk,
                                            metadata,
                                            physical_vault,
                                            unlocked_vault,
                                            true // GÜÇLÜ YAZMA
                                        ) {
                                            eprintln!("Export failed: {}", err2);
                                        }
                                    } else {
                                        println!("Export cancelled by user. Existing file was preserved.");
                                    }
                                } else {
                                    eprintln!("Export failed: {}", e);
                                }
                            }
                        }
                        
                    } else {
                        println!("Export operation cancelled by user. The vault remains secure.");
                    }
                }
            }

            "cat" => {
                if parts.len() < 2 {
                    println!("Error: Missing argument.");
                    println!("Usage: cat <vfs_name>");
                } else {
                    let vfs_name = parts[1].to_string();

                    if let Err(e) = crate::commands::cat::handle_cat(
                        vfs_name,
                        metadata,
                        physical_vault,
                        unlocked_vault,
                    ) {
                        eprintln!("{}", e);
                    }
                }
            }
            
            "view" => {
                if parts.len() < 2 {
                    println!("Error: Missing argument.");
                    println!("Usage: view <vfs_name>");
                } else {
                    let vfs_name = parts[1];

                    if let Some(file_index) = metadata.file_table.iter().find(|f| f.vfs_name == vfs_name) {
                        
                        // KORUMA 1: Okumadan önce bekleyen tüm yazma işlemlerini diske zorla
                        let _ = physical_vault.sync_all();

                        // CLI'ı dondurmak için senkronizasyon kanalı
                        let (tx, rx) = mpsc::channel();

                        // KORUMA 2: '?' kullanmıyoruz! Hata gelirse ekrana basıp shell'e devam ediyoruz.
                        match crate::commands::view::execute(
                            physical_vault,
                            file_index,
                            unlocked_vault,
                            move || {
                                // Harici okuyucu kapanıp RAM silindikten sonra sinyal gönder
                                let _ = tx.send(()); 
                            }
                        ) {
                            Ok(_) => {
                                // Harici okuyucu açık olduğu sürece CLI burada sessizce bekler (blocking)
                                let _ = rx.recv();
                            }
                            Err(e) => {
                                eprintln!("❌ View Error: {}", e);
                            }
                        }
                        
                    } else {
                        println!("Error: File '{}' not found inside the vault.", vfs_name);
                    }
                }
            }
            
            "vacuum" => {
                match crate::commands::vacuum::handle_vacuum(&vault_path, metadata, physical_vault, unlocked_vault) {
                    Ok(new_offset) => {
                        // Kasa yeniden oluşturulduğu için dosya tanımlayıcısını tazele ve offset'i güncelle
                        match File::options().read(true).write(true).open(&vault_path) {
                            Ok(file) => {
                                *physical_vault = file;
                                current_payload_offset = new_offset;
                            }
                            Err(e) => eprintln!("Error reopening vault after vacuum: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Vacuum error: {}", e),
                }
            
            }

            "help" => {
                println!("\nAvailable Commands inside the Secure Shell:");
                println!("  ls                                  - List all files inside the vault");
                println!(
                    "  cat <vfs_name>                      - Read and display a file securely in RAM"
                );
                println!(
                    "  import <from_disk> <vfs_name>       - Encrypt and import a host file into the vault"
                );
                println!(
                    "  export <vfs_name> <to_disk>         - Decrypt and export a file back to the host disk"
                );
                println!(
                    "  rm <vfs_name>                       - Cryptographically shred a file reference from metadata"
                );
                println!(
                    "  view <vfs_name>                     - Securely isolate and view a file inside the sandbox"
                );
                println!(
                    "  vacuum                              - Defragment and shrink the physical .aegis container"
                );
                println!("  help                                - Show this help menu");
                println!(
                    "  exit                                - Lock vault, purge cryptographic keys, and exit\n"
                );
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