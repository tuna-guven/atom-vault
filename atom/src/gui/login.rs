use eframe::egui;
use egui::Context;
use eff_wordlist::large::random_word;
use rfd::FileDialog;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

use super::{AtomVaultApp, Screen, VaultSession};

// ── Pure validation helpers (tested below) ────────────────────────────────────

/// Returns true when `name` is a safe vault/file name: non-empty, no path
/// separators, no null bytes.
pub(super) fn is_valid_vault_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

// ── Login screen ──────────────────────────────────────────────────────────────

impl AtomVaultApp {
    pub(super) fn show_login(&mut self, ctx: &Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(egui::RichText::new("Atom Vault").size(28.0).strong());
                ui.add_space(24.0);

                let vault_label = self
                    .selected_vault_path
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| format!("Selected: {}", n.to_string_lossy()))
                    .unwrap_or_else(|| "Select .aegis Vault".to_string());

                if ui.button(&vault_label).clicked() {
                    let tx = Arc::clone(&self.pending_vault_path);
                    std::thread::spawn(move || {
                        if let Some(path) = FileDialog::new()
                            .add_filter("Aegis Vault", &["aegis"])
                            .pick_file()
                        {
                            if let Ok(mut g) = tx.lock() {
                                *g = Some(path);
                            }
                        }
                    });
                }

                ui.add_space(8.0);
                let pass_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(true)
                        .hint_text("Master Password")
                        .desired_width(280.0),
                );
                if pass_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.try_unlock();
                }

                ui.add_space(8.0);
                if ui.button("Unlock Vault").clicked() {
                    self.try_unlock();
                }

                ui.add_space(8.0);
                if ui.button("Create New Vault").clicked() {
                    let tx = Arc::clone(&self.pending_folder_path);
                    std::thread::spawn(move || {
                        if let Some(path) = FileDialog::new().pick_folder() {
                            if let Ok(mut g) = tx.lock() {
                                *g = Some(path);
                            }
                        }
                    });
                }

                ui.add_space(16.0);
                let color = if self.login_status.starts_with("Error") {
                    egui::Color32::from_rgb(220, 60, 60)
                } else {
                    egui::Color32::GRAY
                };
                ui.label(egui::RichText::new(&self.login_status).color(color));
            });
        });
    }

    fn try_unlock(&mut self) {
        let path = match self.selected_vault_path.clone() {
            Some(p) => p,
            None => {
                self.login_status = "Error: Please select a vault first!".to_string();
                return;
            }
        };
        if self.password.is_empty() {
            self.login_status = "Error: Password cannot be empty!".to_string();
            return;
        }

        let secure_password = Zeroizing::new(std::mem::take(&mut self.password));
        self.login_status = "Decrypting...".to_string();

        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(mut file) => {
                match crate::storage::load_vault_metadata(&mut file, &secure_password) {
                    Ok((metadata, unlocked_vault, current_offset)) => {
                        self.current_vault_path = path.to_string_lossy().to_string();
                        self.vault_session = Some(VaultSession {
                            file,
                            metadata,
                            unlocked_vault,
                            current_offset,
                        });
                        self.screen = Screen::VaultExplorer;
                        self.login_status = String::new();
                    }
                    Err(_) => {
                        self.login_status =
                            "Error: Invalid password or corrupted vault.".to_string();
                    }
                }
            }
            Err(e) => {
                self.login_status = format!("Error: Could not open file: {}", e);
            }
        }
    }
}

// ── Create vault screen ───────────────────────────────────────────────────────

impl AtomVaultApp {
    pub(super) fn show_create_vault(&mut self, ctx: &Context) {
        let folder_display = self
            .create_folder_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("Initialize Secure Vault");
                ui.add_space(8.0);
                ui.label(format!("Path: {}", folder_display));
                ui.add_space(8.0);

                ui.label("Vault Name:");
                ui.text_edit_singleline(&mut self.create_name);
                ui.add_space(4.0);

                ui.label("Master Password:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.create_password)
                            .password(!self.create_show_password)
                            .hint_text("Master Password")
                            .desired_width(220.0),
                    );
                    if ui
                        .button(if self.create_show_password { "Hide" } else { "Show" })
                        .clicked()
                    {
                        self.create_show_password = !self.create_show_password;
                    }
                });

                ui.label("Confirm Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.create_confirm)
                        .password(!self.create_show_password)
                        .hint_text("Confirm Password"),
                );
                ui.add_space(4.0);

                if ui.button("Generate Secure Passphrase").clicked() {
                    let pass = (0..10)
                        .map(|_| random_word())
                        .collect::<Vec<_>>()
                        .join(" ");
                    self.create_password = pass.clone();
                    self.create_confirm = pass;
                    self.create_show_password = true;
                    self.create_status =
                        "Passphrase generated! Toggle Show to view and copy.".to_string();
                }

                ui.add_space(4.0);
                ui.collapsing("Advanced Crypto Settings", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("KDF:");
                        ui.radio_value(&mut self.create_kdf_argon, true, "Argon2id");
                        ui.radio_value(&mut self.create_kdf_argon, false, "Scrypt");
                    });
                    ui.label("Target Decryption Time (ms):");
                    ui.text_edit_singleline(&mut self.create_dec_time);
                    ui.label("Memory (KiB) [Optional]:");
                    ui.text_edit_singleline(&mut self.create_memory);
                    ui.label("Explicit Rounds [Optional]:");
                    ui.text_edit_singleline(&mut self.create_rounds);
                    ui.label("Parallelism (Threads) [Optional]:");
                    ui.text_edit_singleline(&mut self.create_threads);
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Create Vault").clicked() {
                        if let Some(folder) = self.create_folder_path.clone() {
                            self.do_create_vault(folder);
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.screen = Screen::Login;
                    }
                });

                if !self.create_status.is_empty() {
                    ui.add_space(4.0);
                    let is_error = self.create_status.starts_with("Error")
                        || self.create_status.starts_with("Invalid")
                        || self.create_status.starts_with("Password")
                        || self.create_status.starts_with("Passwords");
                    let color = if is_error {
                        egui::Color32::from_rgb(220, 60, 60)
                    } else {
                        egui::Color32::from_rgb(80, 180, 80)
                    };
                    ui.label(egui::RichText::new(&self.create_status).color(color));
                }
            });
        });
    }

    fn do_create_vault(&mut self, folder_path: PathBuf) {
        let name = self.create_name.clone();
        if !is_valid_vault_name(&name) {
            self.create_status = "Invalid or empty vault name.".to_string();
            return;
        }
        if self.create_password.is_empty() {
            self.create_status = "Password cannot be empty.".to_string();
            return;
        }
        if self.create_password != self.create_confirm {
            self.create_status = "Passwords do not match.".to_string();
            return;
        }

        let kdf = if self.create_kdf_argon { "argon2id" } else { "scrypt" };
        let dec_time: u32 = self.create_dec_time.parse().unwrap_or(1000);
        let mem_arg: Option<u32> = self.create_memory.parse().ok();
        let rounds_arg: Option<u32> = self.create_rounds.parse().ok();
        let threads_arg: Option<u32> = self.create_threads.parse().ok();

        let secure_pass = Zeroizing::new(std::mem::take(&mut self.create_password));
        let _ = std::mem::take(&mut self.create_confirm);

        self.create_status = "Deriving keys, please wait...".to_string();

        match crate::commands::create::handle_create(
            &folder_path.to_string_lossy(),
            &name,
            kdf,
            mem_arg,
            rounds_arg,
            threads_arg,
            dec_time,
            false,
            Some(secure_pass),
        ) {
            Ok(_) => {
                self.login_status = "Vault created! Select it to unlock.".to_string();
                self.create_name = String::new();
                self.create_status = String::new();
                self.screen = Screen::Login;
            }
            Err(e) => {
                self.create_status = format!("Error: {}", e);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::is_valid_vault_name;

    #[test]
    fn empty_name_is_invalid() {
        assert!(!is_valid_vault_name(""));
    }

    #[test]
    fn forward_slash_is_invalid() {
        assert!(!is_valid_vault_name("work/personal"));
    }

    #[test]
    fn backslash_is_invalid() {
        assert!(!is_valid_vault_name("work\\personal"));
    }

    #[test]
    fn null_byte_is_invalid() {
        assert!(!is_valid_vault_name("bad\0name"));
    }

    #[test]
    fn normal_names_are_valid() {
        assert!(is_valid_vault_name("my-vault"));
        assert!(is_valid_vault_name("vault123"));
        assert!(is_valid_vault_name("My Vault"));
        assert!(is_valid_vault_name("secure.aegis"));
        assert!(is_valid_vault_name("über-tresor")); // unicode fine
    }

    #[test]
    fn single_char_name_is_valid() {
        assert!(is_valid_vault_name("v"));
    }
}
