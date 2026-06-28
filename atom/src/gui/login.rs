use eframe::egui;
use egui::{Color32, Context, Margin, RichText, Rounding, Stroke};
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

const ACCENT:      Color32 = Color32::from_rgb(64,  160, 255);
const ACCENT_DARK: Color32 = Color32::from_rgb(38,  110, 200);
const PANEL_BG:    Color32 = Color32::from_rgb(20,  24,  38);
const CARD_BG:     Color32 = Color32::from_rgb(30,  35,  54);
const TEXT_PRI:    Color32 = Color32::from_rgb(218, 224, 245);
const TEXT_SEC:    Color32 = Color32::from_rgb(130, 142, 175);
const TEXT_DIM:    Color32 = Color32::from_rgb(85,  95, 125);

impl AtomVaultApp {
    pub(super) fn show_login(&mut self, ctx: &Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(PANEL_BG))
            .show(ctx, |ui| {
                ui.add_space(30.0);
                // vertical_centered constrains layout to a centred column;
                // set_max_width clamps it so the card doesn't fill a wide window.
                ui.vertical_centered(|ui| {
                    ui.set_max_width(400.0);

                    // ── Lock icon ─────────────────────────────────────────────
                    ui.label(RichText::new("🔐").size(52.0));
                    ui.add_space(8.0);

                    // ── Vault name ─────────────────────────────────────────────
                    if let Some(ref p) = self.selected_vault_path.clone() {
                        let name = p
                            .file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| p.to_string_lossy().to_string());
                        ui.label(
                            RichText::new(&name).size(22.0).strong().color(TEXT_PRI),
                        );
                        ui.add_space(2.0);
                        ui.label(RichText::new(".aegis vault").size(11.5).color(TEXT_DIM));
                    } else {
                        ui.label(
                            RichText::new("No vault selected")
                                .size(18.0)
                                .color(TEXT_SEC),
                        );
                    }

                    ui.add_space(18.0);

                    // ── Unlock card ────────────────────────────────────────────
                    egui::Frame::none()
                        .fill(CARD_BG)
                        .stroke(Stroke::new(1.0, Color32::from_rgb(50, 58, 88)))
                        .rounding(Rounding::same(12.0))
                        .inner_margin(Margin::symmetric(22.0, 18.0))
                        .show(ui, |ui| {
                            // Password label + field
                            ui.label(
                                RichText::new("Master Password")
                                    .size(13.0)
                                    .color(TEXT_SEC),
                            );
                            ui.add_space(4.0);
                            let pass_resp = ui.add(
                                egui::TextEdit::singleline(&mut self.password)
                                    .password(true)
                                    .hint_text("Enter master password…")
                                    .desired_width(f32::INFINITY),
                            );
                            if pass_resp.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                            {
                                self.try_unlock();
                            }

                            ui.add_space(12.0);

                            // Full-width Unlock button — use add_sized instead of
                            // min_size(vec2(INFINITY, H)) which causes NaN in egui.
                            let unlock_btn = egui::Button::new(
                                RichText::new("Unlock Vault")
                                    .size(16.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .fill(ACCENT_DARK)
                            .stroke(Stroke::new(1.5, ACCENT));

                            if ui
                                .add_sized([ui.available_width(), 42.0], unlock_btn)
                                .clicked()
                            {
                                self.try_unlock();
                            }

                            // Status message
                            if !self.login_status.is_empty() {
                                ui.add_space(10.0);
                                let color = if self.login_status.starts_with("Error") {
                                    Color32::from_rgb(255, 90, 80)
                                } else {
                                    Color32::from_rgb(130, 190, 255)
                                };
                                ui.label(
                                    RichText::new(&self.login_status)
                                        .size(13.0)
                                        .color(color),
                                );
                            }
                        });

                    ui.add_space(12.0);

                    // ── Secondary actions ──────────────────────────────────────
                    ui.horizontal(|ui| {
                        // In Flatpak all vaults live in the app data dir and are
                        // listed on the Home screen — no arbitrary file browsing.
                        if !std::path::Path::new("/.flatpak-info").exists() {
                            let browse_btn = egui::Button::new(
                                RichText::new("Browse…").size(13.0).color(TEXT_SEC),
                            )
                            .fill(Color32::from_rgb(30, 35, 54))
                            .stroke(Stroke::new(1.0, Color32::from_rgb(52, 60, 92)));

                            if ui.add(browse_btn).clicked() {
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
                        }

                        let home_btn = egui::Button::new(
                            RichText::new("Back to Home")
                                .size(13.0)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(ACCENT_DARK)
                        .stroke(Stroke::new(1.5, ACCENT));

                        if ui.add(home_btn).clicked() {
                            self.password = String::new();
                            self.login_status = String::new();
                            self.screen = Screen::Home;
                        }
                    });
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

        // Register in the vault registry before locking down the filesystem,
        // so the write to ~/.atom_vault/vaults.json always succeeds.
        crate::commands::vault_registry::register_vault(&path.to_string_lossy());
        self.vault_registry = crate::commands::vault_registry::load_vault_registry();

        // Apply Landlock sandbox once: pins this process to the selected vault
        // file + ~/.atom_vault/ + system paths for the rest of its lifetime.
        if !self.sandbox_applied {
            crate::sandbox::apply_gui_vault_sandbox(&path);
            self.sandbox_applied = true;
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
                        self.home_status = String::new();
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
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(PANEL_BG)
                    .inner_margin(Margin::symmetric(24.0, 16.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("NEW VAULT")
                            .size(11.5)
                            .strong()
                            .color(TEXT_DIM),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("← Cancel").size(13.0).color(TEXT_SEC),
                                )
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::new(
                                    1.0,
                                    Color32::from_rgb(50, 58, 88),
                                )),
                            )
                            .clicked()
                        {
                            self.screen = Screen::Home;
                        }
                    });
                });
                ui.add(egui::Separator::default().spacing(10.0));

                egui::ScrollArea::vertical().show(ui, |ui| {
                    // Vault Name
                    ui.label(RichText::new("Vault Name").size(13.0).color(TEXT_SEC));
                    ui.add_space(3.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.create_name)
                            .hint_text("e.g. personal, work-docs")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(10.0);

                    // Password
                    ui.label(RichText::new("Master Password").size(13.0).color(TEXT_SEC));
                    ui.add_space(3.0);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.create_password)
                                .password(!self.create_show_password)
                                .hint_text("Master password…")
                                .desired_width(f32::INFINITY),
                        );
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(if self.create_show_password {
                                        "Hide"
                                    } else {
                                        "Show"
                                    })
                                    .size(13.0),
                                )
                                .fill(Color32::from_rgb(40, 46, 68)),
                            )
                            .clicked()
                        {
                            self.create_show_password = !self.create_show_password;
                        }
                    });
                    ui.add_space(6.0);

                    // Confirm
                    ui.label(RichText::new("Confirm Password").size(13.0).color(TEXT_SEC));
                    ui.add_space(3.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.create_confirm)
                            .password(!self.create_show_password)
                            .hint_text("Confirm password…")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(8.0);

                    // Passphrase generator
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("🎲  Generate Secure Passphrase")
                                    .size(13.0)
                                    .color(Color32::from_rgb(160, 200, 255)),
                            )
                            .fill(Color32::from_rgb(30, 45, 72))
                            .stroke(Stroke::new(1.0, Color32::from_rgb(55, 90, 140))),
                        )
                        .clicked()
                    {
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
                    ui.add_space(10.0);

                    // Advanced settings
                    ui.collapsing(
                        RichText::new("Advanced Crypto Settings").size(13.0).color(TEXT_SEC),
                        |ui| {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("KDF:").size(13.0).color(TEXT_SEC));
                                ui.radio_value(&mut self.create_kdf_argon, true, "Argon2id");
                                ui.radio_value(&mut self.create_kdf_argon, false, "Scrypt");
                            });
                            ui.label(
                                RichText::new("Target Decryption Time (ms):")
                                    .size(13.0)
                                    .color(TEXT_SEC),
                            );
                            ui.text_edit_singleline(&mut self.create_dec_time);
                            ui.label(
                                RichText::new("Memory (KiB) [Optional]:")
                                    .size(13.0)
                                    .color(TEXT_SEC),
                            );
                            ui.text_edit_singleline(&mut self.create_memory);
                            ui.label(
                                RichText::new("Explicit Rounds [Optional]:")
                                    .size(13.0)
                                    .color(TEXT_SEC),
                            );
                            ui.text_edit_singleline(&mut self.create_rounds);
                            ui.label(
                                RichText::new("Parallelism (Threads) [Optional]:")
                                    .size(13.0)
                                    .color(TEXT_SEC),
                            );
                            ui.text_edit_singleline(&mut self.create_threads);
                        },
                    );

                    ui.add_space(14.0);

                    // Create button — full-width via add_sized (not min_size(INFINITY))
                    let create_btn = egui::Button::new(
                        RichText::new("Create Encrypted Vault")
                            .size(15.0)
                            .strong()
                            .color(Color32::WHITE),
                    )
                    .fill(ACCENT_DARK)
                    .stroke(Stroke::new(1.5, ACCENT));
                    if ui
                        .add_sized([ui.available_width(), 40.0], create_btn)
                        .clicked()
                    {
                        let name = self.create_name.clone();
                        if !is_valid_vault_name(&name) {
                            self.create_status = "Invalid or empty vault name.".to_string();
                        } else if self.create_password.is_empty() {
                            self.create_status = "Password cannot be empty.".to_string();
                        } else if self.create_password != self.create_confirm {
                            self.create_status = "Passwords do not match.".to_string();
                        } else {
                            // Vaults always live in ~/.atom_vault/ (which maps to
                            // the Flatpak data dir when sandboxed via --persist).
                            // No file-chooser dialog is ever needed for creation.
                            if let Some(home) = dirs::home_dir() {
                                let vault_dir = home.join(".atom_vault");
                                std::fs::create_dir_all(&vault_dir).ok();
                                let full_path = vault_dir.join(format!("{}.aegis", name));
                                self.do_create_vault_at_path(full_path);
                            } else {
                                self.create_status = "Error: Cannot determine home directory.".to_string();
                            }
                        }
                    }

                    // Status message
                    if !self.create_status.is_empty() {
                        ui.add_space(8.0);
                        let is_error = self.create_status.starts_with("Error")
                            || self.create_status.starts_with("Invalid")
                            || self.create_status.starts_with("Password")
                            || self.create_status.starts_with("Passwords");
                        let (color, bg) = if is_error {
                            (
                                Color32::from_rgb(255, 90, 80),
                                Color32::from_rgb(55, 18, 16),
                            )
                        } else {
                            (
                                Color32::from_rgb(80, 210, 110),
                                Color32::from_rgb(16, 48, 26),
                            )
                        };
                        egui::Frame::none()
                            .fill(bg)
                            .rounding(Rounding::same(6.0))
                            .inner_margin(Margin::symmetric(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(&self.create_status)
                                        .size(13.0)
                                        .color(color),
                                );
                            });
                    }
                });
            });
    }

    // Called by poll_file_dialog_results() once the XDG save-file portal returns.
    // Validation already passed at button-click time; here we just run the KDF
    // and write the vault header to the chosen path.
    pub(super) fn do_create_vault_at_path(&mut self, full_path: PathBuf) {
        // Derive the vault name from the file stem chosen in the save dialog
        // (the user may have edited it there).
        let name = full_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| self.create_name.clone());

        let folder = match full_path.parent() {
            Some(p) => p.to_string_lossy().to_string(),
            None => {
                self.create_status = "Error: Invalid save path.".to_string();
                return;
            }
        };

        // Lock the process to this file before any key derivation or disk write.
        if !self.sandbox_applied {
            crate::sandbox::apply_gui_vault_sandbox(&full_path);
            self.sandbox_applied = true;
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
            &folder,
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
                // Register after the file exists so load_vault_registry() does not
                // filter it out. ~/.atom_vault/ is in the Landlock RW set so this
                // write succeeds even after the sandbox has been applied.
                crate::commands::vault_registry::register_vault(&full_path.to_string_lossy());
                self.vault_registry = crate::commands::vault_registry::load_vault_registry();
                self.home_status = format!("Vault '{}' created. Select it to unlock.", name);
                self.create_name = String::new();
                self.create_status = String::new();
                self.screen = Screen::Home;
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
