use eframe::egui;
use egui::{Color32, Context, Margin, RichText, Rounding, Stroke};
use rfd::FileDialog;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::{AtomVaultApp, FileAction, RenameState, Screen};

// ── Pure helpers (tested below) ───────────────────────────────────────────────

/// Same rule as `is_valid_vault_name`: non-empty, no path separators or nulls.
pub(super) fn is_valid_vfs_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}


// ── Colour palette (matching home screen) ─────────────────────────────────────

const HEADER_BG:      Color32 = Color32::from_rgb(18,  22,  38);
const PANEL_BG:       Color32 = Color32::from_rgb(20,  24,  38);
const CARD_BG:        Color32 = Color32::from_rgb(34,  39,  58);
const CARD_STROKE:    Color32 = Color32::from_rgb(52,  60,  92);
const BADGE_BG:       Color32 = Color32::from_rgb(40,  46,  70);
const ACCENT:         Color32 = Color32::from_rgb(64,  160, 255);
const ACCENT_DARK:    Color32 = Color32::from_rgb(40,  120, 210);
const SUCCESS:        Color32 = Color32::from_rgb(48,  190,  90);
const SUCCESS_DARK:   Color32 = Color32::from_rgb(28,  120,  55);
const DANGER:         Color32 = Color32::from_rgb(255,  75,  65);
const WARN:           Color32 = Color32::from_rgb(235, 165,  50);
const TEXT_PRIMARY:   Color32 = Color32::from_rgb(218, 224, 245);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(130, 142, 175);
const TEXT_DIM:       Color32 = Color32::from_rgb(85,  95, 125);

fn card_frame(bg: Color32, stroke: Color32) -> egui::Frame {
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(1.0, stroke))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::symmetric(14.0, 10.0))
}

// ── Vault explorer screen ─────────────────────────────────────────────────────

impl AtomVaultApp {
    pub(super) fn show_vault_explorer(&mut self, ctx: &Context) {
        // Collect file names before any mutable borrows of vault_session.
        let file_names: Vec<String> = self
            .vault_session
            .as_ref()
            .map(|s| s.metadata.file_table.iter().map(|f| f.vfs_name.clone()).collect())
            .unwrap_or_default();

        let vault_label = self
            .current_vault_path
            .rsplit('/')
            .next()
            .and_then(|s| s.strip_suffix(".aegis"))
            .unwrap_or("Vault")
            .to_string();

        let mut action: Option<FileAction> = None;

        // ── Header toolbar ────────────────────────────────────────────────────
        egui::TopBottomPanel::top("explorer_toolbar")
            .frame(
                egui::Frame::none()
                    .fill(HEADER_BG)
                    .inner_margin(Margin::symmetric(18.0, 10.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // Vault name
                    ui.label(
                        RichText::new(format!("🔓  {}", vault_label))
                            .size(18.0)
                            .strong()
                            .color(TEXT_PRIMARY),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // ← Home — most prominent navigation button
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Home")
                                        .size(13.5)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(ACCENT_DARK)
                                .stroke(Stroke::new(1.5, ACCENT)),
                            )
                            .on_hover_text("Lock vault and return to home screen")
                            .clicked()
                        {
                            self.vault_session = None;
                            self.vault_registry =
                                crate::commands::vault_registry::load_vault_registry();
                            self.friends_full = crate::commands::p2p_utils::load_friends();
                            self.home_status = String::new();
                            self.screen = Screen::Home;
                        }

                        ui.add_space(6.0);

                        // Import File
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("+ Import File")
                                        .size(13.5)
                                        .color(Color32::WHITE),
                                )
                                .fill(SUCCESS_DARK)
                                .stroke(Stroke::new(1.0, SUCCESS)),
                            )
                            .clicked()
                        {
                            let tx = Arc::clone(&self.pending_import_path);
                            std::thread::spawn(move || {
                                if let Some(path) = FileDialog::new().pick_file() {
                                    if let Ok(mut g) = tx.lock() {
                                        *g = Some(path);
                                    }
                                }
                            });
                        }

                        ui.add_space(6.0);

                        // P2P Network
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("P2P Network").size(13.5),
                                )
                                .fill(BADGE_BG)
                                .stroke(Stroke::new(1.0, CARD_STROKE)),
                            )
                            .clicked()
                        {
                            self.friends_cache = crate::commands::p2p_utils::load_friends()
                                .into_iter()
                                .map(|f| f.nickname)
                                .collect();
                            self.screen = Screen::P2PDialog;
                        }
                    });
                });
            });

        // ── Status bar ────────────────────────────────────────────────────────
        if !self.explorer_status.is_empty() {
            let (text_color, bg_color) = if self.explorer_status.contains("Error")
                || self.explorer_status.contains("failed")
                || self.explorer_status.contains("Failed")
            {
                (DANGER, Color32::from_rgb(55, 18, 16))
            } else if self.explorer_status.contains("Success")
                || self.explorer_status.contains("imported")
                || self.explorer_status.contains("Shredded")
                || self.explorer_status.contains("Renamed")
                || self.explorer_status.contains("Closed")
            {
                (SUCCESS, Color32::from_rgb(16, 48, 26))
            } else {
                (TEXT_SECONDARY, BADGE_BG)
            };

            egui::TopBottomPanel::bottom("explorer_status")
                .frame(
                    egui::Frame::none()
                        .fill(bg_color)
                        .inner_margin(Margin::symmetric(18.0, 8.0)),
                )
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new(&self.explorer_status)
                            .size(13.0)
                            .color(text_color),
                    );
                });
        }

        // ── Central file list ─────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(PANEL_BG)
                    .inner_margin(Margin::symmetric(18.0, 14.0)),
            )
            .show(ctx, |ui| {
                // Section label
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("FILES")
                            .size(11.5)
                            .strong()
                            .color(TEXT_DIM),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{} file(s)", file_names.len()))
                                .size(11.5)
                                .color(TEXT_DIM),
                        );
                    });
                });
                ui.add(egui::Separator::default().spacing(8.0));

                if file_names.is_empty() {
                    ui.add_space(44.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("📂").size(52.0));
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new("Vault is empty")
                                .size(19.0)
                                .strong()
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("Click '+ Import File' in the toolbar to add files.")
                                .size(13.0)
                                .color(TEXT_DIM),
                        );
                    });
                    return;
                }

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for name in &file_names {
                        let ext = name.rsplit('.').next().unwrap_or("");
                        let icon = file_icon(ext);

                        card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                            // ── Row 1: icon + file name ──────────────────────
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(icon).size(22.0));
                                ui.add_space(8.0);
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(name)
                                            .size(15.0)
                                            .strong()
                                            .color(TEXT_PRIMARY),
                                    );
                                    ui.label(
                                        RichText::new(format!(".{} file", ext.to_uppercase()))
                                            .size(11.0)
                                            .color(TEXT_DIM),
                                    );
                                });
                            });

                            // ── Row 2: action buttons (right-aligned) ────────
                            // Put on a separate row so the greedy vertical above
                            // doesn't leave zero width for the buttons (NaN crash).
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        // Delete — red
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("Delete")
                                                        .size(12.5)
                                                        .color(DANGER),
                                                )
                                                .fill(Color32::from_rgb(55, 22, 20))
                                                .stroke(Stroke::new(
                                                    1.0,
                                                    Color32::from_rgb(140, 50, 45),
                                                )),
                                            )
                                            .on_hover_text("Permanently shred this file")
                                            .clicked()
                                        {
                                            action = Some(FileAction::Delete(name.clone()));
                                        }

                                        ui.add_space(4.0);

                                        // Rename — muted
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("Rename")
                                                        .size(12.5)
                                                        .color(WARN),
                                                )
                                                .fill(Color32::from_rgb(45, 38, 20))
                                                .stroke(Stroke::new(
                                                    1.0,
                                                    Color32::from_rgb(120, 100, 40),
                                                )),
                                            )
                                            .clicked()
                                        {
                                            action = Some(FileAction::Rename(name.clone()));
                                        }

                                        ui.add_space(4.0);

                                        // Export
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("Export")
                                                        .size(12.5)
                                                        .color(TEXT_SECONDARY),
                                                )
                                                .fill(BADGE_BG)
                                                .stroke(Stroke::new(1.0, CARD_STROKE)),
                                            )
                                            .clicked()
                                        {
                                            action = Some(FileAction::Export(name.clone()));
                                        }

                                        ui.add_space(4.0);

                                        // Open — accent blue
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("Open")
                                                        .size(13.5)
                                                        .strong()
                                                        .color(Color32::WHITE),
                                                )
                                                .fill(ACCENT_DARK)
                                                .stroke(Stroke::new(1.0, ACCENT)),
                                            )
                                            .clicked()
                                        {
                                            action = Some(FileAction::Open(name.clone()));
                                        }
                                    },
                                );
                            });
                        });
                        ui.add_space(6.0);
                    }
                });
            });

        // Handle actions after all panels — vault_session is no longer borrowed.
        if let Some(act) = action {
            match act {
                FileAction::Open(name) => self.do_open(&name),
                FileAction::Export(name) => self.do_export_file(&name),
                FileAction::Rename(name) => {
                    self.rename_dialog = Some(RenameState {
                        old_name: name.clone(),
                        new_name: name,
                    });
                }
                FileAction::Delete(name) => self.do_delete(&name),
            }
        }

        if self.rename_dialog.is_some() {
            self.show_rename_dialog(ctx);
        }
    }
}

// ── File operations ───────────────────────────────────────────────────────────

impl AtomVaultApp {
    /// Called from `poll_broker_results` once the broker sub-thread has read
    /// the user-chosen file.  Encrypts and stores the bytes in the vault.
    pub(super) fn do_import_bytes(&mut self, data: Vec<u8>) {
        let vfs_name = std::mem::take(&mut self.pending_import_vfs_name);
        if let Some(sess) = &mut self.vault_session {
            match crate::commands::import::handle_import_from_bytes(
                data,
                vfs_name.clone(),
                &mut sess.file,
                &mut sess.metadata,
                &sess.unlocked_vault,
                &mut sess.current_offset,
            ) {
                Ok(_) => {
                    let _ = sess.file.sync_all();
                    self.explorer_status = format!("Success: {} imported.", vfs_name);
                }
                Err(e) => self.explorer_status = format!("Import Error: {}", e),
            }
        }
    }

    fn do_open(&mut self, vfs_name: &str) {
        let sess = match &mut self.vault_session {
            Some(s) => s,
            None => return,
        };

        self.explorer_status = format!("Opening {} securely...", vfs_name);

        let bytes = match crate::commands::export::decrypt_to_bytes(
            vfs_name,
            &sess.metadata,
            &mut sess.file,
            &sess.unlocked_vault,
        ) {
            Ok(b) => b,
            Err(e) => {
                self.explorer_status = format!("Open failed: {}", e);
                return;
            }
        };

        let done_flag = Arc::new(AtomicBool::new(false));
        let spawn_result = self.file_broker.open_viewer(
            bytes,
            vfs_name.to_string(),
            Arc::clone(&done_flag),
        );
        self.pending_viewer_spawn = Some(spawn_result);
        self.viewer_done = Some((done_flag, vfs_name.to_string()));
    }

    fn do_export_file(&mut self, vfs_name: &str) {
        self.pending_export_vfs_name = Some(vfs_name.to_string());
        let file_name = vfs_name.to_string();
        let tx = Arc::clone(&self.pending_export_path);
        std::thread::spawn(move || {
            if let Some(path) = FileDialog::new().set_file_name(&file_name).save_file() {
                if let Ok(mut g) = tx.lock() {
                    *g = Some(path);
                }
            }
        });
        self.explorer_status = "Choose where to save the decrypted file...".to_string();
    }

    /// Called from `poll_file_dialog_results` once the user has chosen a save path.
    pub(super) fn do_export_via_broker(&mut self, path: PathBuf, vfs_name: String) {
        let sess = match &mut self.vault_session {
            Some(s) => s,
            None => return,
        };
        match crate::commands::export::decrypt_to_bytes(
            &vfs_name,
            &sess.metadata,
            &mut sess.file,
            &sess.unlocked_vault,
        ) {
            Ok(bytes) => {
                self.explorer_status = "Writing file...".to_string();
                self.pending_export_write_result =
                    Some(self.file_broker.write_file(path, bytes));
            }
            Err(e) => self.explorer_status = format!("Export Error: {}", e),
        }
    }

    fn do_delete(&mut self, vfs_name: &str) {
        let sess = match &mut self.vault_session {
            Some(s) => s,
            None => return,
        };

        match crate::commands::rm::handle_rm(
            vfs_name.to_string(),
            &mut sess.metadata,
            &mut sess.file,
            &sess.unlocked_vault,
            &mut sess.current_offset,
        ) {
            Ok(_) => self.explorer_status = format!("Permanently Shredded: {}", vfs_name),
            Err(e) => self.explorer_status = format!("Delete failed: {}", e),
        }
    }
}

// ── Overlay dialogs ───────────────────────────────────────────────────────────

impl AtomVaultApp {
    fn show_rename_dialog(&mut self, ctx: &Context) {
        let mut do_rename = false;
        let mut cancel = false;

        {
            if let Some(ref mut state) = self.rename_dialog {
                egui::Window::new("Rename File")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(Color32::from_rgb(30, 35, 54))
                            .stroke(Stroke::new(1.0, CARD_STROKE)),
                    )
                    .show(ctx, |ui| {
                        ui.label(
                            RichText::new("New file name:")
                                .size(13.0)
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(4.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut state.new_name)
                                .desired_width(280.0),
                        );
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Save")
                                            .size(13.5)
                                            .strong()
                                            .color(Color32::WHITE),
                                    )
                                    .fill(ACCENT_DARK)
                                    .stroke(Stroke::new(1.0, ACCENT)),
                                )
                                .clicked()
                            {
                                do_rename = true;
                            }
                            ui.add_space(6.0);
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Cancel").size(13.0).color(TEXT_SECONDARY),
                                    )
                                    .fill(BADGE_BG)
                                    .stroke(Stroke::new(1.0, CARD_STROKE)),
                                )
                                .clicked()
                            {
                                cancel = true;
                            }
                        });
                    });
            }
        }

        if do_rename {
            if let Some(state) = self.rename_dialog.take() {
                if !is_valid_vfs_filename(&state.new_name) {
                    self.explorer_status = "Rename Error: Invalid characters.".to_string();
                } else if let Some(sess) = &mut self.vault_session {
                    if sess.metadata.file_table.iter().any(|f| f.vfs_name == state.new_name) {
                        self.explorer_status =
                            "Rename Error: A file with that name already exists.".to_string();
                    } else if let Some(fi) = sess
                        .metadata
                        .file_table
                        .iter_mut()
                        .find(|f| f.vfs_name == state.old_name)
                    {
                        fi.vfs_name = state.new_name.clone();
                        // Persist the updated metadata so the rename survives lock/re-open.
                        // sync_all() alone only flushes OS buffers — it doesn't re-encrypt
                        // or rewrite the vault header which holds the file table.
                        match crate::storage::save_vault_metadata(
                            &mut sess.file,
                            &sess.metadata,
                            &sess.unlocked_vault,
                            sess.current_offset,
                        ) {
                            Ok(()) => {
                                self.explorer_status =
                                    format!("Renamed to: {}", state.new_name);
                            }
                            Err(e) => {
                                self.explorer_status =
                                    format!("Rename Error: Failed to save: {}", e);
                            }
                        }
                    }
                }
            }
        } else if cancel {
            self.rename_dialog = None;
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn file_icon(ext: &str) -> &'static str {
    match ext.to_lowercase().as_str() {
        "pdf"                              => "📄",
        "png" | "jpg" | "jpeg" | "gif"
        | "webp" | "svg" | "bmp"          => "🖼",
        "mp4" | "mkv" | "avi" | "mov"
        | "webm"                           => "🎬",
        "mp3" | "flac" | "ogg" | "wav"
        | "aac" | "opus"                   => "🎵",
        "zip" | "tar" | "gz" | "xz"
        | "bz2" | "7z" | "rar" | "zst"   => "🗜",
        "txt" | "md" | "rst"               => "📝",
        "rs" | "py" | "js" | "ts"
        | "c" | "cpp" | "go" | "rb"
        | "java" | "sh" | "toml"
        | "yaml" | "json"                  => "💾",
        _                                  => "📁",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::is_valid_vfs_filename;
    use eframe::egui;

    fn status_color(msg: &str) -> egui::Color32 {
        if msg.contains("Error") || msg.contains("failed") || msg.contains("Failed") {
            egui::Color32::from_rgb(220, 60, 60)
        } else if msg.contains("Success")
            || msg.contains("imported")
            || msg.contains("Shredded")
            || msg.contains("Closed")
            || msg.contains("Renamed")
            || msg.contains("Extracted")
            || msg.contains("overwritten")
        {
            egui::Color32::from_rgb(80, 180, 80)
        } else {
            egui::Color32::GRAY
        }
    }

    // — Filename validation —

    #[test]
    fn empty_filename_is_invalid() {
        assert!(!is_valid_vfs_filename(""));
    }

    #[test]
    fn path_traversal_with_slash_is_invalid() {
        assert!(!is_valid_vfs_filename("../../etc/passwd"));
    }

    #[test]
    fn backslash_in_filename_is_invalid() {
        assert!(!is_valid_vfs_filename("dir\\file.txt"));
    }

    #[test]
    fn null_byte_in_filename_is_invalid() {
        assert!(!is_valid_vfs_filename("evil\0file"));
    }

    #[test]
    fn normal_filenames_are_valid() {
        assert!(is_valid_vfs_filename("document.pdf"));
        assert!(is_valid_vfs_filename("my notes.txt"));
        assert!(is_valid_vfs_filename("archive.tar.gz"));
        assert!(is_valid_vfs_filename("résumé.docx")); // unicode
    }

    // — Status colour mapping —

    #[test]
    fn error_message_maps_to_red() {
        let red = egui::Color32::from_rgb(220, 60, 60);
        assert_eq!(status_color("Error: something went wrong"), red);
        assert_eq!(status_color("Export failed: oops"), red);
        assert_eq!(status_color("Open Failed: viewer crashed"), red);
    }

    #[test]
    fn success_message_maps_to_green() {
        let green = egui::Color32::from_rgb(80, 180, 80);
        assert_eq!(status_color("Success: file.txt imported."), green);
        assert_eq!(status_color("Permanently Shredded: secret.pdf"), green);
        assert_eq!(status_color("Closed securely: notes.txt"), green);
        assert_eq!(status_color("Renamed to: new_name.txt"), green);
        assert_eq!(status_color("Success: File exported."), green);
    }

    #[test]
    fn neutral_message_maps_to_gray() {
        assert_eq!(status_color("Opening file.txt securely in sandbox..."), egui::Color32::GRAY);
        assert_eq!(status_color(""), egui::Color32::GRAY);
    }
}
