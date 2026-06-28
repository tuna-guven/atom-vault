use eframe::egui;
use egui::Context;
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

/// Maps a status-bar message to a display colour.
pub(super) fn status_color(msg: &str) -> egui::Color32 {
    if msg.contains("Error")
        || msg.contains("failed")
        || msg.contains("Failed")
    {
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

// ── Vault explorer screen ─────────────────────────────────────────────────────

impl AtomVaultApp {
    pub(super) fn show_vault_explorer(&mut self, ctx: &Context) {
        // Collect file names before any mutable borrows of vault_session.
        let file_names: Vec<String> = self
            .vault_session
            .as_ref()
            .map(|s| s.metadata.file_table.iter().map(|f| f.vfs_name.clone()).collect())
            .unwrap_or_default();

        let mut action: Option<FileAction> = None;

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Encrypted File System").strong().size(16.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Lock & Exit").clicked() {
                        self.vault_session = None;
                        self.screen = Screen::Login;
                        self.login_status = "Vault locked.".to_string();
                    }
                    if ui.button("P2P Network").clicked() {
                        self.friends_cache = crate::commands::p2p_utils::load_friends()
                            .into_iter()
                            .map(|f| f.nickname)
                            .collect();
                        self.screen = Screen::P2PDialog;
                    }
                    if ui.button("Import File").clicked() {
                        let tx = Arc::clone(&self.pending_import_path);
                        std::thread::spawn(move || {
                            if let Some(path) = FileDialog::new().pick_file() {
                                if let Ok(mut g) = tx.lock() {
                                    *g = Some(path);
                                }
                            }
                        });
                    }
                });
            });
            ui.add_space(4.0);
        });

        if !self.explorer_status.is_empty() {
            egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(&self.explorer_status)
                        .color(status_color(&self.explorer_status)),
                );
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if file_names.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("Vault is empty. Click 'Import File' to add.");
                });
                return;
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
                for name in &file_names {
                    ui.horizontal(|ui| {
                        ui.label(name);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Delete").clicked() {
                                action = Some(FileAction::Delete(name.clone()));
                            }
                            if ui.button("Rename").clicked() {
                                action = Some(FileAction::Rename(name.clone()));
                            }
                            if ui.button("Export").clicked() {
                                action = Some(FileAction::Export(name.clone()));
                            }
                            if ui.button("Open").clicked() {
                                action = Some(FileAction::Open(name.clone()));
                            }
                        });
                    });
                    ui.separator();
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

        // Decrypt on the main thread (vault FD access), then hand raw bytes to
        // the broker.  The broker writes them to XDG_RUNTIME_DIR (RAM-backed
        // tmpfs, mode 0600) and opens with `gio open` via the XDG portal.
        // We skip bwrap: SELinux-enforcing kernels block unprivileged namespace
        // creation (EPERM), and Papers is already Flatpak-sandboxed.
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
        // Store which vault file to export, then open a save dialog.
        // The path comes back via pending_export_path; poll_file_dialog_results
        // picks it up, decrypts the bytes, and sends them to the broker.
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

    /// Called from `poll_file_dialog_results` once the user has chosen a save
    /// path.  Decrypts the vault file in the main thread, then hands the bytes
    /// to the broker for a sandboxed write.
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

        // Scoped borrow so rename_dialog is freed before we act on the result.
        {
            if let Some(ref mut state) = self.rename_dialog {
                egui::Window::new("Rename File")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("Enter new file name:");
                        ui.text_edit_singleline(&mut state.new_name);
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Save").clicked() {
                                do_rename = true;
                            }
                            if ui.button("Cancel").clicked() {
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
                        self.explorer_status = "Rename Error: Name already exists.".to_string();
                    } else if let Some(fi) = sess
                        .metadata
                        .file_table
                        .iter_mut()
                        .find(|f| f.vfs_name == state.old_name)
                    {
                        fi.vfs_name = state.new_name.clone();
                        let _ = sess.file.sync_all();
                        self.explorer_status = format!("Renamed to: {}", state.new_name);
                    }
                }
            }
        } else if cancel {
            self.rename_dialog = None;
        }
    }

}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{is_valid_vfs_filename, status_color};
    use eframe::egui;

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
