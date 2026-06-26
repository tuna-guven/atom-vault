use eframe::egui;
use egui::Context;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::commands::daemon::SyncResponse;
use super::{AtomVaultApp, IncomingSyncState, Screen};

// ── Pure helpers (tested below) ───────────────────────────────────────────────

/// Maps a sync status string to a display colour.
pub(super) fn sync_status_color(msg: &str) -> egui::Color32 {
    if msg.contains("Failed") {
        egui::Color32::from_rgb(220, 60, 60)
    } else if msg.contains("Complete") {
        egui::Color32::from_rgb(80, 180, 80)
    } else {
        egui::Color32::GRAY
    }
}

/// Returns `save_path` unchanged if non-empty; otherwise builds a default path
/// under `~/Downloads/<sender_nick>/<filename>`.
pub(super) fn resolve_save_path(save_path: &str, sender_nick: &str, filename: &str) -> String {
    if save_path.is_empty() {
        dirs::home_dir()
            .unwrap_or_default()
            .join(format!("Downloads/{}/{}", sender_nick, filename))
            .to_string_lossy()
            .to_string()
    } else {
        save_path.to_string()
    }
}

// ── P2P screen ────────────────────────────────────────────────────────────────

impl AtomVaultApp {
    pub(super) fn show_p2p_dialog(&mut self, ctx: &Context) {
        let sync_status = self
            .sync_status_shared
            .lock()
            .ok()
            .map(|g| g.clone())
            .unwrap_or_default();
        let sync_running = !self.sync_done.load(Ordering::SeqCst);
        if sync_running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        let identity = crate::commands::id::get_id_string()
            .map(|s| format!("atom://{}", s.trim_start_matches("atom://")))
            .unwrap_or_else(|_| "Identity not generated yet. Run daemon.".to_string());
        // Local mutable copy so the TextEdit widget renders; edits are discarded.
        let mut identity_display = identity;

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("P2P Network & Friends").strong().size(18.0),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Back").clicked() {
                            self.screen = Screen::VaultExplorer;
                        }
                    });
                });
                ui.add_space(8.0);
                ui.separator();

                // — Identity —
                ui.label(egui::RichText::new("Your Identity:").strong());
                ui.add(
                    egui::TextEdit::singleline(&mut identity_display)
                        .desired_width(f32::INFINITY),
                );

                ui.add_space(12.0);
                ui.separator();

                // — Add friend —
                ui.label(egui::RichText::new("Add New Friend:").strong());
                ui.label("Nickname:");
                ui.text_edit_singleline(&mut self.friend_nick);
                ui.label("atom:// URL:");
                ui.text_edit_singleline(&mut self.friend_url);

                if ui.button("Add to Address Book").clicked() {
                    let nick = self.friend_nick.clone();
                    let url = self.friend_url.clone();
                    if nick.is_empty() || url.is_empty() {
                        self.add_friend_status =
                            "Error: Nickname and URL are required.".to_string();
                    } else {
                        match crate::commands::friend::add_friend_core(&url, &nick) {
                            Ok(msg) => {
                                self.add_friend_status = msg;
                                self.friend_nick = String::new();
                                self.friend_url = String::new();
                                self.friends_cache =
                                    crate::commands::p2p_utils::load_friends()
                                        .into_iter()
                                        .map(|f| f.nickname)
                                        .collect();
                            }
                            Err(e) => self.add_friend_status = format!("Error: {}", e),
                        }
                    }
                }

                if !self.add_friend_status.is_empty() {
                    let color = if self.add_friend_status.starts_with("Error") {
                        egui::Color32::from_rgb(220, 60, 60)
                    } else {
                        egui::Color32::from_rgb(80, 180, 80)
                    };
                    ui.label(egui::RichText::new(&self.add_friend_status).color(color));
                }

                ui.add_space(12.0);
                ui.separator();

                // — Sync —
                ui.label(egui::RichText::new("Push Current Vault to Friend:").strong());

                if self.friends_cache.is_empty() {
                    ui.label("No friends in address book.");
                } else {
                    let selected_name = self
                        .friends_cache
                        .get(self.selected_friend_idx)
                        .cloned()
                        .unwrap_or_default();

                    egui::ComboBox::from_label("Friend")
                        .selected_text(&selected_name)
                        .show_ui(ui, |ui| {
                            for (i, name) in self.friends_cache.iter().enumerate() {
                                ui.selectable_value(&mut self.selected_friend_idx, i, name);
                            }
                        });

                    if ui
                        .add_enabled(!sync_running, egui::Button::new("Start Sync"))
                        .clicked()
                    {
                        if let Some(friend_name) =
                            self.friends_cache.get(self.selected_friend_idx).cloned()
                        {
                            self.start_sync(friend_name);
                        }
                    }

                    if !sync_status.is_empty() {
                        ui.label(
                            egui::RichText::new(&sync_status)
                                .color(sync_status_color(&sync_status)),
                        );
                    }
                }
            });
        });
    }

    fn start_sync(&self, friend_name: String) {
        let vault_path = self.current_vault_path.clone();
        let status_shared = Arc::clone(&self.sync_status_shared);
        let done_flag = Arc::clone(&self.sync_done);
        done_flag.store(false, Ordering::SeqCst);

        if let Ok(mut lock) = status_shared.lock() {
            *lock = "Initiating background sync...".to_string();
        }

        std::thread::spawn(move || {
            let (std_tx, std_rx) = std::sync::mpsc::channel::<String>();
            let status_inner = Arc::clone(&status_shared);

            std::thread::spawn(move || {
                while let Ok(msg) = std_rx.recv() {
                    if let Ok(mut lock) = status_inner.lock() {
                        *lock = msg;
                    }
                }
            });

            match crate::commands::sync::sync_core(&vault_path, &friend_name, Some(std_tx)) {
                Ok(_) => {
                    if let Ok(mut lock) = status_shared.lock() {
                        *lock = format!("Sync Complete with {}", friend_name);
                    }
                }
                Err(e) => {
                    if let Ok(mut lock) = status_shared.lock() {
                        *lock = format!("Sync Failed: {}", e);
                    }
                }
            }
            done_flag.store(true, Ordering::SeqCst);
        });
    }
}

// ── Incoming sync overlay ─────────────────────────────────────────────────────

impl AtomVaultApp {
    pub(super) fn show_incoming_sync_dialog(&mut self, ctx: &Context) {
        let mut accept = false;
        let mut reject = false;

        // Scoped borrow so incoming_sync is freed before we act on the result.
        {
            if let Some(ref mut state) = self.incoming_sync {
                egui::Window::new("Incoming P2P Sync Request")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(format!(
                            "{} wants to sync {} with you over the P2P network.",
                            state.sender_nick, state.filename
                        ));
                        ui.add_space(8.0);
                        ui.label("Assign local label:");
                        ui.text_edit_singleline(&mut state.vault_label);
                        ui.label("Destination path:");
                        ui.text_edit_singleline(&mut state.save_path);
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Accept").clicked() {
                                accept = true;
                            }
                            if ui.button("Reject").clicked() {
                                reject = true;
                            }
                        });
                    });
            }
        }

        if accept {
            if let Some(state) = self.incoming_sync.take() {
                if let Some(chan) = state.response_channel {
                    let save = resolve_save_path(
                        &state.save_path,
                        &state.sender_nick,
                        &state.filename,
                    );
                    let label = if state.vault_label.is_empty() {
                        "Synced Vault".to_string()
                    } else {
                        state.vault_label
                    };
                    let _ = chan.send(SyncResponse {
                        accepted: true,
                        label: Some(label),
                        save_path: Some(save),
                    });
                }
            }
        } else if reject {
            if let Some(state) = self.incoming_sync.take() {
                if let Some(chan) = state.response_channel {
                    let _ = chan.send(SyncResponse {
                        accepted: false,
                        label: None,
                        save_path: None,
                    });
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{resolve_save_path, sync_status_color};
    use eframe::egui;

    // — Sync status colour —

    #[test]
    fn sync_failed_maps_to_red() {
        let red = egui::Color32::from_rgb(220, 60, 60);
        assert_eq!(sync_status_color("Sync Failed: connection refused"), red);
    }

    #[test]
    fn sync_complete_maps_to_green() {
        let green = egui::Color32::from_rgb(80, 180, 80);
        assert_eq!(sync_status_color("Sync Complete with alice"), green);
    }

    #[test]
    fn sync_in_progress_maps_to_gray() {
        assert_eq!(
            sync_status_color("Initiating background sync..."),
            egui::Color32::GRAY,
        );
        assert_eq!(sync_status_color(""), egui::Color32::GRAY);
    }

    // — Save-path resolution —

    #[test]
    fn custom_path_returned_unchanged() {
        assert_eq!(
            resolve_save_path("/home/user/docs/secret.aegis", "bob", "secret.aegis"),
            "/home/user/docs/secret.aegis",
        );
    }

    #[test]
    fn empty_path_generates_default_containing_nick_and_file() {
        let result = resolve_save_path("", "alice", "vault.aegis");
        assert!(
            result.contains("alice"),
            "default path should include sender nick, got: {result}",
        );
        assert!(
            result.contains("vault.aegis"),
            "default path should include filename, got: {result}",
        );
    }

    #[test]
    fn empty_path_with_different_nick_and_file() {
        let r1 = resolve_save_path("", "carol", "report.pdf");
        let r2 = resolve_save_path("", "dave", "notes.txt");
        assert!(r1.contains("carol") && r1.contains("report.pdf"));
        assert!(r2.contains("dave") && r2.contains("notes.txt"));
        assert_ne!(r1, r2);
    }
}
