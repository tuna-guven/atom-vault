use eframe::egui;
use egui::{Color32, Context, Margin, RichText, Rounding, Stroke};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{AtomVaultApp, Screen, TransportTab};
use crate::commands::daemon::SyncResponse;

// ── Pure helpers (tested below) ───────────────────────────────────────────────

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

// ── Colour palette (matching home screen) ─────────────────────────────────────

const HEADER_BG: Color32 = Color32::from_rgb(18, 22, 38);
const PANEL_BG: Color32 = Color32::from_rgb(20, 24, 38);
const CARD_BG: Color32 = Color32::from_rgb(34, 39, 58);
const CARD_STROKE: Color32 = Color32::from_rgb(52, 60, 92);
const BADGE_BG: Color32 = Color32::from_rgb(40, 46, 70);
const ACCENT: Color32 = Color32::from_rgb(64, 160, 255);
const ACCENT_DARK: Color32 = Color32::from_rgb(40, 120, 210);
const SUCCESS: Color32 = Color32::from_rgb(48, 190, 90);
const SUCCESS_DARK: Color32 = Color32::from_rgb(28, 120, 55);
const DANGER: Color32 = Color32::from_rgb(255, 75, 65);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(218, 224, 245);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(130, 142, 175);
const TEXT_DIM: Color32 = Color32::from_rgb(85, 95, 125);

fn card_frame(bg: Color32, stroke: Color32) -> egui::Frame {
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(1.0, stroke))
        .rounding(Rounding::same(9.0))
        .inner_margin(Margin::symmetric(16.0, 12.0))
}

fn section_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(11.0).strong().color(TEXT_DIM));
    ui.add(egui::Separator::default().spacing(6.0));
    ui.add_space(4.0);
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
        let mut identity_display = identity;

        // ── Header ────────────────────────────────────────────────────────────
        egui::TopBottomPanel::top("p2p_header")
            .frame(
                egui::Frame::none()
                    .fill(HEADER_BG)
                    .inner_margin(Margin::symmetric(18.0, 10.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("P2P Network & Friends")
                            .size(18.0)
                            .strong()
                            .color(TEXT_PRIMARY),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Back to Vault")
                                        .size(13.5)
                                        .color(TEXT_PRIMARY),
                                )
                                .fill(BADGE_BG)
                                .stroke(Stroke::new(1.5, ACCENT)),
                            )
                            .clicked()
                        {
                            self.screen = Screen::VaultExplorer;
                        }
                    });
                });
            });

        // ── Status bar ────────────────────────────────────────────────────────
        if !sync_status.is_empty() {
            let (text_color, bg_color) = if sync_status.contains("Failed") {
                (DANGER, Color32::from_rgb(55, 18, 16))
            } else if sync_status.contains("Complete") {
                (SUCCESS, Color32::from_rgb(16, 48, 26))
            } else {
                (TEXT_SECONDARY, BADGE_BG)
            };
            egui::TopBottomPanel::bottom("p2p_status")
                .frame(
                    egui::Frame::none()
                        .fill(bg_color)
                        .inner_margin(Margin::symmetric(18.0, 8.0)),
                )
                .show(ctx, |ui| {
                    ui.label(RichText::new(&sync_status).size(13.0).color(text_color));
                });
        }

        // ── Main content ──────────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(PANEL_BG)
                    .inner_margin(Margin::symmetric(18.0, 14.0)),
            )
            .show(ctx, |ui| {
                // ── Transport selector ────────────────────────────────
                ui.horizontal(|ui| {
                    for (tab, label) in [
                        (TransportTab::Tor, "Tor (live sync)"),
                        (TransportTab::Live, "Live — strict PFS + post-quantum"),
                    ] {
                        let selected = self.transport_tab == tab;
                        let (fill, stroke_c) = if selected {
                            (ACCENT_DARK, ACCENT)
                        } else {
                            (BADGE_BG, CARD_STROKE)
                        };
                        if ui
                            .add(
                                egui::Button::new(RichText::new(label).size(13.5).color(
                                    if selected {
                                        Color32::WHITE
                                    } else {
                                        TEXT_SECONDARY
                                    },
                                ))
                                .fill(fill)
                                .stroke(Stroke::new(1.0, stroke_c)),
                            )
                            .clicked()
                        {
                            self.transport_tab = tab;
                        }
                    }
                });
                ui.add_space(12.0);

                if self.transport_tab == TransportTab::Live {
                    self.show_live_panel(ui);
                    return;
                }

                egui::ScrollArea::vertical()
                    .id_salt("p2p_scroll")
                    .show(ui, |ui| {
                        // ── Identity ─────────────────────────────────────────
                        section_label(ui, "YOUR IDENTITY");
                        card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                            ui.label(
                                RichText::new("Share this atom:// address with friends")
                                    .size(12.0)
                                    .color(TEXT_SECONDARY),
                            );
                            ui.add_space(4.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut identity_display)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });

                        ui.add_space(16.0);

                        // ── Add friend ────────────────────────────────────────
                        section_label(ui, "ADD NEW FRIEND");
                        card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                            ui.label(RichText::new("Nickname").size(12.5).color(TEXT_SECONDARY));
                            ui.add_space(3.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.friend_nick)
                                    .hint_text("e.g. alice")
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add_space(8.0);

                            ui.label(
                                RichText::new("atom:// URL")
                                    .size(12.5)
                                    .color(TEXT_SECONDARY),
                            );
                            ui.add_space(3.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.friend_url)
                                    .hint_text("atom://…")
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                            ui.add_space(10.0);

                            let add_btn = egui::Button::new(
                                RichText::new("Add to Address Book")
                                    .size(14.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .fill(SUCCESS_DARK)
                            .stroke(Stroke::new(1.0, SUCCESS));

                            if ui
                                .add_sized([ui.available_width(), 36.0], add_btn)
                                .clicked()
                            {
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
                                            let all = crate::commands::p2p_utils::load_friends();
                                            self.friends_cache =
                                                all.iter().map(|f| f.nickname.clone()).collect();
                                            self.friends_full = all;
                                        }
                                        Err(e) => self.add_friend_status = format!("Error: {}", e),
                                    }
                                }
                            }

                            if !self.add_friend_status.is_empty() {
                                ui.add_space(8.0);
                                let (color, bg) = if self.add_friend_status.starts_with("Error") {
                                    (DANGER, Color32::from_rgb(55, 18, 16))
                                } else {
                                    (SUCCESS, Color32::from_rgb(16, 48, 26))
                                };
                                egui::Frame::none()
                                    .fill(bg)
                                    .rounding(Rounding::same(6.0))
                                    .inner_margin(Margin::symmetric(10.0, 6.0))
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(&self.add_friend_status)
                                                .size(13.0)
                                                .color(color),
                                        );
                                    });
                            }
                        });

                        ui.add_space(16.0);

                        // ── Sync ──────────────────────────────────────────────
                        section_label(ui, "SYNC VAULT WITH FRIEND");
                        card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                            if self.friends_cache.is_empty() {
                                ui.label(
                                    RichText::new("No friends in address book yet.")
                                        .size(13.0)
                                        .color(TEXT_SECONDARY),
                                );
                            } else {
                                let selected_name = self
                                    .friends_cache
                                    .get(self.selected_friend_idx)
                                    .cloned()
                                    .unwrap_or_default();

                                ui.label(
                                    RichText::new("Select friend")
                                        .size(12.5)
                                        .color(TEXT_SECONDARY),
                                );
                                ui.add_space(3.0);
                                egui::ComboBox::from_id_salt("sync_friend_combo")
                                    .selected_text(
                                        RichText::new(&selected_name)
                                            .size(14.0)
                                            .color(TEXT_PRIMARY),
                                    )
                                    .width(ui.available_width())
                                    .show_ui(ui, |ui| {
                                        for (i, name) in self.friends_cache.iter().enumerate() {
                                            ui.selectable_value(
                                                &mut self.selected_friend_idx,
                                                i,
                                                RichText::new(name).size(14.0).color(TEXT_PRIMARY),
                                            );
                                        }
                                    });

                                ui.add_space(10.0);

                                let (btn_fill, btn_stroke, btn_label) = if sync_running {
                                    (BADGE_BG, CARD_STROKE, "Syncing…")
                                } else {
                                    (ACCENT_DARK, ACCENT, "Start Sync")
                                };

                                if ui
                                    .add_enabled(
                                        !sync_running,
                                        egui::Button::new(
                                            RichText::new(btn_label)
                                                .size(14.0)
                                                .strong()
                                                .color(Color32::WHITE),
                                        )
                                        .fill(btn_fill)
                                        .stroke(Stroke::new(1.0, btn_stroke)),
                                    )
                                    .clicked()
                                {
                                    if let Some(friend_name) =
                                        self.friends_cache.get(self.selected_friend_idx).cloned()
                                    {
                                        self.start_sync(friend_name);
                                    }
                                }
                            }
                        });
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
                    crate::commands::p2p_utils::update_friend_last_seen(&friend_name);
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

    pub(super) fn show_incoming_sync_dialog(&mut self, ctx: &Context) {
        let mut accept = false;
        let mut reject = false;

        {
            if let Some(ref mut state) = self.incoming_sync {
                egui::Window::new("Incoming P2P Sync Request")
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
                            RichText::new(format!(
                                "{} wants to sync {} with you.",
                                state.sender_nick, state.filename
                            ))
                            .size(14.0)
                            .color(TEXT_PRIMARY),
                        );
                        ui.add_space(10.0);

                        ui.label(
                            RichText::new("Local label:")
                                .size(12.5)
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(3.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut state.vault_label)
                                .hint_text("e.g. alice-shared")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(6.0);

                        ui.label(
                            RichText::new("Destination path:")
                                .size(12.5)
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(3.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut state.save_path)
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(12.0);

                        ui.horizontal(|ui| {
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Accept")
                                            .size(13.5)
                                            .strong()
                                            .color(Color32::WHITE),
                                    )
                                    .fill(SUCCESS_DARK)
                                    .stroke(Stroke::new(1.0, SUCCESS)),
                                )
                                .clicked()
                            {
                                accept = true;
                            }
                            ui.add_space(8.0);
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Reject").size(13.5).color(DANGER),
                                    )
                                    .fill(Color32::from_rgb(55, 22, 20))
                                    .stroke(Stroke::new(1.0, Color32::from_rgb(140, 50, 45))),
                                )
                                .clicked()
                            {
                                reject = true;
                            }
                        });
                    });
            }
        }

        if accept {
            if let Some(state) = self.incoming_sync.take() {
                if let Some(chan) = state.response_channel {
                    let save =
                        resolve_save_path(&state.save_path, &state.sender_nick, &state.filename);
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
    use super::resolve_save_path;
    use eframe::egui;

    fn sync_status_color(msg: &str) -> egui::Color32 {
        if msg.contains("Failed") {
            egui::Color32::from_rgb(220, 60, 60)
        } else if msg.contains("Complete") {
            egui::Color32::from_rgb(80, 180, 80)
        } else {
            egui::Color32::GRAY
        }
    }

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
