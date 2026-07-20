use eframe::egui;
use egui::{Color32, Context, Margin, RichText, Rounding, Stroke};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::commands::daemon::SyncResponse;
use crate::commands::direct::{self, PaddingProfile};
use super::{AtomVaultApp, DirectRole, DirectStage, Screen, TransportTab};

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
const TEXT_PRIMARY:   Color32 = Color32::from_rgb(218, 224, 245);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(130, 142, 175);
const TEXT_DIM:       Color32 = Color32::from_rgb(85,  95, 125);

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
                    ui.label(
                        RichText::new(&sync_status)
                            .size(13.0)
                            .color(text_color),
                    );
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
                // ── Transport selector ────────────────────────────────────────
                ui.horizontal(|ui| {
                    for (tab, label) in [
                        (TransportTab::Tor, "Tor (live sync)"),
                        (TransportTab::Direct, "Direct — no Tor (async)"),
                    ] {
                        let selected = self.transport_tab == tab;
                        let (fill, stroke_c) = if selected {
                            (ACCENT_DARK, ACCENT)
                        } else {
                            (BADGE_BG, CARD_STROKE)
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(label).size(13.5).color(if selected {
                                        Color32::WHITE
                                    } else {
                                        TEXT_SECONDARY
                                    }),
                                )
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

                if self.transport_tab == TransportTab::Direct {
                    self.show_direct_panel(ui);
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
                            ui.label(
                                RichText::new("Nickname").size(12.5).color(TEXT_SECONDARY),
                            );
                            ui.add_space(3.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.friend_nick)
                                    .hint_text("e.g. alice")
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add_space(8.0);

                            ui.label(
                                RichText::new("atom:// URL").size(12.5).color(TEXT_SECONDARY),
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

                            if ui.add_sized([ui.available_width(), 36.0], add_btn).clicked() {
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
                                        Err(e) => {
                                            self.add_friend_status = format!("Error: {}", e)
                                        }
                                    }
                                }
                            }

                            if !self.add_friend_status.is_empty() {
                                ui.add_space(8.0);
                                let (color, bg) =
                                    if self.add_friend_status.starts_with("Error") {
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
                                                RichText::new(name)
                                                    .size(14.0)
                                                    .color(TEXT_PRIMARY),
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

    // ── Non-Tor Mode A (blind store) panel ────────────────────────────────────

    /// Clear the handshake *and* the shared slots a background thread may have
    /// written. Without clearing those, `poll_direct_results` would immediately
    /// restore the stale status on the next frame.
    fn reset_direct(&mut self) {
        self.direct.reset_handshake();
        if let Ok(mut lock) = self.direct_status_shared.lock() {
            lock.clear();
        }
        if let Ok(mut slot) = self.direct_sealed_result.lock() {
            *slot = None;
        }
    }

    pub(super) fn show_direct_panel(&mut self, ui: &mut egui::Ui) {
        let busy = !self.direct_done.load(Ordering::SeqCst);

        egui::ScrollArea::vertical()
            .id_salt("direct_scroll")
            .show(ui, |ui| {
                // ── Threat-model notice (kept visible, per spec §10) ──────────
                egui::Frame::none()
                    .fill(Color32::from_rgb(48, 38, 14))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(120, 95, 30)))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::symmetric(12.0, 8.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(
                                "Non-Tor transfer. The blind store sees only equal-sized, \
                                 opaque ciphertext under random IDs — never your vault, its \
                                 size, or who downloads it. But your ISP and the store do see \
                                 that you connected to the store: upload from behind a VPN if \
                                 that matters. The short secret below is the root of trust — \
                                 share it in person or over Signal, never alongside the blobs.",
                            )
                            .size(12.0)
                            .color(Color32::from_rgb(235, 205, 130)),
                        );
                    });
                ui.add_space(14.0);

                // ── Role ──────────────────────────────────────────────────────
                section_label(ui, "ROLE");
                card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        for (role, label) in [
                            (DirectRole::Send, "Send a vault"),
                            (DirectRole::Receive, "Receive a vault"),
                        ] {
                            let selected = self.direct.role == role;
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(label).size(13.5).color(if selected {
                                            Color32::WHITE
                                        } else {
                                            TEXT_SECONDARY
                                        }),
                                    )
                                    .fill(if selected { ACCENT_DARK } else { BADGE_BG })
                                    .stroke(Stroke::new(
                                        1.0,
                                        if selected { ACCENT } else { CARD_STROKE },
                                    )),
                                )
                                .clicked()
                                && !selected
                            {
                                self.direct.role = role;
                                self.reset_direct();
                            }
                        }
                    });
                });
                ui.add_space(16.0);

                // ── Step 1: short secret ──────────────────────────────────────
                section_label(ui, "STEP 1 — SHARED SHORT SECRET");
                card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "Both sides type the same short, single-use secret. Agree on it \
                             out-of-band — this is what protects the capability.",
                        )
                        .size(12.0)
                        .color(TEXT_SECONDARY),
                    );
                    ui.add_space(6.0);

                    let editable = self.direct.stage == DirectStage::Secret;
                    let resp = ui.add_enabled(
                        editable,
                        egui::TextEdit::singleline(&mut self.direct.short_secret)
                            .hint_text("e.g. seven word diceware phrase")
                            .desired_width(f32::INFINITY),
                    );
                    if resp.changed() {
                        // Any edit invalidates a started handshake.
                        self.direct.our_blob.clear();
                    }
                    ui.add_space(8.0);

                    if editable {
                        let btn = egui::Button::new(
                            RichText::new("Begin handshake")
                                .size(14.0)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(ACCENT_DARK)
                        .stroke(Stroke::new(1.0, ACCENT));

                        if ui.add_sized([ui.available_width(), 34.0], btn).clicked() {
                            match direct::begin_handshake(&self.direct.short_secret) {
                                Ok((state, blob)) => {
                                    self.direct.spake_state = Some(state);
                                    self.direct.our_blob = blob;
                                    self.direct.stage = DirectStage::Exchange;
                                    self.direct.status =
                                        "Send your handshake message to your peer.".to_string();
                                }
                                Err(e) => self.direct.status = format!("Failed: {}", e),
                            }
                        }
                    } else if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Restart handshake").size(13.0).color(DANGER),
                            )
                            .fill(Color32::from_rgb(55, 22, 20))
                            .stroke(Stroke::new(1.0, Color32::from_rgb(140, 50, 45))),
                        )
                        .clicked()
                    {
                        self.reset_direct();
                    }
                });

                // ── Step 2: blob exchange ─────────────────────────────────────
                if self.direct.stage != DirectStage::Secret {
                    ui.add_space(16.0);
                    section_label(ui, "STEP 2 — EXCHANGE HANDSHAKE MESSAGES");
                    card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                        ui.label(
                            RichText::new("Send this to your peer:")
                                .size(12.5)
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(3.0);
                        let mut our = self.direct.our_blob.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut our)
                                .desired_width(f32::INFINITY)
                                .desired_rows(2)
                                .font(egui::TextStyle::Monospace),
                        );
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Copy").size(12.5).color(TEXT_PRIMARY),
                                )
                                .fill(BADGE_BG)
                                .stroke(Stroke::new(1.0, CARD_STROKE)),
                            )
                            .clicked()
                        {
                            ui.ctx().copy_text(self.direct.our_blob.clone());
                        }

                        ui.add_space(10.0);
                        ui.label(
                            RichText::new("Paste your peer's handshake message:")
                                .size(12.5)
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(3.0);
                        let can_edit = self.direct.stage == DirectStage::Exchange;
                        ui.add_enabled(
                            can_edit,
                            egui::TextEdit::multiline(&mut self.direct.peer_blob)
                                .desired_width(f32::INFINITY)
                                .desired_rows(2)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.add_space(8.0);

                        if can_edit {
                            let btn = egui::Button::new(
                                RichText::new("Derive session key")
                                    .size(14.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .fill(ACCENT_DARK)
                            .stroke(Stroke::new(1.0, ACCENT));

                            if ui.add_sized([ui.available_width(), 34.0], btn).clicked() {
                                let peer = self.direct.peer_blob.clone();
                                match self.direct.spake_state.take() {
                                    Some(state) => {
                                        match direct::complete_handshake(state, &peer) {
                                            Ok(key) => {
                                                self.direct.session_key = Some(key);
                                                self.direct.stage = DirectStage::Transfer;
                                                self.direct.status =
                                                    "Session key derived.".to_string();
                                            }
                                            Err(e) => {
                                                self.direct.status = format!("Failed: {}", e);
                                                // State was consumed — force a clean restart.
                                                self.reset_direct();
                                            }
                                        }
                                    }
                                    None => {
                                        self.direct.status =
                                            "Handshake expired. Restart it.".to_string();
                                        self.reset_direct();
                                    }
                                }
                            }
                        }
                    });
                }

                // ── Step 3: transfer ──────────────────────────────────────────
                if self.direct.stage == DirectStage::Transfer {
                    ui.add_space(16.0);
                    section_label(ui, "STEP 3 — TRANSFER");
                    card_frame(CARD_BG, CARD_STROKE).show(ui, |ui| {
                        ui.label(
                            RichText::new("Blind store URL (https://)")
                                .size(12.5)
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(3.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.direct.store_url)
                                .hint_text("https://store.example/blobs")
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.add_space(10.0);

                        match self.direct.role {
                            DirectRole::Send => self.show_direct_send_controls(ui, busy),
                            DirectRole::Receive => self.show_direct_receive_controls(ui, busy),
                        }
                    });
                }

                // ── Status ────────────────────────────────────────────────────
                if !self.direct.status.is_empty() {
                    ui.add_space(14.0);
                    let (color, bg) = if self.direct.status.starts_with("Failed") {
                        (DANGER, Color32::from_rgb(55, 18, 16))
                    } else if self.direct.status.contains("Received")
                        || self.direct.status.contains("sealed")
                    {
                        (SUCCESS, Color32::from_rgb(16, 48, 26))
                    } else {
                        (TEXT_SECONDARY, BADGE_BG)
                    };
                    egui::Frame::none()
                        .fill(bg)
                        .rounding(Rounding::same(6.0))
                        .inner_margin(Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(&self.direct.status).size(13.0).color(color),
                            );
                        });
                }
            });
    }

    fn show_direct_send_controls(&mut self, ui: &mut egui::Ui, busy: bool) {
        ui.label(
            RichText::new(format!(
                "Vault to send: {}",
                if self.current_vault_path.is_empty() {
                    "(none open)"
                } else {
                    &self.current_vault_path
                }
            ))
            .size(12.5)
            .color(TEXT_SECONDARY),
        );
        ui.add_space(8.0);

        ui.label(
            RichText::new("Size padding (decoy blocks)")
                .size(12.5)
                .color(TEXT_SECONDARY),
        );
        ui.add_space(3.0);
        egui::ComboBox::from_id_salt("direct_padding")
            .selected_text(
                RichText::new(self.direct.padding.label())
                    .size(13.5)
                    .color(TEXT_PRIMARY),
            )
            .width(ui.available_width())
            .show_ui(ui, |ui| {
                for profile in PaddingProfile::ALL {
                    ui.selectable_value(
                        &mut self.direct.padding,
                        profile,
                        RichText::new(profile.label()).size(13.5).color(TEXT_PRIMARY),
                    );
                }
            });
        ui.add_space(10.0);

        let ready = !self.current_vault_path.is_empty()
            && !self.direct.store_url.trim().is_empty()
            && self.direct.session_key.is_some();

        let (fill, stroke_c, label) = if busy {
            (BADGE_BG, CARD_STROKE, "Uploading…")
        } else {
            (ACCENT_DARK, ACCENT, "Encrypt & upload to store")
        };

        if ui
            .add_enabled(
                ready && !busy,
                egui::Button::new(
                    RichText::new(label).size(14.0).strong().color(Color32::WHITE),
                )
                .fill(fill)
                .stroke(Stroke::new(1.0, stroke_c)),
            )
            .clicked()
        {
            self.start_direct_send();
        }

        if !self.direct.sealed_cap.is_empty() {
            ui.add_space(12.0);
            ui.label(
                RichText::new("Sealed capability — send this to your recipient:")
                    .size(12.5)
                    .color(SUCCESS),
            );
            ui.add_space(3.0);
            let mut sealed = self.direct.sealed_cap.clone();
            ui.add(
                egui::TextEdit::multiline(&mut sealed)
                    .desired_width(f32::INFINITY)
                    .desired_rows(3)
                    .font(egui::TextStyle::Monospace),
            );
            if ui
                .add(
                    egui::Button::new(RichText::new("Copy").size(12.5).color(TEXT_PRIMARY))
                        .fill(BADGE_BG)
                        .stroke(Stroke::new(1.0, CARD_STROKE)),
                )
                .clicked()
            {
                ui.ctx().copy_text(self.direct.sealed_cap.clone());
            }
        }
    }

    fn show_direct_receive_controls(&mut self, ui: &mut egui::Ui, busy: bool) {
        ui.label(
            RichText::new("Sealed capability from the sender:")
                .size(12.5)
                .color(TEXT_SECONDARY),
        );
        ui.add_space(3.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.direct.sealed_cap)
                .desired_width(f32::INFINITY)
                .desired_rows(3)
                .font(egui::TextStyle::Monospace),
        );
        ui.add_space(10.0);

        ui.label(
            RichText::new("Save decoded vault to:")
                .size(12.5)
                .color(TEXT_SECONDARY),
        );
        ui.add_space(3.0);
        ui.add(
            egui::TextEdit::singleline(&mut self.direct.save_path)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        ui.add_space(10.0);

        let ready = !self.direct.sealed_cap.trim().is_empty()
            && !self.direct.store_url.trim().is_empty()
            && !self.direct.save_path.trim().is_empty()
            && self.direct.session_key.is_some();

        let (fill, stroke_c, label) = if busy {
            (BADGE_BG, CARD_STROKE, "Downloading…")
        } else {
            (SUCCESS_DARK, SUCCESS, "Fetch & decrypt from store")
        };

        if ui
            .add_enabled(
                ready && !busy,
                egui::Button::new(
                    RichText::new(label).size(14.0).strong().color(Color32::WHITE),
                )
                .fill(fill)
                .stroke(Stroke::new(1.0, stroke_c)),
            )
            .clicked()
        {
            self.start_direct_receive();
        }
    }

    /// Spawn the Mode A upload. Consumes the session key (single-use).
    fn start_direct_send(&mut self) {
        let Some(session) = self.direct.session_key.take() else {
            self.direct.status = "Failed: no session key. Restart the handshake.".to_string();
            return;
        };

        let vault_path = self.current_vault_path.clone();
        let store_url = self.direct.store_url.clone();
        let padding = self.direct.padding;
        let status_shared = Arc::clone(&self.direct_status_shared);
        let result_slot = Arc::clone(&self.direct_sealed_result);
        let done = Arc::clone(&self.direct_done);
        done.store(false, Ordering::SeqCst);

        if let Ok(mut lock) = status_shared.lock() {
            *lock = "Starting upload...".to_string();
        }

        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            let status_inner = Arc::clone(&status_shared);
            std::thread::spawn(move || {
                while let Ok(msg) = rx.recv() {
                    if let Ok(mut lock) = status_inner.lock() {
                        *lock = msg;
                    }
                }
            });

            let outcome =
                crate::commands::direct::send_core(&vault_path, &store_url, &session, padding, Some(tx))
                    .map_err(|e| e.to_string());

            if let Ok(mut slot) = result_slot.lock() {
                *slot = Some(outcome);
            }
            done.store(true, Ordering::SeqCst);
        });
    }

    /// Spawn the Mode A download. Consumes the session key (single-use).
    fn start_direct_receive(&mut self) {
        let Some(session) = self.direct.session_key.take() else {
            self.direct.status = "Failed: no session key. Restart the handshake.".to_string();
            return;
        };

        let save_path = self.direct.save_path.clone();
        let store_url = self.direct.store_url.clone();
        let sealed = self.direct.sealed_cap.clone();
        let status_shared = Arc::clone(&self.direct_status_shared);
        let done = Arc::clone(&self.direct_done);
        done.store(false, Ordering::SeqCst);

        if let Ok(mut lock) = status_shared.lock() {
            *lock = "Starting download...".to_string();
        }

        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            let status_inner = Arc::clone(&status_shared);
            std::thread::spawn(move || {
                while let Ok(msg) = rx.recv() {
                    if let Ok(mut lock) = status_inner.lock() {
                        *lock = msg;
                    }
                }
            });

            if let Err(e) = crate::commands::direct::receive_core(
                &save_path,
                &store_url,
                &session,
                &sealed,
                Some(tx),
            ) {
                if let Ok(mut lock) = status_shared.lock() {
                    *lock = format!("Failed: {}", e);
                }
            }
            done.store(true, Ordering::SeqCst);
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
}

// ── Incoming sync overlay ─────────────────────────────────────────────────────

impl AtomVaultApp {
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
                            RichText::new("Local label:").size(12.5).color(TEXT_SECONDARY),
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
    use super::resolve_save_path;
    use crate::gui::{DirectStage, DirectState};
    use eframe::egui;

    // — Mode A handshake state machine —

    #[test]
    fn reset_clears_all_handshake_derived_state() {
        let mut s = DirectState::default();
        s.stage = DirectStage::Transfer;
        s.our_blob = "ours".into();
        s.peer_blob = "theirs".into();
        s.sealed_cap = "cap".into();
        s.status = "something happened".into();

        s.reset_handshake();

        assert_eq!(s.stage, DirectStage::Secret);
        assert!(s.our_blob.is_empty());
        assert!(s.peer_blob.is_empty());
        assert!(s.sealed_cap.is_empty());
        assert!(s.status.is_empty());
        assert!(s.spake_state.is_none());
        assert!(s.session_key.is_none());
    }

    #[test]
    fn reset_preserves_user_typed_transport_settings() {
        // The store URL and destination are not handshake-derived; forcing the
        // user to retype them on every restart would be hostile.
        let mut s = DirectState::default();
        s.store_url = "https://store.example/blobs".into();
        s.save_path = "/tmp/out.aegis".into();
        s.short_secret = "words".into();

        s.reset_handshake();

        assert_eq!(s.store_url, "https://store.example/blobs");
        assert_eq!(s.save_path, "/tmp/out.aegis");
        assert_eq!(s.short_secret, "words");
    }

    #[test]
    fn default_state_starts_at_secret_stage_with_no_keys() {
        let s = DirectState::default();
        assert_eq!(s.stage, DirectStage::Secret);
        assert!(s.session_key.is_none());
        assert!(s.spake_state.is_none());
        assert!(!s.save_path.is_empty(), "should offer a default destination");
    }

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
