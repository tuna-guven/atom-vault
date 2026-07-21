//! The live-transfer panel — `p2p-live` with a window in front of it.
//!
//! Every action here calls a `commands::live::*` function, the same ones
//! `atom live` uses from a terminal. There is deliberately no second copy of the
//! pairing logic: per `CLAUDE.md` §9 the human factor is the real attack surface,
//! and two implementations of an out-of-band exchange means two chances to get
//! it subtly wrong.
//!
//! # What this UI has to communicate, not just do
//!
//! The cryptography underneath is only as good as the human steps around it, so
//! three things are on screen rather than in a manual:
//!
//! * the **code must travel a different channel** from the blobs — stated at the
//!   point the code appears, not in a tooltip;
//! * the **fingerprints must be compared aloud** — shown side by side after
//!   pairing, because that comparison is the only thing that catches a
//!   man-in-the-middle at pairing time;
//! * **both peers must be online together** — said before the wait begins, so a
//!   timeout reads as "they weren't there" rather than "it's broken".

use eframe::egui;
use egui::{Color32, Margin, RichText, Stroke};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{AtomVaultApp, LiveRole, LiveStage};
use crate::commands::live;

// Palette shared with the rest of the P2P screen.
const CARD_BG: Color32 = Color32::from_rgb(34, 39, 58);
const CARD_STROKE: Color32 = Color32::from_rgb(52, 60, 92);
const ACCENT: Color32 = Color32::from_rgb(64, 160, 255);
const ACCENT_DARK: Color32 = Color32::from_rgb(40, 120, 210);
const SUCCESS: Color32 = Color32::from_rgb(48, 190, 90);
const WARN: Color32 = Color32::from_rgb(235, 170, 60);
const DANGER: Color32 = Color32::from_rgb(255, 75, 65);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(218, 224, 245);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(130, 142, 175);
const BADGE_BG: Color32 = Color32::from_rgb(40, 46, 70);

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(CARD_BG)
        .stroke(Stroke::new(1.0, CARD_STROKE))
        .rounding(8.0)
        .inner_margin(Margin::symmetric(14.0, 12.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
}

fn section(ui: &mut egui::Ui, text: &str) {
    ui.add_space(10.0);
    ui.label(
        RichText::new(text)
            .size(11.0)
            .strong()
            .color(TEXT_SECONDARY),
    );
    ui.add_space(4.0);
}

/// Format bytes for a progress line.
pub(super) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

impl AtomVaultApp {
    pub(super) fn show_live_panel(&mut self, ui: &mut egui::Ui) {
        let busy = !self.live_done.load(Ordering::SeqCst);
        if busy {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::ScrollArea::vertical()
            .id_salt("live_scroll")
            .show(ui, |ui| {
                self.live_identity_card(ui);
                self.live_pairing_card(ui, busy);
                self.live_transfer_card(ui, busy);
                self.live_status_line(ui);
            });
    }

    // ── Identity ─────────────────────────────────────────────────────────────

    fn live_identity_card(&mut self, ui: &mut egui::Ui) {
        section(ui, "YOUR LIVE IDENTITY");
        card(ui, |ui| match live::identity_summary() {
            Ok(s) => {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Fingerprint")
                            .size(12.0)
                            .color(TEXT_SECONDARY),
                    );
                    ui.label(
                        RichText::new(&s.fingerprint)
                            .size(13.5)
                            .monospace()
                            .color(TEXT_PRIMARY),
                    );
                    if ui.small_button("Copy id").clicked() {
                        ui.ctx().copy_text(s.id.clone());
                    }
                });
                ui.label(
                    RichText::new(if s.hybrid {
                        "Post-quantum: Ed25519 + ML-DSA-65"
                    } else {
                        "Post-quantum: no — classical only"
                    })
                    .size(11.5)
                    .color(if s.hybrid { SUCCESS } else { WARN }),
                );

                ui.add_space(8.0);
                ui.label(
                    RichText::new("Address peers reach you on")
                        .size(12.0)
                        .color(TEXT_SECONDARY),
                );
                let mut addr = s.endpoints.first().cloned().unwrap_or_default();
                ui.horizontal(|ui| {
                    let edited = ui
                        .add(
                            egui::TextEdit::singleline(&mut addr)
                                .desired_width(280.0)
                                .hint_text("203.0.113.7:4433  or  <56-char>.onion:4433"),
                        )
                        .changed();
                    if edited {
                        self.live.status.clear();
                    }
                    if ui.button("Save").clicked() {
                        match live::set_endpoints(&[addr.clone()]) {
                            Ok(()) => {
                                self.live.status = if addr.contains(".onion") {
                                    "Address saved. Transfers to you will run over Tor.".into()
                                } else {
                                    "Address saved. Note: both ISPs will see that you and \
                                     your peer exchanged packets."
                                        .into()
                                }
                            }
                            Err(e) => self.live.status = format!("Failed: {e}"),
                        }
                    }
                });
                if s.endpoints.is_empty() {
                    ui.label(
                        RichText::new("Set this before pairing — it goes into your ticket.")
                            .size(11.0)
                            .color(WARN),
                    );
                }
            }
            Err(e) => {
                ui.label(RichText::new(format!("Identity unavailable: {e}")).color(DANGER));
            }
        });
    }

    // ── Pairing ──────────────────────────────────────────────────────────────

    fn live_pairing_card(&mut self, ui: &mut egui::Ui, busy: bool) {
        section(ui, "PAIR WITH A PEER");
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Nickname").size(12.0).color(TEXT_SECONDARY));
                let editable = self.live.stage == LiveStage::Code;
                ui.add_enabled(
                    editable,
                    egui::TextEdit::singleline(&mut self.live.nickname)
                        .desired_width(160.0)
                        .hint_text("bob"),
                );
            });

            ui.add_space(8.0);
            ui.label(
                RichText::new("Short code — say it out loud, on a DIFFERENT channel")
                    .size(12.0)
                    .color(TEXT_PRIMARY),
            );
            ui.label(
                RichText::new(
                    "Never send the code through the same channel as the blobs below. \
                     The whole design rests on those being two different channels. \
                     Single use: if pairing fails, start again with a new code.",
                )
                .size(11.0)
                .color(TEXT_SECONDARY),
            );
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                let editable = self.live.stage == LiveStage::Code;
                if ui
                    .add_enabled(
                        editable,
                        egui::TextEdit::singleline(&mut self.live.code)
                            .desired_width(200.0)
                            .hint_text("code your peer read to you"),
                    )
                    .changed()
                {
                    self.live.reset_pairing();
                }
                if ui
                    .add_enabled(editable, egui::Button::new("Generate one instead"))
                    .clicked()
                {
                    match p2p_live::pairing::PairingCode::generate() {
                        Ok(c) => {
                            self.live.our_code = c.display();
                            self.live.code = c.display();
                            self.live.status =
                                "Read this code aloud to your peer, then start round 1.".into();
                        }
                        Err(e) => self.live.status = format!("Failed: {e}"),
                    }
                }
            });

            if !self.live.our_code.is_empty() {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(&self.live.our_code)
                        .size(20.0)
                        .monospace()
                        .strong()
                        .color(ACCENT),
                );
            }

            // ── Round 1 ──
            ui.add_space(10.0);
            if ui
                .add_enabled(
                    self.live.stage == LiveStage::Code
                        && !self.live.code.trim().is_empty()
                        && !self.live.nickname.trim().is_empty(),
                    egui::Button::new(RichText::new("Start round 1").color(Color32::WHITE))
                        .fill(ACCENT_DARK),
                )
                .clicked()
            {
                match p2p_live::pairing::PairingCode::parse(&self.live.code)
                    .map_err(|e| e.to_string())
                    .and_then(|c| {
                        // Fail here if no address is set, rather than after the
                        // user has already sent a blob to their peer.
                        live::my_ticket().map_err(|e| e.to_string())?;
                        Ok(live::pair_begin(&c))
                    }) {
                    Ok((state, blob)) => {
                        self.live.pairing = Some(state);
                        self.live.our_blob = blob;
                        self.live.stage = LiveStage::Exchange;
                        self.live.status = "Send your round-1 blob, paste theirs below.".into();
                    }
                    Err(e) => self.live.status = format!("Failed: {e}"),
                }
            }

            if self.live.stage != LiveStage::Code && !self.live.our_blob.is_empty() {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(if self.live.stage == LiveStage::Exchange {
                        "Round 1 — send this to your peer"
                    } else {
                        "Round 2 — send this to your peer"
                    })
                    .size(12.0)
                    .color(TEXT_SECONDARY),
                );
                let mut shown = self.live.our_blob.clone();
                ui.add(
                    egui::TextEdit::multiline(&mut shown)
                        .desired_width(f32::INFINITY)
                        .desired_rows(2)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(self.live.our_blob.clone());
                }
            }

            // ── Peer's blob ──
            if matches!(self.live.stage, LiveStage::Exchange) {
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Paste your peer's message")
                        .size(12.0)
                        .color(TEXT_SECONDARY),
                );
                ui.add(
                    egui::TextEdit::multiline(&mut self.live.peer_blob)
                        .desired_width(f32::INFINITY)
                        .desired_rows(2)
                        .font(egui::TextStyle::Monospace),
                );

                let ready = !self.live.peer_blob.trim().is_empty() && !busy;
                if ui
                    .add_enabled(
                        ready,
                        egui::Button::new(RichText::new("Continue").color(Color32::WHITE))
                            .fill(ACCENT_DARK),
                    )
                    .clicked()
                {
                    let peer_blob = self.live.peer_blob.trim().to_string();
                    // Round 1 → 2 if we still hold the SPAKE2 state; otherwise
                    // this is the sealed ticket that completes the pairing.
                    if let Some(state) = self.live.pairing.take() {
                        match live::pair_exchange(state, &peer_blob) {
                            Ok((channel, sealed)) => {
                                self.live.channel = Some(channel);
                                self.live.our_blob = sealed;
                                self.live.peer_blob.clear();
                                self.live.status =
                                    "Now exchange round 2: send yours, paste theirs.".into();
                            }
                            Err(e) => self.live.status = format!("Failed: {e}"),
                        }
                    } else if let Some(channel) = &self.live.channel {
                        let nickname = self.live.nickname.trim().to_string();
                        match live::pair_complete(channel, &peer_blob, &nickname) {
                            Ok(peer) => {
                                self.live.peer_fingerprint = peer.fingerprint();
                                self.live.our_fingerprint = live::my_ticket()
                                    .map(|t| t.fingerprint())
                                    .unwrap_or_default();
                                self.live.stage = LiveStage::Paired;
                                self.live.selected_peer = nickname.clone();
                                self.live.status = format!("Paired with {nickname}.");
                            }
                            Err(e) => self.live.status = format!("Failed: {e}"),
                        }
                    }
                }
            }

            // ── The human check ──
            if self.live.stage == LiveStage::Paired {
                ui.add_space(10.0);
                egui::Frame::none()
                    .fill(BADGE_BG)
                    .stroke(Stroke::new(1.0, WARN))
                    .rounding(6.0)
                    .inner_margin(Margin::symmetric(10.0, 8.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("Read these aloud and check they match")
                                .size(12.5)
                                .strong()
                                .color(WARN),
                        );
                        ui.label(
                            RichText::new(format!("  yours: {}", self.live.our_fingerprint))
                                .size(13.0)
                                .monospace()
                                .color(TEXT_PRIMARY),
                        );
                        ui.label(
                            RichText::new(format!("  theirs: {}", self.live.peer_fingerprint))
                                .size(13.0)
                                .monospace()
                                .color(TEXT_PRIMARY),
                        );
                        ui.label(
                            RichText::new(
                                "If they do not match what your peer sees, someone sat in the \
                                 middle of the exchange. Remove the peer and start over.",
                            )
                            .size(11.0)
                            .color(TEXT_SECONDARY),
                        );
                    });
                if ui.button("Pair another peer").clicked() {
                    let keep = std::mem::take(&mut self.live.selected_peer);
                    self.live.reset_pairing();
                    self.live.code.clear();
                    self.live.our_code.clear();
                    self.live.nickname.clear();
                    self.live.selected_peer = keep;
                }
            }
        });
    }

    // ── Transfer ─────────────────────────────────────────────────────────────

    fn live_transfer_card(&mut self, ui: &mut egui::Ui, busy: bool) {
        let peers = live::load_state().map(|s| s.peers).unwrap_or_default();

        section(ui, "TRANSFER");
        card(ui, |ui| {
            if peers.is_empty() {
                ui.label(
                    RichText::new("No paired peers yet — pair with someone above first.")
                        .size(12.0)
                        .color(TEXT_SECONDARY),
                );
                return;
            }

            ui.horizontal(|ui| {
                ui.label(RichText::new("Peer").size(12.0).color(TEXT_SECONDARY));
                egui::ComboBox::from_id_salt("live_peer")
                    .selected_text(if self.live.selected_peer.is_empty() {
                        "choose…".to_string()
                    } else {
                        self.live.selected_peer.clone()
                    })
                    .show_ui(ui, |ui| {
                        for p in &peers {
                            ui.selectable_value(
                                &mut self.live.selected_peer,
                                p.nickname.clone(),
                                &p.nickname,
                            );
                        }
                    });

                for (role, label) in [(LiveRole::Send, "Send"), (LiveRole::Receive, "Receive")] {
                    let selected = self.live.role == role;
                    if ui
                        .add(
                            egui::Button::new(RichText::new(label).color(if selected {
                                Color32::WHITE
                            } else {
                                TEXT_SECONDARY
                            }))
                            .fill(if selected {
                                ACCENT_DARK
                            } else {
                                BADGE_BG
                            }),
                        )
                        .clicked()
                    {
                        self.live.role = role;
                    }
                }
            });

            ui.add_space(8.0);
            match self.live.role {
                LiveRole::Send => {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Vault").size(12.0).color(TEXT_SECONDARY));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.live.vault_path)
                                .desired_width(320.0)
                                .hint_text("/path/to/my_data.aegis"),
                        );
                        if ui.button("Browse").clicked()
                            && let Some(p) = rfd::FileDialog::new()
                                .add_filter("Aegis Vault", &["aegis"])
                                .pick_file()
                        {
                            self.live.vault_path = p.to_string_lossy().to_string();
                        }
                    });
                }
                LiveRole::Receive => {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Save to").size(12.0).color(TEXT_SECONDARY));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.live.save_path)
                                .desired_width(320.0),
                        );
                    });
                }
            }

            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Both of you must press this at the same time — there is no server \
                     holding anything in between.",
                )
                .size(11.0)
                .color(TEXT_SECONDARY),
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                let ready = !busy && !self.live.selected_peer.is_empty();
                if ui
                    .add_enabled(
                        ready,
                        egui::Button::new(
                            RichText::new(match self.live.role {
                                LiveRole::Send => "Send now",
                                LiveRole::Receive => "Receive now",
                            })
                            .color(Color32::WHITE),
                        )
                        .fill(ACCENT_DARK),
                    )
                    .clicked()
                {
                    self.start_live_transfer();
                }

                if busy && ui.button("Stop").clicked() {
                    self.live_cancel.cancel();
                    self.live.status = "Stopping…".into();
                }
            });

            if busy {
                let (done, total) = self.live_progress.lock().ok().map(|g| *g).unwrap_or((0, 0));
                let frac = if total == 0 {
                    0.0
                } else {
                    done as f32 / total as f32
                };
                ui.add_space(6.0);
                ui.add(
                    egui::ProgressBar::new(frac).show_percentage().text(
                        RichText::new(format!("{} / {}", human_bytes(done), human_bytes(total)))
                            .size(11.5),
                    ),
                );
            }
        });
    }

    fn live_status_line(&mut self, ui: &mut egui::Ui) {
        if let Ok(g) = self.live_status_shared.lock()
            && !g.is_empty()
        {
            self.live.status = g.clone();
        }
        if self.live.status.is_empty() {
            return;
        }
        ui.add_space(10.0);
        let failed = self.live.status.starts_with("Failed") || self.live.status.contains("error");
        ui.label(
            RichText::new(&self.live.status)
                .size(12.0)
                .color(if failed { DANGER } else { SUCCESS }),
        );
    }

    /// Launch the transfer on a worker thread so the window keeps painting.
    fn start_live_transfer(&mut self) {
        let peer = self.live.selected_peer.clone();
        let role = self.live.role;
        let path = match role {
            LiveRole::Send => self.live.vault_path.clone(),
            LiveRole::Receive => self.live.save_path.clone(),
        };

        // A fresh token per run: reusing a cancelled one would stop the next
        // transfer the instant it started.
        self.live_cancel = p2p_live::transfer::Cancel::new();
        let cancel = self.live_cancel.clone();
        let status = Arc::clone(&self.live_status_shared);
        let progress = Arc::clone(&self.live_progress);
        let done = Arc::clone(&self.live_done);

        done.store(false, Ordering::SeqCst);
        if let Ok(mut g) = status.lock() {
            *g = format!("Waiting to meet {peer} — they must run their side now.");
        }
        if let Ok(mut g) = progress.lock() {
            *g = (0, 0);
        }

        std::thread::spawn(move || {
            let p = Arc::clone(&progress);
            let mut on_progress = move |pr: p2p_live::transfer::Progress| {
                if let Ok(mut g) = p.lock() {
                    *g = (pr.transferred, pr.total);
                }
            };

            let result = match role {
                LiveRole::Send => live::send_core(&path, &peer, &mut on_progress, Some(cancel)),
                LiveRole::Receive => {
                    live::receive_core(&path, &peer, &mut on_progress, Some(cancel))
                }
            };

            if let Ok(mut g) = status.lock() {
                *g = match result {
                    Ok(s) => format!(
                        "Done — {} verified, {} cover frames.",
                        human_bytes(s.total),
                        s.cover_frames
                    ),
                    Err(e) => format!("Failed: {e}"),
                };
            }
            done.store(true, Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

    #[test]
    fn bytes_are_readable_at_every_scale() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }
}
