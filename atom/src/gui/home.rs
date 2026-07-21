use eframe::egui;
use egui::{Color32, Context, Margin, RichText, Rounding, Stroke, Vec2};
use rfd::FileDialog;
use std::sync::Arc;

use super::{AtomVaultApp, Screen};

// ── Colour palette ────────────────────────────────────────────────────────────

const ONLINE: Color32 = Color32::from_rgb(52, 210, 90);
const OFFLINE: Color32 = Color32::from_rgb(115, 120, 135);
const ACCENT: Color32 = Color32::from_rgb(64, 160, 255);
const ACCENT_DARK: Color32 = Color32::from_rgb(40, 120, 210);
const SUCCESS: Color32 = Color32::from_rgb(48, 190, 90);
const SUCCESS_DARK: Color32 = Color32::from_rgb(28, 120, 55);
const DANGER: Color32 = Color32::from_rgb(255, 75, 65);
const SHARED_TEAL: Color32 = Color32::from_rgb(100, 210, 210);

const HEADER_BG: Color32 = Color32::from_rgb(18, 22, 38);
const PANEL_BG: Color32 = Color32::from_rgb(24, 28, 44);
const CARD_BG: Color32 = Color32::from_rgb(34, 39, 58);
const CARD_BG_WARN: Color32 = Color32::from_rgb(48, 32, 28);
const CARD_STROKE: Color32 = Color32::from_rgb(52, 60, 92);
const CARD_STROKE_W: Color32 = Color32::from_rgb(100, 60, 45);
const BADGE_BG: Color32 = Color32::from_rgb(40, 46, 70);
const FRIEND_BG: Color32 = Color32::from_rgb(30, 35, 54);

const TEXT_PRIMARY: Color32 = Color32::from_rgb(218, 224, 245);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(130, 142, 175);
const TEXT_DIM: Color32 = Color32::from_rgb(85, 95, 125);

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn relative_time(now: u64, ts: u64) -> String {
    let diff = now.saturating_sub(ts);
    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

fn card_frame(bg: Color32, stroke: Color32) -> egui::Frame {
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(1.0, stroke))
        .rounding(Rounding::same(9.0))
        .inner_margin(Margin::symmetric(14.0, 10.0))
}

fn badge_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(BADGE_BG)
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(10.0, 5.0))
}

fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(14.0, 20.0), egui::Sense::hover());
    ui.painter()
        .circle_filled(rect.center() + egui::vec2(0.0, 1.0), 5.5, color);
}

// ── Home screen ───────────────────────────────────────────────────────────────

impl AtomVaultApp {
    pub(super) fn show_home(&mut self, ctx: &Context) {
        // ── Header ───────────────────────────────────────────────────────────
        egui::TopBottomPanel::top("home_header")
            .frame(
                egui::Frame::none()
                    .fill(HEADER_BG)
                    .inner_margin(Margin::symmetric(24.0, 14.0)),
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("ATOM VAULT")
                            .size(30.0)
                            .strong()
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new("Secure Encrypted Virtual File System")
                            .size(12.0)
                            .color(TEXT_DIM),
                    );
                });
            });

        // ── Friends side panel ────────────────────────────────────────────────
        egui::SidePanel::right("home_friends")
            .resizable(false)
            .exact_width(230.0)
            .frame(
                egui::Frame::none()
                    .fill(PANEL_BG)
                    .inner_margin(Margin::symmetric(12.0, 14.0)),
            )
            .show(ctx, |ui| {
                self.draw_friends_panel(ui);
            });

        // ── Vault list ────────────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(20, 24, 38))
                    .inner_margin(Margin::symmetric(18.0, 14.0)),
            )
            .show(ctx, |ui| {
                self.draw_vault_panel(ui);
            });
    }

    // ── Friends panel ─────────────────────────────────────────────────────────

    fn draw_friends_panel(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("FRIENDS").size(11.5).strong().color(TEXT_DIM));
        ui.add(egui::Separator::default().spacing(8.0));
        ui.add_space(4.0);

        if self.friends_full.is_empty() {
            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("👥").size(36.0));
                ui.add_space(6.0);
                ui.label(
                    RichText::new("No friends yet")
                        .size(14.0)
                        .strong()
                        .color(TEXT_SECONDARY),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Open a vault and use\nP2P Network to add friends.")
                        .size(11.5)
                        .color(TEXT_DIM),
                );
            });
            return;
        }

        let now = unix_now();
        let online_count = self
            .friends_full
            .iter()
            .filter(|f| {
                f.last_seen
                    .map(|t| now.saturating_sub(t) < 300)
                    .unwrap_or(false)
            })
            .count();
        let offline_count = self.friends_full.len() - online_count;

        // ── Summary badge ────────────────────────────────────────────────────
        badge_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{}", online_count))
                        .size(20.0)
                        .strong()
                        .color(ONLINE),
                );
                ui.label(RichText::new("online").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(10.0);
                ui.label(
                    RichText::new(format!("{}", offline_count))
                        .size(20.0)
                        .strong()
                        .color(OFFLINE),
                );
                ui.label(RichText::new("offline").size(12.0).color(TEXT_SECONDARY));
            });
        });
        ui.add_space(10.0);

        // ── Friend cards ─────────────────────────────────────────────────────
        egui::ScrollArea::vertical()
            .id_salt("friends_scroll")
            .show(ui, |ui| {
                for friend in &self.friends_full {
                    let is_online = friend
                        .last_seen
                        .map(|t| now.saturating_sub(t) < 300)
                        .unwrap_or(false);

                    egui::Frame::none()
                        .fill(FRIEND_BG)
                        .stroke(Stroke::new(
                            1.0,
                            if is_online {
                                Color32::from_rgb(40, 100, 60)
                            } else {
                                Color32::from_rgb(48, 52, 72)
                            },
                        ))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 8.0))
                        .show(ui, |ui| {
                            // Name row
                            ui.horizontal(|ui| {
                                status_dot(ui, if is_online { ONLINE } else { OFFLINE });
                                ui.label(
                                    RichText::new(&friend.nickname)
                                        .size(15.0)
                                        .strong()
                                        .color(TEXT_PRIMARY),
                                );
                            });

                            // Last seen / status line
                            ui.add_space(2.0);
                            let (status_text, status_color) = if is_online {
                                ("● online now".to_string(), ONLINE)
                            } else if let Some(t) = friend.last_seen {
                                (
                                    format!("last seen {}", relative_time(now, t)),
                                    TEXT_SECONDARY,
                                )
                            } else {
                                ("never synced".to_string(), TEXT_DIM)
                            };
                            ui.label(RichText::new(status_text).size(11.5).color(status_color));

                            // Shared vaults
                            ui.add_space(5.0);
                            if friend.shared_vaults.is_empty() {
                                ui.label(
                                    RichText::new("no shared vaults")
                                        .size(11.0)
                                        .italics()
                                        .color(TEXT_DIM),
                                );
                            } else {
                                ui.label(
                                    RichText::new("Shared vaults:")
                                        .size(11.5)
                                        .color(TEXT_SECONDARY),
                                );
                                for sv in &friend.shared_vaults {
                                    ui.horizontal(|ui| {
                                        ui.add_space(6.0);
                                        let (dot_r, _) = ui.allocate_exact_size(
                                            Vec2::new(10.0, 14.0),
                                            egui::Sense::hover(),
                                        );
                                        ui.painter().circle_filled(
                                            dot_r.center(),
                                            2.5,
                                            SHARED_TEAL,
                                        );
                                        let display = if sv.label.is_empty() {
                                            &sv.original_name
                                        } else {
                                            &sv.label
                                        };
                                        ui.label(
                                            RichText::new(display).size(11.5).color(SHARED_TEAL),
                                        );
                                    });
                                }
                            }
                        });
                    ui.add_space(6.0);
                }
            });
    }

    // ── Vault panel ───────────────────────────────────────────────────────────

    fn draw_vault_panel(&mut self, ui: &mut egui::Ui) {
        // Toolbar
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("MY VAULTS")
                    .size(11.5)
                    .strong()
                    .color(TEXT_DIM),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("+ Create New")
                                .size(13.5)
                                .color(Color32::WHITE),
                        )
                        .fill(SUCCESS_DARK)
                        .stroke(Stroke::new(1.0, SUCCESS)),
                    )
                    .clicked()
                {
                    self.home_status = String::new();
                    self.screen = Screen::CreateVault;
                }
                ui.add_space(6.0);
                if !std::path::Path::new("/.flatpak-info").exists() {
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Browse…").size(13.5))
                                .fill(BADGE_BG)
                                .stroke(Stroke::new(1.0, CARD_STROKE)),
                        )
                        .clicked()
                    {
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
                }
            });
        });
        ui.add_space(2.0);
        ui.add(egui::Separator::default().spacing(8.0));

        // Status notification
        if !self.home_status.is_empty() {
            let (msg_color, bg_color) = if self.home_status.starts_with("Error") {
                (DANGER, Color32::from_rgb(55, 18, 16))
            } else {
                (SUCCESS, Color32::from_rgb(16, 48, 26))
            };
            egui::Frame::none()
                .fill(bg_color)
                .stroke(Stroke::new(1.0, msg_color))
                .rounding(Rounding::same(7.0))
                .inner_margin(Margin::symmetric(12.0, 7.0))
                .show(ui, |ui| {
                    ui.label(RichText::new(&self.home_status).size(13.5).color(msg_color));
                });
            ui.add_space(6.0);
        }

        // Vault list
        egui::ScrollArea::vertical()
            .id_salt("vault_scroll")
            .show(ui, |ui| {
                if self.vault_registry.is_empty() {
                    ui.add_space(44.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("🔒").size(52.0));
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new("No vaults yet")
                                .size(19.0)
                                .strong()
                                .color(TEXT_SECONDARY),
                        );
                        ui.add_space(6.0);
                        let hint = if std::path::Path::new("/.flatpak-info").exists() {
                            "Create a new encrypted vault — it will be\nstored securely in your app data folder."
                        } else {
                            "Create a new encrypted vault or browse\nfor an existing .aegis file."
                        };
                        ui.label(RichText::new(hint).size(13.0).color(TEXT_DIM));
                    });
                    return;
                }

                let now = unix_now();
                let mut open_path: Option<std::path::PathBuf> = None;
                let mut remove_path: Option<String> = None;

                for entry in &self.vault_registry {
                    let exists = std::path::Path::new(&entry.path).exists();
                    let (bg, stroke) = if exists {
                        (CARD_BG, CARD_STROKE)
                    } else {
                        (CARD_BG_WARN, CARD_STROKE_W)
                    };

                    card_frame(bg, stroke).show(ui, |ui| {
                        // ── Row 1: icon + info ───────────────────────────────
                        // Split: info.vertical() consumes all width, so buttons
                        // live on a separate row below to avoid a zero-width
                        // right-to-left section that triggers !widget_rect.any_nan().
                        ui.horizontal(|ui| {
                            if exists {
                                ui.label(RichText::new("🔒").size(24.0));
                            } else {
                                ui.label(
                                    RichText::new("⚠")
                                        .size(24.0)
                                        .color(Color32::from_rgb(230, 150, 50)),
                                );
                            }
                            ui.add_space(8.0);
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(&entry.name)
                                        .size(17.0)
                                        .strong()
                                        .color(if exists { TEXT_PRIMARY } else { OFFLINE }),
                                );
                                ui.label(
                                    RichText::new(&entry.path)
                                        .size(11.0)
                                        .color(TEXT_DIM),
                                );
                                if !exists {
                                    ui.label(
                                        RichText::new("⚠  File not found on disk")
                                            .size(11.5)
                                            .color(Color32::from_rgb(225, 145, 50)),
                                    );
                                } else if entry.last_opened > 0 {
                                    ui.label(
                                        RichText::new(format!(
                                            "Last opened  {}",
                                            relative_time(now, entry.last_opened)
                                        ))
                                        .size(11.5)
                                        .color(TEXT_SECONDARY),
                                    );
                                } else {
                                    ui.label(
                                        RichText::new("Newly created")
                                            .size(11.5)
                                            .color(SUCCESS),
                                    );
                                }
                            });
                        });

                        // ── Row 2: action buttons (right-aligned) ────────────
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    // Remove — clearly labelled so it's always visible
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("Remove")
                                                    .size(12.5)
                                                    .color(DANGER),
                                            )
                                            .fill(Color32::from_rgb(55, 22, 20))
                                            .stroke(Stroke::new(1.0, Color32::from_rgb(140, 50, 45))),
                                        )
                                        .on_hover_text("Remove from vault list (does not delete the file)")
                                        .clicked()
                                    {
                                        remove_path = Some(entry.path.clone());
                                    }

                                    if exists {
                                        ui.add_space(6.0);
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("Open")
                                                        .size(13.5)
                                                        .strong()
                                                        .color(Color32::WHITE),
                                                )
                                                .fill(ACCENT_DARK)
                                                .stroke(Stroke::new(1.0, ACCENT))
                                                .min_size(Vec2::new(70.0, 30.0)),
                                            )
                                            .clicked()
                                        {
                                            open_path =
                                                Some(std::path::PathBuf::from(&entry.path));
                                        }
                                    }
                                },
                            );
                        });
                    });
                    ui.add_space(6.0);
                }

                if let Some(path) = open_path {
                    self.selected_vault_path = Some(path);
                    self.login_status =
                        "Vault selected. Enter master password.".to_string();
                    self.home_status = String::new();
                    self.screen = Screen::Login;
                }
                if let Some(path) = remove_path {
                    crate::commands::vault_registry::remove_vault_from_registry(&path);
                    self.vault_registry =
                        crate::commands::vault_registry::load_vault_registry();
                }
            });
    }
}
