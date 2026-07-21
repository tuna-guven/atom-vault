use eframe::egui;
use egui::Context;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::commands::daemon::{DaemonEvent, SyncResponse};

mod broker;
mod explorer;
mod home;
mod live;
mod login;
mod p2p;

// ── Shared types ─────────────────────────────────────────────────────────────

struct VaultSession {
    file: std::fs::File,
    metadata: crate::vfs::VaultMetadata,
    unlocked_vault: crate::crypto::UnlockedVault,
    current_offset: u64,
}

enum Screen {
    Home,
    Login,
    VaultExplorer,
    CreateVault,
    P2PDialog,
}

struct IncomingSyncState {
    sender_nick: String,
    filename: String,
    vault_label: String,
    save_path: String,
    response_channel: Option<tokio::sync::oneshot::Sender<SyncResponse>>,
}

struct RenameState {
    old_name: String,
    new_name: String,
}

/// Which transport the P2P screen is showing.
#[derive(PartialEq, Eq, Clone, Copy)]
enum TransportTab {
    /// Live sync over Tor onion services (the original mechanism).
    Tor,
    /// Strict-PFS, post-quantum live transfer (`p2p-live`).
    Live,
}

/// Which side of a live transfer this user is performing.
#[derive(PartialEq, Eq, Clone, Copy)]
enum LiveRole {
    Send,
    Receive,
}

/// Progress through the two-round pairing exchange. Both rounds travel the
/// user's own channel; the short code must travel a *different* one.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum LiveStage {
    /// Agree the short secret; produce our round-1 blob.
    Code,
    /// Paste the peer's round-1 blob; produce our sealed ticket.
    Exchange,
    /// Paste the peer's sealed ticket; the pairing is saved.
    Paired,
}

/// State for the live-transfer panel.
struct LiveState {
    role: LiveRole,
    stage: LiveStage,
    /// Empty means "generate one"; non-empty means the peer read it to us.
    code: String,
    /// The code we generated, shown for the user to read aloud.
    our_code: String,
    nickname: String,
    our_blob: String,
    peer_blob: String,
    /// Held between round 1 and round 2.
    pairing: Option<p2p_live::pairing::PairingState>,
    /// Derived at round 2; used to open the peer's sealed ticket.
    channel: Option<p2p_live::pairing::PairedChannel>,
    /// Fingerprints to read aloud once paired — the human MITM check.
    our_fingerprint: String,
    peer_fingerprint: String,
    /// Transfer settings.
    selected_peer: String,
    vault_path: String,
    save_path: String,
    status: String,
}

impl Default for LiveState {
    fn default() -> Self {
        Self {
            role: LiveRole::Send,
            stage: LiveStage::Code,
            code: String::new(),
            our_code: String::new(),
            nickname: String::new(),
            our_blob: String::new(),
            peer_blob: String::new(),
            pairing: None,
            channel: None,
            our_fingerprint: String::new(),
            peer_fingerprint: String::new(),
            selected_peer: String::new(),
            vault_path: String::new(),
            save_path: dirs::home_dir()
                .unwrap_or_default()
                .join(".atom_vault/received/live.aegis")
                .to_string_lossy()
                .to_string(),
            status: String::new(),
        }
    }
}

impl LiveState {
    /// Reset everything derived from the code. A SPAKE2 exchange is strictly
    /// single-use, so editing the code must discard every value derived from it
    /// rather than leaving a half-finished pairing on screen.
    fn reset_pairing(&mut self) {
        self.stage = LiveStage::Code;
        self.our_blob.clear();
        self.peer_blob.clear();
        self.pairing = None;
        self.channel = None;
        self.our_fingerprint.clear();
        self.peer_fingerprint.clear();
        self.status.clear();
    }
}

enum FileAction {
    Open(String),
    Export(String),
    Rename(String),
    Delete(String),
}

// ── App state ─────────────────────────────────────────────────────────────────

struct AtomVaultApp {
    screen: Screen,

    // Home screen
    vault_registry: Vec<crate::commands::vault_registry::VaultEntry>,
    friends_full: Vec<crate::commands::p2p_utils::FriendRecord>,
    home_status: String,
    // Detects sync completion to refresh friends_full
    prev_sync_done: bool,

    // Login screen
    selected_vault_path: Option<PathBuf>,
    password: String,
    login_status: String,
    sandbox_applied: bool,

    // File broker — pre-spawned before any Landlock domain fires so its
    // threads are never restricted by the vault sandbox.
    file_broker: broker::FileBroker,

    // File dialog results — written by bg threads, polled every frame
    pending_vault_path: Arc<Mutex<Option<PathBuf>>>,
    pending_import_path: Arc<Mutex<Option<PathBuf>>>,
    pending_create_path: Arc<Mutex<Option<PathBuf>>>,
    pending_export_path: Arc<Mutex<Option<PathBuf>>>,

    // Broker operation results (None = in-flight, Some = ready to process)
    pending_import_bytes: Option<Arc<Mutex<Option<Result<Vec<u8>, String>>>>>,
    pending_import_vfs_name: String,
    pending_export_vfs_name: Option<String>,
    pending_export_write_result: Option<Arc<Mutex<Option<Result<(), String>>>>>,

    // Open vault
    vault_session: Option<VaultSession>,
    current_vault_path: String,
    explorer_status: String,
    viewer_done: Option<(Arc<AtomicBool>, String)>,
    // Polled for bwrap spawn success/failure (set by broker thread, fast)
    pending_viewer_spawn: Option<Arc<Mutex<Option<Result<(), String>>>>>,

    // Create vault screen
    create_name: String,
    create_password: String,
    create_confirm: String,
    create_show_password: bool,
    create_kdf_argon: bool,
    create_dec_time: String,
    create_memory: String,
    create_rounds: String,
    create_threads: String,
    create_status: String,

    // P2P screen
    friends_cache: Vec<String>,
    friend_nick: String,
    friend_url: String,
    add_friend_status: String,
    selected_friend_idx: usize,
    sync_status_shared: Arc<Mutex<String>>,
    sync_done: Arc<AtomicBool>,

    // P2P screen — live transfer (p2p-live)
    transport_tab: TransportTab,
    live: LiveState,
    /// Status text written by the background transfer thread.
    live_status_shared: Arc<Mutex<String>>,
    /// False while a live transfer is in flight.
    live_done: Arc<AtomicBool>,
    /// Progress written by the transfer thread: (transferred, total).
    live_progress: Arc<Mutex<(u64, u64)>>,
    /// Set so the Stop button can reach a running transfer.
    live_cancel: p2p_live::transfer::Cancel,

    // Overlay dialogs
    incoming_sync: Option<IncomingSyncState>,
    rename_dialog: Option<RenameState>,
}

impl AtomVaultApp {
    fn new() -> Self {
        Self {
            screen: Screen::Home,
            vault_registry: crate::commands::vault_registry::load_vault_registry(),
            friends_full: crate::commands::p2p_utils::load_friends(),
            home_status: String::new(),
            prev_sync_done: true,
            selected_vault_path: None,
            password: String::new(),
            login_status: String::new(),
            sandbox_applied: false,
            file_broker: broker::FileBroker::spawn(),
            pending_vault_path: Arc::new(Mutex::new(None)),
            pending_import_path: Arc::new(Mutex::new(None)),
            pending_create_path: Arc::new(Mutex::new(None)),
            pending_export_path: Arc::new(Mutex::new(None)),
            pending_import_bytes: None,
            pending_import_vfs_name: String::new(),
            pending_export_vfs_name: None,
            pending_export_write_result: None,
            vault_session: None,
            current_vault_path: String::new(),
            explorer_status: String::new(),
            viewer_done: None,
            pending_viewer_spawn: None,
            create_name: String::new(),
            create_password: String::new(),
            create_confirm: String::new(),
            create_show_password: false,
            create_kdf_argon: true,
            create_dec_time: "1000".to_string(),
            create_memory: String::new(),
            create_rounds: String::new(),
            create_threads: String::new(),
            create_status: String::new(),
            friends_cache: Vec::new(),
            friend_nick: String::new(),
            friend_url: String::new(),
            add_friend_status: String::new(),
            selected_friend_idx: 0,
            sync_status_shared: Arc::new(Mutex::new(String::new())),
            sync_done: Arc::new(AtomicBool::new(true)),
            transport_tab: TransportTab::Tor,
            live: LiveState::default(),
            live_status_shared: Arc::new(Mutex::new(String::new())),
            live_done: Arc::new(AtomicBool::new(true)),
            live_progress: Arc::new(Mutex::new((0, 0))),
            live_cancel: p2p_live::transfer::Cancel::new(),
            incoming_sync: None,
            rename_dialog: None,
        }
    }

    // ── Per-frame polling ────────────────────────────────────────────────────

    fn poll_daemon_events(&mut self) {
        let mut events = Vec::new();
        if let Ok(mut queue) = INCOMING_EVENTS.lock() {
            std::mem::swap(&mut events, &mut *queue);
        }
        for event in events {
            match event {
                DaemonEvent::SyncRequest {
                    sender_nick,
                    filename,
                    response_channel,
                } => {
                    let default_path = dirs::home_dir()
                        .unwrap_or_default()
                        .join(format!(".atom_vault/received/{}/{}", sender_nick, filename))
                        .to_string_lossy()
                        .to_string();
                    self.incoming_sync = Some(IncomingSyncState {
                        sender_nick,
                        filename,
                        vault_label: String::new(),
                        save_path: default_path,
                        response_channel: Some(response_channel),
                    });
                }
                DaemonEvent::Log(msg) => {
                    println!("[Daemon Log] {}", msg);
                }
            }
        }
    }

    fn poll_file_dialog_results(&mut self) {
        // Use and_then so the MutexGuard is dropped before we borrow self mutably.
        if let Some(path) = self
            .pending_vault_path
            .lock()
            .ok()
            .and_then(|mut g| g.take())
        {
            // Sandbox is applied later in try_unlock(), immediately before the
            // first cryptographic operation, so the user can still navigate
            // Back → Home and pick a different vault before committing.
            self.selected_vault_path = Some(path);
            self.login_status = "Vault selected. Enter master password.".to_string();
            // If the file dialog was opened from the Home screen, navigate to Login.
            if matches!(self.screen, Screen::Home) {
                self.screen = Screen::Login;
            }
        }
        if let Some(full_path) = self
            .pending_create_path
            .lock()
            .ok()
            .and_then(|mut g| g.take())
        {
            self.do_create_vault_at_path(full_path);
        }
        if let Some(path) = self
            .pending_import_path
            .lock()
            .ok()
            .and_then(|mut g| g.take())
        {
            // Send to the pre-sandbox broker for a sandboxed read; the result
            // is polled in poll_broker_results() once the sub-thread finishes.
            let vfs_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            self.pending_import_vfs_name = vfs_name;
            self.pending_import_bytes = Some(self.file_broker.read_file(path));
            self.explorer_status = "Reading file...".to_string();
        }
        if let Some(path) = self
            .pending_export_path
            .lock()
            .ok()
            .and_then(|mut g| g.take())
        {
            if let Some(vfs_name) = self.pending_export_vfs_name.take() {
                self.do_export_via_broker(path, vfs_name);
            }
        }
    }

    fn poll_broker_results(&mut self, ctx: &Context) {
        // Clone the Arc so we release the borrow on `self` before calling
        // do_import_bytes / assigning back to the field.
        if let Some(arc) = self.pending_import_bytes.clone() {
            if let Ok(mut g) = arc.lock() {
                if g.is_some() {
                    let result = g.take().unwrap();
                    drop(g);
                    self.pending_import_bytes = None;
                    match result {
                        Ok(data) => self.do_import_bytes(data),
                        Err(e) => self.explorer_status = format!("Import Error: {}", e),
                    }
                }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
        if let Some(arc) = self.pending_export_write_result.clone() {
            if let Ok(mut g) = arc.lock() {
                if g.is_some() {
                    let result = g.take().unwrap();
                    drop(g);
                    self.pending_export_write_result = None;
                    match result {
                        Ok(()) => self.explorer_status = "Success: File exported.".to_string(),
                        Err(e) => self.explorer_status = format!("Export Error: {}", e),
                    }
                }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
        if let Some(arc) = self.pending_viewer_spawn.clone() {
            if let Ok(mut g) = arc.lock() {
                if g.is_some() {
                    let result = g.take().unwrap();
                    drop(g);
                    self.pending_viewer_spawn = None;
                    if let Err(e) = result {
                        self.explorer_status = format!("Open failed: {}", e);
                        self.viewer_done = None;
                    }
                }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }

    fn poll_viewer_done(&mut self, ctx: &Context) {
        let done = self
            .viewer_done
            .as_ref()
            .map(|(flag, _)| flag.load(Ordering::SeqCst))
            .unwrap_or(false);
        if done {
            if let Some((_, name)) = self.viewer_done.take() {
                self.explorer_status = format!("Closed securely: {}", name);
            }
        } else if self.viewer_done.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

// ── Daemon event bridge ───────────────────────────────────────────────────────

static INCOMING_EVENTS: Mutex<Vec<DaemonEvent>> = Mutex::new(Vec::new());

fn start_daemon_and_listener() {
    let (tokio_tx, mut tokio_rx) = tokio::sync::mpsc::channel(10);
    crate::commands::daemon::set_event_sender(tokio_tx);

    std::thread::spawn(|| {
        if let Err(e) = crate::commands::daemon::handle_daemon() {
            eprintln!("[Daemon Error] {}", e);
        }
    });

    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            rt.block_on(async {
                while let Some(event) = tokio_rx.recv().await {
                    if let Ok(mut queue) = INCOMING_EVENTS.lock() {
                        queue.push(event);
                    }
                }
            });
        }
    });
}

// ── eframe glue ───────────────────────────────────────────────────────────────

impl eframe::App for AtomVaultApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.poll_daemon_events();
        self.poll_file_dialog_results();
        self.poll_viewer_done(ctx);
        self.poll_broker_results(ctx);

        // Refresh friends list once after each completed sync so the home
        // screen online/offline indicator reflects the latest last_seen value.
        let sync_now_done = self.sync_done.load(std::sync::atomic::Ordering::SeqCst);
        if !self.prev_sync_done && sync_now_done {
            self.friends_full = crate::commands::p2p_utils::load_friends();
        }
        self.prev_sync_done = sync_now_done;

        // Overlay dialogs render on top of any screen
        if self.incoming_sync.is_some() {
            self.show_incoming_sync_dialog(ctx);
        }

        match self.screen {
            Screen::Home => self.show_home(ctx),
            Screen::Login => self.show_login(ctx),
            Screen::VaultExplorer => self.show_vault_explorer(ctx),
            Screen::CreateVault => self.show_create_vault(ctx),
            Screen::P2PDialog => self.show_p2p_dialog(ctx),
        }
    }
}

pub fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    start_daemon_and_listener();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Atom Vault")
            .with_inner_size([800.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Atom Vault",
        options,
        Box::new(|cc| {
            // Force consistent dark theme regardless of system setting.
            cc.egui_ctx.set_visuals(egui::Visuals::dark());

            // Larger, more readable typography.
            let mut style = (*cc.egui_ctx.style()).clone();
            use egui::{FontFamily::Proportional, FontId, TextStyle::*};
            style.text_styles = [
                (Heading, FontId::new(22.0, Proportional)),
                (Body, FontId::new(14.5, Proportional)),
                (Monospace, FontId::new(13.0, egui::FontFamily::Monospace)),
                (Button, FontId::new(14.0, Proportional)),
                (Small, FontId::new(11.5, Proportional)),
            ]
            .into();
            style.spacing.button_padding = egui::vec2(12.0, 7.0);
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            cc.egui_ctx.set_style(style);

            Ok(Box::new(AtomVaultApp::new()))
        }),
    )?;

    Ok(())
}
