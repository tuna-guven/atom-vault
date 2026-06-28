use eframe::egui;
use egui::Context;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::commands::daemon::{DaemonEvent, SyncResponse};

mod broker;
mod explorer;
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

enum FileAction {
    Open(String),
    Export(String),
    Rename(String),
    Delete(String),
}

// ── App state ─────────────────────────────────────────────────────────────────

struct AtomVaultApp {
    screen: Screen,

    // Login screen
    selected_vault_path: Option<PathBuf>,
    password: String,
    login_status: String,

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

    // Overlay dialogs
    incoming_sync: Option<IncomingSyncState>,
    rename_dialog: Option<RenameState>,
}

impl AtomVaultApp {
    fn new() -> Self {
        Self {
            screen: Screen::Login,
            selected_vault_path: None,
            password: String::new(),
            login_status: "Please select or create a vault to begin.".to_string(),
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
                        .join(format!("Downloads/{}/{}", sender_nick, filename))
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
        if let Some(path) = self.pending_vault_path.lock().ok().and_then(|mut g| g.take()) {
            // The vault path is now known.  Apply the Landlock sandbox with
            // exactly this file before any unlock attempt so the kernel denies
            // access to every other host path for the rest of the process.
            crate::sandbox::apply_gui_vault_sandbox(&path);
            self.selected_vault_path = Some(path);
            self.login_status = "Vault selected. Enter master password.".to_string();
        }
        if let Some(full_path) = self.pending_create_path.lock().ok().and_then(|mut g| g.take()) {
            self.do_create_vault_at_path(full_path);
        }
        if let Some(path) = self.pending_import_path.lock().ok().and_then(|mut g| g.take()) {
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
        if let Some(path) = self.pending_export_path.lock().ok().and_then(|mut g| g.take()) {
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

        // Overlay dialogs render on top of any screen
        if self.incoming_sync.is_some() {
            self.show_incoming_sync_dialog(ctx);
        }

        match self.screen {
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
            .with_inner_size([480.0, 420.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Atom Vault",
        options,
        Box::new(|_cc| Ok(Box::new(AtomVaultApp::new()))),
    )?;

    Ok(())
}
