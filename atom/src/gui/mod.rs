use eframe::egui;
use egui::Context;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::commands::daemon::{DaemonEvent, SyncResponse};

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

struct ExportOverwriteState {
    vfs_name: String,
    target_path: String,
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

    // File dialog results — written by bg threads, polled every frame
    pending_vault_path: Arc<Mutex<Option<PathBuf>>>,
    pending_import_path: Arc<Mutex<Option<PathBuf>>>,
    pending_folder_path: Arc<Mutex<Option<PathBuf>>>,

    // Open vault
    vault_session: Option<VaultSession>,
    current_vault_path: String,
    explorer_status: String,
    viewer_done: Option<(Arc<AtomicBool>, String)>,

    // Create vault screen
    create_folder_path: Option<PathBuf>,
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
    export_overwrite: Option<ExportOverwriteState>,
}

impl AtomVaultApp {
    fn new() -> Self {
        Self {
            screen: Screen::Login,
            selected_vault_path: None,
            password: String::new(),
            login_status: "Please select or create a vault to begin.".to_string(),
            pending_vault_path: Arc::new(Mutex::new(None)),
            pending_import_path: Arc::new(Mutex::new(None)),
            pending_folder_path: Arc::new(Mutex::new(None)),
            vault_session: None,
            current_vault_path: String::new(),
            explorer_status: String::new(),
            viewer_done: None,
            create_folder_path: None,
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
            export_overwrite: None,
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
            self.selected_vault_path = Some(path);
            self.login_status = "Vault selected. Enter master password.".to_string();
        }
        if let Some(path) = self.pending_folder_path.lock().ok().and_then(|mut g| g.take()) {
            self.create_folder_path = Some(path);
            self.screen = Screen::CreateVault;
        }
        if let Some(path) = self.pending_import_path.lock().ok().and_then(|mut g| g.take()) {
            self.do_import(path);
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
    // The daemon thread is spawned first so it can finish any crypto
    // initialisation (identity key derivation, Arti bootstrap) before the
    // Landlock domain is established.  Landlock domains are per-task: the
    // daemon thread, already running, is unaffected by restrict_self() below.
    // Only the calling (main) thread and all threads it creates after this
    // point will be bound by the filesystem restrictions.
    start_daemon_and_listener();

    // ── Inner Landlock sandbox ───────────────────────────────────────────────
    //
    // Allowed read-only paths:
    //   /usr  — egui/eframe runtime libraries, system fonts, bwrap binary
    //   /etc  — locale, fontconfig rules, TLS certificate store
    //
    // Allowed read-write paths:
    //   $XDG_RUNTIME_DIR — Wayland socket, D-Bus socket, portal IPC, and the
    //                       document-portal directory ($XDG_RUNTIME_DIR/doc/)
    //                       where the XDG File Chooser Portal deposits the
    //                       user's chosen vault file when running under Flatpak.
    //
    // Home directory is intentionally absent: when deployed as a Flatpak the
    // outer cage already hides /home, and vault files arrive through the portal
    // path inside $XDG_RUNTIME_DIR.  If Landlock is not supported by the
    // kernel, log_sandbox_status() reports it and the app continues normally.
    {
        let xdg_runtime = std::env::var("XDG_RUNTIME_DIR")
            .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));

        // /sys is needed by Mesa's drmGetDevices() which reads
        // /sys/dev/char/<major>:<minor>/device/driver to identify the GPU
        // before opening any /dev/dri node.  Without it Mesa cannot retrieve
        // device information and the entire EGL probe chain fails (fd -1).
        // /dev/dri is the DRM render-node directory eframe opens for rendering.
        let ro: &[&Path] = &[Path::new("/usr"), Path::new("/etc"), Path::new("/sys")];
        let rw_runtime = Path::new(xdg_runtime.as_str());
        let rw: &[&Path] = &[rw_runtime, Path::new("/dev/dri")];

        let status = crate::sandbox::apply_process_sandbox(ro, rw)?;
        crate::sandbox::log_sandbox_status(status);
    }

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
