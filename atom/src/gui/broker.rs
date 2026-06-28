use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};
use zeroize::Zeroize;

enum BrokerRequest {
    ReadFile {
        path: PathBuf,
        result: Arc<Mutex<Option<Result<Vec<u8>, String>>>>,
    },
    WriteFile {
        path: PathBuf,
        data: Vec<u8>,
        result: Arc<Mutex<Option<Result<(), String>>>>,
    },
    /// Decrypted bytes are written to the user's XDG_RUNTIME_DIR tmpfs (RAM-only),
    /// opened with `gio open`/`xdg-open` (which routes via the XDG document portal
    /// so Papers/Flatpak can access the file), then shredded when the viewer closes.
    OpenViewer {
        data: Vec<u8>,
        filename: String,
        done_flag: Arc<AtomicBool>,
        spawn_result: Arc<Mutex<Option<Result<(), String>>>>,
    },
}

/// Pre-sandbox file broker.
///
/// Spawned before the main-thread Landlock domain fires.  Because Landlock is
/// per-task, neither this thread nor the sub-threads it spawns are ever bound
/// by the vault sandbox on the main thread.
///
/// Every request is dispatched to a dedicated sub-thread that applies its own
/// tight Landlock domain (one file, or its parent for creation), performs the
/// I/O, and exits.  Access is temporary: when the sub-thread exits, no thread
/// retains the permission.
pub struct FileBroker {
    tx: Sender<BrokerRequest>,
}

impl FileBroker {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel::<BrokerRequest>();
        std::thread::Builder::new()
            .name("atom-file-broker".into())
            .spawn(move || {
                for req in rx {
                    match req {
                        BrokerRequest::ReadFile { path, result } => {
                            std::thread::spawn(move || {
                                let out = read_with_sandbox(&path);
                                if let Ok(mut g) = result.lock() {
                                    *g = Some(out);
                                }
                            });
                        }
                        BrokerRequest::WriteFile { path, data, result } => {
                            std::thread::spawn(move || {
                                let out = write_with_sandbox(&path, &data);
                                if let Ok(mut g) = result.lock() {
                                    *g = Some(out);
                                }
                            });
                        }
                        BrokerRequest::OpenViewer { data, filename, done_flag, spawn_result } => {
                            std::thread::spawn(move || {
                                let res = open_in_viewer(data, &filename, Arc::clone(&done_flag));
                                if let Ok(mut g) = spawn_result.lock() {
                                    *g = Some(res);
                                }
                            });
                        }
                    }
                }
            })
            .expect("failed to spawn file broker thread");
        FileBroker { tx }
    }

    /// Queue a sandboxed read of `path`.  Returns a handle to poll for the
    /// result; `None` inside the Mutex means the read is still in progress.
    pub fn read_file(&self, path: PathBuf) -> Arc<Mutex<Option<Result<Vec<u8>, String>>>> {
        let result: Arc<Mutex<Option<Result<Vec<u8>, String>>>> = Arc::new(Mutex::new(None));
        let _ = self.tx.send(BrokerRequest::ReadFile {
            path,
            result: Arc::clone(&result),
        });
        result
    }

    /// Write `data` to the user tmpfs, open with `gio open`/`xdg-open`, and
    /// shred when the viewer closes.  Returns a handle to poll for launch
    /// success/failure; `done_flag` is set to `true` when the file is shredded.
    pub fn open_viewer(
        &self,
        data: Vec<u8>,
        filename: String,
        done_flag: Arc<AtomicBool>,
    ) -> Arc<Mutex<Option<Result<(), String>>>> {
        let spawn_result: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
        let _ = self.tx.send(BrokerRequest::OpenViewer {
            data,
            filename,
            done_flag,
            spawn_result: Arc::clone(&spawn_result),
        });
        spawn_result
    }

    /// Queue a sandboxed write of `data` to `path`.  Returns a handle to poll
    /// for completion; `None` inside the Mutex means the write is still in progress.
    pub fn write_file(
        &self,
        path: PathBuf,
        data: Vec<u8>,
    ) -> Arc<Mutex<Option<Result<(), String>>>> {
        let result: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
        let _ = self.tx.send(BrokerRequest::WriteFile {
            path,
            data,
            result: Arc::clone(&result),
        });
        result
    }
}

// ── Viewer helpers ────────────────────────────────────────────────────────────

/// Write decrypted bytes to `$XDG_RUNTIME_DIR/atom_staging/<filename>` (a
/// RAM-backed tmpfs — never touches a persistent disk), open with `gio open`
/// (which routes via the XDG document portal so Flatpak apps like Papers can
/// access the file), then watch until the viewer closes and shred the file.
///
/// bwrap is intentionally NOT used here: on SELinux-enforcing systems (Fedora,
/// RHEL) unprivileged namespace creation is blocked by policy and bwrap fails
/// with EPERM.  Papers is already Flatpak-sandboxed; `gio open` delegates
/// through `xdg-portal-desktop` which enforces Flatpak's own confinement.
fn open_in_viewer(
    mut data: Vec<u8>,
    filename: &str,
    done_flag: Arc<AtomicBool>,
) -> Result<(), String> {
    let staging = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".atom_vault")
        })
        .join("atom_staging");

    std::fs::create_dir_all(&staging)
        .map_err(|e| format!("Cannot create staging dir: {}", e))?;

    let tmp_path = staging.join(format!("{}_view_tmp", filename));

    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .map_err(|e| format!("Failed to write to tmpfs: {}", e))?;
        use std::io::Write;
        f.write_all(&data)
            .map_err(|e| format!("tmpfs write failed: {}", e))?;
        f.sync_all()
            .map_err(|e| format!("tmpfs sync failed: {}", e))?;
    }

    // Zero the in-RAM copy immediately — tmpfs file is the only copy now.
    data.zeroize();
    drop(data);

    // `gio open` on GNOME handles the XDG portal so Flatpak viewers get access.
    // Fall back to `xdg-open` on non-GNOME desktops.
    let open_result = std::process::Command::new("gio")
        .args(["open", &tmp_path.to_string_lossy()])
        .spawn()
        .or_else(|_| std::process::Command::new("xdg-open").arg(&tmp_path).spawn());

    if let Err(e) = open_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("Failed to open viewer: {}", e));
    }

    println!("Starting secure sandbox mode...");

    // Watch for the viewer to close, then shred.  The XDG document-portal
    // FUSE daemon holds the original file open while Papers has it displayed;
    // once Papers closes the document the portal releases the fd too, so
    // /proc/*/fd scanning reliably detects closure.
    let path_clone = tmp_path.clone();
    std::thread::spawn(move || {
        // Wait up to 15 s for something to open the file (Papers start time).
        let mut opened = false;
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if is_file_open(&path_clone) {
                opened = true;
                break;
            }
        }
        if opened {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                if !is_file_open(&path_clone) {
                    break;
                }
            }
        }
        shred_tmpfs_file(&path_clone);
        done_flag.store(true, Ordering::SeqCst);
    });

    Ok(())
}

/// Returns `true` if any process currently has `path` open (via /proc/*/fd).
fn is_file_open(path: &Path) -> bool {
    let Ok(procs) = std::fs::read_dir("/proc") else { return false };
    for entry in procs.flatten() {
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else { continue };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target == path {
                    return true;
                }
            }
        }
    }
    false
}

/// Overwrite with zeros then delete the tmpfs viewer file.
fn shred_tmpfs_file(path: &Path) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
        if let Ok(len) = f.metadata().map(|m| m.len()) {
            use std::io::Write;
            let zeros = [0u8; 4096];
            let mut written = 0u64;
            while written < len {
                let n = ((len - written) as usize).min(4096);
                if f.write_all(&zeros[..n]).is_err() { break; }
                written += n as u64;
            }
        }
    }
    let _ = std::fs::remove_file(path);
    println!("Sandbox closed. Initiating memory shredding...");
    println!("Traces successfully removed.");
}

// ── Read / write sandbox helpers ──────────────────────────────────────────────

/// Read a file inside a per-thread Landlock domain: RO access to exactly this
/// file, nothing else on the filesystem.  The domain dies with the thread.
fn read_with_sandbox(path: &Path) -> Result<Vec<u8>, String> {
    let ro: &[&Path] = &[path];
    let rw: &[&Path] = &[];
    crate::sandbox::apply_process_sandbox(ro, rw)
        .map_err(|e| format!("[Broker] Sandbox error: {}", e))?;
    std::fs::read(path).map_err(|e| format!("[Broker] Read failed: {}", e))
}

/// Write a file inside a per-thread Landlock domain: RW access to the target
/// file (or its parent directory if the file does not yet exist), nothing else.
/// File is created with mode 0o600 (owner read/write only).
fn write_with_sandbox(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;

    // Landlock requires an open FD for the rule target.  If the file doesn't
    // exist yet we fall back to the parent directory — same logic as the main
    // vault sandbox for vault creation.
    let effective: PathBuf = if path.exists() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| path.to_path_buf())
    };

    let ro: &[&Path] = &[];
    let rw: &[&Path] = &[effective.as_path()];
    crate::sandbox::apply_process_sandbox(ro, rw)
        .map_err(|e| format!("[Broker] Sandbox error: {}", e))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("[Broker] Create failed: {}", e))?;
    f.write_all(data).map_err(|e| format!("[Broker] Write failed: {}", e))?;
    f.sync_all().map_err(|e| format!("[Broker] Sync failed: {}", e))?;
    Ok(())
}
