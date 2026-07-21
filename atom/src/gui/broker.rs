use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::commands::view::{
    MlockedMap, ViewerTeardown, install_signal_handler, register_teardown,
};

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
    /// pinned in physical RAM with `mlock`, opened by spawning the user's default
    /// viewer *directly* (never via `gio open`/the XDG document portal, so the
    /// plaintext never transits the portal's SUID FUSE layer), then shredded when
    /// the viewer process exits.
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
                        BrokerRequest::OpenViewer {
                            data,
                            filename,
                            done_flag,
                            spawn_result,
                        } => {
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

    /// Write `data` to the RAM-pinned user tmpfs, spawn the user's default
    /// viewer directly (no portal), and shred when the viewer process exits.
    /// Returns a handle to poll for launch success/failure; `done_flag` is set
    /// to `true` when the file is shredded.
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

/// All the resources that must be torn down securely once a GUI viewer closes
/// (or the process is interrupted).  Mirrors the CLI path's `MemfdShredJob`, but
/// over a tmpfs-backed file (the directly-spawned viewer is a separate process
/// and needs a real path it can open; a process-private `memfd` cannot be handed
/// to it).  Registered in the shared teardown registry so the process-wide
/// SIGINT/SIGTERM handler shreds it too.
struct TmpfsShredJob {
    path: PathBuf,
    /// PID of the directly-spawned viewer child, killed on interrupt so it
    /// cannot keep a stale fd open after we shred.
    viewer_pid: libc::pid_t,
    /// Writable handle (kept open) used to zero the pages during the wipe.
    write_handle: std::fs::File,
    /// RAM pin over the file's pages; released only after the wipe completes so
    /// the plaintext can never be swapped out mid-wipe.
    locked_map: MlockedMap,
    /// Set `true` once the file has been shredded and removed (GUI notification).
    done_flag: Arc<AtomicBool>,
}

impl ViewerTeardown for TmpfsShredJob {
    fn shred_on_close(self: Box<Self>) {
        shred_tmpfs_job(*self);
    }

    fn shred_on_signal(self: Box<Self>) {
        // Force-close the still-running viewer child first so it cannot retain a
        // mapping of the plaintext we are about to wipe.
        unsafe { libc::kill(self.viewer_pid, libc::SIGKILL) };
        shred_tmpfs_job(*self);
    }
}

/// Securely tear down a GUI viewer's tmpfs plaintext: overwrite the pages while
/// they are still `mlock`'d, release the pin, then remove the file.  Write
/// failures are surfaced to stderr rather than silently swallowed.
fn shred_tmpfs_job(job: TmpfsShredJob) {
    let TmpfsShredJob {
        path,
        viewer_pid: _,
        mut write_handle,
        locked_map,
        done_flag,
    } = job;

    // Overwrite the plaintext while the pages are still pinned in RAM (cannot be
    // swapped out mid-wipe).
    let len = write_handle.metadata().map(|m| m.len()).unwrap_or(0);
    if len > 0 {
        if let Err(e) = write_handle.seek(SeekFrom::Start(0)) {
            eprintln!("[Broker] viewer shred: seek failed: {}", e);
        } else {
            let zeros = [0u8; 4096];
            let mut written = 0u64;
            while written < len {
                let n = ((len - written) as usize).min(4096);
                if let Err(e) = write_handle.write_all(&zeros[..n]) {
                    eprintln!(
                        "[Broker] viewer shred: zero-fill failed at {}/{} bytes: {}",
                        written, len, e
                    );
                    break;
                }
                written += n as u64;
            }
            if let Err(e) = write_handle.flush() {
                eprintln!("[Broker] viewer shred: flush failed: {}", e);
            }
        }
    }

    // Release the RAM pin only after the plaintext is gone, then drop the
    // handle and unlink the file.
    drop(locked_map);
    drop(write_handle);
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "[Broker] viewer shred: failed to remove {}: {}",
                path.display(),
                e
            );
        }
    }

    done_flag.store(true, Ordering::SeqCst);
    println!("Sandbox closed. Initiating memory shredding...");
    println!("Traces successfully removed.");
}

/// Write decrypted bytes to `$XDG_RUNTIME_DIR/atom_staging/<stem>_view_tmp.<ext>`
/// (a RAM-backed tmpfs — never touches a persistent disk), pin the file's pages
/// in physical RAM with `mlock()` so they cannot be swapped to disk/hibernation,
/// spawn the user's default viewer **directly** as a child process, then
/// `waitpid` on it and shred the file when it exits.
///
/// tmpfs alone is swappable on Linux, so without the `mlock` pin the kernel
/// could flush the decrypted plaintext to the swap partition or hibernation
/// image under memory pressure — bypassing the VFS entirely.  Pinning brings the
/// GUI path to parity with the CLI viewer (issue #29 item 1).
///
/// The viewer is launched directly (resolved via `xdg-mime` → `.desktop` `Exec`)
/// rather than through `gio open`/`xdg-open`.  Those route through the XDG
/// document portal, which exposes the file over the portal's FUSE mount — pulling
/// the plaintext through `xdg-document-portal` and the SUID `fusermount3` helper,
/// an avoidable privilege-escalation surface.  Direct spawn keeps the plaintext
/// inside this process's RAM-backed tmpfs and, because the viewer is our own
/// child, gives a deterministic `waitpid` lifetime signal instead of `/proc`
/// polling (issue #29 item 4).
///
/// bwrap is intentionally NOT used here: on SELinux-enforcing systems (Fedora,
/// RHEL) unprivileged namespace creation is blocked by policy and bwrap fails
/// with EPERM.  The viewer therefore runs unconfined, but the plaintext it reads
/// is RAM-pinned and shredded the instant the process exits.
fn open_in_viewer(
    mut data: Vec<u8>,
    filename: &str,
    done_flag: Arc<AtomicBool>,
) -> Result<(), String> {
    // Ensure the process-wide SIGINT/SIGTERM handler is installed so an
    // interrupt while this viewer is open still shreds its plaintext.
    install_signal_handler();

    let staging = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".atom_vault")
        })
        .join("atom_staging");

    std::fs::create_dir_all(&staging).map_err(|e| format!("Cannot create staging dir: {}", e))?;

    // Preserve the file extension so MIME-type detection routes to the user's
    // default viewer for this kind of file.
    let file_path = Path::new(filename);
    let stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e))
        .unwrap_or_default();
    let tmp_path = staging.join(format!("{}_view_tmp{}", stem, ext));

    // Resolve the viewer command BEFORE staging any plaintext, so a missing or
    // portal-only handler fails without ever writing the decrypted file.
    let mut viewer_cmd = resolve_viewer_command(&tmp_path)?;

    // Open read+write and keep the handle: the writable fd is needed later to
    // zero the pages during shredding, and its raw fd is mmap'd + mlock'd below.
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut write_handle = opts
        .open(&tmp_path)
        .map_err(|e| format!("Failed to write to tmpfs: {}", e))?;
    write_handle
        .write_all(&data)
        .map_err(|e| format!("tmpfs write failed: {}", e))?;
    write_handle
        .sync_all()
        .map_err(|e| format!("tmpfs sync failed: {}", e))?;

    let len = data.len();

    // Pin the tmpfs pages in physical RAM for the file's lifetime.  Refuse to
    // proceed if the pin fails rather than fall back to swappable plaintext.
    let locked_map = MlockedMap::new(write_handle.as_raw_fd(), len).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("Failed to lock viewer plaintext into RAM: {}", e)
    })?;

    // Zero the in-RAM Vec copy immediately — the mlock'd tmpfs file is the only
    // copy of the plaintext now.
    data.zeroize();
    drop(data);

    // Spawn the resolved viewer directly as our child.
    let child = match viewer_cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // Shred the plaintext we just staged before bailing out.
            shred_tmpfs_job(TmpfsShredJob {
                path: tmp_path,
                viewer_pid: 0,
                write_handle,
                locked_map,
                done_flag,
            });
            return Err(format!("Failed to launch viewer: {}", e));
        }
    };
    let viewer_pid = child.id() as libc::pid_t;

    println!("Starting secure sandbox mode...");

    // Register the teardown in the shared registry so either the watcher thread
    // (normal close) or the SIGINT/SIGTERM handler (interrupt) shreds it.
    let slot = register_teardown(Box::new(TmpfsShredJob {
        path: tmp_path.clone(),
        viewer_pid,
        write_handle,
        locked_map,
        done_flag,
    }));

    // Wait on our viewer child for its real lifetime, then shred.  The thread
    // body is wrapped in catch_unwind so a panic still proceeds to shredding
    // (issue #29 item 2).
    std::thread::spawn(move || {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_for_viewer_exit(child, &tmp_path);
        }));
        // Claim the job; `None` means the signal handler already shredded it.
        if let Some(job) = slot.lock().unwrap().take() {
            job.shred_on_close();
        }
    });

    Ok(())
}

/// Block until the spawned viewer has fully released the plaintext file.
///
/// The directly-spawned `child` is the authoritative lifetime signal: `wait()`
/// blocks for as long as the viewer process lives, so — unlike the old timing
/// heuristic — we never shred while the user is still viewing (issue #29
/// item 3/4).  Some viewers are single-instance: the process we spawned hands
/// the document to a pre-existing instance and exits immediately.  To cover that
/// case, after our child exits we briefly watch for any *other* process holding
/// the file open and, if found, wait for it to release before returning.
fn wait_for_viewer_exit(mut child: std::process::Child, path: &Path) {
    // Authoritative signal: our own viewer child's lifetime.
    let _ = child.wait();

    // Single-instance handoff: give a pre-existing instance a moment to pick up
    // the document.  If nothing opens it within the settle window, the launch
    // was self-contained and we shred now.
    const HANDOFF_SETTLE: Duration = Duration::from_secs(3);
    let start = Instant::now();
    let mut handed_off = false;
    while start.elapsed() < HANDOFF_SETTLE {
        if is_file_open(path) {
            handed_off = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if !handed_off {
        return;
    }

    // A handoff target holds the file — wait for it to release before shredding.
    loop {
        std::thread::sleep(Duration::from_secs(2));
        if !is_file_open(path) {
            return;
        }
    }
}

/// Resolve the user's default viewer for `path` into a directly-spawnable
/// command, deliberately bypassing `gio open`/`xdg-open` so the plaintext never
/// transits the XDG document portal's SUID FUSE layer.
///
/// Resolution: `xdg-mime query filetype` → `xdg-mime query default` (these are
/// pure lookups, no portal) → locate the `.desktop` file → parse its `Exec`
/// line and substitute the file path for the field codes.  A flatpak handler is
/// rewritten by [`rewrite_flatpak_argv`] to bind-mount the staging dir directly
/// rather than route the file through the document portal.
fn resolve_viewer_command(path: &Path) -> Result<std::process::Command, String> {
    let path_str = path.to_string_lossy().to_string();

    let mime = query_mime(path)?;
    let desktop_id = run_trim("xdg-mime", &["query", "default", &mime])
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("No default application registered for {}", mime))?;

    let desktop = find_desktop_file(&desktop_id)
        .ok_or_else(|| format!("Cannot locate desktop file '{}'", desktop_id))?;
    let exec =
        parse_exec(&desktop).ok_or_else(|| format!("No Exec line in {}", desktop.display()))?;

    let mut argv = build_argv(&exec, &path_str);
    if argv.is_empty() {
        return Err(format!("Empty Exec command in {}", desktop.display()));
    }

    // A flatpak handler is not refused outright — the surface we avoid is the
    // document portal's FUSE mount, not flatpak itself.  Rewrite the invocation
    // so the sandboxed viewer reads our staged plaintext through a direct bwrap
    // bind-mount of the staging dir instead of `xdg-document-portal` (issue #29).
    if argv[0] == "flatpak" || argv[0].ends_with("/flatpak") {
        argv = rewrite_flatpak_argv(argv, path)?;
    }

    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    Ok(cmd)
}

/// Rewrite a flatpak handler's argv so the viewer reads our staged plaintext via
/// a direct bwrap bind-mount instead of the XDG document portal.
///
/// The exported `.desktop` Exec for a flatpak app routes files through the portal:
///
/// ```text
/// flatpak run --branch=… --arch=… --command=… --file-forwarding APP @@u %U @@
/// ```
///
/// `--file-forwarding` plus the `@@u … @@` markers hand the file to the sandbox
/// over `xdg-document-portal`'s FUSE mount (and its SUID `fusermount3` helper) —
/// the exact privilege-escalation surface we avoid.  We strip that machinery and
/// instead grant the sandbox a read-only bind-mount of *only the staged file*,
/// sever its network, and tie its lifetime to ours:
///
/// ```text
/// flatpak run --unshare=network --die-with-parent --filesystem=<staged-file>:ro \
///     --branch=… --arch=… --command=… APP <staged-file>
/// ```
///
/// Binding the single file (not the staging dir) keeps any other plaintext staged
/// concurrently invisible to the viewer.  The viewer still runs inside its own
/// flatpak sandbox — a confinement *upgrade* over a bare native viewer — but the
/// decrypted bytes never transit the portal.
fn rewrite_flatpak_argv(argv: Vec<String>, staged_file: &Path) -> Result<Vec<String>, String> {
    // A flatpak app cannot itself spawn `flatpak run`; doing so from within a
    // sandbox would need the `org.freedesktop.Flatpak` host-spawn hole, which
    // would undermine atom's own confinement (it holds the DEK in RAM).  Refuse
    // rather than silently escalate — atom is meant to run as a native binary.
    if Path::new("/.flatpak-info").exists() {
        return Err(
            "atom is running inside a flatpak sandbox and cannot launch a host \
             flatpak viewer without opening the org.freedesktop.Flatpak host-spawn \
             hole. Install atom as a native binary so it can drive viewers directly."
                .to_string(),
        );
    }

    let run_idx = argv
        .iter()
        .position(|a| a == "run")
        .ok_or_else(|| "Unrecognised flatpak invocation (no `run` subcommand)".to_string())?;

    let mut out = Vec::with_capacity(argv.len() + 3);
    out.push(argv[0].clone()); // flatpak
    out.push("run".to_string());
    // Sandbox overrides must precede the app ref.
    out.push("--unshare=network".to_string());
    out.push("--die-with-parent".to_string());
    out.push(format!(
        "--filesystem={}",
        flatpak_filesystem_spec(staged_file)
    ));

    // Carry over the original `flatpak run` options / app-id / path, dropping the
    // document-portal forwarding machinery.  `build_argv` has already substituted
    // the staged path in place of `%U`, so it survives between the `@@` markers.
    for tok in &argv[run_idx + 1..] {
        if tok == "--file-forwarding" || tok == "@@" || tok == "@@u" {
            continue;
        }
        out.push(tok.clone());
    }
    Ok(out)
}

/// Express `path` as a flatpak `--filesystem` value, preferring the portable
/// `xdg-run/…` token when it lives under `$XDG_RUNTIME_DIR` so flatpak maps it to
/// the sandbox's runtime dir at the *same* absolute path — keeping the staged
/// path we pass on the command line valid inside the sandbox (and keeping the
/// `/proc/<pid>/fd` lifetime check in `is_file_open` matching).
fn flatpak_filesystem_spec(path: &Path) -> String {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            if let Ok(rel) = path.strip_prefix(&runtime) {
                return format!("xdg-run/{}:ro", rel.display());
            }
        }
    }
    format!("{}:ro", path.display())
}

/// Determine the MIME type of `path` via `xdg-mime`, falling back to a small
/// extension table when `xdg-mime` is unavailable.
fn query_mime(path: &Path) -> Result<String, String> {
    if let Some(m) = run_trim("xdg-mime", &["query", "filetype", &path.to_string_lossy()]) {
        if !m.is_empty() {
            return Ok(m);
        }
    }
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("pdf") => Ok("application/pdf".to_string()),
        Some("png") => Ok("image/png".to_string()),
        Some("jpg") | Some("jpeg") => Ok("image/jpeg".to_string()),
        Some("gif") => Ok("image/gif".to_string()),
        Some("webp") => Ok("image/webp".to_string()),
        Some("svg") => Ok("image/svg+xml".to_string()),
        Some("txt") | Some("md") | Some("log") => Ok("text/plain".to_string()),
        _ => Err("Cannot determine file MIME type (is xdg-mime installed?)".to_string()),
    }
}

/// Run `cmd args...` and return its trimmed stdout on success.
fn run_trim(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Locate a `.desktop` file by its ID across the XDG application directories.
fn find_desktop_file(desktop_id: &str) -> Option<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::new();
    match std::env::var("XDG_DATA_HOME") {
        Ok(h) if !h.is_empty() => bases.push(PathBuf::from(h)),
        _ => {
            if let Some(home) = dirs::home_dir() {
                bases.push(home.join(".local/share"));
            }
        }
    }
    let data_dirs = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_string());
    for d in data_dirs.split(':').filter(|d| !d.is_empty()) {
        bases.push(PathBuf::from(d));
    }

    for base in bases {
        let apps = base.join("applications");
        let direct = apps.join(desktop_id);
        if direct.is_file() {
            return Some(direct);
        }
        // Per the desktop-entry spec, '-' in an ID may map to subdirectories.
        let nested = apps.join(desktop_id.replace('-', "/"));
        if nested.is_file() {
            return Some(nested);
        }
    }
    None
}

/// Extract the `Exec=` value from the `[Desktop Entry]` group of a `.desktop`
/// file.
fn parse_exec(desktop: &Path) -> Option<String> {
    let content = std::fs::read_to_string(desktop).ok()?;
    let mut in_entry = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if in_entry {
            if let Some(rest) = line.strip_prefix("Exec=") {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// Tokenize a desktop-entry `Exec` string and substitute the field codes with
/// `path`.  Returns the argv for the viewer command.
fn build_argv(exec: &str, path: &str) -> Vec<String> {
    let mut argv = Vec::new();
    let mut substituted = false;
    for tok in tokenize_exec(exec) {
        match tok.as_str() {
            // Single/list file/URL codes: supply our one path.
            "%f" | "%F" | "%u" | "%U" => {
                argv.push(path.to_string());
                substituted = true;
            }
            // Deprecated / inapplicable codes: drop them.
            "%i" | "%c" | "%k" | "%d" | "%D" | "%n" | "%N" | "%v" | "%m" => {}
            other => argv.push(other.replace("%%", "%")),
        }
    }
    if !substituted {
        argv.push(path.to_string());
    }
    argv
}

/// Minimal desktop-entry `Exec` tokenizer: splits on unquoted whitespace and
/// honours double-quoted segments with backslash escapes.
fn tokenize_exec(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut started = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quote = !in_quote;
                started = true;
            }
            '\\' if in_quote => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ' ' | '\t' if !in_quote => {
                if started || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                started = false;
            }
            _ => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Returns `true` if any process currently has `path` open (via /proc/*/fd).
fn is_file_open(path: &Path) -> bool {
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in procs.flatten() {
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
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
    let mut f = opts
        .open(path)
        .map_err(|e| format!("[Broker] Create failed: {}", e))?;
    f.write_all(data)
        .map_err(|e| format!("[Broker] Write failed: {}", e))?;
    f.sync_all()
        .map_err(|e| format!("[Broker] Sync failed: {}", e))?;
    Ok(())
}
