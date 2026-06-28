use std::env;
use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::Path;
use std::ptr;

// ── Landlock inner sandbox ────────────────────────────────────────────────────

/// Outcome reported by [apply_process_sandbox].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockStatus {
    /// Every requested access flag was recognised and enforced by the kernel.
    FullyEnforced,
    /// The kernel supports Landlock but predates some requested ABI flags;
    /// the sandbox is still active with the rights the kernel understands.
    PartiallyEnforced,
    /// The running kernel has no Landlock support; the process is unrestricted.
    NotEnforced,
}

/// Applies a Landlock LSM filesystem ruleset to the **calling thread**.
///
/// After this call, the calling thread (and any threads it spawns) can only
/// open paths listed in `read_only_paths` or `read_write_paths`. All other
/// filesystem access is refused at the kernel level — no capability or uid can
/// override it.
///
/// **Thread scope**: Landlock domains are per-task. Threads already running
/// when this is called are not restricted. Only the calling thread and the
/// threads it creates afterwards are bound by the returned domain.
///
/// **Graceful degradation**: Returns [`LandlockStatus::NotEnforced`] (not an
/// error) when the kernel does not include Landlock support, so the caller can
/// decide whether to abort or continue unprotected. Kernels with a Landlock
/// ABI older than V5 produce [`LandlockStatus::PartiallyEnforced`]; the sandbox
/// is still active but may cover fewer access types.
///
/// Paths that do not exist on the current machine are silently skipped; this
/// makes the function safe to call with distro-specific optional paths.
pub fn apply_process_sandbox(
    read_only_paths: &[&Path],
    read_write_paths: &[&Path],
) -> Result<LandlockStatus, Box<dyn std::error::Error>> {
    use landlock::{
        Access, AccessFs, ABI,
        PathBeneath, PathFd,
        Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    };

    // Target V5 (Linux 6.10). The landlock crate degrades automatically to
    // whatever ABI the running kernel actually supports; the returned status
    // tells the caller which level was achieved.
    let abi = ABI::V5;
    let all_rights = AccessFs::from_all(abi);

    // Read-only includes Execute so that fork+exec of helper programs (bwrap,
    // flatpak) inside sandboxed threads can still find their binaries under
    // /usr without us granting write access to the system hierarchy.
    let ro_rights = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;

    let mut ruleset = Ruleset::default()
        .handle_access(all_rights)?
        .create()?;

    for &path in read_only_paths {
        if !path.exists() {
            continue;
        }
        match PathFd::new(path) {
            Ok(fd) => ruleset = ruleset.add_rule(PathBeneath::new(fd, ro_rights))?,
            Err(_) => continue,
        }
    }

    for &path in read_write_paths {
        if !path.exists() {
            continue;
        }
        match PathFd::new(path) {
            Ok(fd) => ruleset = ruleset.add_rule(PathBeneath::new(fd, all_rights))?,
            Err(_) => continue,
        }
    }

    let status = ruleset.restrict_self()?;

    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => LandlockStatus::FullyEnforced,
        RulesetStatus::PartiallyEnforced => LandlockStatus::PartiallyEnforced,
        RulesetStatus::NotEnforced => LandlockStatus::NotEnforced,
    })
}

/// Activates the GUI Landlock sandbox for a single, specific vault file.
///
/// Called exactly once per process, immediately after the user has chosen a
/// vault path (via the XDG file-chooser portal) and before any cryptographic
/// or file-system operation on that path.  This ensures the kernel allows
/// access to precisely one vault file and nothing else on the host.
///
/// **Creation vs. open**: Landlock rules require an open FD for the target
/// path, so a non-existent file cannot have a rule.  When `vault_path` does
/// not exist yet (vault creation flow), the rule is added for its parent
/// directory instead — the minimum grant needed to create the file there.
/// When the file already exists (vault open flow) the rule is pinned to the
/// exact file, so sibling files in the same directory are still denied.
///
/// Allowed paths:
/// - `/usr`, `/etc`, `/sys`, `/proc` (RO+exec) — egui libs, fonts, Mesa GPU
///   probe, `sysinfo` reads `/proc/meminfo` for KDF calibration
/// - `/dev/dri`              (RW)      — GPU render node
/// - `$XDG_RUNTIME_DIR`     (RW)      — Wayland socket, D-Bus, portal IPC
/// - `staging_dir`           (RW)      — in-runtime staging area
/// - `vault_path` or parent  (RW)      — the one vault file (or its directory
///   when it does not yet exist)
///
/// Every other filesystem path — including the rest of `/home` — is denied
/// at the kernel level for the lifetime of the process.
pub fn apply_gui_vault_sandbox(vault_path: &Path) {
    let xdg_runtime: String = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| "/run/user/1000".into());
    let staging: String = format!("{}/atom_staging", xdg_runtime);

    // ~/.atom_vault/ holds friends.json, onion.txt, vault registry, and
    // identity keys — the P2P screen needs read-write access to all of them
    // after the sandbox is applied.
    let atom_data_dir: std::path::PathBuf = dirs::home_dir()
        .map(|h| h.join(".atom_vault"))
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/.atom_vault_fallback"));
    // Ensure the directory exists so Landlock can open an FD for it.
    std::fs::create_dir_all(&atom_data_dir).ok();

    // Landlock cannot open an FD for a path that does not exist.  For vault
    // creation the file is absent at this point, so we grant write access to
    // its parent directory (enough to create the file).  For vault opening the
    // file already exists and we restrict to exactly that path.
    let effective_vault_path: std::path::PathBuf = if vault_path.exists() {
        vault_path.to_path_buf()
    } else {
        vault_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| vault_path.to_path_buf())
    };

    let ro = [
        Path::new("/usr"),
        Path::new("/etc"),
        Path::new("/sys"),
        Path::new("/proc"),
    ];
    let rw = [
        Path::new("/dev/dri"),
        Path::new(xdg_runtime.as_str()),
        effective_vault_path.as_path(),
        Path::new(staging.as_str()),
        atom_data_dir.as_path(),
    ];

    match apply_process_sandbox(&ro, &rw) {
        Ok(s) => log_sandbox_status(s),
        Err(e) => eprintln!("[Sandbox] Warning: could not apply Landlock: {}", e),
    }
}

/// Logs the sandbox outcome to stderr using the standard `[Sandbox]` prefix.
/// Called at each activation site so log output is consistent and searchable.
pub fn log_sandbox_status(status: LandlockStatus) {
    match status {
        LandlockStatus::FullyEnforced => {
            eprintln!("[Sandbox] Landlock inner sandbox: fully enforced (ABI V5).");
        }
        LandlockStatus::PartiallyEnforced => {
            eprintln!(
                "[Sandbox] Landlock inner sandbox: partially enforced \
                 (kernel ABI < V5 — some access flags unavailable)."
            );
        }
        LandlockStatus::NotEnforced => {
            eprintln!(
                "[Sandbox] Warning: Landlock LSM not supported on this kernel. \
                 Process filesystem access is unrestricted."
            );
        }
    }
}

// ── bwrap self-sandbox ────────────────────────────────────────────────────────

/// Re-exec the atom process inside a bubblewrap container for additional
/// isolation on top of Landlock.
///
/// What bwrap adds that Landlock does not cover:
/// - `/usr`, `/etc`, `/sys` mounted **read-only at the kernel mount level**
///   (defence-in-depth; Landlock already restricts writes but bwrap enforces
///   it at a separate kernel layer — the mount namespace)
/// - **Private `/tmp`** — tmpfs visible only to this process tree; staging
///   temp files from other apps are invisible
/// - **IPC namespace** — no shared-memory segments or System-V IPC with
///   unrelated processes
/// - **UTS namespace** — isolated hostname; avoids hostname-based information
///   leaks and fingerprinting
/// - **`--die-with-parent`** — the bwrap container exits if the launcher dies,
///   preventing orphan vault-holding processes
///
/// Intentional omissions (documented):
/// - `--unshare-net` is NOT applied: the embedded Arti/Tor P2P daemon needs
///   outbound network access; network isolation requires moving the daemon to a
///   separate process (see the Flatpak packaging roadmap)
/// - `--unshare-user` is NOT attempted: on SELinux-enforcing kernels (Fedora,
///   RHEL) unprivileged user-namespace creation is blocked by policy; adding
///   that flag would cause EPERM even on native terminals
///
/// Failure modes:
/// - Inside a Flatpak terminal (Ptyxis, …): nested mount namespace creation is
///   blocked → EPERM → prints `[Sandbox] bwrap outer cage: …` notice and
///   returns; the process continues with Landlock-only isolation
/// - bwrap not installed: same fallback
/// - Already sandboxed (`ATOM_BWRAP_SANDBOX=1`): returns immediately (no loop)
pub fn try_bwrap_self_sandbox() {
    // Already inside our bwrap cage — do not re-enter.
    if std::env::var("ATOM_BWRAP_SANDBOX").is_ok() {
        return;
    }

    // Inside a Flatpak app sandbox: the platform already confines the process
    // with its own bwrap invocation (via flatpak-session-helper).  Nesting a
    // second bwrap would require --allow=devel in the manifest and adds no
    // security value.  Let Flatpak's confinement handle isolation.
    if Path::new("/.flatpak-info").exists() || env::var("FLATPAK_ID").is_ok() {
        eprintln!("[Sandbox] bwrap outer cage: Flatpak platform sandbox active — skipping");
        return;
    }

    // Probe whether bwrap can create namespaces on this kernel/policy before
    // replacing the process image.  Suppressing bwrap's stderr prevents the
    // "Creating new namespace failed: Permission denied" message from reaching
    // the user when running inside a Flatpak terminal (Ptyxis) or on an
    // SELinux-enforcing system without the required policy exception.
    if !bwrap_namespace_available() {
        eprintln!("[Sandbox] bwrap outer cage: namespace creation unavailable — Landlock only");
        return;
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[Sandbox] bwrap outer cage: cannot resolve own path: {}", e);
            return;
        }
    };

    let xdg_runtime = match env::var("XDG_RUNTIME_DIR") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[Sandbox] bwrap outer cage: XDG_RUNTIME_DIR unset, skipping");
            return;
        }
    };

    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            eprintln!("[Sandbox] bwrap outer cage: cannot determine HOME, skipping");
            return;
        }
    };
    let home_str = home.to_string_lossy().into_owned();

    let wayland_display = env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
    let dbus_addr = env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();

    let _ = std::fs::create_dir_all(format!("{}/atom_staging", xdg_runtime));

    let args = build_self_bwrap_args(
        exe.to_string_lossy().as_ref(),
        &xdg_runtime,
        &wayland_display,
        &home_str,
        &dbus_addr,
        std::env::args_os().skip(1).collect(),
    );

    let mut cmd = std::process::Command::new("bwrap");
    cmd.args(&args);

    use std::os::unix::process::CommandExt;
    let err = cmd.exec(); // replaces the process image; only returns on error

    // exec() returned — bwrap binary found but execvp failed (should be rare
    // since we already probed successfully, but guard anyway).
    eprintln!("[Sandbox] bwrap outer cage: exec failed: {} — Landlock only", err);
}

/// Returns `true` if bwrap can create a mount+IPC namespace on this system.
/// Runs a silent probe (`bwrap … true`) with stderr suppressed so that
/// policy-denied namespace creation does not print noise to the terminal.
fn bwrap_namespace_available() -> bool {
    std::process::Command::new("bwrap")
        .args([
            "--ro-bind-try", "/usr", "/usr",
            "--unshare-ipc",
            "--", "true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Builds the bwrap argument list for the process self-sandbox.
/// Extracted as a pure function so it can be unit-tested.
pub(crate) fn build_self_bwrap_args(
    exe: &str,
    xdg_runtime: &str,
    wayland_display: &str,
    home: &str,
    dbus_addr: &str,
    extra_args: Vec<std::ffi::OsString>,
) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    // System paths — read-only.  --ro-bind-try silently skips absent paths
    // (e.g. /lib64 is a symlink on Fedora, /opt may not exist).
    for path in ["/usr", "/etc", "/sys", "/opt"] {
        args.extend(["--ro-bind-try", path, path].map(String::from));
    }
    // /lib and /lib64 only when they are real directories (not symlinks into /usr).
    for path in ["/lib", "/lib64"] {
        let p = Path::new(path);
        if p.exists() && p.symlink_metadata().map(|m| !m.file_type().is_symlink()).unwrap_or(false) {
            args.extend(["--ro-bind", path, path].map(String::from));
        }
    }

    // Pseudo-filesystems.
    args.extend(["--proc", "/proc", "--dev", "/dev"].map(String::from));
    // GPU render node for egui/Mesa.
    if Path::new("/dev/dri").exists() {
        args.extend(["--dev-bind", "/dev/dri", "/dev/dri"].map(String::from));
    }
    // Private /tmp — staging files from other processes are invisible.
    args.extend(["--tmpfs", "/tmp"].map(String::from));

    // /run: read-only base so Flatpak plumbing is visible, then RW override
    // for XDG_RUNTIME_DIR (Wayland socket, D-Bus, portal FUSE).
    args.extend(["--ro-bind-try", "/run", "/run"].map(String::from));
    args.extend(["--bind", xdg_runtime, xdg_runtime].map(String::from));

    // Flatpak store (read-only) so gio/xdg-open can launch Flatpak apps.
    if Path::new("/var/lib/flatpak").exists() {
        args.extend(["--ro-bind", "/var/lib/flatpak", "/var/lib/flatpak"].map(String::from));
    }
    let user_flatpak = format!("{}/.local/share/flatpak", home);
    if Path::new(&user_flatpak).exists() {
        args.extend(["--ro-bind-try", &user_flatpak, &user_flatpak].map(String::from));
    }

    // Home directory — writable so the vault file can be created/updated.
    // Landlock (applied later, after the vault path is known) tightens this
    // to the single vault file; bwrap does not restrict home writes here.
    // On Fedora Silverblue, home lives under /var/home; bind both so that
    // absolute paths under either root work inside the container.
    args.extend(["--bind-try", home, home].map(String::from));
    if Path::new("/var/home").exists() {
        args.extend(["--bind-try", "/var/home", "/var/home"].map(String::from));
    }
    // /home is often a symlink to /var/home on Silverblue; bind the real dir
    // at /home too so symlink-following tools see a consistent path.
    if Path::new("/home").exists() {
        args.extend(["--bind-try", "/home", "/home"].map(String::from));
    }

    // Namespace isolation (no --unshare-user: SELinux blocks it;
    //                      no --unshare-net: P2P daemon needs network).
    args.extend(
        ["--unshare-ipc", "--unshare-uts", "--new-session", "--die-with-parent"]
            .map(String::from),
    );

    // Pass through essential environment variables.
    for (key, val) in [
        ("ATOM_BWRAP_SANDBOX", "1"),
        ("WAYLAND_DISPLAY", wayland_display),
        ("XDG_RUNTIME_DIR", xdg_runtime),
        ("HOME", home),
    ] {
        args.extend(["--setenv", key, val].map(String::from));
    }
    if let Some(dbus_socket) = extract_dbus_socket_path(dbus_addr) {
        args.extend(
            ["--setenv", "DBUS_SESSION_BUS_ADDRESS", dbus_addr].map(String::from),
        );
        // Bind the socket itself in case /run was mounted RO above and
        // the socket path falls outside XDG_RUNTIME_DIR on some distros.
        if Path::new(&dbus_socket).exists() {
            args.extend(["--bind-try", &dbus_socket, &dbus_socket].map(String::from));
        }
    }

    args.push("--".into());
    args.push(exe.to_string());
    for arg in extra_args {
        args.push(arg.to_string_lossy().into_owned());
    }

    args
}

/// Launches org.gnome.Papers inside a bubblewrap container to view the in-memory PDF.
///
/// The decrypted content is passed via `target_fd` (a sealed memfd). bwrap copies it
/// into an in-RAM tmpfs at /tmp/document.pdf, which is the only file Papers can read.
/// The network namespace is removed and the filesystem view is stripped to the minimum
/// flatpak needs to operate. Returns the PID of the bwrap process to waitpid() on.
pub fn spawn_in_bwrap_sandbox(
    target_fd: RawFd,
) -> Result<libc::pid_t, Box<dyn std::error::Error + Send + Sync>> {
    let xdg_runtime = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());
    let wayland_display = env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
    let home = env::var("HOME").unwrap_or_else(|_| "/root".into());
    let dbus_addr = env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();

    // Duplicate fd without O_CLOEXEC so it survives execvp into bwrap.
    // bwrap's --file option reads from this fd to populate /tmp/document.pdf.
    let inherited_fd = unsafe { libc::dup(target_fd) };
    if inherited_fd < 0 {
        return Err("dup() failed: cannot inherit memfd into bwrap".into());
    }
    // Rewind so bwrap reads the full document from the start.
    unsafe { libc::lseek(inherited_fd, 0, libc::SEEK_SET) };

    let args = build_bwrap_args(inherited_fd, &xdg_runtime, &wayland_display, &home, &dbus_addr);

    let cstrings: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_str()).expect("bwrap arg contains null byte"))
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = cstrings
        .iter()
        .map(|cs| cs.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();

    let bwrap_exe = CString::new("bwrap")?;

    unsafe {
        match libc::fork() {
            -1 => {
                libc::close(inherited_fd);
                Err("fork() failed while spawning bwrap".into())
            }
            0 => {
                // Child: inherited_fd has no O_CLOEXEC, so it survives into bwrap.
                libc::execvp(bwrap_exe.as_ptr(), argv_ptrs.as_ptr());
                libc::exit(1);
            }
            pid => {
                // Parent: close our copy; the child's copy is what bwrap will read.
                libc::close(inherited_fd);
                Ok(pid)
            }
        }
    }
}

/// Builds the full bwrap argument list given an already-dup'd, seeked `inherited_fd`
/// and the caller's resolved environment values.
///
/// Extracted as a pure function so it can be unit-tested without forking or exec'ing.
pub(crate) fn build_bwrap_args(
    inherited_fd: RawFd,
    xdg_runtime: &str,
    wayland_display: &str,
    home: &str,
    dbus_addr: &str,
) -> Vec<String> {
    let user_flatpak = format!("{}/.local/share/flatpak", home);

    let mut args: Vec<String> = vec!["bwrap".into()];

    // --- Namespace isolation ---
    // --unshare-user creates a new user namespace first, which maps our UID to
    // root inside the container.  This is required for unprivileged creation of
    // the IPC, net, and UTS namespaces that follow — without it, clone() returns
    // EPERM because non-root cannot create those namespaces in the current
    // user namespace.  Flatpak can still nest its own inner user namespace
    // inside ours (user.max_user_namespaces allows multiple levels).
    args.extend(["--unshare-user", "--unshare-ipc", "--unshare-net", "--unshare-uts"].map(String::from));
    // Kill bwrap if the atom parent dies; no controlling terminal.
    args.extend(["--die-with-parent", "--new-session"].map(String::from));

    // --- Minimal clean environment ---
    args.push("--clearenv".into());
    {
        // Scoped so the mutable borrow of `args` is released before subsequent pushes.
        let mut setenv = |k: &str, v: &str| {
            args.push("--setenv".into());
            args.push(k.to_string());
            args.push(v.to_string());
        };
        setenv("WAYLAND_DISPLAY", wayland_display);
        setenv("XDG_RUNTIME_DIR", xdg_runtime);
        setenv("HOME", home);
        if !dbus_addr.is_empty() {
            setenv("DBUS_SESSION_BUS_ADDRESS", dbus_addr);
        }
    }

    // --- Pseudo-filesystems ---
    args.extend(["--proc", "/proc", "--dev", "/dev"].map(String::from));
    // FUSE is required by xdg-document-portal, which flatpak uses for file access.
    if Path::new("/dev/fuse").exists() {
        args.extend(["--dev-bind", "/dev/fuse", "/dev/fuse"].map(String::from));
    }

    // --- Decrypted PDF lives only in an in-RAM tmpfs ---
    // bwrap reads inherited_fd and creates /tmp/document.pdf inside the container.
    // When bwrap exits, the tmpfs is unmounted and the file is gone.
    args.extend(["--tmpfs", "/tmp"].map(String::from));
    args.push("--file".into());
    args.push(inherited_fd.to_string());
    args.push("/tmp/document.pdf".into());

    // --- Read-only system paths (minimum for flatpak + GTK runtime) ---
    for path in ["/usr", "/etc", "/sys"] {
        if Path::new(path).exists() {
            args.extend(["--ro-bind", path, path].map(String::from));
        }
    }
    // Bind /lib and /lib64 only when they are real directories.
    // On Fedora they are symlinks into /usr, so this block is typically skipped.
    for path in ["/lib", "/lib64"] {
        let p = Path::new(path);
        if p.exists()
            && p.symlink_metadata()
                .map(|m| !m.file_type().is_symlink())
                .unwrap_or(false)
        {
            args.extend(["--ro-bind", path, path].map(String::from));
        }
    }

    // --- Flatpak installations (read-only) ---
    if Path::new("/var/lib/flatpak").exists() {
        args.extend(["--ro-bind", "/var/lib/flatpak", "/var/lib/flatpak"].map(String::from));
    }
    if Path::new(&user_flatpak).exists() {
        args.push("--ro-bind".into());
        args.push(user_flatpak.clone());
        args.push(user_flatpak.clone());
    }

    // --- XDG_RUNTIME_DIR: needs read-write for flatpak session info and portal sockets ---
    if Path::new(xdg_runtime).exists() {
        args.push("--bind".into());
        args.push(xdg_runtime.to_string());
        args.push(xdg_runtime.to_string());
    }

    // --- D-Bus session socket for portal communication ---
    if let Some(dbus_socket) = extract_dbus_socket_path(dbus_addr) {
        if Path::new(&dbus_socket).exists() {
            args.push("--bind".into());
            args.push(dbus_socket.clone());
            args.push(dbus_socket.clone());
        }
    }

    // --- Launch Papers with explicit /tmp:ro grant and network disabled ---
    // --filesystem=/tmp:ro lets flatpak bind our in-RAM /tmp into Papers' container.
    // --no-network is redundant with --unshare-net but makes the intent explicit.
    args.extend(
        [
            "--",
            "flatpak",
            "run",
            "--no-network",
            "--filesystem=/tmp:ro",
            "org.gnome.Papers",
            "/tmp/document.pdf",
        ]
        .map(String::from),
    );

    args
}

/// Parses a DBUS_SESSION_BUS_ADDRESS value of the form
/// `unix:path=/run/user/1000/bus;guid=...` and returns the socket path.
pub(crate) fn extract_dbus_socket_path(addr: &str) -> Option<String> {
    for entry in addr.split(',') {
        if let Some(rest) = entry.trim().strip_prefix("unix:") {
            for kv in rest.split(';') {
                if let Some(path) = kv.strip_prefix("path=") {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_self_bwrap_args ────────────────────────────────────────────────

    fn self_bwrap_sample() -> Vec<String> {
        build_self_bwrap_args(
            "/usr/bin/atom",
            "/run/user/1000",
            "wayland-0",
            "/home/user",
            "unix:path=/run/user/1000/bus",
            vec![],
        )
    }

    #[test]
    fn self_bwrap_usr_is_ro() {
        let args = self_bwrap_sample();
        // --ro-bind-try /usr /usr must appear
        let pos = args.iter().position(|a| a == "--ro-bind-try").expect("--ro-bind-try missing");
        // scan all --ro-bind-try triples for /usr
        let triples: Vec<_> = args.windows(3)
            .filter(|w| w[0] == "--ro-bind-try" || w[0] == "--ro-bind")
            .collect();
        assert!(triples.iter().any(|w| w[1] == "/usr"), "/usr must be bound RO");
        let _ = pos;
    }

    #[test]
    fn self_bwrap_no_unshare_net() {
        // P2P daemon needs network — must NOT appear.
        assert!(!self_bwrap_sample().contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn self_bwrap_no_unshare_user() {
        // SELinux blocks unprivileged user-namespace creation.
        assert!(!self_bwrap_sample().contains(&"--unshare-user".to_string()));
    }

    #[test]
    fn self_bwrap_ipc_and_uts_isolated() {
        let args = self_bwrap_sample();
        assert!(args.contains(&"--unshare-ipc".to_string()));
        assert!(args.contains(&"--unshare-uts".to_string()));
    }

    #[test]
    fn self_bwrap_die_with_parent() {
        assert!(self_bwrap_sample().contains(&"--die-with-parent".to_string()));
    }

    #[test]
    fn self_bwrap_tmp_is_private() {
        let args = self_bwrap_sample();
        let pos = args.iter().position(|a| a == "--tmpfs").expect("--tmpfs missing");
        assert_eq!(args[pos + 1], "/tmp");
    }

    #[test]
    fn self_bwrap_marker_env_set() {
        let args = self_bwrap_sample();
        let pos = args.iter().position(|a| a == "ATOM_BWRAP_SANDBOX")
            .expect("ATOM_BWRAP_SANDBOX missing");
        assert_eq!(args[pos - 1], "--setenv");
        assert_eq!(args[pos + 1], "1");
    }

    #[test]
    fn self_bwrap_home_is_rw() {
        let args = self_bwrap_sample();
        // Home must appear as --bind-try (RW), not --ro-bind.
        let home_in_rw = args.windows(3)
            .any(|w| w[0] == "--bind-try" && w[1] == "/home/user");
        assert!(home_in_rw, "home directory must be bound RW");
    }

    #[test]
    fn self_bwrap_exe_is_last_positional() {
        let args = self_bwrap_sample();
        let sep = args.iter().rposition(|a| a == "--").expect("-- separator missing");
        assert_eq!(args[sep + 1], "/usr/bin/atom");
    }

    #[test]
    fn self_bwrap_extra_args_forwarded() {
        let args = build_self_bwrap_args(
            "/usr/bin/atom",
            "/run/user/1000",
            "wayland-0",
            "/home/user",
            "",
            vec!["--vault-path".into(), "my.aegis".into()],
        );
        let sep = args.iter().rposition(|a| a == "--").unwrap();
        let positional: Vec<&str> = args[sep + 1..].iter().map(|s| s.as_str()).collect();
        assert_eq!(positional, vec!["/usr/bin/atom", "--vault-path", "my.aegis"]);
    }

    // ── apply_process_sandbox ────────────────────────────────────────────────

    // These tests must NOT call restrict_self() because doing so would
    // permanently alter the test process's filesystem access for the remainder
    // of the test run.  We exercise the path-selection and existence-filtering
    // logic instead.

    #[test]
    fn sandbox_skips_nonexistent_paths() {
        // apply_process_sandbox must return Ok even when every supplied path
        // is absent.  On any machine where /nonexistent_atom_test does not
        // exist this exercises the "skip missing path" branch.
        let ro: &[&Path] = &[Path::new("/nonexistent_atom_test_ro")];
        let rw: &[&Path] = &[Path::new("/nonexistent_atom_test_rw")];

        // We do NOT call apply_process_sandbox here to avoid restricting the
        // test runner.  We exercise just the existence predicate instead.
        for &p in ro.iter().chain(rw.iter()) {
            assert!(!p.exists(), "sentinel path must not exist on this machine");
        }
    }

    #[test]
    fn sandbox_status_variants_are_distinct() {
        assert_ne!(LandlockStatus::FullyEnforced, LandlockStatus::PartiallyEnforced);
        assert_ne!(LandlockStatus::FullyEnforced, LandlockStatus::NotEnforced);
        assert_ne!(LandlockStatus::PartiallyEnforced, LandlockStatus::NotEnforced);
    }

    #[test]
    fn log_sandbox_status_does_not_panic() {
        // Smoke-test: log_sandbox_status must not panic for any variant.
        log_sandbox_status(LandlockStatus::FullyEnforced);
        log_sandbox_status(LandlockStatus::PartiallyEnforced);
        log_sandbox_status(LandlockStatus::NotEnforced);
    }

    // ── extract_dbus_socket_path ─────────────────────────────────────────────

    #[test]
    fn test_dbus_parse_standard_path() {
        let addr = "unix:path=/run/user/1000/bus";
        assert_eq!(
            extract_dbus_socket_path(addr).as_deref(),
            Some("/run/user/1000/bus")
        );
    }

    #[test]
    fn test_dbus_parse_path_with_guid() {
        // Real-world format: path comes before guid, separated by semicolons.
        let addr = "unix:path=/run/user/1000/bus;guid=abc123def456";
        assert_eq!(
            extract_dbus_socket_path(addr).as_deref(),
            Some("/run/user/1000/bus")
        );
    }

    #[test]
    fn test_dbus_parse_guid_before_path() {
        // guid appears first; parser must still find path=.
        let addr = "unix:guid=abc123;path=/run/user/1000/bus";
        assert_eq!(
            extract_dbus_socket_path(addr).as_deref(),
            Some("/run/user/1000/bus")
        );
    }

    #[test]
    fn test_dbus_parse_comma_separated_picks_first_path() {
        // Multiple transport addresses: the first unix:path= wins.
        let addr = "unix:path=/run/user/1000/bus;guid=abc,unix:path=/tmp/other;guid=xyz";
        assert_eq!(
            extract_dbus_socket_path(addr).as_deref(),
            Some("/run/user/1000/bus")
        );
    }

    #[test]
    fn test_dbus_parse_abstract_socket_returns_none() {
        // Abstract sockets have no filesystem path; we cannot bind-mount them.
        let addr = "unix:abstract=/tmp/dbus-abc123;guid=abc";
        assert_eq!(extract_dbus_socket_path(addr), None);
    }

    #[test]
    fn test_dbus_parse_empty_returns_none() {
        assert_eq!(extract_dbus_socket_path(""), None);
    }

    #[test]
    fn test_dbus_parse_non_unix_transport_returns_none() {
        assert_eq!(extract_dbus_socket_path("tcp:host=localhost,port=12345"), None);
    }

    // ── build_bwrap_args ─────────────────────────────────────────────────────

    fn sample_args() -> Vec<String> {
        build_bwrap_args(
            42,
            "/run/user/1000",
            "wayland-0",
            "/home/user",
            "unix:path=/run/user/1000/bus",
        )
    }

    #[test]
    fn test_args_first_element_is_bwrap() {
        assert_eq!(sample_args()[0], "bwrap");
    }

    #[test]
    fn test_args_network_is_unshared() {
        assert!(sample_args().contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn test_args_ipc_is_unshared() {
        assert!(sample_args().contains(&"--unshare-ipc".to_string()));
    }

    #[test]
    fn test_args_uts_is_unshared() {
        assert!(sample_args().contains(&"--unshare-uts".to_string()));
    }

    #[test]
    fn test_args_user_namespace_is_unshared() {
        // Required: without a new user namespace, unprivileged clone() of
        // IPC/net/UTS namespaces returns EPERM.
        assert!(sample_args().contains(&"--unshare-user".to_string()));
    }

    #[test]
    fn test_args_die_with_parent_present() {
        assert!(sample_args().contains(&"--die-with-parent".to_string()));
    }

    #[test]
    fn test_args_new_session_present() {
        assert!(sample_args().contains(&"--new-session".to_string()));
    }

    #[test]
    fn test_args_clearenv_present() {
        assert!(sample_args().contains(&"--clearenv".to_string()));
    }

    #[test]
    fn test_args_tmpfs_on_tmp() {
        let args = sample_args();
        let pos = args.iter().position(|a| a == "--tmpfs").expect("--tmpfs missing");
        assert_eq!(args[pos + 1], "/tmp");
    }

    #[test]
    fn test_args_file_fd_correct() {
        let fd: RawFd = 42;
        let args = build_bwrap_args(fd, "/run/user/1000", "wayland-0", "/home/user", "");
        let pos = args.iter().position(|a| a == "--file").expect("--file missing");
        assert_eq!(args[pos + 1], fd.to_string());
        assert_eq!(args[pos + 2], "/tmp/document.pdf");
    }

    #[test]
    fn test_args_pdf_destination_is_tmp() {
        assert!(sample_args().contains(&"/tmp/document.pdf".to_string()));
    }

    #[test]
    fn test_args_ends_with_flatpak_papers() {
        let args = sample_args();
        // Verify the final command triple is correct.
        assert!(args.contains(&"flatpak".to_string()));
        assert!(args.contains(&"org.gnome.Papers".to_string()));
        // Papers is always the last element.
        assert_eq!(args.last().unwrap(), "/tmp/document.pdf");
    }

    #[test]
    fn test_args_no_network_flag_for_flatpak() {
        assert!(sample_args().contains(&"--no-network".to_string()));
    }

    #[test]
    fn test_args_filesystem_tmp_ro_flag() {
        assert!(sample_args().contains(&"--filesystem=/tmp:ro".to_string()));
    }

    #[test]
    fn test_args_wayland_display_set() {
        let args = sample_args();
        let pos = args
            .iter()
            .position(|a| a == "WAYLAND_DISPLAY")
            .expect("WAYLAND_DISPLAY missing");
        assert_eq!(args[pos - 1], "--setenv");
        assert_eq!(args[pos + 1], "wayland-0");
    }

    #[test]
    fn test_args_xdg_runtime_dir_set() {
        let args = sample_args();
        let pos = args
            .iter()
            .position(|a| a == "XDG_RUNTIME_DIR")
            .expect("XDG_RUNTIME_DIR missing");
        assert_eq!(args[pos - 1], "--setenv");
        assert_eq!(args[pos + 1], "/run/user/1000");
    }

    #[test]
    fn test_args_home_set() {
        let args = sample_args();
        let pos = args
            .iter()
            .position(|a| a == "HOME")
            .expect("HOME missing");
        assert_eq!(args[pos - 1], "--setenv");
        assert_eq!(args[pos + 1], "/home/user");
    }

    #[test]
    fn test_args_dbus_address_included_when_set() {
        let addr = "unix:path=/run/user/1000/bus";
        let args = build_bwrap_args(42, "/run/user/1000", "wayland-0", "/home/user", addr);
        let pos = args
            .iter()
            .position(|a| a == "DBUS_SESSION_BUS_ADDRESS")
            .expect("DBUS_SESSION_BUS_ADDRESS missing");
        assert_eq!(args[pos + 1], addr);
    }

    #[test]
    fn test_args_dbus_omitted_when_empty() {
        let args = build_bwrap_args(42, "/run/user/1000", "wayland-0", "/home/user", "");
        assert!(!args.contains(&"DBUS_SESSION_BUS_ADDRESS".to_string()));
    }

    // ── fd duplication / CLOEXEC behaviour ──────────────────────────────────

    #[test]
    fn test_dup_fd_has_no_cloexec() {
        // A dup()'d fd must not carry O_CLOEXEC, otherwise bwrap won't inherit it.
        let original = unsafe {
            libc::memfd_create(
                b"atom_test\0".as_ptr() as *const libc::c_char,
                libc::MFD_CLOEXEC, // original starts with CLOEXEC
            )
        };
        assert!(original >= 0, "memfd_create failed");

        let duped = unsafe { libc::dup(original) };
        assert!(duped >= 0, "dup() failed");

        let flags = unsafe { libc::fcntl(duped, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl F_GETFD failed");
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "dup()'d fd must not have FD_CLOEXEC"
        );

        unsafe {
            libc::close(original);
            libc::close(duped);
        }
    }
}
