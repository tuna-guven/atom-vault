use std::env;
use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::Path;
use std::ptr;

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
    // User namespace is kept shared: flatpak creates its own inner user namespace.
    args.extend(["--unshare-ipc", "--unshare-net", "--unshare-uts"].map(String::from));
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
    fn test_args_user_namespace_not_unshared() {
        // Must stay shared so flatpak can create its own inner user namespace.
        assert!(!sample_args().contains(&"--unshare-user".to_string()));
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
