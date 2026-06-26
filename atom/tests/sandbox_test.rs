/// Integration tests for the bubblewrap sandbox.
///
/// These tests exercise the actual bwrap binary and Linux kernel primitives
/// that the sandbox relies on. They are kept separate from the unit tests in
/// sandbox.rs so they can be skipped cleanly in environments without bwrap.
///
/// Run with:
///   cargo test --test sandbox_test
///
/// Skip on systems without bwrap:
///   SKIP_BWRAP_TESTS=1 cargo test --test sandbox_test
use std::process::Command;

fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn skip_if_no_bwrap() -> bool {
    if std::env::var("SKIP_BWRAP_TESTS").is_ok() {
        eprintln!("SKIP_BWRAP_TESTS set — skipping bwrap integration tests");
        return true;
    }
    if !bwrap_available() {
        eprintln!("bwrap not found — skipping bwrap integration tests");
        return true;
    }
    false
}

/// Verify bwrap is installed and reports a version string.
/// If this test fails, all other sandbox integration tests will also fail.
#[test]
fn test_bwrap_is_installed() {
    if std::env::var("SKIP_BWRAP_TESTS").is_ok() {
        return;
    }
    let out = Command::new("bwrap")
        .arg("--version")
        .output()
        .expect("failed to run bwrap --version");

    assert!(
        out.status.success(),
        "bwrap --version exited with non-zero status"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bubblewrap"),
        "unexpected bwrap --version output: {stdout}"
    );
}

/// Core mechanism test: bwrap's `--file FD DEST` must be able to read an
/// inherited file descriptor and expose its contents as a file inside the
/// container. This is exactly how the sandbox delivers the decrypted PDF to
/// Papers without writing it to disk.
///
/// Flow:
///   1. Create a memfd without O_CLOEXEC so it survives execvp.
///   2. Write a known payload into it and rewind.
///   3. Spawn bwrap with `--file <fd> /tmp/payload.txt` and run `cat` inside.
///   4. Assert that bwrap's stdout matches the original payload.
#[test]
fn test_bwrap_file_fd_passes_memfd_content() {
    if skip_if_no_bwrap() {
        return;
    }

    const PAYLOAD: &[u8] = b"atom-vault-bwrap-test-payload";

    // 1. Create a memfd WITHOUT MFD_CLOEXEC so the fd survives into bwrap.
    let fd = unsafe {
        libc::memfd_create(
            b"atom_bwrap_test\0".as_ptr() as *const libc::c_char,
            0, // no MFD_CLOEXEC
        )
    };
    assert!(fd >= 0, "memfd_create failed");

    // 2. Write payload and rewind.
    let written = unsafe { libc::write(fd, PAYLOAD.as_ptr() as *const libc::c_void, PAYLOAD.len()) };
    assert_eq!(written as usize, PAYLOAD.len(), "write to memfd failed");
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };

    // 3. Spawn bwrap with a minimal container:
    //    --tmpfs /tmp         → fresh in-RAM tmpfs (mirrors real sandbox)
    //    --file FD /tmp/...   → copies memfd content into the tmpfs file
    //    -- cat /tmp/...      → reads and prints the file to stdout
    let out = Command::new("bwrap")
        .args([
            "--ro-bind", "/usr", "/usr",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--file", &fd.to_string(), "/tmp/payload.txt",
            "--",
            "cat", "/tmp/payload.txt",
        ])
        .output()
        .expect("failed to spawn bwrap for fd-passing test");

    unsafe { libc::close(fd) };

    assert!(
        out.status.success(),
        "bwrap exited with non-zero status: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, PAYLOAD,
        "bwrap did not reproduce the memfd payload"
    );
}

/// Verify that the sandbox removes network access: a command that requires
/// name resolution (or any network) must fail inside the container.
#[test]
fn test_bwrap_network_is_unshared() {
    if skip_if_no_bwrap() {
        return;
    }

    // `hostname -f` attempts a DNS lookup for the FQDN; it fails when the
    // network namespace is unshared and there is no loopback interface.
    // We use `ping -c1 -W1 1.1.1.1` as a more direct network reachability probe.
    let out = Command::new("bwrap")
        .args([
            "--unshare-net",
            "--ro-bind", "/usr", "/usr",
            "--proc", "/proc",
            "--dev", "/dev",
            "--",
            "sh", "-c", "ping -c1 -W1 1.1.1.1 2>/dev/null; echo $?",
        ])
        .output()
        .expect("failed to spawn bwrap for network test");

    let stdout = String::from_utf8_lossy(&out.stdout);
    // ping exits non-zero when the host is unreachable; we capture the exit
    // code via `echo $?` so the outer bwrap still exits 0.
    let ping_exit: u32 = stdout.trim().parse().unwrap_or(0);
    assert_ne!(ping_exit, 0, "ping succeeded inside --unshare-net sandbox; network was not isolated");
}

/// Verify that the sandbox's tmpfs is truly ephemeral: a file written inside
/// the container must not appear on the host filesystem after bwrap exits.
#[test]
fn test_bwrap_tmpfs_does_not_leak_to_host() {
    if skip_if_no_bwrap() {
        return;
    }

    let sentinel = "/tmp/atom_bwrap_sentinel_should_not_exist";

    // Write a sentinel file inside the sandbox's /tmp.
    let out = Command::new("bwrap")
        .args([
            "--ro-bind", "/usr", "/usr",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--",
            "sh", "-c", &format!("echo leaked > {sentinel}"),
        ])
        .output()
        .expect("failed to spawn bwrap for tmpfs-leak test");

    assert!(out.status.success(), "bwrap exited non-zero");

    // The sentinel must not exist on the host after bwrap exits.
    assert!(
        !std::path::Path::new(sentinel).exists(),
        "tmpfs file leaked to host filesystem at {sentinel}"
    );
}

/// Verify that a file created inside the container via `--file` is read-only:
/// Papers cannot overwrite the decrypted PDF through the path bwrap exposes.
#[test]
fn test_bwrap_file_dest_is_readonly() {
    if skip_if_no_bwrap() {
        return;
    }

    let fd = unsafe {
        libc::memfd_create(
            b"atom_ro_test\0".as_ptr() as *const libc::c_char,
            0,
        )
    };
    assert!(fd >= 0);

    let payload = b"original";
    unsafe { libc::write(fd, payload.as_ptr() as *const libc::c_void, payload.len()) };
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };

    // Attempt to overwrite the --file destination; the write must fail.
    let out = Command::new("bwrap")
        .args([
            "--ro-bind", "/usr", "/usr",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--file", &fd.to_string(), "/tmp/document.pdf",
            "--",
            "sh", "-c", "echo overwritten > /tmp/document.pdf; echo $?",
        ])
        .output()
        .expect("failed to spawn bwrap for read-only test");

    unsafe { libc::close(fd) };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let sh_exit: u32 = stdout.trim().parse().unwrap_or(0);
    assert_ne!(
        sh_exit, 0,
        "--file destination was writable inside the sandbox; expected read-only"
    );
}
