use memfd::MemfdOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

use crate::crypto::UnlockedVault;
use crate::sandbox;
use crate::vfs::{FileIndex, process_secure_chunk};

/// A read-only mmap of a memfd (CLI path) or tmpfs viewer file (GUI path) that
/// is pinned into physical RAM with `mlock()`.  This prevents the kernel from
/// swapping the decrypted plaintext to disk (or to the hibernation image) while
/// the viewer is open.  Dropping the guard unlocks and unmaps the region.
///
/// Exposed to the GUI broker (`crate::gui::broker`) so the GUI viewer can pin
/// its tmpfs-backed plaintext with the same primitive the CLI path uses.
pub(crate) struct MlockedMap {
    ptr: *mut libc::c_void,
    len: usize,
}

// The raw pointer is owned exclusively by this struct and only touched in
// `new`/`drop`; it is safe to move the guard across threads (worker thread,
// signal handler).
unsafe impl Send for MlockedMap {}

impl MlockedMap {
    /// Map `len` bytes of `fd` read-only and pin them in RAM.  A zero length
    /// yields an inert guard (mmap rejects zero-length requests).
    pub(crate) fn new(fd: RawFd, len: usize) -> std::io::Result<Self> {
        if len == 0 {
            return Ok(Self {
                ptr: std::ptr::null_mut(),
                len: 0,
            });
        }

        // PROT_READ is sufficient: we only need the pages resident so mlock can
        // pin them.  A PROT_WRITE shared mapping would be rejected by
        // F_SEAL_FUTURE_WRITE anyway.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        if unsafe { libc::mlock(ptr, len) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::munmap(ptr, len) };

            // The pin only exists to keep decrypted plaintext off persistent
            // storage (a disk swap device or the hibernation image).  When the
            // lock cannot fit the per-process `RLIMIT_MEMLOCK` budget (`ENOMEM`)
            // but no such storage path exists — no disk-backed swap and no
            // hibernation — the plaintext physically cannot reach disk, so an
            // unpinned mapping is just as safe.  Proceed with an inert guard.
            //
            // This is scoped narrowly: only `ENOMEM` (the budget case) is
            // tolerated, and only when `disk_persistence_possible()` is provably
            // false.  Any other error, or any system with a real swap/hibernation
            // target, still fails closed.
            if err.raw_os_error() == Some(libc::ENOMEM) && !disk_persistence_possible() {
                eprintln!(
                    "Note: viewer plaintext is not RAM-pinned ({} B exceeds the \
                     RLIMIT_MEMLOCK budget), but this host has no disk-backed swap \
                     and hibernation is unavailable, so it cannot reach disk.",
                    len
                );
                return Ok(Self {
                    ptr: std::ptr::null_mut(),
                    len: 0,
                });
            }
            return Err(err);
        }

        Ok(Self { ptr, len })
    }
}

/// Raise this process's soft `RLIMIT_MEMLOCK` to its hard limit so the viewer can
/// pin as much plaintext as the system permits without privilege.  Called once at
/// startup, before the bwrap re-exec, so the raised soft limit is inherited.
///
/// Unprivileged processes may raise the soft limit up to the hard limit but not
/// beyond; where the hard limit is already the ceiling this is a no-op.  Failure
/// is non-fatal — `MlockedMap::new` still enforces the actual pin-or-fail policy.
pub(crate) fn raise_memlock_limit() {
    unsafe {
        let mut lim = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
        }
    }
}

/// Returns `true` if decrypted plaintext held in RAM could be written to
/// persistent storage by the kernel — i.e. a disk-backed swap device is active.
/// (Hibernation likewise requires a disk swap target, so this single check
/// covers both vectors.)  Fails safe: any uncertainty returns `true`.
fn disk_persistence_possible() -> bool {
    let swaps = match std::fs::read_to_string("/proc/swaps") {
        Ok(s) => s,
        // Cannot determine the swap configuration — assume the worst.
        Err(_) => return true,
    };
    // Skip the header row; each remaining row's first field is the device.
    for line in swaps.lines().skip(1) {
        let Some(dev) = line.split_whitespace().next() else {
            continue;
        };
        if is_ram_only_zram(dev) {
            continue;
        }
        return true; // a disk-backed swap (partition or file) is active
    }
    false
}

/// Returns `true` only for a zram device with no writeback `backing_dev` — such a
/// device lives entirely in RAM and never spills to disk.  A zram with a backing
/// device, or any non-zram swap, is treated as disk-backed.  Fails safe: if the
/// backing state cannot be read, the device is not considered RAM-only.
fn is_ram_only_zram(dev: &str) -> bool {
    let name = dev.rsplit('/').next().unwrap_or(dev);
    if !name.starts_with("zram") {
        return false;
    }
    match std::fs::read_to_string(format!("/sys/block/{}/backing_dev", name)) {
        Ok(s) => s.trim() == "none",
        Err(_) => false,
    }
}

impl Drop for MlockedMap {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            unsafe {
                libc::munlock(self.ptr, self.len);
                libc::munmap(self.ptr, self.len);
            }
            self.ptr = std::ptr::null_mut();
            self.len = 0;
        }
    }
}

/// A viewer teardown that securely shreds its decrypted plaintext.  Whichever
/// of the worker thread (normal close) or the SIGINT/SIGTERM handler (interrupt)
/// claims the shared slot first runs the teardown exactly once.
///
/// Implemented by both viewer paths: `MemfdShredJob` (CLI, `memfd` + bwrap) and
/// `crate::gui::broker`'s tmpfs job (GUI, `gio open` + tmpfs file).  This lets a
/// single process-wide signal handler shred *every* open viewer regardless of
/// which path opened it.
pub(crate) trait ViewerTeardown: Send {
    /// Normal close (worker thread): shred and fire the caller's callback.
    fn shred_on_close(self: Box<Self>);
    /// Interrupt (signal handler): kill any child viewer, shred, skip callback.
    fn shred_on_signal(self: Box<Self>);
}

/// Shared slot holding a single in-flight teardown.  `None` once claimed.
pub(crate) type TeardownSlot = Arc<Mutex<Option<Box<dyn ViewerTeardown>>>>;

/// Registry of in-flight viewer teardowns.  The SIGINT handler drains this on
/// termination so no decrypted page survives an interrupted session.
fn registry() -> &'static Mutex<Vec<TeardownSlot>> {
    static REGISTRY: OnceLock<Mutex<Vec<TeardownSlot>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register `job` in the shared registry and return its slot.  The worker thread
/// keeps the slot to claim the job on normal close; the signal handler claims
/// any slots still occupied at interrupt time.  Completed slots are pruned here
/// to keep the registry small.
pub(crate) fn register_teardown(job: Box<dyn ViewerTeardown>) -> TeardownSlot {
    let slot: TeardownSlot = Arc::new(Mutex::new(Some(job)));
    let mut reg = registry().lock().unwrap();
    reg.retain(|s| s.lock().unwrap().is_some());
    reg.push(Arc::clone(&slot));
    slot
}

/// Install (once) a SIGINT/SIGTERM handler that shreds every open viewer's
/// decrypted RAM before letting the process die.  Without this, a Ctrl+C while
/// a viewer is open would kill the detached shred thread and leave plaintext
/// resident in memory.  Idempotent: safe to call from both the CLI and GUI
/// paths.
pub(crate) fn install_signal_handler() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = ctrlc::set_handler(|| {
            eprintln!(
                "\n[SIGINT] Termination requested. Shredding open viewer memory before exit..."
            );
            let jobs: Vec<TeardownSlot> = {
                let mut reg = registry().lock().unwrap();
                std::mem::take(&mut *reg)
            };
            for slot in jobs {
                if let Some(job) = slot.lock().unwrap().take() {
                    job.shred_on_signal();
                }
            }
            std::process::exit(130);
        });
    });
}

/// Decrypt `file_index` chunks into a sealed, anonymous memfd.
///
/// Returns the memfd `File`; the caller is responsible for spawning the viewer
/// and shredding the file when done.  Used by the GUI path so that the bwrap
/// spawn can happen on the pre-sandbox broker thread rather than the
/// Landlock-restricted main thread.
pub fn prepare_decrypted_memfd(
    physical_vault: &mut std::fs::File,
    file_index: &FileIndex,
    unlocked_vault: &UnlockedVault,
) -> Result<std::fs::File, Box<dyn std::error::Error + Send + Sync>> {
    let memfd_name = format!("atom_vault_memfd_{}", file_index.vfs_name);
    let mut memfd_file = MemfdOptions::default()
        .close_on_exec(true)
        .allow_sealing(true)
        .create(&memfd_name)?
        .into_file();

    for chunk in &file_index.chunks {
        process_secure_chunk(
            physical_vault,
            chunk.cipher_len,
            &chunk.nonce,
            unlocked_vault,
            chunk.offset,
            chunk.plain_len,
            |secure_plaintext| {
                memfd_file
                    .write_all(secure_plaintext)
                    .expect("Fatal: Failed to write to RAM disk");
            },
        )?;
    }

    memfd_file.flush()?;
    memfd_file.seek(SeekFrom::Start(0))?;

    // F_SEAL_FUTURE_WRITE prevents any new writable fd or mmap from being
    // created on this memfd (including inside the sandboxed viewer), while
    // leaving the existing writable fd (`memfd_file`) fully functional so that
    // shredding can zero the pages after the viewer exits.
    // F_SEAL_WRITE would block ALL writes — including our own shredder.
    //
    // F_SEAL_SHRINK is intentionally omitted: the sandbox only ever receives a
    // read-only fd and cannot ftruncate, so F_SEAL_GROW + F_SEAL_FUTURE_WRITE
    // already block tampering, while the parent retains the ability to shrink
    // the file to 0 during cleanup to release the RAM promptly.
    unsafe {
        libc::fcntl(
            memfd_file.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_GROW | libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL,
        );
    }

    Ok(memfd_file)
}

/// Overwrite the entire backing store of `memfd_file` with zeros via its
/// (pre-seal) writable fd.
fn zero_fill(memfd_file: &mut std::fs::File) {
    let size = memfd_file.metadata().map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return;
    }
    if memfd_file.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    let zero_page = [0u8; 4096];
    let mut written = 0u64;
    while written < size {
        let to_write = std::cmp::min(4096, size - written) as usize;
        if memfd_file.write_all(&zero_page[..to_write]).is_err() {
            break;
        }
        written += to_write as u64;
    }
    let _ = memfd_file.flush();
}

/// All the resources that must be torn down securely once a CLI (memfd + bwrap)
/// viewer closes or the process is interrupted.
struct MemfdShredJob {
    pid: libc::pid_t,
    /// Strict read-only handle handed to the sandbox; closed before shredding.
    ro_memfd: std::fs::File,
    /// Original writable handle (created before F_SEAL_FUTURE_WRITE) used to
    /// zero and then shrink the backing pages.
    memfd_file: std::fs::File,
    /// RAM pin; released only after the plaintext has been overwritten.
    locked_map: MlockedMap,
    /// Caller notification fired after the shred completes (normal path only).
    on_close: Box<dyn FnOnce() + Send>,
}

impl ViewerTeardown for MemfdShredJob {
    fn shred_on_close(self: Box<Self>) {
        complete_shred(*self);
    }

    fn shred_on_signal(mut self: Box<Self>) {
        // Force-close the still-running viewer child first.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        // Drop the on_close notifier without firing it; the process is exiting
        // so no one is waiting on it.
        self.on_close = Box::new(|| {});
        complete_shred(*self);
    }
}

/// Securely tear down a viewer's resources: close the sandbox handle, zero the
/// RAM while it is still locked, release the lock, shrink the file to free the
/// pages, then fire the completion callback.
fn complete_shred(job: MemfdShredJob) {
    let MemfdShredJob {
        ro_memfd,
        mut memfd_file,
        locked_map,
        on_close,
        ..
    } = job;

    // Close the sandbox's read-only handle so no fd alias remains.
    drop(ro_memfd);

    // Overwrite plaintext while the pages are still mlock'd (cannot be swapped
    // out mid-wipe).
    zero_fill(&mut memfd_file);

    // Unlock/unmap only after the plaintext is gone, and before shrinking so we
    // never ftruncate a still-mapped region.
    drop(locked_map);

    // With F_SEAL_SHRINK removed this now succeeds, releasing the backing pages
    // immediately rather than waiting for the fd to be dropped.
    let _ = memfd_file.set_len(0);
    drop(memfd_file);

    println!("Traces successfully removed.");
    on_close();
}

/// CLI entry point: decrypt, spawn bwrap directly, wait and shred.
///
/// Used by the interactive shell `view` command where there is no GUI broker.
/// Note: if Landlock is active (CLI `enter` path), bwrap inherits the domain
/// and may fail namespace creation — run `cargo run -- enter` outside Landlock
/// for full viewer support.
pub fn execute<F>(
    physical_vault: &mut std::fs::File,
    file_index: &FileIndex,
    unlocked_vault: &UnlockedVault,
    on_close: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnOnce() + Send + 'static,
{
    install_signal_handler();

    let memfd_file = prepare_decrypted_memfd(physical_vault, file_index, unlocked_vault)?;

    // Pin the decrypted memfd in physical RAM so the kernel cannot swap the
    // plaintext to disk (or hibernation) while the viewer is open.
    let size = memfd_file.metadata()?.len() as usize;
    let locked_map = MlockedMap::new(memfd_file.as_raw_fd(), size)
        .map_err(|e| format!("Failed to lock decrypted memfd into RAM: {}", e))?;

    // Open a strictly read-only handle via procfs.  F_SEAL_FUTURE_WRITE blocks
    // new writable fds, so this open with O_RDONLY always succeeds.  We pass
    // this to bwrap instead of the original fd so the sandbox cannot write
    // through it, while `memfd_file` (created before the seal) retains write
    // access for the shredder.
    let ro_path = format!("/proc/self/fd/{}", memfd_file.as_raw_fd());
    let ro_memfd = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(&ro_path)
        .map_err(|e| format!("Failed to open read-only memfd handle: {}", e))?;

    println!("Starting secure sandbox mode...");
    let pid = sandbox::spawn_in_bwrap_sandbox(ro_memfd.as_raw_fd())?;

    // Register the teardown resources in a shared slot so either the worker
    // thread (normal close) or the SIGINT handler (interrupt) can shred them.
    let slot = register_teardown(Box::new(MemfdShredJob {
        pid,
        ro_memfd,
        memfd_file,
        locked_map,
        on_close: Box::new(on_close),
    }));

    std::thread::spawn(move || {
        // Wrap waitpid so a panic here still proceeds to shredding.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }));

        println!("Sandbox closed. Initiating memory shredding...");
        // Take ownership of the job; if the signal handler already claimed it,
        // this is None and we do nothing.
        if let Some(job) = slot.lock().unwrap().take() {
            job.shred_on_close();
        }
    });

    Ok(())
}
