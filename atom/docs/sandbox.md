# Atom Vault — Sandboxing and Process Hardening

This document describes every layer of the defense-in-depth confinement strategy applied
to Atom Vault processes.  The architecture stacks two independent kernel/userspace
mechanisms — a Flatpak outer cage and a Linux Landlock inner lock — on top of in-process
memory-safety primitives, so that a successful exploit of any single layer still leaves
the attacker in a heavily restricted environment.

---

## Threat Model

The primary threat this sandboxing strategy defends against is a compromise of the Atom
Vault process itself — whether through a memory-corruption vulnerability in the GUI
toolkit, the PDF renderer, a dependency, or the Rust runtime.  An attacker who achieves
code execution inside the process should be unable to:

- Read or exfiltrate files outside the one vault the user explicitly opened.
- Write to arbitrary locations on the host filesystem.
- Contact the network (for the PDF viewer process).
- Escalate via IPC, D-Bus, or other inter-process communication paths.

The sandbox does **not** protect against a kernel exploit.  It also does not attempt to
hide the vault's existence from other processes running as the same UID; those guarantees
require full-system solutions (dm-crypt, SELinux MAC policy) that are out of scope here.

---

## Layer 1 — Flatpak Outer Cage (`io.atom_vault.AtomVault.json`)

When Atom Vault is distributed as a Flatpak, the application is started inside an
[OCI-style container](https://docs.flatpak.org/en/latest/sandbox-permissions.html) before
any Rust code runs.  The manifest intentionally omits all broad filesystem permissions:

```json
"finish-args": [
    "--share=ipc",
    "--socket=wayland",
    "--socket=fallback-x11",
    "--device=dri",
    "--share=network",
    "--talk-name=org.freedesktop.portal.FileChooser",
    "--talk-name=org.freedesktop.portal.Documents",
    "--talk-name=org.freedesktop.portal.OpenURI"
]
```

### What is deliberately absent

| Missing flag | What it would grant | Why we omit it |
|---|---|---|
| `--filesystem=home` | Read/write access to `~` | Would let a compromised process steal any user file |
| `--filesystem=host` | Full host filesystem | Equivalent to running unconfined |
| `--filesystem=/tmp` | `/tmp` shared with host | Not needed; we use memfd and `$XDG_RUNTIME_DIR` |
| `--talk-name=org.freedesktop.Notifications` | Desktop notifications | Not used |

### How vault files arrive inside the Flatpak

The Atom Vault GUI never receives a raw path to a file in the user's home directory.
Instead, file dialogs (`rfd::FileDialog`) talk to the **XDG FileChooser portal**
(`org.freedesktop.portal.FileChooser`).  The portal runs outside the Flatpak sandbox and
presents a native GTK file picker.  When the user selects a vault, the portal registers
the file with the **Document portal** (`org.freedesktop.portal.Documents`) and hands the
Flatpak-sandboxed process a path under `$XDG_RUNTIME_DIR/doc/<hash>/vault.aegis`.

From Atom Vault's perspective the path looks like a normal file path; the portal
transparently translates reads and writes to the real location.  The app never needs
`--filesystem=home` because the portal does the brokering.

### Network permission

`--share=network` is granted because the **Arti embedded Tor client** (P2P sync) needs
to reach the Tor network.  The Landlock inner sandbox (Layer 2) cannot restrict network
calls — Landlock is a filesystem LSM only.  If network access is not desired it can be
removed from the manifest to disable the P2P sync feature entirely at the OS level.

---

## Layer 2 — Landlock Inner Lock (`atom/src/sandbox.rs`)

[Linux Landlock](https://landlock.io/) is a Linux Security Module (LSM) introduced in
kernel 5.13.  It lets an unprivileged process restrict its own future filesystem access
via a `landlock_restrict_self()` syscall.  The restriction is:

- **Monotonically tightening** — once applied it can only be further restricted, never
  relaxed.
- **Per-task (thread-scoped)** — applies to the calling thread and all threads that
  thread creates afterwards; threads already running when `restrict_self()` is called are
  unaffected.
- **Inherited across `execve()`** — a child process spawned after restriction is also
  confined to the same ruleset.

Atom Vault targets **Landlock ABI V5** (Linux 6.10, `AccessFs::from_all(ABI::V5)`).  On
older kernels the `landlock` crate degrades automatically to whatever ABI level the
running kernel supports.  The outcome is reported as one of three `LandlockStatus`
variants and logged to stderr:

```
[Sandbox] Landlock inner sandbox: fully enforced (ABI V5).
[Sandbox] Landlock inner sandbox: partially enforced (kernel ABI < V5 — some access flags unavailable).
[Sandbox] Warning: Landlock LSM not supported on this kernel. Process filesystem access is unrestricted.
```

### ABI version compatibility

Each Landlock ABI version adds new access flags on top of the previous one.  The table
below shows what is gained or lost depending on the running kernel:

| ABI | Min kernel | New flag | Missing coverage if below this |
|-----|------------|----------|-------------------------------|
| V1 | 5.13 | All base flags: `ReadFile`, `WriteFile`, `MakeReg`, `Execute`, `ReadDir`, `RemoveFile`, `RemoveDir`, `MakeDir`, `MakeSym`, `MakeSock`, `MakeChar`, `MakeBlock`, `MakeFifo` | Core filesystem isolation — absent means no enforcement at all |
| V2 | 5.19 | `Refer` (cross-directory rename / hard-link) | Attacker could rename files across directories |
| V3 | 6.2  | `Truncate` | Attacker could truncate allowed files |
| V4 | 6.7  | TCP `bind` / `connect` control | Network restriction (filesystem sandbox unaffected) |
| V5 | 6.10 | `IoctlDev` (ioctl on device nodes) | Attacker could call ioctl on an allowed device node (e.g. `/dev/dri`) |

**"Partially enforced" is safe for Atom Vault's threat model.**  The protections that
matter — blocking reads of arbitrary home-directory files, blocking writes outside the
vault path, blocking file creation in wrong directories — are all V1 behavior and are
fully active on any kernel that supports Landlock at all (≥ 5.13).  The only gap on
kernels older than 6.10 is `IoctlDev`, which is a narrow vector with no practical
exploitation path in this context given the Flatpak outer cage.

### Core rules

Two privilege levels are applied:

| Level | `AccessFs` flags | Used for |
|---|---|---|
| Read-only + Execute (`ro_rights`) | `ReadFile \| ReadDir \| Execute` | System libraries, locale data, GPU device enumeration |
| Read-Write (`all_rights`) | All flags from `AccessFs::from_all(V5)` | The vault file, staging directory, GPU render node, Wayland/portal sockets |

Paths that do not exist on the running machine are silently skipped so the function is
safe to call on any distro configuration.

### The Landlock lifecycle — why activation is deferred

Landlock imposes an ordering constraint: the vault file path must be known **before**
`restrict_self()` is called, because afterwards only explicitly allowed paths are
accessible.  Activating the sandbox at process startup without a path would force a
choice between two bad options:

- Grant broad `/home` write access (defeats the purpose).
- Block all home directory writes (vault creation fails with a spurious "file already
  exists" error because `create_new(true)` gets EACCES from the kernel).

The solution is to defer sandbox activation to the exact moment the vault path is
resolved from the file-chooser portal.

```
Process start
│
├─ GUI init, egui/Wayland setup   (no Landlock yet)
│
├─ User clicks "Open Vault"
│   └─ XDG FileChooser portal runs (outside the process)
│       └─ User picks /home/user/Documents/my_vault.aegis
│
├─ poll_file_dialog_results() receives portal path
│   └─ apply_gui_vault_sandbox(&path)       ← restrict_self() here
│       RO: /usr  /etc  /sys
│       RW: /dev/dri  $XDG_RUNTIME_DIR  <vault path>  <staging dir>
│
└─ try_unlock() → load_vault_metadata()   (vault FD already held)
```

For vault **creation** the same deferred approach applies: the form is validated first;
the XDG save-file portal runs; `do_create_vault_at_path()` calls
`apply_gui_vault_sandbox()` with the chosen path before any KDF work or disk write.

### Creation vs. open — how the vault path rule differs

Landlock rules require an open file descriptor to the target path.  A file that does not
yet exist cannot be given a rule, so the two flows receive subtly different grants:

| Flow | File exists when sandbox activates? | Rule target | Scope |
|------|-------------------------------------|-------------|-------|
| **Open** | Yes | Exact file (`my_vault.aegis`) | Only that one file; siblings in the same directory are denied |
| **Create** | No | Parent directory (`Documents/`) | The directory chosen by the user in the save dialog; no access to `/home` or its other subdirectories |

When a user creates a vault and then opens it in the same session, the second
`restrict_self()` call layers a new domain on top of the first.  Because Landlock takes
the **intersection** of all active domains, access is tightened from "that directory"
down to "that specific file" — the ceiling only ever goes down, never up.

`/home` itself is never in any ruleset.  The narrowest possible grant is always used.

### GUI path — allowed paths and rationale

| Path | Level | Reason |
|---|---|---|
| `/usr` | RO+exec | egui, fontconfig, shared libraries, `bwrap` binary |
| `/etc` | RO+exec | locale, fontconfig, TLS certificates |
| `/sys` | RO+exec | Mesa `drmGetDevices()` reads `/sys/dev/char/<major>:<minor>/device/driver` to enumerate GPU nodes before opening `/dev/dri`; without this, Mesa falls back to software rendering with error `MESA-LOADER: failed to retrieve device information` |
| `/proc` | RO+exec | `sysinfo` reads `/proc/meminfo` for total-memory display and KDF parallelism calibration; without this, sysinfo returns 0 for all values |
| `/dev/dri` | RW | GPU render node (required by the Zink/Vulkan Mesa backend) |
| `$XDG_RUNTIME_DIR` | RW | Wayland socket, D-Bus socket, XDG portal IPC, Flatpak session info |
| `$XDG_RUNTIME_DIR/atom_staging` | RW | Staging area for encrypted-import workflow |
| `<vault path or parent>` | RW | Exact vault file on open; parent directory on create (see above) |

Everything else on the host filesystem — including the rest of `$HOME`, `/root`, other
users' home directories, `/var`, `/opt`, `/mnt` — is denied at the kernel level for the
remainder of the process lifetime.

### CLI path (`atom enter`) — allowed paths and rationale

The CLI does not use a GPU so `/sys` and `/dev/dri` are omitted.

| Path | Level | Reason |
|---|---|---|
| `/usr` | RO+exec | Shell helper binaries (`bwrap`, `flatpak`, `less`) |
| `/etc` | RO+exec | Locale, TLS certs for helper processes |
| `<vault path>` | RW | The vault file; `vacuum` must reopen it after compaction |
| `<staging dir>` | RW | `export` writes decrypted files here; `import` reads from here |

The Landlock domain is activated in `handle_enter()` immediately after
`load_vault_metadata()` completes.  At that point the vault file FD is already held;
Landlock restricts only **future `open()` calls**, so the existing open FD is unaffected
and vault read/write operations continue without interruption.

**Import security constraint**: Because the staging directory is the only writable
location outside the vault, the `import` shell command can only import files that have
been staged there beforehand.  Direct imports from arbitrary host paths are impossible
once the sandbox is active.  This is intentional.

### Thread-scope property — why Arti is unaffected

The P2P daemon (Arti embedded Tor client) is started in a background Tokio thread inside
`start_daemon_and_listener()` before the user opens any vault.  The Landlock domain is
applied on the **GUI/main thread** only.  Because Landlock is per-task, the already-
running Arti thread is not bound by the restriction.  This matters because Arti needs
access to its SQLite state database (`~/.atom_vault/`), its Ed25519 identity key, and the
Tor network — paths and resources that the GUI thread has no business touching after vault
selection.

---

## Layer 3 — Bubblewrap PDF Sandbox (`sandbox.rs: spawn_in_bwrap_sandbox`)

When a user runs the `view` command on an encrypted document, Atom Vault decrypts the
content into an anonymous `memfd_create` file descriptor (never touching disk) and then
launches `org.gnome.Papers` inside a **bubblewrap** (`bwrap`) container to display it.

### What bwrap does

[Bubblewrap](https://github.com/containers/bubblewrap) is an unprivileged namespace
container tool used by Flatpak for application isolation.  The Atom Vault wrapper calls
it directly to create a minimal, purpose-built container:

```
bwrap
  --unshare-ipc                     # isolated IPC namespace
  --unshare-net                     # no network access
  --unshare-uts                     # cannot change hostname
  --die-with-parent                 # killed when atom exits
  --new-session                     # no controlling TTY
  --clearenv                        # start with empty environment
  --setenv WAYLAND_DISPLAY …        # only the vars Papers needs
  --setenv XDG_RUNTIME_DIR …
  --setenv HOME …
  [--setenv DBUS_SESSION_BUS_ADDRESS …]
  --proc /proc  --dev /dev          # pseudo-filesystems
  --tmpfs /tmp                      # RAM-backed, not host /tmp
  --file <memfd>  /tmp/document.pdf # decrypted content into RAM
  --ro-bind /usr  /usr              # GTK runtime, flatpak binary
  --ro-bind /etc  /etc              # locale, fonts
  --ro-bind /sys  /sys              # GPU enumeration
  --ro-bind /var/lib/flatpak …      # system flatpak installations
  --ro-bind ~/.local/share/flatpak … # user flatpak installations
  --bind $XDG_RUNTIME_DIR …         # Wayland + portal sockets (RW)
  --bind <dbus socket> …
  --
  flatpak run --no-network --filesystem=/tmp:ro org.gnome.Papers /tmp/document.pdf
```

### Key hardening choices

**Decrypted content never hits the host filesystem.** The memfd is passed to bwrap via
`--file <fd>` which writes it into an in-RAM tmpfs mounted at `/tmp` inside the container.
When Papers exits, bwrap unmounts the tmpfs and the file is gone.  The memfd in the
parent process is sealed with `MFD_CLOEXEC` and only `dup()`'d (without `O_CLOEXEC`) for
the one inherited copy that bwrap reads.

**Network namespace isolation (`--unshare-net`).** Papers cannot make any network
connections.  This prevents a malicious PDF from exfiltrating data over the network even
if it achieves code execution inside Papers.

**IPC and UTS isolation.** `--unshare-ipc` prevents shared-memory IPC with host
processes.  `--unshare-uts` prevents the container from changing its hostname to
impersonate other processes.

**No user namespace isolation.** `--unshare-user` is deliberately absent.  Flatpak
requires the ability to create its own inner user namespace for Papers; unsetting it would
break the Papers launch.

**`--die-with-parent`.** If the Atom Vault process exits for any reason, the bwrap
container is killed.  This prevents orphaned Papers processes from continuing to hold a
copy of decrypted content after Atom Vault has shut down.

**`--no-network` for flatpak.** Passed to `flatpak run` in addition to `--unshare-net`
on bwrap itself.  Belt-and-suspenders: even if somehow bwrap's network unshare is
bypassed, Flatpak's own network isolation is still active inside Papers.

---

## Layer 4 — In-Process Memory Safety

The sandbox layers above restrict which files the process may touch.  These primitives
restrict how cryptographic key material is handled inside the process address space.

### Key and plaintext buffers

All cryptographic key material and plaintext content must be wrapped in types that
guarantee zeroing on drop:

- **`Zeroizing<T>`** (from the `zeroize` crate) — wraps `Vec<u8>` or fixed-size arrays;
  calls `volatile_write` + `compiler_fence` on drop so the compiler cannot elide the
  zeroing.
- **`ZeroizeOnDrop`** derive — applied to structs that own key material.
- **`secrecy::Secret<T>`** — combines zeroize-on-drop with debug-output redaction so key
  material is never accidentally printed to logs.

The DEK (Data Encryption Key) wrapped in the vault header and the per-session `UnlockedVault`
struct both use these types.  The KDF password buffer is a `Zeroizing<String>` that is
consumed (`std::mem::take`) immediately after use.

### In-memory file content (`memfd_create`)

Decrypted file content is never written to `/tmp` or any other disk-backed path.
`MemFile` in `vfs/mod.rs` wraps an anonymous file descriptor created via `memfd_create(2)`
with `MFD_CLOEXEC`.  The decrypted bytes live only in kernel page cache backed by
anonymous memory.  When the FD is closed the pages are released — no swap, no disk write,
no `MADV_FREE` delay.

### Password input hardening (`secure_input.rs`)

`read_password_pinentry()` reads the master password directly from the TTY
(bypassing `stdin`) then:

- Calls `mlock(2)` on the buffer to pin it in physical RAM and prevent it from being
  paged to swap.
- Calls `madvise(MADV_DONTDUMP)` on the buffer region so the password is excluded from
  kernel core dumps even if the process crashes.

### Panic hook and `catch_unwind`

The main entry points wrap their logic in `catch_unwind` with a custom panic hook.  If the
process panics unexpectedly the hook fires before the stack unwinds, giving the zeroize
destructors an opportunity to run and purge key material from memory before the process
exits.

### Compile-time hardening (`RUSTFLAGS`)

The Flatpak build passes `-C link-arg=-Wl,-z,relro,-z,now` in `RUSTFLAGS`:

- **`-z relro`** — marks the GOT (Global Offset Table) read-only after dynamic linking
  to prevent GOT-overwrite attacks.
- **`-z now`** — forces eager symbol resolution so no lazy-binding stubs remain writable
  after startup (full RELRO).

---

## Layer Interaction Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  Host OS                                                        │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Flatpak container (Layer 1)                              │  │
│  │  Visible filesystem: XDG portals only; no ~/home access   │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  Atom Vault process                                 │  │  │
│  │  │                                                     │  │  │
│  │  │  Landlock active (Layer 2) after vault selection:   │  │  │
│  │  │    RO: /usr  /etc  /sys  /proc                     │  │  │
│  │  │    RW: /dev/dri  $XDG_RUNTIME_DIR  <vault|dir>    │  │  │
│  │  │                                                     │  │  │
│  │  │  In-process (Layer 4):                              │  │  │
│  │  │    Zeroizing keys, memfd content, mlock passwords   │  │  │
│  │  │                                                     │  │  │
│  │  │  ┌─────────────────────────────────────────────┐   │  │  │
│  │  │  │  bwrap + Papers (Layer 3)                   │   │  │  │
│  │  │  │  --unshare-net/ipc/uts                      │   │  │  │
│  │  │  │  /tmp ← memfd (RAM only, never disk)        │   │  │  │
│  │  │  └─────────────────────────────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

| Attack surface | Mitigated by |
|---|---|
| Arbitrary file read from `$HOME` | Flatpak (no `--filesystem`) + Landlock (path allowlist) |
| Arbitrary file write | Landlock (only vault path and staging are RW) |
| Network exfiltration from PDF viewer | bwrap `--unshare-net` |
| Key material in core dump | `mlock` + `MADV_DONTDUMP` + Zeroizing drop |
| Key material in swap | `mlock` pins pages in RAM |
| Sensitive FDs inherited by child | `MFD_CLOEXEC` on memfds; only `dup()` for the one bwrap FD |
| Compiler elision of memset on keys | `zeroize` uses `volatile_write` + `compiler_fence` |
| GOT-overwrite attack | `-z relro,-z now` (full RELRO) |
| Orphaned PDF viewer after exit | bwrap `--die-with-parent` |
| P2P daemon inheriting vault Landlock | Landlock is per-task; daemon runs in a separate thread |
