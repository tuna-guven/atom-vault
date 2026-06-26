# Bubblewrap PDF Sandbox

This document describes how `atom/src/sandbox.rs` opens a decrypted PDF inside a
bubblewrap container without writing plaintext to disk, and how to run and
interpret its tests.

---

## Overview

When the user opens a file from the vault, `view.rs` decrypts the ciphertext
chunks into a `memfd` — an anonymous, kernel-backed file descriptor that lives
entirely in RAM. No path exists for it in the filesystem. The sandbox then
hands this fd to bubblewrap, which transfers the content into a private in-RAM
`tmpfs` inside a restricted container and launches `org.gnome.Papers` to
display it.

```
atom process                     kernel                    bwrap container
──────────────────               ──────────────────        ─────────────────
view.rs
  └─ decrypt chunks
  └─ write → memfd (RAM)
  └─ seal memfd (read-only)
  └─ spawn_in_bwrap_sandbox()
       └─ dup(memfd) ─────────────── inherited_fd ──────► bwrap --file <fd>
                                                               └─ copy → /tmp/document.pdf (tmpfs)
                                                               └─ flatpak run org.gnome.Papers
                                                                    └─ Papers reads /tmp/document.pdf
                                                               └─ Papers exits
                                                               └─ tmpfs unmounted → file gone
  └─ waitpid(bwrap_pid)
  └─ zero + drop memfd
```

---

## Code Walk-Through

### 1. `spawn_in_bwrap_sandbox(target_fd)` — entry point

Located at `sandbox.rs:13`.

**Step 1 — dup without `O_CLOEXEC`**

```rust
let inherited_fd = unsafe { libc::dup(target_fd) };
```

The memfd is created in `view.rs` with `close_on_exec(true)`. `O_CLOEXEC` means
the fd is automatically closed in any child process that calls `exec`. Because
bwrap is launched via `execvp`, the original memfd would vanish before bwrap
could read it. `dup()` creates a second reference to the same underlying file
description, and `dup()` never copies the `O_CLOEXEC` flag, so the duplicate
survives into bwrap's process space.

The `test_dup_fd_has_no_cloexec` unit test verifies this property directly.

**Step 2 — `lseek` to the beginning**

```rust
libc::lseek(inherited_fd, 0, libc::SEEK_SET);
```

The memfd's write pointer was left at the end after `view.rs` finished writing
all decrypted chunks. Rewinding is required so bwrap reads from byte 0.

**Step 3 — build args and fork/exec**

`build_bwrap_args()` assembles the complete argument list. The parent forks;
the child calls `execvp("bwrap", ...)`. The parent closes `inherited_fd` (the
child has its own copy) and returns the PID to the background thread in
`view.rs`, which `waitpid`s and then zeroes and drops the original memfd.

---

### 2. `build_bwrap_args(...)` — argument construction

Located at `sandbox.rs:67`. Accepts all environment values as parameters
(no `env::var` calls inside) to make it deterministic and unit-testable.

#### Namespace flags

| Flag | Effect |
|---|---|
| `--unshare-net` | New network namespace — no connectivity |
| `--unshare-ipc` | New IPC namespace — no shared memory with host |
| `--unshare-uts` | New UTS namespace — separate hostname |
| *(no `--unshare-user`)* | User namespace stays shared so flatpak can create its own inner user namespace |

#### Environment hardening

`--clearenv` wipes all inherited environment variables. Only four are
re-injected via `--setenv`:

- `WAYLAND_DISPLAY` — Papers needs to find the compositor socket
- `XDG_RUNTIME_DIR` — Wayland socket, D-Bus socket, and flatpak session info live here
- `HOME` — GTK looks up font and theme config under `$HOME`
- `DBUS_SESSION_BUS_ADDRESS` — flatpak portals communicate over D-Bus

#### Filesystem restrictions

```
/proc          --proc   (fresh procfs)
/dev           --dev    (minimal devtmpfs: null, zero, random, tty…)
/dev/fuse      --dev-bind  (if present; required by xdg-document-portal)
/tmp           --tmpfs  (empty in-RAM tmpfs — only the PDF lives here)
/usr           --ro-bind
/etc           --ro-bind
/sys           --ro-bind
/lib, /lib64   --ro-bind  (only when real directories; symlinks on Fedora are skipped)
/var/lib/flatpak            --ro-bind  (system flatpak installation)
~/.local/share/flatpak      --ro-bind  (user flatpak installation, if present)
$XDG_RUNTIME_DIR            --bind (read-write; flatpak writes session info here)
$DBUS_SOCKET_PATH           --bind (read-write; portal IPC)
```

Home directory, `/root`, network paths, and everything else are absent from
the container's filesystem view.

#### PDF delivery — `--file FD DEST`

```
--file <inherited_fd> /tmp/document.pdf
```

bwrap reads from `inherited_fd` sequentially and creates `/tmp/document.pdf`
inside the container's `tmpfs`. This is the only copy of the plaintext visible
to Papers. When bwrap exits, the tmpfs is unmounted and the file ceases to
exist.

#### flatpak invocation

```
flatpak run --no-network --filesystem=/tmp:ro org.gnome.Papers /tmp/document.pdf
```

- `--no-network`: belt-and-suspenders on top of `--unshare-net`
- `--filesystem=/tmp:ro`: grants Papers' inner flatpak sandbox read-only access
  to the outer bwrap's `/tmp`, where the PDF lives. Without this flag flatpak
  would not expose `/tmp` to Papers at all.

#### Why user namespace is not unshared

`flatpak run` launches Papers by calling `bwrap` internally with
`--unshare-user`. Creating a user namespace requires the caller to already be
in an unprivileged user namespace OR to have the `CAP_SYS_ADMIN` capability.
If our outer bwrap unshared the user namespace, flatpak's inner bwrap would
have no unprivileged path to create its own. Leaving `--unshare-user` out lets
flatpak proceed normally, and flatpak then applies its own (stricter, per-app)
restrictions to Papers.

---

### 3. `extract_dbus_socket_path(addr)` — D-Bus socket parser

Located at `sandbox.rs:155`. Parses `DBUS_SESSION_BUS_ADDRESS` values of the
form:

```
unix:path=/run/user/1000/bus;guid=abc123
```

Returns `None` for abstract sockets (`unix:abstract=...`) because abstract
namespace sockets have no filesystem path to bind-mount. If `None` is returned,
the D-Bus socket is simply omitted from the bwrap args; Papers may still work
if the portal socket is accessible via `$XDG_RUNTIME_DIR`.

---

## Running the Tests

### Prerequisites

| Requirement | Check |
|---|---|
| Rust toolchain | `rustc --version` |
| bubblewrap ≥ 0.4 | `bwrap --version` |
| `cat`, `ping`, `sh` in `/usr/bin` or `/usr/sbin` | present on any standard Linux system |

Install bubblewrap on Fedora:
```bash
sudo dnf install bubblewrap
```

### Unit tests (no bwrap required)

These test pure Rust logic and fd semantics using only `libc` primitives.

```bash
# Run all unit tests inside sandbox.rs
cargo test --lib sandbox

# Run a specific test by name
cargo test --lib sandbox::tests::test_dbus_parse_path_with_guid
cargo test --lib sandbox::tests::test_args_network_is_unshared
cargo test --lib sandbox::tests::test_dup_fd_has_no_cloexec
```

Full list of unit tests:

| Test | What it verifies |
|---|---|
| `test_dbus_parse_standard_path` | Minimal `unix:path=...` parses correctly |
| `test_dbus_parse_path_with_guid` | `guid=` suffix after path= is ignored |
| `test_dbus_parse_guid_before_path` | `path=` is found anywhere in the semicolon list |
| `test_dbus_parse_comma_separated_picks_first_path` | First `unix:path=` wins when addresses are comma-separated |
| `test_dbus_parse_abstract_socket_returns_none` | Abstract sockets return `None` |
| `test_dbus_parse_empty_returns_none` | Empty string returns `None` |
| `test_dbus_parse_non_unix_transport_returns_none` | TCP transports return `None` |
| `test_args_first_element_is_bwrap` | Argv[0] is always `"bwrap"` |
| `test_args_network_is_unshared` | `--unshare-net` is present |
| `test_args_ipc_is_unshared` | `--unshare-ipc` is present |
| `test_args_uts_is_unshared` | `--unshare-uts` is present |
| `test_args_user_namespace_not_unshared` | `--unshare-user` is **absent** |
| `test_args_die_with_parent_present` | `--die-with-parent` is present |
| `test_args_new_session_present` | `--new-session` is present |
| `test_args_clearenv_present` | `--clearenv` is present |
| `test_args_tmpfs_on_tmp` | `--tmpfs /tmp` is present |
| `test_args_file_fd_correct` | `--file <fd> /tmp/document.pdf` uses the right fd number |
| `test_args_pdf_destination_is_tmp` | Destination path is `/tmp/document.pdf` |
| `test_args_ends_with_flatpak_papers` | Final command is `flatpak run ... org.gnome.Papers /tmp/document.pdf` |
| `test_args_no_network_flag_for_flatpak` | `--no-network` passed to flatpak |
| `test_args_filesystem_tmp_ro_flag` | `--filesystem=/tmp:ro` passed to flatpak |
| `test_args_wayland_display_set` | `WAYLAND_DISPLAY` is injected via `--setenv` |
| `test_args_xdg_runtime_dir_set` | `XDG_RUNTIME_DIR` is injected via `--setenv` |
| `test_args_home_set` | `HOME` is injected via `--setenv` |
| `test_args_dbus_address_included_when_set` | D-Bus address is injected when non-empty |
| `test_args_dbus_omitted_when_empty` | D-Bus is absent when address is empty |
| `test_dup_fd_has_no_cloexec` | `dup()` of a `O_CLOEXEC` fd yields a fd without that flag |

### Integration tests (bwrap required)

These spawn real bwrap processes and exercise the mechanisms the sandbox
depends on.

```bash
# Run all integration tests
cargo test --test sandbox_test

# Run a single integration test
cargo test --test sandbox_test test_bwrap_file_fd_passes_memfd_content

# Skip integration tests on systems without bwrap
SKIP_BWRAP_TESTS=1 cargo test --test sandbox_test
```

| Test | What it verifies |
|---|---|
| `test_bwrap_is_installed` | bwrap is present and reports a version |
| `test_bwrap_file_fd_passes_memfd_content` | A memfd without `O_CLOEXEC` is inherited by bwrap; `--file` copies its bytes into the container's tmpfs; `cat` reads back the exact payload |
| `test_bwrap_network_is_unshared` | `--unshare-net` makes `ping` fail inside the container |
| `test_bwrap_tmpfs_does_not_leak_to_host` | A file written to `/tmp` inside the container is absent from the host after bwrap exits |
| `test_bwrap_file_dest_is_readonly` | The destination file created by `--file` cannot be overwritten by a process inside the container |

### Running everything

```bash
# All tests (unit + integration); bwrap must be installed
cargo test -p atom

# Unit tests only (no bwrap)
cargo test -p atom --lib

# Integration tests only
cargo test -p atom --tests
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| Plaintext never touches disk | memfd lives in RAM; tmpfs lives in RAM; both are gone after bwrap exits |
| Papers cannot reach the network | `--unshare-net` + `flatpak run --no-network` |
| Papers cannot read the host filesystem | Only `/usr`, `/etc`, `/sys`, flatpak dirs, and the tmpfs are mounted |
| Papers cannot write to the PDF | `--file` creates a read-only file in the tmpfs |
| bwrap dies if atom is killed | `--die-with-parent` |
| Papers cannot hijack atom's terminal | `--new-session` |
| Papers cannot escalate privileges | flatpak enforces `PR_SET_NO_NEW_PRIVS` inside its own bwrap invocation |
| Environment is clean | `--clearenv` removes all host env vars before the four allowed ones are set |
