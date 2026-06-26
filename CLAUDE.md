# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Atom Vault** is a secure, application-level Virtual File System (VFS) written in Rust. It provides a cryptographic container for sensitive data with hardware-level memory isolation, ephemeral shell execution, and P2P vault synchronization over Tor — without requiring FUSE or kernel filesystem modifications.

## Commands

```bash
# Build
cargo build --release

# Run all tests
cargo test

# Run a specific test file
cargo test --test chunker_test
cargo test --test loopback        # P2P loopback test

# Integration test
chmod +x atom/integration-test.sh && ./atom/integration-test.sh

# Run (GUI launches when no args given)
cargo run -- create --vault-name my_vault
cargo run -- enter --vault-path ./my_vault.aegis
```

P2P live Tor tests require a local Tor daemon and manual .onion address configuration — see `/p2p-sync/testing_guide.md`.

## Architecture

**Workspace members**: `/atom` (main binary: CLI + GUI) and `/p2p-sync` (sync engine).

### Cryptographic Design (`atom/src/crypto/mod.rs`)

Two-layer key scheme: a password-derived **KEK** (Key Encryption Key) wraps the **DEK** (Data Encryption Key) stored in the vault header. Files are encrypted with XChaCha20-Poly1305 per-chunk with unique nonces. KDF is Argon2id by default (64 MiB, 3 iterations, 4 threads) or Scrypt (256 MiB). `calibrate_kdf()` auto-tunes parameters at vault creation. All sensitive buffers use `zeroize`/`secrecy` for automatic destruction.

### VFS Layer (`atom/src/vfs/mod.rs`)

Files are split by content-defined chunking (`atom/src/chunker.rs`, FastCDC v2020) with XOR-masked input to prevent chunk-boundary fingerprinting. Each chunk is independently encrypted and stored at byte offsets tracked in `ChunkEntry`. `VaultMetadata` is the in-memory catalog (file list + CDC salt) that is serialized, encrypted, and written to the vault header on save.

### Storage Header Layout (`atom/src/storage.rs`)

```
[master pointer 8B][KDF settings 13B][salt 32B][DEK nonce 24B][wrapped DEK 48B]
```

`load_vault_metadata()` / `save_vault_metadata()` handle header I/O with atomic sync guarantees.

### Ephemeral Shell (`atom/src/commands/enter.rs`, `shell.rs`)

Decrypted files are materialized into `memfd_create`-backed anonymous FDs (`MemFile` in `vfs/mod.rs`) that exist only in RAM, never touching disk. The interactive shell loop runs commands against these memory-backed file descriptors.

### Sandbox (`atom/src/sandbox.rs`)

Uses Linux Landlock LSM to confine child processes (e.g., Zathura PDF viewer) to `XDG_RUNTIME_DIR`, system libraries, and Wayland sockets only.

### P2P Sync Protocol (`p2p-sync/src/`)

Follows the Briar Protocol Stack (see `p2p-sync/p2p_sync_architecture.md`):

1. **Tor Transport** — Arti embedded client, Tor hidden services, 3-hop circuits
2. **Noise_XX** — Ephemeral key exchange with Ed25519 long-term identity verification (PFS)
3. **Yamux** — Concurrent stream multiplexing over the Noise-encrypted channel
4. **Vault Sync** — Merkle-tree state exchange → chunk-level incremental transfer

.onion addresses rotate daily via ephemeral Ed25519 key derivation (`p2p-sync/src/address.rs`).

### GUI (`atom/src/gui.rs`)

GTK4 interface that spawns the background P2P daemon in a dedicated thread. GTK main loop receives async Tokio events via a shared `Mutex` queue. Handles vault creation, file operations, and sync dialogs.

### Secure Input (`atom/src/secure_input.rs`)

Password input reads directly from the TTY (bypassing stdin), applies `mlock` to pin buffers in RAM, and uses `madvise(MADV_DONTDUMP)` to exclude them from core dumps.

## Memory Safety Conventions

- All cryptographic key material and plaintext buffers must use `Zeroizing<>`, `ZeroizeOnDrop`, or `secrecy::Secret<>`.
- The custom panic hook + `catch_unwind` wrappers ensure memory purge on unexpected termination — preserve these in new entry points.
- Staging temp files go to `$XDG_RUNTIME_DIR/atom_staging` (fallback: `~/.atom_vault/staging`), never `/tmp`.
