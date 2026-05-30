# Atom Vault

Atom Vault is a security-focused, application-level Virtual File System (VFS) written in Rust. The project operates entirely in user space and provides encrypted file storage, memory protection mechanisms, secure deletion, and container maintenance utilities.

## Overview

Atom Vault stores files inside a custom container format (`.aegis`) using authenticated encryption and a metadata-driven architecture. The system focuses on protecting sensitive data both at rest and during runtime by combining cryptographic storage, memory sanitization, and secure lifecycle management.

## Container Layout

The container uses a structured byte layout consisting of a metadata pointer, reserved cryptographic space, encrypted payload chunks, and an encrypted metadata table.

```text
+------------------------------------------------------------+
| Offset 0 - 8   | Metadata Pointer (8 Bytes)                |
+------------------------------------------------------------+
| Offset 8 - 40  | Reserved Salt Area (32 Bytes)             |
+------------------------------------------------------------+
| Offset 40+     | Encrypted Data Chunks                     |
+------------------------------------------------------------+
| End of File    | Encrypted VaultMetadata Table             |
+------------------------------------------------------------+
```

## Security Features

### Ephemeral Mount Daemon

When a vault is unlocked, Atom Vault creates a detached background process using low-level Unix primitives such as `fork()` and `setsid()`.

Key characteristics:

* Keeps decrypted data accessible through isolated memory-backed storage.
* Runs independently from the controlling terminal.
* Communicates through a Unix Domain Socket.
* Supports graceful shutdown using signal handling for `SIGINT` and `SIGTERM`.

### Memory Protection

Sensitive information is protected during runtime through several mechanisms:

* Critical memory regions are locked using `mlock()` to reduce the risk of swapping sensitive data to disk.
* Plaintext buffers are wrapped with automatic zeroization mechanisms.
* Temporary cryptographic material is securely erased when no longer needed.

### Secure Deletion

File removal is implemented through crypto-shredding principles.

* Encryption metadata associated with deleted files is removed from the metadata index.
* Deleted content becomes cryptographically inaccessible.
* The approach avoids the limitations of traditional overwrite-based deletion on modern SSDs.

### Vacuum and Defragmentation

The `vacuum` operation reclaims unused space inside the container.

* Active encrypted chunks are copied into a new container structure.
* No decryption or re-encryption is required during migration.
* The original container is atomically replaced after completion.
* Container size is reduced by removing orphaned data blocks.

## Command Line Interface

### Create a Container

Create a new container with dynamic growth:

```bash
cargo run -- create
```

Create a preallocated container with a fixed size:

```bash
cargo run -- create --size 50
```

### Import Files

Import a file from the host filesystem into the vault:

```bash
cargo run -- import --from-disk sample.txt --vfs-name target_file.txt
```

### List Stored Files

Display the files currently stored in the vault:

```bash
cargo run -- ls
```

### Unlock the Vault

Start the background daemon and make vault contents available:

```bash
cargo run -- unlock
```

### Vacuum the Container

Remove unused space and compact the container:

```bash
cargo run -- vacuum
```

### Lock the Vault

Terminate background services and clear sensitive runtime state:

```bash
cargo run -- lock
```

## Technologies

* Rust
* AES-GCM authenticated encryption
* Unix Domain Sockets
* `memfd_create`
* `mlock`
* `zeroize`
* `signal-hook`
* `bincode`

## Project Goals

* Provide a secure application-level virtual file system.
* Minimize plaintext exposure in memory and storage.
* Support secure deletion through cryptographic techniques.
* Maintain portability while leveraging low-level operating system primitives.
* Explore practical applications of systems programming and security engineering in Rust.
