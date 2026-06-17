# Atom Vault

Atom Vault is a secure, application-level Virtual File System (VFS) written in Rust. It provides hardware-level memory isolation, cryptographic shredding, and an interactive ephemeral shell while avoiding the security and complexity concerns associated with FUSE-based architectures.

## Core Features

* Application-Level VFS with no FUSE dependencies.
* Ephemeral Shell powered by `memfd_create` for RAM-only plaintext handling.
* Strict memory sanitation through automatic buffer zeroization.
* Cryptographic file shredding with instant metadata and key destruction.
* Storage compaction through zero-crypto vacuum operations.
* Dynamic tail-based vault architecture for efficient storage management.
* Anti-forensics design preventing plaintext persistence on physical storage.
* Secure virtual file import, export, and management capabilities.

---

## Build and Installation

```bash
git clone https://github.com/YOUR_USERNAME/atom-vault.git
cd atom-vault
cargo build --release
```

---

## Testing and Usage Scenarios

The following scenarios demonstrate the complete lifecycle of the vault system and its security mechanisms.

### Scenario 1: Vault Initialization

Create a new vault container.

```bash
atom create --vault-name my_secure_vault
```

Expected Result:

* A new vault file named `my_secure_vault.aegis` is created.
* The user is prompted to define a master password.
* The initial vault size consists only of the vault header and metadata structures.

Verification:

```bash
ls -lh my_secure_vault.aegis
```

---

### Scenario 2: Entering the Ephemeral Shell and Importing Files

Create a test file and import it into the vault.

```bash
echo "Top Secret VFS Architecture Data" > host_secret.txt
dd if=/dev/zero bs=1M count=10 >> host_secret.txt 2>/dev/null
```

Enter the vault:

```bash
atom enter --vault-path my_secure_vault.aegis
```

Import the file:

```text
atom-vault> import host_secret.txt isolated_secret.txt
atom-vault> ls
```

Expected Result:

* `isolated_secret.txt` appears in the virtual file table.
* The encrypted payload is stored inside the vault container.
* The physical vault file grows according to the imported content size.

---

### Scenario 3: Volatile In-Memory Access

Display the file contents directly from the vault.

```text
atom-vault> cat isolated_secret.txt
```

Expected Result:

* Plaintext is temporarily reconstructed in memory.
* Data is processed through anonymous memory-backed file descriptors.
* Internal buffers are wiped immediately after command completion.

Verification:

* No plaintext files are created on the host filesystem.
* Data exists only during active command execution.

---

### Scenario 4: Secure File Export

Export the file back to the host operating system.

```text
atom-vault> export isolated_secret.txt extracted_data.txt
```

Expected Result:

* A file named `extracted_data.txt` is created.
* Exported content matches the original imported file.

Verification:

```bash
cat extracted_data.txt
```

---

### Scenario 5: Cryptographic Shredding

Remove the file from the vault.

```text
atom-vault> rm isolated_secret.txt
atom-vault> ls
```

Expected Result:

* The file disappears from the virtual file table.
* Metadata references are destroyed.
* Cryptographic material associated with the file is removed.

Note:

The physical vault size remains unchanged until compaction is performed.

---

### Scenario 6: Storage Compaction

Reclaim unused vault space.

```text
atom-vault> vacuum
```

Expected Result:

* Dead storage regions are eliminated.
* Active encrypted records are rewritten sequentially.
* Unused physical space is removed.

Exit the shell:

```text
atom-vault> exit
```

Verification:

```bash
ls -lh my_secure_vault.aegis
```

The vault size should return close to its original footprint if no active files remain.

---

## Automated Integration Testing

Run the complete vault lifecycle automatically.

```bash
chmod +x integration_test.sh
./integration_test.sh
```

The integration suite validates:

* Vault creation
* Authentication workflow
* File import
* File access
* File export
* Cryptographic deletion
* Storage compaction
* Data integrity checks

---

## Security Design Summary

* Plaintext never resides permanently on physical storage.
* Memory buffers are automatically sanitized after use.
* Cryptographic deletion removes access to protected data without expensive overwrite operations.
* Dynamic vault growth eliminates fixed-size container limitations.
* Storage compaction reclaims abandoned encrypted regions efficiently.
* The entire architecture operates in user space without kernel-level filesystem dependencies.
