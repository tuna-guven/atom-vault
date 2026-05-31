# Atom Vault: Secure Application-Level Virtual File System

Atom Vault is a security-focused Virtual File System (VFS) built on advanced Linux memory isolation mechanisms (`memfd_create`, `mmap`, `mlock`) and industry-standard cryptographic primitives (`Argon2id`, `XChaCha20-Poly1305`).

The system features a cryptographically isolated interactive shell (REPL) designed to prevent command history leakage and keep sensitive encryption keys protected exclusively in locked memory regions.

---

# Features

* Secure vault creation with encrypted metadata headers
* Argon2id-based master password key derivation
* XChaCha20-Poly1305 authenticated encryption
* Memory-locked cryptographic keys using `mlock`
* Anonymous in-memory file operations using `memfd_create`
* Automatic memory sanitization with secure zeroization
* Chunk-based storage architecture
* Interactive VFS shell (REPL)
* Secure file import and export operations
* Zero-trace file viewing without disk exposure
* Anti-forensics protections against shell history leakage

---

# End-to-End Testing Guide

This guide demonstrates how to validate the complete security pipeline of Atom Vault, from vault creation to secure file destruction.

## Step 1: Create a Sample File

Prepare a plaintext file that will later be imported into the vault.

```bash
echo "Computer Engineering Virtual File System Project Success Message!" > secret_note.txt
```

---

## Step 2: Create a New Encrypted Vault

Create a new vault container with an encrypted header and define the master password when prompted.

```bash
./target/debug/atom create --vault-path vault.aegis --vault-name "Secure Storage"
```

---

## Step 3: Enter the Secure Vault Shell

Authenticate using the master password and enter the isolated VFS shell.

```bash
./target/debug/atom enter --vault-path vault.aegis
```

Once authenticated, the Data Encryption Key (DEK) is securely loaded into locked memory.

Example prompt:

```text
atom-vault>
```

---

# Interactive Shell Operations

After entering the vault, execute the following commands to verify functionality.

## 1. List Vault Contents

```bash
atom-vault> ls
```

Since the vault is empty, no files should be displayed.

---

## 2. Import a File Into the Vault

Import and encrypt the file created earlier.

```bash
atom-vault> import secret_note.txt virtual_note.txt
```

During this process, the file is chunked, encrypted, and securely stored inside the vault.

---

## 3. Verify Imported Files

```bash
atom-vault> ls
```

You should now see the imported virtual file along with its metadata.

---

## 4. Zero-Trace Memory-Only Read Test

This is one of Atom Vault's most important security features.

Display file contents directly from anonymous memory without writing decrypted data to disk.

```bash
atom-vault> cat virtual_note.txt
```

Expected output:

```text
Computer Engineering Virtual File System Project Success Message!
```

The plaintext exists only in protected memory and is automatically destroyed afterward.

---

## 5. Export a File

Export and decrypt a file from the vault back to the host filesystem.

```bash
atom-vault> export virtual_note.txt exported_note.txt
```

After leaving the shell, verify file integrity:

```bash
cat exported_note.txt
```

---

## 6. Remove a File

Permanently remove file references and metadata mappings from the vault.

```bash
atom-vault> rm virtual_note.txt
```

Verify removal:

```bash
atom-vault> ls
```

The file should no longer appear in the vault.

---

## 7. Secure Shutdown

Exit the vault shell.

```bash
atom-vault> exit
```

All sensitive cryptographic material is securely wiped from memory before termination.

---

# Security Architecture Validation

## Anti-Forensics

Commands executed within the Atom Vault shell are isolated from the host shell environment and are not written to standard shell history files such as:

```text
.bash_history
.zsh_history
```

## Memory Isolation

Sensitive cryptographic keys remain locked in RAM using Linux memory protection mechanisms and are protected against accidental swapping.

## Zero-Trace File Viewing

The `cat` command never writes decrypted data to disk. Files are reconstructed inside anonymous memory-backed objects and automatically destroyed after use.

## Secure Memory Sanitization

Sensitive buffers are securely erased using explicit zeroization techniques before memory deallocation.

## Authenticated Encryption

All stored file chunks are protected using authenticated encryption, ensuring both confidentiality and integrity.

---

# Technology Stack

* Rust
* Linux Kernel APIs

  * `memfd_create`
  * `mmap`
  * `mlock`
* Argon2id
* XChaCha20-Poly1305
* Zeroize
* Secure REPL Architecture

---

# Project Goal

Atom Vault was developed as an educational and research-oriented cybersecurity project to explore secure storage systems, memory-safe cryptographic engineering, and application-level virtual filesystem design on Linux platforms.
