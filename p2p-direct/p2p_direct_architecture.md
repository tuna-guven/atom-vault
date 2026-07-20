# `p2p-direct` — Non-Tor Mode A (Blind Store) Architecture

> Sibling crate to `p2p-sync` (Tor). Implements the **broker-free, non-Tor**
> transfer mechanism specified in the project `CLAUDE.md`. This document
> describes the architecture as built. A sequence diagram and a formal threat
> model will be layered on top of it later (see [§9](#9-planned-follow-ups)).

---

## 1. Purpose and scope

`p2p-direct` moves a large encrypted Atom vault to a single high-risk recipient
**without Tor and without any connection broker**. It implements **Mode A**
(async, via a blind object store) from the spec. Mode L (live QUIC hole-punch)
is out of scope for this crate today.

The design resolves the spec's hard constraint (`async` + `pure-P2P` +
`no-broker` are not simultaneously satisfiable) by keeping **zero connection
brokers** and filling the async gap with a **blind content store** that learns
nothing about the peer relationship — only an anonymous `PUT` and a later
anonymous `GET` of opaque, padded ciphertext.

What the store sees:

- N + 1 objects of opaque, random 32-byte IDs.
- Every block object is byte-for-byte the same length (`block_size + 16`).
- One manifest object (also encrypted).
- **Never**: plaintext, filenames, true size, block boundaries, the root key,
  or any link between uploader and downloader.

---

## 2. Layer model

The spec's layered design is realised as four modules. Crypto is identical to
what a future Mode L transport would use; only L1 differs.

```
+-------------------------------------------------------------+
| L4  pake.rs      short SPAKE2 secret -> sealed ReadCap       |  out-of-band
+-------------------------------------------------------------+
| L3  encode.rs    stream -> fixed blocks + decoy ladder       |  local, no secrets
+-------------------------------------------------------------+
| L2  crypto.rs    per-block AEAD, HKDF keys, commitment        |  local
+-------------------------------------------------------------+
| L1  store.rs     BlindStore PUT/GET  (Mode A)                 |  wire
+-------------------------------------------------------------+
```

**Core principle (from the spec):** L4 carries only a *short secret* through the
hardest-to-surveil channel; L1 carries only *padded ciphertext*. The `root_key`
/ full read-cap must never appear on L1. This is enforced structurally: `upload`
puts only ciphertext and random IDs to the store; the cap is returned to the
caller for L4 delivery.

---

## 3. Module map

| Module | Layer | Secrets? | I/O? | Responsibility |
|--------|-------|----------|------|----------------|
| `crypto.rs` | L2 | yes | no | AEAD, key derivation, commitment, CSPRNG helpers |
| `encode.rs` | L3 | no | no | Block framing math, the decoy ladder, the `Manifest` type |
| `pake.rs`   | L4 | yes | no | SPAKE2 handshake, cap sealing |
| `store.rs`  | L1 | no* | yes | `BlindStore` backends + `upload`/`download` orchestration |
| `lib.rs`    | —  | —   | no | `Error`, `ReadCap` |

\* `store.rs` handles ciphertext and derives keys via `crypto`, but treats the
store itself as untrusted and content-only.

---

## 4. L2 — Object encryption (`crypto.rs`)

- **AEAD:** XChaCha20-Poly1305, 24-byte random nonce per block (extended nonce
  means random selection is safe across a very large block count — no counter
  reuse risk). Tag is 16 bytes. Ciphertext length = plaintext + 16.
- **Convergence-free key derivation** (spec §5 — convergent encryption is
  *banned*):
  ```
  block_key_i    = HKDF-SHA256(root_key, info = "atom-block-v1|" || i_le32)
  manifest_key   = HKDF-SHA256(root_key, info = "atom-manifest-v1")
  ```
  Keys depend only on the root and the block **index**, never on block content,
  so an adversary who guesses a block's plaintext cannot confirm its presence.
- **Label separation** between block and manifest keys keeps the door open for a
  future manifest-cap / block-read-cap split (Tahoe-LAFS style).
- **Commitment:** `commitment = SHA256("atom-cap-commitment-v1" || root_key)`.
  Published out-of-band so a recipient can bind received blocks to the cap.
- **`RootKey`** is a `Zeroizing<[u8; 32]>` — wiped on drop. All derived keys are
  `Zeroizing` too.
- **Randomness** comes from the OS CSPRNG via `getrandom::fill`. A failure is
  treated as unrecoverable (panic) — correct for a security tool.

A known-answer test pins the exact HKDF wiring so a dependency bump that
silently changes derivation is caught. AEAD round-trip and tamper-rejection
tests guard the seal/open path.

---

## 5. L3 — Vault encoding (`encode.rs`)

Contains **no secrets and no I/O** — pure framing math, independently testable.

1. **Framing.** The input byte stream is split into fixed-size blocks
   (`DEFAULT_BLOCK_SIZE = 1 MiB`). The final real block is **zero-padded** up to
   full size, so every block that reaches L1 is exactly the same length. The
   true length lives only in the manifest.
2. **Decoy ladder.** The real block *count* is rounded **up** a coarse quantized
   ladder; the gap is filled with random decoy blocks (created in `store.rs`).

   | `Ladder` variant | Rounding | Use |
   |------------------|----------|-----|
   | `NextPowerOfTwo` | up to next 2ⁿ | **default** — ≤2× overhead, coarse buckets |
   | `MultipleOf(n)`  | up to next multiple of n | tunable coarseness |
   | `Exact`          | none | tests / explicitly lower-risk |

   Example: a 5.0 GB (5120 × 1 MiB) and a 6.3 GB (6451) vault both land on
   **8192** blocks — indistinguishable by count.
3. **Manifest.** The only artifact that knows the truth:
   ```
   Manifest {
     version:    u16,
     block_size: u32,
     real_len:   u64,              // true plaintext length
     blocks:     Vec<BlockRef>,    // real + decoy, shuffled
   }
   BlockRef { object_id: [u8;32], nonce: [u8;24], index: Option<u32> }
   ```
   `index = Some(i)` marks real block `i` (and drives its HKDF key);
   `index = None` marks a decoy. Because real blocks carry an explicit index,
   the `blocks` vector can be **shuffled**, so the store learns nothing from
   object order.

Property tests assert the ladder is always covering (`total ≥ real`), lands on
its quantization, and that framing handles empty / exact-multiple / partial-last
cases.

---

## 6. L1 / Mode A — Blind store (`store.rs`)

### `BlindStore` trait

```rust
#[async_trait]
pub trait BlindStore: Send + Sync {
    async fn put(&self, id: &[u8; 32], data: &[u8]) -> Result<(), Error>;
    async fn get(&self, id: &[u8; 32]) -> Result<Vec<u8>, Error>;
}
```

Backends:
- **`InMemoryStore`** — for tests and local round-trips. Exposes `len()` and
  `object_lengths()` for test assertions.
- **`HttpStore`** *(feature `http-store`, on by default)* — `PUT`/`GET`
  `<base>/<hex-id>` over HTTPS (rustls). The endpoint only serves opaque IDs and
  performs no auth of its own, so it cannot link uploader to downloader. Disable
  the feature for a dependency-light, in-memory-only build.

### `upload` — L3 → L2 → L1

Streams block-by-block (≤1 block held in RAM at a time):

1. Read a padded block → derive `block_key_i` → seal with a random nonce → PUT
   under a random object ID → record a real `BlockRef`.
2. After EOF, compute `total = ladder.total_blocks(real)` and PUT
   `total - real` **decoy** blocks: random bytes of length `block_size + 16`
   (indistinguishable from real ciphertext), each under a random ID.
3. **Shuffle** all `BlockRef`s (Fisher–Yates over the OS CSPRNG).
4. Serialize the manifest (bincode), seal with `manifest_key` + random nonce,
   and PUT it under a random `manifest_id` as `nonce || ciphertext`.
5. Return `ReadCap { root_key, manifest_id }` for **L4** delivery.

### `download` — L1 → L2 → L3

1. GET `manifest_id`, split `nonce || ciphertext`, open with `manifest_key`
   (derived from the cap's root), deserialize.
2. Reject unknown versions; cross-check the real-block count against what
   `real_len` implies.
3. For each real block in **index order** (decoys ignored): GET, derive
   `block_key_i`, open (AEAD tag verifies integrity), assert full block length,
   write only the non-padding bytes (trim the last block using `real_len`).
4. Assert reassembled length == `real_len`.

Reassembly is by `index`, never by store order, so shuffling is transparent.

---

## 7. L4 — Capability delivery (`pake.rs`)

The read-cap is **never sent directly**. The two humans share a short, single-
use secret out-of-band (~a few words / ~50 bits). Both expand it via **SPAKE2**
(symmetric variant, Ed25519 group, shared context identity `atom-vault-cap-v1`)
into a strong ephemeral channel key. One round trip:

```
sender:    (state, msg_s) = start(secret)
recipient: (state, msg_r) = start(secret)
--- exchange msg_s / msg_r over the OOB channel ---
sender:    key = state.finish(msg_r);  sealed = seal_cap(key, cap)
recipient: key = state.finish(msg_s);  cap    = open_cap(key, sealed)
```

- Both sides derive the same `key` **iff** they used the same short secret. A
  wrong secret yields a different key; the AEAD `open_cap` then fails and **no
  cap leaks** — online guessing is limited to one attempt per handshake.
- `seal_cap` derives a distinct sealing key
  (`HKDF-SHA256(spake2_key, "atom-cap-seal-v1")`) and encrypts the 64-byte cap
  (`root_key(32) || manifest_id(32)`) with XChaCha20-Poly1305. Output is
  `nonce || ciphertext`.
- The transport of the two SPAKE2 messages + sealed cap is intentionally left to
  the out-of-band channel (the spec's "hardest-to-surveil channel"); this crate
  provides only the primitives, not a rendezvous.

---

## 8. Current status and limitations

**Done:** L2/L3/L4 + Mode A L1, end-to-end, with 16 passing tests (crypto KAT +
tamper, ladder property tests, SPAKE2 round-trip/wrong-secret, and full
`encode→PUT→SPAKE2 cap→GET→decode` round-trips).

**Not yet done (tracked next steps):**
- **CLI/GUI integration** into the `atom` binary (e.g. `push` / `pull <cap>`).
  The library is standalone and transport-complete; the UX for the OOB steps is
  a separate increment.
- **k-of-n multi-store erasure** (spec §6): the spec recommends spreading blocks
  across n stores so no single store sees the whole set, for a targeted
  recipient. Today: single store.
- **`HttpStore` live-server integration test** (in-memory store is fully
  covered; the HTTP path is not yet exercised against a real endpoint).
- **Egress hardening** (VPN/one-shot egress for the upload) is an operational
  concern documented in the spec, not enforced by code.

**Non-goals (per spec):** anonymity from a global passive adversary (that is
Tor's job, explicitly excluded here). Mode A avoids peer co-occurrence on the
wire entirely, but the store operator sees the upload/download events
themselves (from whatever egress the peer uses).

---

## 9. Planned follow-ups

- **Sequence diagram** — the full sender→store→recipient timeline including the
  OOB SPAKE2 exchange and commitment check.
- **Threat model** — a structured pass over the three spec adversary axes (IP
  exposure, timing/correlation, size/structure fingerprinting) mapped to the
  concrete mitigations above, plus residual risks (store-operator visibility,
  egress metadata, OOB channel compromise).

---

## Appendix: dependencies

Resolved at build time (not pinned from memory, per spec §8):
`chacha20poly1305` 0.11, `hkdf` 0.13 + `sha2` 0.11, `spake2` 0.4 (Ed25519
group), `getrandom` 0.4, `zeroize`, `bincode` 1.3 + `serde`, `async-trait`,
`tokio`, and (optional) `reqwest` 0.13 with rustls for `HttpStore`.
