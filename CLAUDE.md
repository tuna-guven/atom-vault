# ATOM Vault — Non-Tor P2P Sharing Mechanism (CLAUDE.md)

> Project brief for Claude CLI. This file is the authoritative spec. Build against
> it. When a decision is ambiguous, prefer the option that leaks less metadata,
> and surface the tradeoff rather than silently choosing.

---

## 0. One-paragraph summary

A broker-free, non-Tor mechanism for transferring a large (5GB+) encrypted vault
to a single high-risk recipient. Connection setup uses **manual out-of-band ticket
exchange** (no discovery server, no relay pool, no rendezvous broker). Transport is
**QUIC over a directly hole-punched UDP path** when both peers can be online
together, or a **blind ciphertext store** (dumb object storage, content-only) when
the transfer must be time-decoupled. In both modes the store/network sees only
padded ciphertext; identity, key agreement, and capability delivery ride a
separate short-secret channel expanded via PAKE.

---

## 1. Hard constraint the design resolves

The requested properties `async` + `pure-P2P` + `no-broker` are not simultaneously
satisfiable: async requires the bytes to exist somewhere while both peers are
offline, and "somewhere" is a third party. Resolution adopted:

- **No connection broker** is treated as the firm requirement (manual address
  exchange, per user decision).
- The async gap, *when needed*, is filled by a **blind store** that brokers
  nothing about the connection — it holds padded ciphertext and never observes a
  peer relationship, only an anonymous PUT and a later anonymous GET.
- **Two operating modes** are therefore specified. Mode L (live) is pure-P2P and
  fully broker-free. Mode A (async) adds only the blind store. The recipient's
  situation selects the mode; the crypto and capability layers are identical
  across both.

Do not attempt to build a mode that is simultaneously async, storage-less, and
third-party-less. It is impossible, not merely hard.

---

## 2. Threat model (target: maximize across all three)

Adversary is assumed to observe network metadata at scale and to specifically
target the recipient. Harden equally against:

1. **IP exposure between peers** — the peer-to-peer relationship must not be
   observable to any service. In Mode L only the two endpoints' ISPs see a UDP
   flow to each other; no third service learns the pairing. In Mode A the two
   peers never co-occur on the wire at all.
2. **Timing / correlation** — upload and download decoupled in time (Mode A);
   in Mode L, cover traffic + constant-rate pacing so start/stop and volume do
   not track real payload boundaries.
3. **Size / structure fingerprinting** — the vault is transformed into
   fixed-size padded blocks before it ever touches the wire or store. No
   filenames, no directory structure, no per-file sizes cross the boundary.

Non-goals: this is not anonymity-from-a-global-passive-adversary (that is Tor's
job and the user explicitly excluded Tor). Mode L reveals to each peer's ISP that
*a* UDP flow to the other IP occurred. If that pairing itself must be hidden,
Mode L is the wrong tool and the user should be told so explicitly.

---

## 3. Architecture — layers (identical crypto in both modes)

```
+-------------------------------------------------------------+
| L4  Capability delivery   short PAKE seed -> read-cap        |  out-of-band
+-------------------------------------------------------------+
| L3  Vault encoding        cleartext tree -> padded blocks    |  local
+-------------------------------------------------------------+
| L2  Object encryption     per-block AEAD, convergence-free   |  local
+-------------------------------------------------------------+
| L1  Transport             Mode L: QUIC/hole-punch            |  wire
|                           Mode A: blind store PUT/GET        |
+-------------------------------------------------------------+
| L0  Bootstrap             manual ticket exchange (no broker) |  out-of-band
+-------------------------------------------------------------+
```

The design principle: **L0 and L4 travel through the hardest-to-surveil channel
you have and carry only short secrets. L1 carries only padded ciphertext.** Never
put a full read-cap on any channel an adversary might log — put a *seed* that
derives it (Syncthing/Magic-Wormhole bootstrap pattern).

---

## 4. L3 — Vault encoding (kills structure + size fingerprinting)

Before anything touches L1, transform the vault:

1. **Serialize** the whole tree into a single stream (e.g. a tar-like container).
   Filenames, mtimes, and directory structure now live *inside* the stream and
   will be encrypted in L2 — none of it is visible as transport metadata.
2. **Split** the stream into fixed-size blocks. Recommend **1 MiB** blocks.
   Every block is exactly block-size; the final block is zero-padded to full size.
3. **Pad the block count** up to a value drawn from a coarse quantized ladder
   (e.g. round total block count up to the next power of two, or next multiple of
   1024) by appending decoy blocks of random bytes. This ensures a 5.0 GB and a
   6.3 GB vault can present the same on-wire block count.
4. Emit a **manifest**: an ordered list of block IDs, per-block AEAD nonces, and
   which blocks are decoys. The manifest is itself encrypted and treated as
   block 0's payload (or a separate cap). The manifest is the only thing that
   knows the real length; nothing on the wire does.

Result: L1 sees N identical opaque blocks. No filename, no file boundary, no true
size crosses the trust boundary.

---

## 5. L2 — Object encryption

- Per-block AEAD: **XChaCha20-Poly1305** (24-byte random nonce, no counter-reuse
  risk across a large block count).
- **Do NOT use convergent / content-derived keys.** Convergent encryption (as in
  some dedup systems and IPFS-adjacent designs) leaks equality: an adversary who
  guesses a block's plaintext can confirm its presence. For a targeted recipient
  this is a real attack. Every block key is derived from a per-vault random root
  via HKDF: `block_key_i = HKDF(root_key, "atom-block" || i)`.
- The **root_key** is what the read-cap ultimately grants access to. It never
  transits L1. It is derived at L4.
- Manifest and block payloads use distinct HKDF labels so a manifest cap and a
  block-read cap can be separated later (mirrors Tahoe-LAFS read-cap/verify-cap
  separation — keep the door open for that even if v1 uses one cap).

---

## 6. L1 — Transport

### Mode L — live, pure-P2P, broker-free (QUIC + manual hole punch)

Use when both peers can be online together. No discovery server, no relay.

1. **Manual ticket exchange (L0).** Each peer runs the tool once to produce a
   *ticket*: `{ ed25519_pubkey, observed_external_ip:port (via one STUN query OR
   manually entered), quic_alpn, cap_commitment }`. Tickets are exchanged
   out-of-band by the humans (the same trusted channel used for the PAKE seed).
   No online directory ever holds a ticket.
   - STUN is optional and is the *only* borderline third-party touch in Mode L.
     If even a STUN server is unacceptable, peers enter their external
     `ip:port` manually (router UPnP mapping or known static IP). Document both
     paths; default to manual entry for maximum purity, STUN as a convenience
     opt-in with an explicit warning that a STUN server learns your IP.
2. **Simultaneous open.** Both sides start sending QUIC initial packets to each
   other's ticket address at an agreed wall-clock time (or via a
   send-until-connected loop). Stateful NATs on both sides see outbound-first
   packets and hold the return path open → direct path forms. QUIC's
   UDP+connection-migration behavior suits this better than TCP.
3. **Mutual auth = key-hash identity.** The QUIC TLS handshake is pinned to the
   ed25519 keys from the tickets (raw public keys, RFC 7250, or a self-signed
   cert whose SPKI hash == the ticket key). No CA. MITM requires the peer's
   private key. This is the Syncthing device-ID primitive.
4. **Pacing + cover.** Send padded blocks at a **constant rate** with the QUIC
   stream kept busy by decoy blocks so the flow's rate and duration are
   independent of real payload size. Ramp down over a randomized tail so the
   stop time doesn't mark the true end.

Broker count in Mode L: **zero** (STUN optional and off by default).

### Mode A — async via blind store (adds one dumb, content-only store)

Use when peers cannot be online together.

1. Sender PUTs the N padded blocks + encrypted manifest to a **blind object
   store** under random opaque object IDs. The store is *any* dumb key-value
   blob store the sender can write to anonymously (self-hosted S3-compatible,
   or a plain HTTPS PUT endpoint). The store never sees plaintext, filenames,
   real size, or the recipient.
2. Access is via **bearer capability**: knowledge of the object-ID set + root_key
   is sufficient to fetch and decrypt. The store performs no auth of its own
   beyond "serve this opaque ID," so it cannot link uploader to downloader.
3. Recipient GETs the blocks later. Upload and download are **decoupled in time**
   → no timing correlation, no IP-pairing, ever.
4. Harden the store touch: sender uploads from behind a VPN/one-shot egress; pad
   the object count per §4; randomize object IDs; optionally spread blocks across
   more than one store (k-of-n erasure, Tahoe-LAFS style) so no single store sees
   the whole set. **This erasure-coding split is the answer to your open
   "storage backend topology" decision — recommend multi-store k-of-n for a
   targeted recipient, single-store only for lower-risk convenience.**

Broker count in Mode A: **zero connection brokers**; **one blind content store**
(or n of them), which learns nothing about the peer relationship.

---

## 7. L4 — Capability / key delivery (the highest-priority failure point)

This is where well-encrypted systems die. Never send the read-cap directly.

1. Sender and recipient share a **short secret** out-of-band (spoken in person, a
   Magic-Wormhole-style code word list, or a Signal message). Short = human-
   transferable, ~few words / ~50 bits, single-use.
2. Expand it via **PAKE (SPAKE2)** into a strong ephemeral channel key. PAKE
   means an eavesdropper on the seed channel who lacks the exact short secret
   gets nothing, and online guessing is limited to one attempt (the rendezvous,
   if any, is ephemeral and holds no identity).
3. Over that PAKE-derived channel, deliver the actual **read-cap** = `root_key`
   (+ object-ID set for Mode A, or nothing extra for Mode L since blocks arrive
   on the wire). The cap is small; it fits in the same out-of-band channel.
4. **Commitment binding.** The L0 ticket / Mode-A object set carries a
   `cap_commitment = H(root_key)` so the recipient can verify the blocks they
   received match the cap they were given — detecting a swapped/decoy payload.

Rule for Claude CLI: if you ever find yourself putting `root_key` or a full
read-cap onto L1 (the wire or the store), stop — that is the canonical bug.
Only the *seed* or the *commitment hash* may appear near L1; the cap itself
travels L4.

---

## 8. Build plan / repo layout

```
atom-vault/
  spec/CLAUDE.md            # this file
  crates/                   # (Rust recommended: quinn for QUIC, ring/dalek crypto)
    atom-encode/            # L3: serialize, block-split, pad, manifest
    atom-crypto/            # L2 + L4: XChaCha20-Poly1305, HKDF, SPAKE2
    atom-transport-live/    # L1 Mode L: quinn QUIC, raw-key TLS, hole punch, pacing
    atom-transport-store/   # L1 Mode A: blind store PUT/GET, k-of-n erasure
    atom-cli/               # ticket gen, seed/PAKE flow, send, receive
  tests/
    vectors/                # known-answer tests for encode + crypto
```

Suggested crate choices (verify current versions before pinning): `quinn`
(QUIC), `rustls` with raw-public-keys, `ed25519-dalek`, `chacha20poly1305`,
`hkdf` + `sha2`, a maintained `spake2` implementation, `reed-solomon-erasure`
for k-of-n. **Do not assume these APIs from memory — fetch current docs/versions
at build time; several have had breaking releases.**

---

## 9. Milestones (build in this order)

1. `atom-encode`: tree -> padded blocks + encrypted manifest, round-trips
   losslessly. Property test: output block count is always on the quantized
   ladder; decoy blocks indistinguishable from real under the store's view.
2. `atom-crypto`: per-block AEAD + HKDF derivation + SPAKE2 handshake, with KATs.
3. `atom-transport-store` (Mode A) first — simpler, no live coordination. End to
   end: encode -> PUT -> (later) GET -> decode, cap delivered via SPAKE2.
4. `atom-transport-live` (Mode L): quinn raw-key handshake pinned to tickets,
   manual hole punch, constant-rate pacing + cover. End to end live transfer.
5. `atom-cli`: wrap both in a UX that makes the L0/L4 out-of-band steps hard to
   get wrong (the human factor is the real attack surface).

---

## 10. Explicit warnings to keep surfacing to the user

- Mode L reveals the peer-IP pairing to each ISP. If that must be hidden, only
  Tor (excluded here) or a self-hosted onion service solves it — say so plainly.
- STUN, if enabled in Mode L, tells a STUN server your external IP. Off by
  default; manual address entry is the pure path.
- The out-of-band seed channel (L0/L4) is the true root of trust. All the
  crypto is downstream of one human exchanging a short secret safely. If that
  channel is compromised, nothing below compensates. This is deliberately the
  smallest, most auditable surface — keep it that way.
- Convergent encryption is banned in this design (§5); if any dependency
  reintroduces content-derived keys for dedup, that is a security regression.
