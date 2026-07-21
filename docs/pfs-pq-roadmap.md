# Roadmap — Strict Forward Secrecy & Post-Quantum Security

> **Status: Phases 0–3 implemented** in the `p2p-live` crate (handshake, session
> layer, live transfer with resume, pairing and rendezvous). Phase 3's *UX* and
> Phases 4–7 remain outstanding. Nothing is wired into the CLI or GUI yet.
>
> This roadmap supersedes the Mode A (blind store) design as the *primary*
> transfer mechanism. Companion docs: `p2p-live/p2p_live_architecture.md` (what
> the new path looks like as built), `p2p-direct/p2p_direct_architecture.md`
> (the Mode A path it supersedes), `CLAUDE.md` (original spec).

---

## 1. The decision

Strict forward secrecy is **incompatible with data at rest**. A recipient who
fetches later must be able to decrypt later, so the key must survive until they
do — and any key that survives can be compelled, stolen, or broken. No amount of
cryptography removes that.

**Decision: require both peers online. Transfer live. No ciphertext at rest, no
bearer capability, ephemeral keys only.**

### What this buys

| Property | Mode A (today) | Live (target) |
|----------|----------------|---------------|
| Forward secrecy | Bounded at best (§3 of old analysis) | **Strict** — ephemeral-only |
| Harvestable artifact | Blocks in store + sealed cap | **None** |
| CRQC retroactive break | Unlocks entire vault via `root_key` | **Nothing to decrypt** |
| Long-lived secret | `root_key` per transfer | **None beyond the session** |

The single most important consequence: **the bearer capability ceases to
exist.** Today `root_key` is the pivot — one discrete-log break unlocks a whole
harvested vault. A live protocol has no cap, so that attack has no target.

### What this costs — read before committing

1. **Async capability is gone.** A recipient with intermittent connectivity, in a
   hostile timezone, or whose device is seized before a rendezvous simply cannot
   receive. For a high-risk recipient this is a real operational cost, not a
   theoretical one.
2. **Peer-IP pairing becomes visible.** Mode A's strongest metadata property was
   that the two peers *never co-occurred on the wire*. A direct connection tells
   both ISPs that A talked to B, when, and for how long. Per spec §10, if that
   pairing must stay hidden, a direct transport is the wrong tool.

**Mitigation, and the core architectural recommendation:** make the AKE
**transport-agnostic**. The same PFS+PQ handshake then runs over:

- **direct QUIC** — broker-free, but ISPs see the pairing; mitigate with a VPN;
- **the existing Tor onion** — hides the pairing, at the cost of using Tor.

One hardened crypto layer, two transports, chosen per recipient. This recovers
the metadata property for cases that need it without maintaining two crypto
stacks.

---

## 2. Target architecture

```
+-------------------------------------------------------------+
| L4  Pairing        SPAKE2 over short secret -> ticket auth   |  out-of-band, once
+-------------------------------------------------------------+
| L3  Framing        fixed blocks + constant-rate pacing/cover |  live
+-------------------------------------------------------------+
| L2  Session        HYBRID EPHEMERAL AKE  (PFS + PQ)          |  live  <-- the core
+-------------------------------------------------------------+
| L1  Transport      QUIC direct  |  OR  |  Tor onion          |  pluggable
+-------------------------------------------------------------+
| L0  Bootstrap      manual ticket exchange (no broker)        |  out-of-band
+-------------------------------------------------------------+
```

Note what vanished versus today: there is no capability layer and no object
store. L4 shrinks from "deliver the vault's master key" to "authenticate a
one-time pairing", which is a far smaller and safer job.

---

## 3. Crypto design

### 3.1 Do not build a custom AKE

Rolling a bespoke authenticated key exchange is the highest-risk thing this
project could do. **Use TLS 1.3 via QUIC.** It gives, off the shelf and already
audited:

- **Strict PFS by construction** — TLS 1.3 is ephemeral-ECDHE-only; there is no
  static-key mode to misconfigure.
- **Hybrid PQ key agreement** — `X25519MLKEM768`, the same construction shipped
  in TLS and Chrome/Firefox.
- **Built-in intra-session key updates** — QUIC key update gives ratcheting
  during a long transfer for free (§3.3).
- **Raw public key identity (RFC 7250)** — pin peer keys with no CA, matching the
  Syncthing/ticket model the spec already specifies.

Recommended stack: `quinn` (QUIC) + `rustls` with the `aws-lc-rs` provider
configured for `X25519MLKEM768`, raw public keys for auth.
**Verify crate versions and MLKEM group availability at build time** — do not
pin from memory; this area is moving fast.

### 3.2 Hybrid, never PQ-only

Key agreement must be `X25519 ⊕ ML-KEM-768`, secure if **either** holds. ML-KEM
is young; a PQ-only build trades a well-understood risk for a poorly-understood
one. This is what TLS, Signal (PQXDH), and iMessage (PQ3) all shipped.

### 3.3 What "strict" PFS requires beyond ephemeral keys

Ephemeral key agreement alone is not sufficient. All of these are in scope:

1. **Ephemeral-only key agreement.** No static-key fallback, no PSK resumption,
   no session tickets, no 0-RTT (0-RTT is *not* forward secret — must be
   explicitly disabled).
2. **Immediate key destruction.** Zeroize ephemeral private keys and derived
   session keys the moment they are no longer needed, not at process exit. The
   codebase already uses `zeroize` consistently — extend that discipline here.
3. **Intra-session ratcheting.** A 5 GB transfer may run for hours. Trigger QUIC
   key updates every N MB / N minutes so a mid-transfer compromise does not
   expose the bytes already sent. This is the detail most implementations skip.
4. **No plaintext session logs.** Ensure no debug path can dump key material
   (`SSLKEYLOGFILE` must be compiled out for release builds).

### 3.4 Authentication: classical is acceptable at first

PQ **signatures** are a lower priority than PQ **key agreement**, and this is
worth understanding rather than treating everything as equally urgent:

- Breaking key agreement retroactively decrypts recorded traffic → **HNDL applies**.
- Breaking signatures does **not** decrypt anything retroactively; it enables
  impersonation, which requires an *active* MITM at the time of the handshake.

So Ed25519 identity + hybrid PQ key agreement is a coherent, defensible first
milestone. Hybrid signatures (Ed25519 + ML-DSA-65) follow later, and carry a real
UX cost: ML-DSA-65 public keys are ~1952 B and signatures ~3309 B, versus 32 B
for Ed25519. The current `atom://` URI inlines a 32-byte key as 52 base32 chars;
inlining a hybrid identity would produce a multi-kilobyte URI. That forces the
URI to carry a **hash** of an identity bundle exchanged via QR/file — a friend-list
format migration, hence its own phase.

### 3.5 Traffic analysis still matters

A live connection reintroduces the size/timing fingerprinting that Mode A's
decoy ladder addressed. `encode.rs` remains relevant, but its job changes from
"pad the object count" to "pad the live stream":

- Fixed-size framing (reuse existing block framing).
- **Constant-rate pacing** so throughput does not track payload boundaries.
- **Cover traffic** to keep the stream busy, with a randomized ramp-down so the
  stop time does not mark the true end of data.

---

## 4. Disposition of existing code

| Module | Fate | Rationale |
|--------|------|-----------|
| `encode.rs` (L3) | **Keep, adapt** | Framing reused; ladder → pacing/cover |
| `crypto.rs` (L2) | **Mostly retire** | `root_key`/block-key machinery is the harvestable artifact we are eliminating. Keep AEAD/HKDF helpers. |
| `pake.rs` (L4) | **Repurpose** | SPAKE2 moves from *cap delivery* to *pairing/ticket authentication* — a smaller, safer role |
| `store.rs` (L1/A) | **Demote** | Keep only if an explicitly-labelled, non-PFS async fallback is wanted (§6) |
| `p2p-sync` handshake | **Supersede** | Noise XX already gives PFS but is X25519-only; the new AKE replaces it and serves the Tor transport too |
| `commands/direct.rs`, GUI panel | **Rework** | Three-step blob flow collapses into a live rendezvous |

**Note the direction of travel: this deletes more than it adds.** No cap, no
store, no manifest, no decoy objects. That is a security win in itself.

---

## 5. Phases

### Phase 0 — Spike: prove the hybrid PQ QUIC handshake ✅ **done**
*Smallest thing that de-risks everything downstream.*

- Stand up `quinn` + `rustls`/`aws-lc-rs` with `X25519MLKEM768` between two local
  processes; assert the negotiated group is the hybrid one.
- Confirm raw-public-key (RFC 7250) pinning works without a CA.
- **Gate:** if hybrid + RPK cannot be made to work together on current crates,
  the design changes — find out now, in a throwaway binary, not in month two.

### Phase 1 — Transport-agnostic session layer ✅ **done** (`p2p-live/src/session.rs`)
- Define a `SecureSession` trait (open, send/recv framed messages, close).
- Implement over QUIC with the Phase 0 handshake.
- Enforce §3.3: no 0-RTT, no resumption, zeroize-on-drop, key-update scheduling.
- Identity pinning from L0 tickets.

Landed as specified. Caveats worth carrying forward: zeroization covers the
long-term identity key, not rustls's internal session secrets (we do not own that
memory); and the key-update counter records updates *requested*, not confirmed.

### Phase 2 — Live transfer protocol ✅ **done** (`p2p-live/src/transfer.rs`)
- Port the chunk/framing logic onto `SecureSession`.
- Progress reporting, cancellation.
- **Resume-without-loss + end-to-end integrity — designed in §2.1 below.** This is
  the part most likely to be built in a way that silently breaks PFS, so the
  design is fixed here before implementation.

Built exactly to §2.1. Two implementation choices worth recording:

- **No sidecar offset file.** The partial's own length, rounded *down* to a
  checkpoint boundary, is the durable offset; the prefix hash is what proves it.
  A separate metadata file would need its own fsync ordering and could fall out of
  sync with the data it describes.
- **The at-rest guard is a type, not a comment.** `Transfer::new` requires an
  `EncryptedAtRest` witness, so the assumption that the streamed artifact is the
  already-encrypted `.aegis` file has to be restated at every call site.

Not yet integrated into any CLI or GUI command — that follows Phase 3's pairing UX,
since a transfer needs a paired peer to be useful.

#### 2.1 Resume-without-loss & integrity (design locked)

**Requirement:** if the connection is interrupted mid-transfer, resume from exactly
where it left off, with no lost bytes and no corruption at the seam.

**The hard rule — resume must never persist session keys.** TLS session resumption,
tickets, and 0-RTT are the obvious way to do this and are *precisely* what §3.3
disables for strict PFS. So resume is a transport-reliability feature layered on
top of the crypto, kept strictly separate from the key lifecycle:

> Every reconnection is a **full, fresh hybrid-PQ handshake** with new ephemeral
> keys. Nothing cryptographic survives the drop. What survives is only the
> *plaintext-payload progress* (a byte offset + the partial data), never a key.

This preserves PFS: a segment recorded before the drop used ephemeral keys that
were destroyed, so resuming grants an adversary no new decryption power.

**Protocol (each session — initial or resumed):**

1. **Fresh handshake** — the Phase 0 mutually-pinned hybrid-PQ handshake. Re-dial
   using the L0 ticket's address/transport hints.
2. **Offset negotiation** — receiver sends, *inside* the fresh encrypted +
   authenticated channel: `have = N` (bytes) and `prefix_hash = BLAKE3(payload[0..N])`.
3. **Boundary verification** — sender recomputes `BLAKE3(source[0..N])` and requires
   it to equal `prefix_hash`. Divergence ⇒ the receiver's partial is corrupt/wrong
   ⇒ roll back to the last verified checkpoint (or restart). This is what stops a
   good suffix being stitched onto a bad prefix — "no loss" also means "no
   corruption at the seam."
4. **Resume** — sender seeks to `N` and streams on.
5. **Completion** — full-payload `BLAKE3` check, end-to-end.

**Integrity decision — BLAKE3 streaming hash, not a hand-rolled Merkle tree.** For
a single-source, in-order stream over an already-authenticated channel (QUIC+TLS
1.3 AEAD authenticates every record; the peer is mutually pinned), a Merkle tree
buys nothing against wire tampering — that threat is already closed. What integrity
verification *does* catch is our own reassembly / resume-seam / disk-write bugs and
bit-rot at the sender before the bytes entered the channel. A BLAKE3 streaming hash
covers that, and the **same rolling hash doubles as the offset-negotiation
commitment** in step 2. BLAKE3 is internally a Merkle tree, so if a future
random-access or prefix-proof need ever arises, adopt `bao` verified streaming
rather than hand-rolling a tree (which invites length-extension / duplicate-leaf
bugs).

**Determinism requirements (or resume-by-offset is unsound):**

- **Offset is over the logical payload, not the wire.** Cover traffic, pacing, and
  the per-session ephemeral TLS encryption are non-deterministic and must never be
  part of the resumable stream. `N` counts payload bytes.
- **The source is stable for the transfer's duration.** Resume assumes
  `source[0..N]` is byte-identical across sessions; the vault file must be immutable
  (or snapshotted at start), else the seam check correctly rejects a changed source.

**What each side persists across the outage:**

- **Sender:** nothing but the source file — it re-seeks to `N`.
- **Receiver:** the partial bytes + the verified offset (hash state is recomputable
  from the partial). Advance the durable verified offset only at chunk boundaries
  and only *after* `fsync` of the data, so a crash mid-chunk rolls back to the last
  fully-durable chunk and never counts half-written bytes as received.

**At-rest note (why on-disk checkpointing is acceptable here).** Surviving a
process/host restart — not just a connection blip — requires persisting the partial
to disk, which normally reintroduces the "data at rest" that going-live eliminates.
It is acceptable here *only because the streamed artifact is the already-encrypted
`.aegis` vault file*: the on-disk partial is ciphertext under the vault's own
password, strictly less exposure than the completed transfer the recipient already
opted into. **Guard this assumption in code:** if a future change ever streams a
decrypted tree instead of the encrypted vault file, the on-disk partial becomes
plaintext and this decision must be revisited.

**QUIC already handles the small stuff.** Packet loss, reordering, and
retransmission *within* a connection are QUIC's job (do not rebuild them), and
connection migration survives many IP/port changes without dropping. The resume
protocol above is only for **full** drops: process death, sleep past the idle
timeout, peer restart, long outage.

### Phase 3 — L0 pairing & rendezvous ✅ **protocol done**, UX outstanding
- Ticket format: identity key(s), transport hints, capability/suite IDs.
  → `ticket.rs`, plus an expiry (a stale ticket names an address that may have
  been reassigned) and a checksummed text form.
- SPAKE2 repurposed to authenticate ticket exchange over an untrusted channel.
  → `pairing.rs`. Note it now delivers a *ticket*, not a capability: if this
  exchange is compromised the attacker can attempt a MITM at pairing time but
  obtains no key that decrypts anything, because none exists.
- NAT traversal: manual address entry by default, STUN opt-in with an explicit
  warning (per spec §6). → `rendezvous.rs` and `stun.rs`; STUN is never called
  automatically.
- **Rendezvous UX: still outstanding.** The protocol works; getting two people
  online at once, guiding a two-round paste, and making fingerprint comparison
  something users actually do is the hard part and is not designed yet. It
  remains, as noted, the thing most likely to sink adoption.

Suite IDs are the hook for §6 below: a non-forward-secret async mode would have
to take a **new** suite value, so a peer can never silently reinterpret a live
ticket as something with weaker guarantees.

### Phase 4 — Traffic-analysis hardening
- Constant-rate pacing, cover traffic, randomized ramp-down (§3.5).

### Phase 5 — Tor transport binding
- Run the same `SecureSession` over the existing onion transport.
- Delivers the metadata property back for recipients who need it (§1).

### Phase 6 — Hybrid PQ signatures
- Ed25519 + ML-DSA-65 identity.
- Requires the `atom://` URI → identity-bundle-hash migration (§3.4).

### Phase 7 — Decide the fate of Mode A
- Either delete it, or keep it behind a loud, explicitly-labelled
  "no forward secrecy" flag for the async case (§6).

---

## 6. The open question you should decide

Phases 0–5 give strict PFS + PQ for peers who can be online together. **They do
not serve a recipient who cannot.** Three options:

| Option | PFS | Async | Notes |
|--------|-----|-------|-------|
| **A. Live only** | Strict | No | Cleanest, smallest attack surface. Recipient who can't rendezvous is unserved. |
| **B. Live + labelled async fallback** | Strict / none | Yes | Honest, but a fallback that silently loses PFS is a footgun — it must be hard to pick by accident. |
| **C. Live + short-TTL async** | Bounded | Limited | Mode A with mandatory expiry + burn-after-fetch. Bounds the harvest window without pretending to be forward secret. |

**Recommendation: A now, revisit C later.** Ship the strict path first and keep
the codebase small; only reintroduce an async mode if a real recipient is
actually blocked by its absence. Adding a weaker mode "just in case" tends to
become the default, which defeats the purpose.

---

## 7. Testing requirements

Every phase lands with:

- **Negotiation assertions** — the session must *fail closed* if the hybrid PQ
  group is unavailable, never silently fall back to X25519-only.
- **Downgrade tests** — a stripped-PQ or stripped-auth handshake must be refused.
- **PFS regression tests** — assert 0-RTT and session resumption stay disabled;
  a test should fail if someone enables them for performance.
- **Key-lifetime tests** — verify key material is zeroized after session close.
- **KATs** against NIST FIPS 203 vectors, pinned like the existing
  `EXPECTED_BLOCK0` HKDF vector in `crypto.rs`.
- **Resume tests** (Phase 2, §2.1): a transfer interrupted at an arbitrary offset
  and resumed produces a byte-identical result to an uninterrupted one; the resume
  handshake is a *fresh* full handshake (no reused session keys — assert
  resumption/0-RTT stay off across the reconnect); a **tampered or divergent
  prefix is rejected** at the seam rather than stitched; and a crash mid-chunk
  rolls the durable offset back to the last fsync'd chunk boundary (no half-written
  bytes counted as received).

---

## 8. Non-goals

- **A post-quantum Tor path.** Onion v3 identity is Ed25519 and ntor is X25519 —
  outside our control. Our session layer inside it is PQ, which is genuine
  defense in depth, but the Tor layer itself stays classical. Do not claim
  otherwise.
- **PQ-only (non-hybrid) modes.** See §3.2.
- **Custom AKE constructions.** See §3.1.
- **Protecting the vault at rest.** The `.aegis` file's own password-derived
  encryption is a separate concern; PFS covers the transport only.

---

## 9. Adjacent finding (not PQ — worth fixing regardless)

While inventorying primitives: `p2p-sync/src/handshake.rs` sets
`master_secret = noise.get_handshake_hash()`. The Noise handshake hash is
**public** — a transcript hash, safe to disclose, intended for channel binding.
Using it to *sign* (as the handshake does) is correct and idiomatic.

But `p2p-sync/src/address.rs::derive_daily_key` treats that same value as secret
key material, HKDF-expanding it into **Tor onion service private keys**. Anyone
who observed the handshake could derive those keys.

`derive_daily_key` is currently **dead code** — nothing calls it, and
`commands/sync.rs` passes a zeroed `dummy_master_secret` — so this is latent, not
live. Fix or remove it before anyone wires it up:

- rename `master_secret` → `handshake_hash` so it stops inviting misuse, and
- derive any real key material from the Noise split/`ck` output or a proper PSK,
  never from `h`.
