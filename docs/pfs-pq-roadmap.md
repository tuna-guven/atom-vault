# Roadmap — Strict Forward Secrecy & Post-Quantum Security

> **Status: all seven phases resolved and shipped to both UIs.** Phases 0–6 are
> implemented in the `p2p-live` crate; Phase 7 is decided and executed — **Mode A
> has been deleted** (§6 option A). The whole path is now reachable as
> `atom live …` and from the GUI's **Live** transport tab, both driving the same
> `commands::live::*` functions.
>
> This roadmap **replaces** the Mode A (blind store) design; the `p2p-direct`
> crate no longer exists. Companion docs: `p2p-live/p2p_live_architecture.md`
> (what the live path looks like as built), `CLAUDE.md` (original spec — note its
> §1/§6 two-mode framing is now historical, see §6 below).

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

*Resolved as follows (Phase 7):*

| Module | Fate | Outcome |
|--------|------|---------|
| `encode.rs` (L3) | Keep, adapt | **Deleted.** Its job — fixed framing and the decoy ladder — was rebuilt against the live stream in `p2p-live/src/pacing.rs`, not ported. |
| `crypto.rs` (L2) | Mostly retire | **Deleted.** The `root_key`/block-key machinery *was* the harvestable artifact; TLS 1.3 supplies the AEAD now. |
| `pake.rs` (L4) | Repurpose | **Deleted, reimplemented.** `p2p-live/src/pairing.rs` uses SPAKE2 for ticket authentication instead of cap delivery — a smaller, safer role. |
| `store.rs` (L1/A) | Demote | **Deleted.** §6 answered A, so no async fallback is kept. |
| `p2p-sync` handshake | Supersede | **Still present.** Superseded in principle by `p2p-live`, but not yet removed — nothing has migrated onto the new AKE. |
| `commands/direct.rs`, GUI panel | Rework | **Deleted and replaced.** `commands/live.rs` + `gui/live.rs` drive the live rendezvous from both surfaces. |

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

### Phase 3 — L0 pairing & rendezvous ✅ **done** (protocol and UX)
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
- **Rendezvous UX: built** in `atom/src/commands/live.rs` (CLI) and
  `atom/src/gui/live.rs` (panel). Both drive the same `*_core` functions, so the
  out-of-band steps have one implementation rather than two. The UX carries three
  warnings on screen rather than in a manual: the code must travel a *different*
  channel from the blobs, the fingerprints must be compared aloud, and both peers
  must be online simultaneously. Whether it is *good* UX needs real users — the
  claim here is only that the dangerous steps are surfaced, not that they are
  easy.

Suite IDs are the hook for §6 below: a non-forward-secret async mode would have
to take a **new** suite value, so a peer can never silently reinterpret a live
ticket as something with weaker guarantees.

### Phase 4 — Traffic-analysis hardening ✅ **done** (`p2p-live/src/pacing.rs`)
- Constant-rate pacing, cover traffic, randomized ramp-down (§3.5).

Delivered as four mechanisms, on by default (`Pacing::disabled()` must be asked
for by name):

- **Uniform frame size** — every frame padded to `chunk_len + 5`, control
  messages included. Without this the short final chunk reveals the payload
  length modulo the chunk size and control frames are identifiable by size alone.
- **Constant rate** — default 4 MiB/s. **The rate must be sustainable or the
  guarantee degrades silently**: above what the link or disk can hold, the
  bottleneck sets the pace again.
- **Frame-count ladder** — default next-power-of-two with a 16-frame floor, so a
  5.0 GB and a 6.3 GB vault present the same count. Power-of-two rather than a
  fixed multiple because it bounds overhead below 2× at *any* size; an absolute
  ladder pads a small vault by an enormous multiple.
- **Randomised tail** — 0–64 extra frames past the ladder, so the stop time does
  not land exactly on a boundary (itself a fingerprint of this tool).

The receiver holds its `ACK` until `FINISH` rather than sending it at `DONE`: an
acknowledgement the moment the data completes would mark the true end with a
reverse-direction packet and undo the ramp-down.

Residual leak, not fixed: the receiver's `RESUME` timing reveals roughly how long
it spent hashing its partial, hence roughly how far an earlier attempt got.

### Phase 5 — Tor transport binding ✅ **done** (`p2p-live/src/{tls,tor}.rs`)
- Run the same `SecureSession` over the existing onion transport.
- Delivers the metadata property back for recipients who need it (§1).

Implemented as `TlsSession<S>`: TLS 1.3 over **any** `AsyncRead + AsyncWrite`,
built from the *same* `client_tls_config`/`server_tls_config` as the QUIC path.
One place sets the PQ group, the TLS version and the PFS switches, and a change
to any of them applies to both transports — which is the whole reason §1 insisted
the AKE be transport-agnostic.

- **TLS-over-TCP, not QUIC-over-Tor.** Onion services are TCP-only, so QUIC
  cannot traverse a circuit at all. Ratcheting uses rustls `refresh_traffic_keys`
  in place of QUIC's `force_key_update`.
- **`transfer.rs` was not touched.** The proof is a test that interrupts a
  transfer on QUIC and resumes it over Tor, byte-identical — possible only
  because resume carries a byte offset and a hash, never transport or key state.
- **Two guards.** `connect_onion` accepts only validated v3 onion addresses with
  no fallback (a locally resolved name leaks a DNS query identifying the peer; a
  direct-TCP fallback would expose the connection while the user believed they
  were on Tor). `OnionListener` refuses any non-loopback bind, since a service
  reachable off-circuit is not hidden.
- **Ticket format extended.** `hints` became `Vec<Endpoint>` so a ticket can
  carry onion endpoints; without that, Phase 5 would have been unreachable
  through the pairing flow. The direct rendezvous refuses an onion-only ticket
  rather than dialling directly.

Framing was factored into `framing.rs` and is now shared, so the frame size cap
cannot drift between transports.

### Phase 6 — Hybrid PQ signatures ⚠️ **partly done** (`p2p-live/src/{bundle,pq_auth}.rs`)
- Ed25519 + ML-DSA-65 identity.
- Requires the `atom://` URI → identity-bundle-hash migration (§3.4).

**Gate finding: PQ signatures cannot go in the TLS handshake on this stack.**
Checked before building anything, per the Phase 0 discipline:

- `rustls` 0.23 defines `SignatureScheme::ML_DSA_65` as a draft code point, but
  its `aws-lc-rs` provider implements **neither signing nor verification** for
  it. There is nothing to switch on.
- Even given an implementation, TLS 1.3's `CertificateVerify` carries exactly
  **one** signature. Hybrid would need a composite scheme
  (draft-ietf-lamps-pq-composite-sigs); defining our own is inventing
  cryptography in the one area §3.1 forbids it.
- ML-DSA *instead of* Ed25519 fails §3.2's hybrid-never-PQ-only reasoning, which
  applies to signatures as much as to key agreement.

**What was built instead:** the PQ signature moved *above* the handshake, where
it needs no new cryptography. After the session is established, each side signs a
BLAKE3 transcript over the **TLS exporter** (RFC 5705, exposed by both
transports) plus a side label and both bundle IDs, using ML-DSA-65, and verifies
the peer's. This is channel binding, not a new key exchange.

- **What it buys:** an attacker who forges Ed25519 completes the handshake but
  cannot produce the proof, so the session is refused before any payload moves.
  Impersonation requires breaking **both** primitives — the Phase 6 goal.
- **Why the exporter matters:** a man in the middle runs two sessions with
  different exporter values, so a proof captured on one leg does not verify on
  the other. Without the binding the scheme would be relayable and worthless.
- **What it is not:** a post-quantum TLS handshake. The attacker still completes
  a handshake and derives session keys before rejection. When rustls ships
  ML-DSA, the signature belongs in `CertificateVerify` and this layer becomes
  redundant.

**The §3.4 migration is done.** `IdentityBundle` = Ed25519 SPKI + optional
ML-DSA-65 key; `BundleId` = BLAKE3 over the whole bundle, 32 bytes, **52 base32
characters — the same shape as the inline key it replaces**, so the `atom://` URI
format is unchanged in size. Tickets carry the full bundle (they travel over the
pairing channel, where ~2 KB is free); the URI carries only the ID. The ID covers
*both* keys, so substituting the PQ half changes the fingerprint a human reads.

**Requirement is undowngradeable:** whether a proof is demanded comes from the
**pinned** bundle, never from what the peer presents. Classical-only identities
still interoperate, so Phase 6 strands nobody.

**Still outstanding:** the `atom://` friend-list format in `atom/` has not been
migrated — `p2p-live` has the types, the rest of the workspace still stores
inline Ed25519 keys.

### Phase 7 — Decide the fate of Mode A ✅ **done — deleted**
- Either delete it, or keep it behind a loud, explicitly-labelled
  "no forward secrecy" flag for the async case (§6).

**Decision: option A. Mode A is gone.** Removed in full:

| Removed | Lines |
|---------|-------|
| `p2p-direct/` crate (`crypto`, `encode`, `pake`, `store`, `lib`) | 1,059 |
| `atom/src/commands/direct.rs` | 456 |
| `atom direct send` / `atom direct receive` CLI + arg validators | ~90 |
| GUI: the Direct transport tab, `DirectState`/`DirectRole`/`DirectStage`, the Mode A panel and its background-thread plumbing | ~560 |

**What this removes from the threat surface.** The `root_key` bearer capability
no longer exists anywhere in the codebase. That was the single artifact one
discrete-log break unlocked a whole harvested vault with, and the only long-lived
secret in the design. There is now no ciphertext at rest and nothing to harvest.

**What it costs.** A recipient who genuinely cannot be online at the same time as
the sender is unserved, with no fallback. This is a real operational cost for a
high-risk recipient (§1), accepted deliberately.

The prior Mode A architecture document went with the crate; it is recoverable
from git history if the analysis is ever wanted again.

---

## 6. The open question — **answered: A**

Phases 0–5 give strict PFS + PQ for peers who can be online together. **They do
not serve a recipient who cannot.** Three options:

| Option | PFS | Async | Notes |
|--------|-----|-------|-------|
| **A. Live only** | Strict | No | Cleanest, smallest attack surface. Recipient who can't rendezvous is unserved. |
| **B. Live + labelled async fallback** | Strict / none | Yes | Honest, but a fallback that silently loses PFS is a footgun — it must be hard to pick by accident. |
| **C. Live + short-TTL async** | Bounded | Limited | Mode A with mandatory expiry + burn-after-fetch. Bounds the harvest window without pretending to be forward secret. |

**Decided: A.** Mode A is deleted (Phase 7). Two facts drove it:

1. **Phase 5 narrowed Mode A's advantage to one thing.** Its two selling points
   were async *and* peers never co-occurring on the wire. Live-over-Tor now
   delivers the second **with** strict PFS, so async was all that remained — and
   it still cost a bearer capability.
2. **A weaker mode kept "just in case" tends to become the default.** Nothing
   else in the design has a long-lived secret; keeping one path that does would
   have made it the one people reach for when a rendezvous is inconvenient.

Revisit C only if a real recipient is actually blocked by the absence of async —
not pre-emptively. The reasoning above is the record of why it was removed, so
re-adding it should have to argue against this, not rediscover it.

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
