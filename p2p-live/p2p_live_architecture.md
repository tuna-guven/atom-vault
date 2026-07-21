# `p2p-live` — Strict-PFS, Post-Quantum Live Transfer Architecture

> Sibling crate to `p2p-sync` (Tor) and `p2p-direct` (Mode A blind store).
> Implements the **live, both-peers-online** transfer mechanism from
> `docs/pfs-pq-roadmap.md`. This document describes the architecture as built
> **through Phase 0** (the hybrid-PQ + raw-public-key handshake spike) and sketches
> the sequences the later phases will fill in. Sequence diagrams will be drawn on
> top of the textual sequences in [§7](#7-sequences); a formal threat model follows
> later (see [§9](#9-planned-follow-ups)).

---

## 1. Purpose and scope

`p2p-live` moves a large encrypted Atom vault to a single high-risk recipient
**while both peers are online**, over a channel with **strict forward secrecy**
and **hybrid post-quantum key agreement**. It is the answer to a property the
other two transports cannot provide: nothing is left at rest for a
"harvest now, decrypt later" (HNDL) adversary to collect.

### Why "live", and what it removes

Strict forward secrecy is **incompatible with data at rest**. A recipient who
fetches later must be able to decrypt later, so a key must survive until they do —
and any key that survives can be compelled, stolen, or eventually broken by a
cryptographically-relevant quantum computer (CRQC). Transferring live removes that
key entirely:

- **No bearer capability.** There is no `root_key` to deliver, so there is no
  single discrete-log break that unlocks a whole harvested vault.
- **No ciphertext at rest.** The bytes exist only in flight, encrypted under
  ephemeral session keys that are destroyed when the transfer ends.
- **Nothing to harvest.** An adversary recording the wire captures only the
  ciphertext of a forward-secret, post-quantum channel.

### What it costs (surfaced deliberately, per `CLAUDE.md` §10)

1. **Async capability is gone.** A recipient who cannot be online at the same time
   as the sender simply cannot receive through this crate. `p2p-direct` (Mode A)
   remains the tool for the time-decoupled case, at the cost of PFS.
2. **Peer-IP pairing becomes visible.** A direct connection tells both ISPs that A
   talked to B, when, and for how long. Mode A's strongest metadata property — the
   two peers never co-occurring on the wire — is not present in a direct live
   transport. The mitigation is architectural, not a patch: the session layer is
   **transport-agnostic**, so the same handshake can run over the existing Tor
   onion when the pairing must stay hidden (roadmap Phase 5).

---

## 2. Layer model

The roadmap's target architecture, and where this crate sits in it:

```
+-------------------------------------------------------------+
| L4  Pairing        SPAKE2 over short secret -> ticket auth   |  out-of-band, once   (Phase 3)
+-------------------------------------------------------------+
| L3  Framing        fixed blocks + constant-rate pacing/cover |  live                (Phase 2/4)
+-------------------------------------------------------------+
| L2  Session        HYBRID EPHEMERAL AKE  (PFS + PQ)          |  live  <-- THIS CRATE, Phase 0/1
+-------------------------------------------------------------+
| L1  Transport      QUIC direct  |  OR  |  Tor onion          |  pluggable           (Phase 1/5)
+-------------------------------------------------------------+
| L0  Bootstrap      manual ticket exchange (no broker)        |  out-of-band         (Phase 3)
+-------------------------------------------------------------+
```

What `p2p-live` contains **today** is L2 (the authenticated key exchange and the
`SecureSession` channel built on it), the identity primitive (L0's payload) it
authenticates against, and L3's transfer protocol — chunked, resumable and
integrity-checked. L1 is the QUIC binding; the `SecureSession` boundary is what
lets Phase 5 substitute Tor without touching L2 or L3. Still absent: L3's
traffic-analysis hardening (pacing, cover traffic — Phase 4) and L4 pairing
(Phase 3). §7 describes the sequences those will implement.

Note what is **absent** compared to `p2p-direct`: there is no capability layer and
no object store. The design deletes more than it adds — no cap, no manifest, no
decoy objects, no ciphertext at rest.

---

## 3. Module map (as built, Phases 0–2)

```
p2p-live/
  src/
    lib.rs        L2 config: hybrid-PQ provider, TLS1.3-only client/server configs,
                  strict-PFS switches, and the negotiation/PFS unit tests.
    identity.rs   L0 payload: Ed25519 identity as an RFC 7250 raw public key (SPKI).
    pinned.rs     L2 auth: raw-public-key pinning verifiers (both directions).
    session.rs    L2 channel: the `SecureSession` trait, its QUIC implementation,
                  message framing, and the intra-session key-update ratchet.
    transfer.rs   L3 protocol: chunked transfer, resume-by-fresh-handshake,
                  BLAKE3 integrity, crash-safe checkpointing, cancellation.
    ticket.rs     L0: the connection ticket — identity, address hints, suite,
                  expiry — and its checksummed text form.
    pairing.rs    L4: SPAKE2 over a short secret, sealing the ticket exchange.
    rendezvous.rs L1: brokerless simultaneous-open / NAT hole punching.
    stun.rs       L1, opt-in and off by default: external-address discovery.
  tests/
    pq_handshake.rs   End-to-end gate tests over real QUIC (Phase 0 gate).
    session.rs        Framing, identity, frame caps, key-update (Phase 1).
    transfer.rs       Round-trip, resume, seam rejection, rollback (Phase 2).
    pairing_e2e.rs    Short secret → ticket → rendezvous → vault (Phase 3).
```

The public surface is deliberately small. L2 exposes the config builders
(`client_config`, `server_config`, `hybrid_pq_provider`), the
`LocalIdentity`/`PeerPublicKey` types, `ALPN`, and the `SecureSession` /
`QuicSession` / `dial` / `Listener` quartet. L3 exposes `Transfer` and its
`Progress`/`Summary`/`Cancel` types. The pinning verifiers stay crate-private —
they are an implementation detail of "pin the peer's key", not an API surface.

**The seam that matters** is `SecureSession`: L3 names no transport, so
`transfer.rs` is already Tor-ready. Nothing in the transfer protocol knows it is
running over QUIC.

---

## 4. L2 — the session layer

### 4.1 Do not build a custom AKE

The single most important design decision: **do not roll a bespoke authenticated
key exchange.** This crate uses **TLS 1.3 via QUIC**, which provides, already
audited and off the shelf:

- **Strict PFS by construction** — TLS 1.3 is ephemeral-ECDHE-only; there is no
  static-key mode to misconfigure into non-forward-secrecy.
- **Hybrid PQ key agreement** — `X25519MLKEM768`, the construction shipped in TLS
  and in Chrome/Firefox.
- **Raw public key identity (RFC 7250)** — pin peer keys with no CA, matching the
  Syncthing device-ID / ticket model the spec already uses.
- **Built-in intra-session key updates** — QUIC key update gives mid-transfer
  ratcheting for free (to be scheduled in Phase 1/2).

Stack: `quinn` (QUIC) + `rustls` 0.23 with the `aws-lc-rs` provider, restricted to
the `X25519MLKEM768` key-exchange group, raw public keys for authentication.

### 4.2 Hybrid, never PQ-only — fail closed

Key agreement is `X25519 ⊕ ML-KEM-768`: secure if **either** component holds.
ML-KEM is young, so a PQ-only build would trade a well-understood risk for a
poorly-understood one. Equally, a build that *offered* a classical group alongside
the hybrid one would let a peer (or a downgrade attacker) negotiate the PQ
protection away.

The enforcement is a single, load-bearing line — the hybrid group is the **only**
one configured:

```rust
pub fn hybrid_pq_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider
}
```

Because there is nothing else to negotiate, a **successful handshake is itself
proof** that post-quantum key agreement was used. A peer that cannot do
`X25519MLKEM768` fails to connect rather than silently downgrading. TLS 1.3 is
likewise pinned as the only version, and both TLS-1.2 signature-verification paths
in the pinning verifiers refuse rather than implement — so there is no version
downgrade path either.

### 4.3 What makes the PFS *strict*

Ephemeral key agreement alone is necessary but not sufficient. The config also:

- **Disables session resumption** (`Resumption::disabled()` on the client;
  `send_tls13_tickets = 0` on the server) — resumption reuses key material across
  connections.
- **Disables 0-RTT / early data** (`enable_early_data = false`;
  `max_early_data_size = 0`) — 0-RTT data is explicitly *not* forward secret.

Still to land in later phases (roadmap §3.3): zeroize-on-drop of ephemeral and
derived keys, scheduled QUIC key updates for long transfers, and ensuring no
`SSLKEYLOGFILE` path survives into release builds.

### 4.4 Authentication: identity vs. key agreement

Long-term identity keys are Ed25519 and are used for **authentication only, never
for key agreement**. This asymmetry is deliberate and is what keeps the forward
secrecy strict:

- Breaking **key agreement** retroactively decrypts recorded traffic → HNDL
  applies → key agreement must be post-quantum *now*.
- Breaking **signatures** decrypts nothing retroactively; it only enables an
  *active* MITM at handshake time. So a classical Ed25519 identity is a coherent
  first milestone; hybrid PQ signatures (Ed25519 + ML-DSA-65) are a later phase
  with their own URI-format migration cost (roadmap §3.4).

Consequently, compromise of a long-term identity key permits impersonation going
forward but **cannot** retroactively decrypt a recorded session.

---

## 5. L0 payload — identity as a raw public key (`identity.rs`)

An identity is an Ed25519 keypair. Its public half, in SubjectPublicKeyInfo (SPKI)
DER form, is what a peer pins — the same role the Ed25519 device ID plays on the
Tor path, and what a manually-exchanged L0 ticket will carry.

- `LocalIdentity` holds the private half (PKCS#8) and never leaks it: its `Debug`
  impl prints only the public fingerprint.
- `PeerPublicKey` wraps the SPKI DER. Comparing these **byte-for-byte is the
  authentication check** — there is no CA, no chain, no name validation.
- `certified_key()` builds the rustls `CertifiedKey` that presents the identity as
  a raw public key. One subtlety, captured in a code comment because it cost a
  debugging session: the "certificate" entry under RFC 7250 is a bare SPKI, so it
  must be built with `CertifiedKey::new` (which trusts the caller) rather than
  `CertifiedKey::from_der` (which runs `keys_match()` and tries to parse the entry
  as X.509, failing with `BadEncoding`).

---

## 6. L2 auth — pinning verifiers (`pinned.rs`)

Two verifiers, one per direction, implementing rustls' `ServerCertVerifier` and
`ClientCertVerifier`:

- **`PinnedServerVerifier`** (client-side) pins the server's raw public key.
- **`PinnedClientVerifier`** (server-side) pins the client's raw public key, and
  makes client auth **mandatory** (`client_auth_mandatory() = true`) — an
  anonymous client is never acceptable; both peers must prove identity.

Shared behaviour:

- `matches_pin` compares the presented SPKI to the pinned bytes. Public keys are
  not secret, so this is not a side-channel boundary.
- A mismatch returns a **generic** `wrong_peer()` error — a prober is told only
  "not the expected peer", never whether its key was well-formed.
- Both `verify_tls12_signature` paths **refuse**: this transport is TLS 1.3 only,
  so reaching a 1.2 path would mean a downgrade.
- `verify_tls13_signature` delegates to rustls'
  `verify_tls13_signature_with_raw_key`, verifying the handshake signature against
  the presented SPKI.
- Both report `requires_raw_public_keys() = true`, selecting the RFC 7250 code
  path over X.509.

The result: a MITM needs the peer's Ed25519 **private** key, not a mis-issued
certificate. This is the Syncthing device-ID trust model.

---

## 7. Sequences

Textual sequences for the diagrams to be drawn later. Phase 0 implements only
§7.2 (the handshake); §7.1 and §7.3–§7.5 describe the surrounding flow the later
phases will build.

### 7.1 L0/L4 — one-time out-of-band pairing (Phase 3, **implemented**)

Two rounds over whatever channel the humans have. Both rounds are assumed
**observed**; neither reveals anything to an observer who lacks the code.

```
A                                                B
  |  generate LocalIdentity (Ed25519, once)       |  generate LocalIdentity
  |                                               |
  |  A reads a short code aloud; B types it in    |   ~55 bits, single use
  |                                               |
  |  (state, msg_a) = pairing::start(code)        |  (state, msg_b) = start(code)
  |------ round 1: msg_a -------------------------->|
  |<----- round 1: msg_b ---------------------------|
  |  chan = state.finish(msg_b)                   |  chan = state.finish(msg_a)
  |                                               |
  |  ticket_a = {SPKI_a, hints, suite, expiry}    |  ticket_b = {...}
  |------ round 2: chan.seal_ticket(ticket_a) ----->|
  |<----- round 2: chan.seal_ticket(ticket_b) ------|
  |                                               |
  |  each side now pins the OTHER's SPKI, and can compare fingerprints aloud
```

The short secret is the **root of trust for the whole transfer** (spec §7): the
crypto below is all downstream of one human exchanging a few words safely. SPAKE2
expands it so that an eavesdropper who lacks the exact secret learns nothing and
an active attacker gets a single online guess rather than an offline dictionary
attack on the transcript.

Three properties beyond plain SPAKE2:

- **Two rounds are inherent.** Neither side can derive the key until it has seen
  the other's SPAKE2 message, so nothing can be sealed in round 1. Any one-paste
  scheme either drops the PAKE or sends the ticket unprotected.
- **Sealed tickets are bound to their exchange.** Both SPAKE2 messages go into
  the AEAD's associated data, so a sealed ticket captured from one pairing cannot
  be replayed into another — even between the same two people reusing a code.
- **What crosses is a ticket, not a capability.** Compare with the Mode A design
  this replaces, where the same PAKE delivered a vault's master key. A ticket
  carries no key material: it lets you *attempt* a connection to someone who has
  pinned you, and decrypts nothing.

### 7.1a L1 — rendezvous (Phase 3, **implemented**)

Both peers run `rendezvous` at roughly the same wall-clock time. No discovery
server, no relay, no signalling.

```
A (smaller identity -> Dialer)                   B (larger identity -> Accepter)
  |  bind ONE UDP socket, client+server config    |  bind ONE UDP socket
  |                                               |
  |-- QUIC Initial -> B's hint (opens A's NAT) -->|  <-- punch attempts open B's
  |     retry every 500ms until connected         |      NAT; results discarded
  |                                               |
  |===== §7.2 handshake on the winning path ======|
```

Roles come from comparing the two identity keys — the smaller dials — so both
sides agree with **no extra round trip**. Without a fixed rule, two connections
can form and a sender could end up on one while the receiver waits on the other.

Both sides transmit regardless of role: a stateful NAT only forwards inbound
packets that match a mapping some earlier outbound packet created, so the
accepter's discarded attempts are what make it reachable at all. This defeats
full-cone, restricted-cone and port-restricted NATs. It does **not** defeat
symmetric or carrier-grade NAT, which allocate a fresh external port per
destination; there is no relay fallback by design, so those cases need port
forwarding, a VPN, or the Tor transport (Phase 5).

### 7.2 L2 — the live handshake (Phase 0, **implemented**)

Roles: the receiving side runs the QUIC **server** (it has an address to reach);
the sending side runs the QUIC **client**. Either mapping is valid — identity comes
from the pinned key, not from who dialed.

```
Client (peer A)                                   Server (peer B)
  | client_config(local=A, expected_peer=SPKI_B)    | server_config(local=B, expected_peer=SPKI_A)
  |   provider = hybrid_pq_provider()   (X25519MLKEM768 only)
  |   TLS 1.3 only; resumption off; 0-RTT off
  |                                                 |
  |------ ClientHello (kx: X25519MLKEM768 only, ALPN=atom-vault/live/1, RPK) ----->|
  |                                                 |  PinnedClientVerifier: is A's
  |                                                 |  presented SPKI == pinned SPKI_A?
  |<----- ServerHello + server RPK (SPKI_B) + hybrid kx share + CertReq -----------|
  |  PinnedServerVerifier: presented SPKI == pinned SPKI_B?  (else generic reject)  |
  |  verify server's TLS1.3 handshake signature against SPKI_B                      |
  |------ client RPK (SPKI_A) + client handshake signature ----------------------->|
  |                                                 |  verify against pinned SPKI_A
  |                                                 |
  |==== hybrid post-quantum, mutually-authenticated, forward-secret channel =======|
```

Failure modes, each covered by a gate test:

- Presented server key ≠ pin → client aborts (`client_rejects_unpinned_server`).
- Presented client key ≠ pin → server aborts (`server_rejects_unpinned_client`).
- Peer offers only classical X25519 → **no common group → handshake fails**, never
  downgrades (`classical_only_client_cannot_downgrade_the_server`).

### 7.3 L3 — live transfer over the session (Phase 2, **implemented**)

One protocol serves both the initial attempt and every resumption; there is no
separate "resume mode". Each message is one `SecureSession` frame.

```
Sender S (source file)                            Receiver R (dest path)
  |====== L2 handshake (§7.2) — always a FRESH one =============================|
  |                                                 |
  |---- OFFER(total_len) -------------------------->|  open <dest>.part
  |                                                 |  have = floor(len/CKPT)*CKPT
  |                                                 |  truncate to have
  |<--- RESUME(have, BLAKE3(partial[0..have])) -----|
  |  verify BLAKE3(source[0..have]) == prefix_hash  |
  |    match    -> offset = have                    |
  |    mismatch -> offset = 0  (reject the seam)    |
  |---- START(offset) ----------------------------->|  truncate to offset
  |  seek(offset)                                   |  seek(offset)
  |---- DATA(chunk) ------------------------------->|  write, BLAKE3 update
  |            ...  (1 MiB chunks)                  |  fsync every CKPT bytes
  |  QUIC key update every 256 MiB sent (ratchet)   |  progress callback / cancel
  |---- DONE(BLAKE3(source)) ---------------------->|  verify full hash
  |                                                 |  fsync, rename .part -> dest
  |<--- ACK ----------------------------------------|
```

Phase 4 adds constant-rate pacing, cover traffic and a randomized ramp-down on top
of this frame sequence. Until then the stream's rate and stop time still track the
real payload.

### 7.4 L3 — resume after interruption (Phase 2, **implemented**)

Resume re-runs §7.3 unchanged over a **fresh handshake**; the only thing that
carries across the outage is the partial file. No session key is ever persisted,
so strict PFS survives an arbitrary number of reconnections. The full design
rationale (determinism requirements, at-rest reasoning, crash-safe checkpointing)
is in `docs/pfs-pq-roadmap.md` §2.1.

Three properties do the work:

- **The file length is the offset.** Rounded *down* to a checkpoint boundary, so
  bytes written but never `fsync`ed are discarded rather than counted. No sidecar
  metadata file exists to fall out of sync with the data.
- **The prefix hash is the proof.** `BLAKE3(partial[0..have])` must equal
  `BLAKE3(source[0..have])` or the sender rewinds the receiver to 0. This is what
  stops a good suffix being stitched onto a bad prefix — "no loss" has to mean
  "no corruption at the seam" too.
- **The destination appears only when verified.** Data lands in `<dest>.part` and
  is renamed into place only after the end-to-end hash matches.

The same BLAKE3 hash serves double duty: end-to-end integrity **and** the
offset-negotiation commitment. On-disk checkpointing of the partial is acceptable
only because the streamed artifact is the already-encrypted `.aegis` vault (the
partial at rest is ciphertext). That assumption is guarded in code by the
`EncryptedAtRest` witness a `Transfer` requires: if a future change ever streams a
decrypted tree, the partial becomes plaintext at rest and the decision must be
revisited rather than inherited.

**Cost:** both sides re-hash the prefix on reconnect (a resumed 4 GiB prefix means
a 4 GiB read each side). Persisting hasher state would avoid it, and would be
exactly the "trust what we wrote down" the seam check exists to reject.

### 7.5 Transport substitution (Phase 5, planned)

The same L2 handshake and L3 transfer run unchanged over the existing Tor onion
transport instead of direct QUIC — `transfer.rs` takes a `&mut dyn SecureSession`
and never names QUIC, so this is an added implementation of the trait, not a
change to the protocol. This recovers the peer-IP-pairing metadata
property for recipients who need it, without a second crypto stack. (Non-goal: the
Tor layer itself stays classical — onion v3 identity is Ed25519 and ntor is
X25519, outside our control; our session *inside* it is PQ, which is genuine
defense in depth but must not be described as a post-quantum Tor path.)

---

## 8. Current status and limitations

**Implemented (Phases 0–2):**

- *Phase 0* — hybrid-PQ (`X25519MLKEM768`), TLS-1.3-only, mutually-pinned
  raw-public-key handshake over real QUIC. Fail-closed: single kx group, single
  TLS version, resumption and 0-RTT disabled on both sides.
- *Phase 1* — `SecureSession` over QUIC: length-prefixed framing with a 16 MiB
  cap enforced before allocation, a QUIC key-update ratchet every 256 MiB sent,
  race-free graceful close, and the identity private key held in `Zeroizing`.
- *Phase 2* — the L3 transfer protocol of §7.3/§7.4: 1 MiB chunks, BLAKE3
  end-to-end integrity, resume-by-fresh-handshake with seam verification,
  checkpointed `fsync` durability, verify-then-rename, progress reporting and
  cooperative cancellation.
- *Phase 3* — L0 tickets with expiry and a checksummed text form, SPAKE2 pairing
  with transcript binding, brokerless rendezvous with deterministic roles, and
  an opt-in STUN client that is never called automatically.
- **53 passing tests** across five targets: 35 unit (`src/`), 4 QUIC gate tests,
  5 session tests, 6 transfer/resume tests, 3 end-to-end pairing tests. The
  resume set covers the roadmap §7 requirements directly — byte-identical
  resumed output, a divergent prefix rejected at the seam, a non-durable tail
  rolled back to the last checkpoint, and a behavioural assertion that a second
  connection offers no 0-RTT. `pairing_e2e.rs` drives the entire path from a
  spoken code to a verified vault with no server of any kind involved.

**Not yet built (later phases):**

- **Rendezvous UX** — the protocol exists; the human-facing part (getting two
  people online at once, guiding the two-round paste, showing fingerprints to
  compare) is the hard problem and is not designed yet.
- **Traffic-analysis hardening** — constant-rate pacing, cover traffic,
  randomized ramp-down (Phase 4). Until it lands, the transfer's rate, duration
  and stop time still track the real payload, and the final short chunk reveals
  the length to within one chunk.
- **Tor transport binding** (Phase 5) and **hybrid PQ signatures** (Phase 6).
- **CLI/GUI integration** — nothing yet drives `Transfer` from a user-facing
  command; `commands/direct.rs` still runs the Mode A blob flow.

**Known limitations, stated plainly:**

- **Session-key zeroization is bounded by what rustls does.** Our own long-term
  identity key is in `Zeroizing`, but the ephemeral TLS secrets live inside
  rustls/aws-lc-rs and we do not own that memory. Forward secrecy holds — the keys
  are ephemeral and nothing persists them — but "scrub the freed heap" is not
  something this crate can fully guarantee, and the roadmap §3.3.2 item should be
  read that way.
- **The key-update counter proves intent, not completion.** `key_updates()` counts
  updates *we requested*; quinn exposes no confirmation that the peer completed
  them, and documents `force_key_update` as existing "primarily for testing".
- **Cancellation is observed at chunk boundaries**, so it is prompt while data
  flows but relies on the 30 s QUIC idle timeout for a fully stalled peer.
- **No cap on the offered size by default.** `Transfer::max_total_len` exists but
  is unset: an authenticated-but-compromised sender could fill the receiver's
  disk. A default cap was rejected because a wrong one silently breaks legitimate
  multi-gigabyte vaults; the CLI should set it from available free space.
- **Rendezvous requires reachable addresses.** Behind symmetric or carrier-grade
  NAT it cannot succeed, and it cannot tell you that is why — it just times out.
  Adding a relay would fix it and would also add a broker, so it is excluded.
- **A ticket is not public.** It links an identity to an IP address, which is
  precisely the pairing metadata the threat model protects. It carries no key
  material, but it must still travel the pairing channel rather than the clear.
- **STUN, if used, tells a server your IP** moments before a transfer. It is off
  by default, never called automatically, and the manual-address path is the
  documented default everywhere.

**Fixed during Phase 3 — worth recording:**

- `PeerPublicKey::fingerprint` returned the first bytes of the SPKI DER, which
  for Ed25519 is a **constant** algorithm identifier. Every identity displayed
  the same fingerprint, so the human comparison step — the thing that catches a
  swapped key — could not have caught anything. It is now BLAKE3 over the whole
  SPKI, with a test asserting two identities differ.
- The application hello is now a **round trip**. In TLS 1.3 the client finishes
  its handshake before the server processes the client certificate, so `dial`
  could return a session the peer was in the middle of rejecting; the caller
  only found out on its next read. Waiting for the peer's hello means a returned
  session is one where *both* sides completed authentication.

---

## 9. Planned follow-ups

- **Sequence diagram** rendered from §7 (the reason this doc separates the
  sequences into their own section).
- **Formal threat model** — adversary capabilities, the metadata each layer does
  and does not protect, and an explicit statement of the peer-IP-pairing exposure
  versus the Tor transport option.
- Cross-link with `docs/pfs-pq-roadmap.md` as each phase lands.

---

## Appendix: dependencies

| Crate | Role |
|-------|------|
| `quinn` 0.11 | QUIC transport (runtime-tokio, rustls/aws-lc-rs) |
| `rustls` 0.23 | TLS 1.3, raw public keys, `aws_lc_rs` provider |
| `rcgen` | Ed25519 keypair generation / SPKI + PKCS#8 serialization |
| `rustls-pki-types` | `CertificateDer` / `PrivateKeyDer` / `SubjectPublicKeyInfoDer` |
| `tokio` | async runtime for the QUIC endpoints; async file I/O for L3 |
| `thiserror` | error enum |
| `async-trait` | object-safe async methods on `SecureSession` |
| `zeroize` | wipe the long-term identity private key on drop |
| `blake3` | L3 end-to-end integrity and the resume offset commitment |

Versions are pinned in `p2p-live/Cargo.toml`; verify current releases before
bumping — the hybrid-PQ group availability in particular is moving fast.
