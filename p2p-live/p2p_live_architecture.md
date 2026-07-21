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

What `p2p-live` contains **today** is L2: the authenticated key exchange, plus the
identity primitive (L0's payload) it authenticates against. L1 is present only as
the QUIC binding used to prove the handshake works end-to-end. L3/L4 are not yet
built; §7 describes the sequences they will implement.

Note what is **absent** compared to `p2p-direct`: there is no capability layer and
no object store. The design deletes more than it adds — no cap, no manifest, no
decoy objects, no ciphertext at rest.

---

## 3. Module map (as built, Phase 0)

```
p2p-live/
  src/
    lib.rs        L2 config: hybrid-PQ provider, TLS1.3-only client/server configs,
                  strict-PFS switches, and the negotiation/PFS unit tests.
    identity.rs   L0 payload: Ed25519 identity as an RFC 7250 raw public key (SPKI).
    pinned.rs     L2 auth: raw-public-key pinning verifiers (both directions).
  tests/
    pq_handshake.rs   End-to-end gate tests over real QUIC (Phases 0 gate).
```

Everything public is deliberately small: three functions (`client_config`,
`server_config`, `hybrid_pq_provider`), the `LocalIdentity`/`PeerPublicKey`
types, and the `ALPN` constant. The pinning verifiers are crate-private — they are
an implementation detail of "pin the peer's key", not an API surface.

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

### 7.1 L0 — one-time out-of-band pairing (Phase 3, planned)

```
Sender S                        Recipient R
  |  generate LocalIdentity (Ed25519)   |  generate LocalIdentity (Ed25519)
  |                                     |
  |-- ticket_S = {SPKI_S, transport hints, suite id} -->|   (out-of-band channel:
  |<-- ticket_R = {SPKI_R, transport hints, suite id} --|    in person / Signal / QR)
  |                                     |
  |  short secret spoken/typed out-of-band (both sides)  |
  |  SPAKE2(short secret) authenticates the ticket swap  |
  |                                     |
  |  each side now pins the OTHER's SPKI as PeerPublicKey |
```

The short secret is the **root of trust for the whole transfer** (spec §7): the
crypto below is all downstream of one human exchanging a few words safely. SPAKE2
expands it so that an eavesdropper who lacks the exact secret learns nothing and
gets a single online guess.

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

### 7.3 L3 — live transfer over the session (Phase 2, planned)

```
  |  open bi-directional stream on the established session               |
  |  S: stream the encrypted vault file -> fixed-size frames            |
  |-- frame 0 .. frame N (constant-rate paced, cover traffic fills gaps) ->|
  |                                   R: append, advance BLAKE3, fsync   |
  |  periodic QUIC key update every N MB / N min (intra-session ratchet)  |
  |  randomized ramp-down so stop time != true end-of-data               |
  |  close: zeroize ephemeral + derived keys                             |
```

### 7.4 L3 — resume after interruption (Phase 2, planned; design locked)

Resume is done by **re-running a fresh handshake** and negotiating a payload byte
offset — never by persisting session keys, which would break strict PFS. The full
design (determinism requirements, at-rest reasoning, crash-safe checkpointing) is
fixed in `docs/pfs-pq-roadmap.md` §2.1.

```
Sender S (has source file)                        Receiver R (has partial, N bytes)
  |====== FRESH full hybrid-PQ handshake (new ephemerals; no reused keys) =========|
  |                                                 |
  |<---- have = N, prefix_hash = BLAKE3(payload[0..N]) ----------------------------|
  |  require BLAKE3(source[0..N]) == prefix_hash                                    |
  |    mismatch -> reject seam, roll R back to last verified checkpoint            |
  |  seek source to N                                                              |
  |------ frame @N .. end (paced + cover) ----------------------------------------->|
  |                                        R: append, advance offset at chunk       |
  |                                           boundaries only, after fsync          |
  |<---- final BLAKE3(payload) for end-to-end verification ------------------------|
```

The BLAKE3 rolling hash serves double duty: end-to-end integrity **and** the
offset-negotiation commitment. On-disk checkpointing of the partial is acceptable
only because the streamed artifact is the already-encrypted `.aegis` vault (the
partial at rest is ciphertext); a guard comment must flag that this stops holding
if a decrypted tree is ever streamed instead.

### 7.5 Transport substitution (Phase 5, planned)

The same L2 handshake and L3 transfer run unchanged over the existing Tor onion
transport instead of direct QUIC. This recovers the peer-IP-pairing metadata
property for recipients who need it, without a second crypto stack. (Non-goal: the
Tor layer itself stays classical — onion v3 identity is Ed25519 and ntor is
X25519, outside our control; our session *inside* it is PQ, which is genuine
defense in depth but must not be described as a post-quantum Tor path.)

---

## 8. Current status and limitations

**Implemented (Phase 0 — gate cleared):**

- Hybrid-PQ (`X25519MLKEM768`), TLS-1.3-only, mutually-pinned raw-public-key
  handshake over real QUIC.
- Fail-closed guarantees: single kx group, single TLS version, resumption and
  0-RTT disabled on both sides.
- 8 passing tests: 4 end-to-end over QUIC (`tests/pq_handshake.rs`) proving the
  roundtrip, both pinning directions, and the no-downgrade property; and 4
  in-memory rustls unit tests (`src/lib.rs`) that read the negotiated group back
  and assert it is `X25519MLKEM768`, assert TLS 1.3, and guard the PFS switches.

**Not yet built (later phases):**

- **L4/L0 pairing** — SPAKE2 ticket authentication and the rendezvous UX
  (Phase 3). Today identities are generated and pinned directly in tests.
- **L3 transfer** — framing, constant-rate pacing, cover traffic, key-update
  scheduling, resumption-by-fresh-handshake (Phases 2, 4).
- **Key-lifetime hardening** — zeroize-on-drop of session key material, and a test
  asserting it (roadmap §3.3, §7).
- **Tor transport binding** (Phase 5) and **hybrid PQ signatures** (Phase 6).
- The `resumption`-disabled assertion is currently structural (there is no public
  accessor on `ClientConfig.resumption` to compare against `disabled()`); a
  behavioural "second connection is a full handshake" test should replace it once
  a session abstraction exists.

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
| `tokio` | async runtime for the QUIC endpoints |
| `thiserror` | error enum |

Versions are pinned in `p2p-live/Cargo.toml`; verify current releases before
bumping — the hybrid-PQ group availability in particular is moving fast.
