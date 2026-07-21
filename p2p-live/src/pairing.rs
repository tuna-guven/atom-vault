//! L4 — pairing: authenticating a ticket exchange with a short secret
//! (roadmap Phase 3).
//!
//! # What this layer is for, and what changed
//!
//! In the Mode A design SPAKE2 delivered a **read capability** — the key to a
//! whole vault. Here it delivers only a **ticket**: an identity to pin and an
//! address to try. That is a far smaller and safer job. If this exchange is
//! compromised the attacker learns who is talking to whom and can attempt a
//! man-in-the-middle *at pairing time*; they do not obtain a key that decrypts
//! anything, because no such key exists in this design.
//!
//! # The problem it solves
//!
//! Two people need to swap tickets over whatever channel they have — chat, email,
//! a phone call. That channel is assumed to be **observed**. A short secret both
//! people can carry (a spoken phrase, a code read aloud) is expanded by SPAKE2
//! into a strong key: an eavesdropper who does not know the exact short secret
//! learns nothing, and an active attacker gets **one** online guess per attempt
//! rather than an offline dictionary attack on a transcript. That property is
//! the entire reason to use a PAKE instead of just encrypting under a hashed
//! password.
//!
//! # Flow (two rounds — inherent, not accidental)
//!
//! ```text
//!   A: (state, msg_a) = start(code)          B: (state, msg_b) = start(code)
//!   -- round 1: exchange msg_a <-> msg_b --
//!   A: key = state.finish(msg_b)             B: key = state.finish(msg_a)
//!   A: sealed_a = key.seal(ticket_a)         B: sealed_b = key.seal(ticket_b)
//!   -- round 2: exchange sealed_a <-> sealed_b --
//!   A: ticket_b = key.open(sealed_b)         B: ticket_a = key.open(sealed_a)
//! ```
//!
//! Two rounds are unavoidable: neither side can derive the key until it has seen
//! the other's SPAKE2 message, so nothing can be sealed in round 1. Any "one
//! paste" scheme either drops the PAKE or sends the ticket unprotected.
//!
//! # Single use
//!
//! A pairing code is **one-shot**. Reusing one turns each reuse into another
//! online guessing opportunity against the same secret, which is precisely the
//! property SPAKE2 exists to bound. [`PairingCode::generate`] returns a fresh
//! one; nothing here caches or reuses.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::Error;
use crate::ticket::Ticket;

/// Shared SPAKE2 identity string, so both sides run the *symmetric* variant.
/// A context string, not a secret.
const PAKE_IDENTITY: &[u8] = b"atom-vault-live-pairing-v1";

/// HKDF label separating the ticket-sealing key from the raw SPAKE2 output.
const SEAL_LABEL: &[u8] = b"atom-live-pair-seal-v1";

/// Prefix of the AAD, binding a sealed ticket to this protocol.
const AAD_DOMAIN: &[u8] = b"atom-live-pair-transcript-v1";

/// XChaCha20-Poly1305 nonce length. Extended-nonce, so a random value per
/// message is safe without any counter state.
const NONCE_LEN: usize = 24;

/// Entropy in a generated pairing code.
///
/// 55 bits is far below what a key needs and far above what an attacker gets to
/// try: SPAKE2 permits exactly **one** guess per pairing attempt, so the bar is
/// "unguessable in one shot", not "unguessable offline". The binding constraint
/// is that a human has to say it out loud correctly.
const CODE_BITS: usize = 55;
const CODE_CHARS: usize = CODE_BITS.div_ceil(5);

/// A short, single-use, human-transferable secret.
///
/// Displayed in hyphen-separated groups because that is how people read strings
/// aloud without losing their place. Comparison and use are on the normalised
/// form, so a peer who types the groups differently still succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingCode(String);

impl PairingCode {
    /// Draw a fresh code from the OS CSPRNG.
    pub fn generate() -> Result<Self, Error> {
        let mut raw = Zeroizing::new([0u8; CODE_BITS.div_ceil(8)]);
        getrandom::fill(raw.as_mut_slice())
            .map_err(|e| Error::Pairing(format!("OS random number generator unavailable: {e}")))?;
        let encoded = BASE32_NOPAD.encode(raw.as_slice()).to_lowercase();
        Ok(PairingCode(encoded[..CODE_CHARS].to_string()))
    }

    /// Accept a code a human typed, normalising case, spaces and hyphens.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let normalised: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .flat_map(|c| c.to_lowercase())
            .collect();
        if normalised.is_empty() {
            return Err(Error::Pairing("pairing code is empty".into()));
        }
        Ok(PairingCode(normalised))
    }

    /// Grouped for reading aloud, e.g. `k7m2p-9qf4t-z3p`.
    pub fn display(&self) -> String {
        self.0
            .as_bytes()
            .chunks(5)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    fn as_secret(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display())
    }
}

/// An in-progress pairing. Consumed by [`PairingState::finish`].
pub struct PairingState {
    inner: Spake2<Ed25519Group>,
    outbound: Vec<u8>,
}

/// Begin pairing from a short secret.
///
/// Returns our state and the message to hand the peer. The message is safe to
/// send over the observed channel — that is the point of a PAKE.
pub fn start(code: &PairingCode) -> (PairingState, Vec<u8>) {
    let (inner, outbound) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code.as_secret()),
        &Identity::new(PAKE_IDENTITY),
    );
    (
        PairingState {
            inner,
            outbound: outbound.clone(),
        },
        outbound,
    )
}

impl PairingState {
    /// Complete the exchange with the peer's message.
    ///
    /// Fails if the peer used a different code or sent a malformed message. A
    /// failure here is the expected outcome of an eavesdropper's guess — and,
    /// equally, of a typo. The two are indistinguishable from inside the
    /// protocol, so a caller must treat repeated failures as a possible attack
    /// and generate a **new** code rather than retrying the old one.
    pub fn finish(self, peer_message: &[u8]) -> Result<PairedChannel, Error> {
        let key = self
            .inner
            .finish(peer_message)
            .map_err(|_| Error::Pairing("pairing failed: wrong code, or tampering".into()))?;

        // Bind sealed tickets to *this* exchange by mixing both SPAKE2 messages
        // into the AAD. A sealed ticket captured from one pairing then cannot be
        // replayed into another, even between the same two people with the same
        // code. Sorted so both sides derive the same transcript without needing
        // an initiator/responder role.
        let mut msgs = [self.outbound.as_slice(), peer_message];
        msgs.sort_unstable();
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + msgs[0].len() + msgs[1].len());
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(msgs[0]);
        aad.extend_from_slice(msgs[1]);

        Ok(PairedChannel {
            key: derive_seal_key(&key),
            aad,
        })
    }
}

/// A short-lived authenticated channel over the out-of-band medium, good for
/// exactly one ticket exchange.
///
/// This is **not** the transfer session. It protects a handful of bytes passing
/// between two humans; the session that moves the vault is negotiated
/// separately, with its own ephemeral hybrid-PQ handshake.
pub struct PairedChannel {
    key: Zeroizing<[u8; 32]>,
    aad: Vec<u8>,
}

impl PairedChannel {
    /// Seal our ticket for the peer. The output is safe to paste into the
    /// observed channel.
    pub fn seal_ticket(&self, ticket: &Ticket) -> Result<String, Error> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| Error::Pairing("bad sealing key".into()))?;

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|e| Error::Pairing(format!("OS random number generator unavailable: {e}")))?;

        let plaintext = ticket.to_bytes();
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Pairing("sealing the ticket failed".into()))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(BASE32_NOPAD.encode(&out).to_lowercase())
    }

    /// Open the peer's sealed ticket.
    ///
    /// Authentication is the AEAD tag: if this succeeds, the ticket came from
    /// someone who knew the pairing code and was part of *this* exchange.
    pub fn open_ticket(&self, sealed: &str) -> Result<Ticket, Error> {
        let raw = BASE32_NOPAD
            .decode(sealed.trim().to_uppercase().as_bytes())
            .map_err(|e| Error::Pairing(format!("sealed ticket is not valid base32: {e}")))?;
        if raw.len() <= NONCE_LEN {
            return Err(Error::Pairing("sealed ticket is too short".into()));
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| Error::Pairing("bad sealing key".into()))?;
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| {
                Error::Pairing(
                    "could not open the sealed ticket: wrong code, tampering, or a \
                     ticket from a different pairing"
                        .into(),
                )
            })?;

        Ticket::from_bytes(&plaintext)
    }
}

fn derive_seal_key(spake_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, spake_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(SEAL_LABEL, okm.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    fn ticket_for(port: u16) -> Ticket {
        let id = LocalIdentity::generate().unwrap();
        Ticket::new(
            id.public_key().clone(),
            vec![format!("198.51.100.9:{port}").parse().unwrap()],
        )
        .unwrap()
    }

    /// The happy path: two peers with the same code exchange tickets.
    #[test]
    fn matching_codes_exchange_tickets() {
        let code = PairingCode::generate().unwrap();
        let (a_state, a_msg) = start(&code);
        let (b_state, b_msg) = start(&code);

        let a = a_state.finish(&b_msg).unwrap();
        let b = b_state.finish(&a_msg).unwrap();

        let (ta, tb) = (ticket_for(1), ticket_for(2));
        let sealed_a = a.seal_ticket(&ta).unwrap();
        let sealed_b = b.seal_ticket(&tb).unwrap();

        assert_eq!(b.open_ticket(&sealed_a).unwrap(), ta);
        assert_eq!(a.open_ticket(&sealed_b).unwrap(), tb);
    }

    /// **The property that matters.** A peer with the wrong code gets nothing —
    /// not a decryption failure to grind on offline, but a dead exchange.
    #[test]
    fn a_wrong_code_yields_nothing() {
        let (a_state, a_msg) = start(&PairingCode::parse("correct-horse").unwrap());
        let (b_state, b_msg) = start(&PairingCode::parse("wrong-horse").unwrap());

        // SPAKE2 itself may or may not report failure at finish; what must hold
        // is that no ticket ever crosses.
        let a = a_state.finish(&b_msg);
        let b = b_state.finish(&a_msg);

        if let (Ok(a), Ok(b)) = (a, b) {
            let sealed = a.seal_ticket(&ticket_for(1)).unwrap();
            assert!(
                b.open_ticket(&sealed).is_err(),
                "a mismatched code must never yield a readable ticket"
            );
        }
    }

    /// A sealed ticket is bound to the exchange it was made in: capturing one
    /// and replaying it into a second pairing — even with the same code — fails.
    #[test]
    fn a_sealed_ticket_cannot_be_replayed_into_another_pairing() {
        let code = PairingCode::parse("shared-secret").unwrap();

        let (a1, a1_msg) = start(&code);
        let (b1, b1_msg) = start(&code);
        let chan1 = a1.finish(&b1_msg).unwrap();
        let _ = b1.finish(&a1_msg).unwrap();
        let captured = chan1.seal_ticket(&ticket_for(1)).unwrap();

        // A second, independent pairing with the identical code.
        let (a2, a2_msg) = start(&code);
        let (b2, b2_msg) = start(&code);
        let _ = a2.finish(&b2_msg).unwrap();
        let chan2 = b2.finish(&a2_msg).unwrap();

        assert!(
            chan2.open_ticket(&captured).is_err(),
            "transcript binding must reject a ticket from a different exchange"
        );
    }

    #[test]
    fn tampering_with_a_sealed_ticket_is_detected() {
        let code = PairingCode::generate().unwrap();
        let (a_state, a_msg) = start(&code);
        let (b_state, b_msg) = start(&code);
        let a = a_state.finish(&b_msg).unwrap();
        let b = b_state.finish(&a_msg).unwrap();

        let sealed = a.seal_ticket(&ticket_for(1)).unwrap();
        let mut chars: Vec<char> = sealed.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        assert!(b.open_ticket(&tampered).is_err());
        assert!(b.open_ticket("").is_err());
        assert!(b.open_ticket("!!!not base32!!!").is_err());
    }

    #[test]
    fn generated_codes_are_fresh_and_readable() {
        let a = PairingCode::generate().unwrap();
        let b = PairingCode::generate().unwrap();
        assert_ne!(a, b, "codes must not repeat");
        assert_eq!(a.0.len(), CODE_CHARS);
        assert!(a.display().contains('-'), "grouped for reading aloud");
        // The grouped display must parse back to the same secret, or a peer who
        // types what they see would fail to pair.
        assert_eq!(PairingCode::parse(&a.display()).unwrap(), a);
    }

    #[test]
    fn typed_codes_normalise() {
        let canonical = PairingCode::parse("k7m2p9qf4").unwrap();
        for variant in ["K7M2P-9QF4", " k7m2p 9qf4 ", "k7m2p-9qf4", "K7m2P9qF4"] {
            assert_eq!(PairingCode::parse(variant).unwrap(), canonical, "{variant}");
        }
        assert!(PairingCode::parse("   ").is_err());
    }
}
