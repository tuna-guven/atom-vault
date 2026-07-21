//! The address record: what a peer publishes so it can be found by ID alone
//! (roadmap Phase 8).
//!
//! # Shape, and why it is always the same shape
//!
//! A sealed record is **exactly [`SEALED_LEN`] bytes**, whatever it contains. A
//! peer offering one IPv4 address and a peer offering three addresses and an
//! onion produce byte-identical sizes, because the plaintext is padded to a fixed
//! width before it is sealed. This is §4 of `CLAUDE.md` applied to the smallest
//! object in the system: the substrate must not learn how many ways a peer is
//! reachable, since "publishes an onion" and "publishes one address" are
//! themselves distinguishing facts about a targeted person.
//!
//! # What sealing does and does not authenticate
//!
//! The record is sealed under the slot key, which is derived from the pairwise
//! rendezvous secret. Opening it therefore proves the writer held that secret —
//! which only the paired peer does. It does **not** prove anything about the
//! addresses inside, and it is not asked to: an address is a *hint*, and the
//! authentication that matters happens later, when the mutually-pinned hybrid-PQ
//! handshake either succeeds against the peer's real identity or fails. A record
//! cannot lie its way into a session.
//!
//! The tag is bound in as associated data, so a substrate cannot take a valid
//! record from one slot and serve it under another.
//!
//! # Rollback, the residual weakness
//!
//! A substrate can always serve an *old but genuine* record instead of the
//! current one — refusing to update is indistinguishable from having nothing new.
//! Two things bound the damage: records carry a short [`MAX_TTL_SECS`] expiry and
//! are refused past it, and they carry a `seq` that a caller compares against the
//! newest it has already seen ([`AddressRecord::supersedes`]). The worst a
//! rollback achieves is pointing the reader at an address the peer held recently,
//! where the handshake fails — or, if that address has since been reassigned, a
//! connection attempt that reveals the reader's IP to its new occupant. That is
//! why the expiry is hours and not days.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::Error;
use crate::discovery::secret::Slot;
use crate::ticket::Reader;
use crate::ticket::{Endpoint, decode_hints, encode_hints};

/// Associated-data domain, binding a sealed record to this format and to the
/// slot it was written to.
const AAD_DOMAIN: &[u8] = b"atom-live-rdv-record-v1";

/// Record format version.
const FORMAT_VERSION: u8 = 1;

/// XChaCha20-Poly1305 nonce width. Extended-nonce, so a random value per record
/// is safe with no counter state to persist across restarts.
const NONCE_LEN: usize = 24;

/// Poly1305 tag width.
const AEAD_TAG_LEN: usize = 16;

/// Fixed plaintext width, padded to before sealing.
///
/// Comfortably above the largest legal record (eight onion hints and a header),
/// so no realistic address set can push a record to a second size class.
pub const PLAINTEXT_LEN: usize = 640;

/// The width of every sealed record on the wire. Constant by construction.
pub const SEALED_LEN: usize = NONCE_LEN + PLAINTEXT_LEN + AEAD_TAG_LEN;

/// Longest life a record may claim.
///
/// Short on purpose. A record names an address, and an address that was the
/// peer's this morning may belong to a stranger tonight — the same reasoning that
/// keeps [`crate::ticket::DEFAULT_TTL_SECS`] short, tightened further because
/// nobody reads a record before acting on it.
pub const MAX_TTL_SECS: u64 = 6 * 3600;

/// Default life of a freshly published record.
pub const DEFAULT_TTL_SECS: u64 = 2 * 3600;

/// A peer's current reachability, as published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressRecord {
    /// Where the peer can currently be reached, in preference order.
    pub hints: Vec<Endpoint>,
    /// Monotonic counter distinguishing newer records from older ones.
    ///
    /// Unix milliseconds at publication, which gives monotonicity across process
    /// restarts for free without persisting a counter. A peer whose clock jumps
    /// backwards publishes a record its own peer will consider stale — annoying,
    /// but it fails closed rather than accepting a rollback.
    pub seq: u64,
    /// Unix seconds after which this record must be refused.
    pub not_after: u64,
}

impl AddressRecord {
    /// Build a record valid for [`DEFAULT_TTL_SECS`] from `now` (Unix seconds).
    pub fn new(hints: Vec<Endpoint>, now: u64) -> Result<Self, Error> {
        if hints.is_empty() {
            return Err(Error::Discovery(
                "refusing to publish a record with no addresses: it would tell the \
                 substrate that this peer is online while giving the peer nothing \
                 to connect to"
                    .into(),
            ));
        }
        Ok(AddressRecord {
            hints,
            seq: now_millis()?,
            not_after: now.saturating_add(DEFAULT_TTL_SECS),
        })
    }

    /// Whether this record is newer than one already seen.
    ///
    /// The caller keeps `newest_seen` per peer and refuses anything that does not
    /// advance it. Without this a substrate could indefinitely replay a stale
    /// record in place of the current one.
    pub fn supersedes(&self, newest_seen: Option<u64>) -> bool {
        match newest_seen {
            None => true,
            Some(seen) => self.seq > seen,
        }
    }

    /// Whether this record has expired as of `now` (Unix seconds).
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.not_after
    }

    fn to_plaintext(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(64);
        body.push(FORMAT_VERSION);
        body.extend_from_slice(&self.seq.to_be_bytes());
        body.extend_from_slice(&self.not_after.to_be_bytes());
        encode_hints(&self.hints, &mut body);
        body
    }

    /// Seal this record for `slot`, producing exactly [`SEALED_LEN`] bytes.
    pub fn seal(&self, slot: &Slot) -> Result<Vec<u8>, Error> {
        let body = self.to_plaintext();
        if body.len() + 2 > PLAINTEXT_LEN {
            return Err(Error::Discovery(format!(
                "address record is {} bytes, past the {PLAINTEXT_LEN}-byte fixed width",
                body.len() + 2
            )));
        }

        // Length-prefix, then pad with random bytes to the fixed width. Random
        // rather than zeros so that a padding oracle has nothing structural to
        // find, and the padding is *inside* the AEAD so it cannot be trimmed.
        let mut plaintext = Zeroizing::new(vec![0u8; PLAINTEXT_LEN]);
        plaintext[..2].copy_from_slice(&(body.len() as u16).to_be_bytes());
        plaintext[2..2 + body.len()].copy_from_slice(&body);
        getrandom::fill(&mut plaintext[2 + body.len()..]).map_err(|e| {
            Error::Discovery(format!("OS random number generator unavailable: {e}"))
        })?;

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| {
            Error::Discovery(format!("OS random number generator unavailable: {e}"))
        })?;

        let cipher = XChaCha20Poly1305::new_from_slice(slot.key())
            .map_err(|_| Error::Discovery("bad slot key".into()))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad_for(slot),
                },
            )
            .map_err(|_| Error::Discovery("sealing the address record failed".into()))?;

        let mut out = Vec::with_capacity(SEALED_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        debug_assert_eq!(out.len(), SEALED_LEN);
        Ok(out)
    }

    /// Open a record served under `slot`, rejecting anything expired at `now`.
    ///
    /// Every failure returns the same shape of error and none of them says *why*
    /// beyond the category: a substrate probing which of its stored blobs a
    /// client can open learns nothing from the response.
    pub fn open(sealed: &[u8], slot: &Slot, now: u64) -> Result<Self, Error> {
        if sealed.len() != SEALED_LEN {
            return Err(Error::Discovery(format!(
                "address record is {} bytes, expected exactly {SEALED_LEN}",
                sealed.len()
            )));
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");

        let cipher = XChaCha20Poly1305::new_from_slice(slot.key())
            .map_err(|_| Error::Discovery("bad slot key".into()))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &aad_for(slot),
                    },
                )
                .map_err(|_| {
                    Error::Discovery(
                        "could not open the address record: it was written by someone \
                         who does not share this pairing, served under the wrong tag, \
                         or corrupted"
                            .into(),
                    )
                })?,
        );

        let record = Self::from_plaintext(&plaintext)?;

        if record.is_expired_at(now) {
            return Err(Error::Discovery(
                "address record has expired — the peer has not published recently, \
                 and this address may since have been reassigned"
                    .into(),
            ));
        }
        // A record claiming to outlive the maximum was written by something that
        // does not follow this spec. Refuse it rather than honouring a lifetime
        // the design does not permit.
        if record.not_after > now.saturating_add(MAX_TTL_SECS) {
            return Err(Error::Discovery(format!(
                "address record claims a lifetime past the {MAX_TTL_SECS}s maximum"
            )));
        }

        Ok(record)
    }

    fn from_plaintext(plaintext: &[u8]) -> Result<Self, Error> {
        if plaintext.len() != PLAINTEXT_LEN {
            return Err(Error::Discovery(
                "address record has the wrong width".into(),
            ));
        }
        let body_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if body_len + 2 > PLAINTEXT_LEN {
            return Err(Error::Discovery(
                "address record declares a body past its own width".into(),
            ));
        }
        let body = &plaintext[2..2 + body_len];

        let mut r = Reader::named(body, "address record");
        let version = r.u8()?;
        if version != FORMAT_VERSION {
            return Err(Error::Discovery(format!(
                "address record format version {version}, this build understands \
                 {FORMAT_VERSION}"
            )));
        }
        let seq = r.u64()?;
        let not_after = r.u64()?;
        let hints = decode_hints(&mut r)?;

        if !r.is_empty() {
            return Err(Error::Discovery(
                "trailing bytes in the address record — refusing an ambiguous encoding".into(),
            ));
        }
        if hints.is_empty() {
            return Err(Error::Discovery(
                "address record carries no addresses".into(),
            ));
        }

        Ok(AddressRecord {
            hints,
            seq,
            not_after,
        })
    }

    /// Only the direct addresses, for the QUIC rendezvous.
    pub fn direct_hints(&self) -> Vec<std::net::SocketAddr> {
        self.hints
            .iter()
            .filter_map(|h| match h {
                Endpoint::Direct(a) => Some(*a),
                Endpoint::Onion(_) => None,
            })
            .collect()
    }
}

/// The associated data binding a record to its slot.
fn aad_for(slot: &Slot) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + slot.tag().len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(slot.tag());
    aad
}

fn now_millis() -> Result<u64, Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| Error::Discovery("system clock is before the Unix epoch".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::secret::{Direction, RendezvousSecret};
    use crate::tor::OnionAddress;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    const NOW: u64 = 1_800_000_000;

    fn secret() -> RendezvousSecret {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        RendezvousSecret::from_bytes(b)
    }

    fn direct(s: &str) -> Endpoint {
        Endpoint::Direct(s.parse().unwrap())
    }

    #[test]
    fn seal_open_round_trips() {
        let s = secret();
        let slot = s.slot(Direction::LowToHigh, 1);
        let rec = AddressRecord::new(
            vec![
                direct("203.0.113.7:4433"),
                direct("[2001:db8::1]:4433"),
                Endpoint::Onion(OnionAddress::new(ONION, 4433).unwrap()),
            ],
            NOW,
        )
        .unwrap();

        let opened = AddressRecord::open(&rec.seal(&slot).unwrap(), &slot, NOW).unwrap();
        assert_eq!(opened, rec);
        assert_eq!(opened.direct_hints().len(), 2);
    }

    /// The central metadata property: what the substrate stores is the same size
    /// no matter what the peer published. If this regresses, "publishes an onion"
    /// becomes visible from the outside.
    #[test]
    fn every_sealed_record_is_the_same_size() {
        let s = secret();
        let slot = s.slot(Direction::LowToHigh, 1);

        let one = AddressRecord::new(vec![direct("10.0.0.1:1")], NOW).unwrap();
        let many = AddressRecord::new(
            vec![
                direct("10.0.0.1:1"),
                direct("10.0.0.2:2"),
                direct("[2001:db8::1]:3"),
                Endpoint::Onion(OnionAddress::new(ONION, 4433).unwrap()),
            ],
            NOW,
        )
        .unwrap();

        assert_eq!(one.seal(&slot).unwrap().len(), SEALED_LEN);
        assert_eq!(many.seal(&slot).unwrap().len(), SEALED_LEN);
    }

    /// Two seals of the *same* record must differ, or a substrate could tell that
    /// a peer's address had not changed between epochs.
    #[test]
    fn sealing_is_randomised() {
        let s = secret();
        let slot = s.slot(Direction::LowToHigh, 1);
        let rec = AddressRecord::new(vec![direct("10.0.0.1:1")], NOW).unwrap();
        assert_ne!(rec.seal(&slot).unwrap(), rec.seal(&slot).unwrap());
    }

    /// A substrate must not be able to move a record between slots — that would
    /// let it answer one epoch's query with another's record.
    #[test]
    fn a_record_cannot_be_relocated_to_another_slot() {
        let s = secret();
        let here = s.slot(Direction::LowToHigh, 1);
        let there = s.slot(Direction::LowToHigh, 2);
        let sealed = AddressRecord::new(vec![direct("10.0.0.1:1")], NOW)
            .unwrap()
            .seal(&here)
            .unwrap();

        assert!(AddressRecord::open(&sealed, &there, NOW).is_err());
    }

    /// Someone who does not hold the pairwise secret must not be able to read a
    /// record, which is the whole reason the substrate stays blind.
    #[test]
    fn a_stranger_cannot_open_a_record() {
        let (mine, theirs) = (secret(), secret());
        let sealed = AddressRecord::new(vec![direct("10.0.0.1:1")], NOW)
            .unwrap()
            .seal(&mine.slot(Direction::LowToHigh, 1))
            .unwrap();

        assert!(
            AddressRecord::open(&sealed, &theirs.slot(Direction::LowToHigh, 1), NOW).is_err(),
            "an unrelated secret opened the record"
        );
    }

    #[test]
    fn an_expired_record_is_refused() {
        let s = secret();
        let slot = s.slot(Direction::LowToHigh, 1);
        let sealed = AddressRecord::new(vec![direct("10.0.0.1:1")], NOW)
            .unwrap()
            .seal(&slot)
            .unwrap();

        let later = NOW + DEFAULT_TTL_SECS + 1;
        let err = AddressRecord::open(&sealed, &slot, later).unwrap_err();
        assert!(err.to_string().contains("expired"), "got: {err}");
    }

    /// A peer that claims an absurd lifetime is not following this spec, and its
    /// record must not be honoured for as long as it asks.
    #[test]
    fn an_overlong_lifetime_is_refused() {
        let s = secret();
        let slot = s.slot(Direction::LowToHigh, 1);
        let mut rec = AddressRecord::new(vec![direct("10.0.0.1:1")], NOW).unwrap();
        rec.not_after = NOW + MAX_TTL_SECS + 60;

        let err = AddressRecord::open(&rec.seal(&slot).unwrap(), &slot, NOW).unwrap_err();
        assert!(err.to_string().contains("maximum"), "got: {err}");
    }

    /// Replaying an old record in place of the current one must be detectable.
    #[test]
    fn an_older_record_does_not_supersede_a_newer_one() {
        let old = AddressRecord {
            hints: vec![direct("10.0.0.1:1")],
            seq: 100,
            not_after: NOW + 60,
        };
        let new = AddressRecord {
            seq: 200,
            ..old.clone()
        };

        assert!(new.supersedes(Some(100)));
        assert!(!old.supersedes(Some(200)));
        assert!(!old.supersedes(Some(100)), "the same seq is not newer");
        assert!(old.supersedes(None), "the first record ever seen is fresh");
    }

    /// Corruption at any single byte must be caught by the AEAD, never parsed.
    #[test]
    fn any_flipped_byte_is_rejected() {
        let s = secret();
        let slot = s.slot(Direction::LowToHigh, 1);
        let sealed = AddressRecord::new(vec![direct("10.0.0.1:1")], NOW)
            .unwrap()
            .seal(&slot)
            .unwrap();

        for i in (0..sealed.len()).step_by(37) {
            let mut damaged = sealed.clone();
            damaged[i] ^= 0x01;
            assert!(
                AddressRecord::open(&damaged, &slot, NOW).is_err(),
                "a flip at byte {i} was accepted"
            );
        }
    }

    /// A truncated or padded blob must error, never panic.
    #[test]
    fn wrong_lengths_never_panic() {
        let s = secret();
        let slot = s.slot(Direction::LowToHigh, 1);
        for n in [0usize, 1, NONCE_LEN, SEALED_LEN - 1, SEALED_LEN + 1] {
            assert!(AddressRecord::open(&vec![0u8; n], &slot, NOW).is_err());
        }
    }

    /// Publishing nothing would tell the substrate a peer is online while being
    /// useless to the peer — refuse it at construction.
    #[test]
    fn an_empty_record_is_refused() {
        assert!(AddressRecord::new(vec![], NOW).is_err());
    }
}
