//! The pairwise rendezvous secret and the blinded slots derived from it
//! (roadmap Phase 8).
//!
//! # What this exists to prevent
//!
//! Syncthing reaches a peer from an ID alone by announcing `device-ID -> current
//! addresses` to a global discovery server. The server cannot impersonate anyone
//! — the ID is a hash of the device key — but it does learn every device's
//! current IP and, from the queries, **who is looking for whom**. That mapping is
//! precisely what `CLAUDE.md` §2.1 exists to deny.
//!
//! So an Atom address record is not filed under an identity. It is filed under a
//! **blinded slot**: an opaque 32-byte label derived from a secret that only the
//! two paired peers hold, rotated every epoch. A substrate holding the record
//! sees a random-looking label and a uniform blob. It cannot tell which identity
//! the record belongs to, cannot recognise the same pair across two epochs, and
//! — decisively — cannot be *asked* to watch a particular person, because
//! computing that person's slots requires a secret it does not have.
//!
//! # Where the secret comes from, and why not from the identity keys
//!
//! The obvious construction is a static Diffie-Hellman over the peers' long-term
//! identity keys: both sides can compute it, no state to store, and it works for
//! any peer whose bundle you already hold. It is rejected here.
//!
//! `docs/pfs-pq-roadmap.md` §3 requires that long-term identity keys are used for
//! **authentication only, never for key agreement** — that separation is what
//! makes the forward secrecy strict, because it means compromising an identity
//! key permits future impersonation but never retroactive decryption. Deriving a
//! long-lived shared secret from those same keys would put a standing key
//! agreement back on them and quietly weaken the property. Instead the secret is
//! a distinct output of the one-time [`crate::pairing`] exchange, stored
//! alongside the peer record.
//!
//! # What its compromise costs
//!
//! A stolen rendezvous secret lets an attacker read the peer's published
//! addresses and forge new ones. It does **not** let them impersonate the peer or
//! decrypt anything: a forged record only points the victim at an address where
//! the mutually-pinned hybrid-PQ handshake fails. The real harm is narrower and
//! worth naming — an attacker who can forge records can induce the victim to send
//! a connection attempt to an address of the attacker's choosing, revealing the
//! victim's IP to them. That is why this secret lives in the encrypted peer
//! record and not in a plain config file.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::bundle::BundleId;

/// Domain separator for slot derivation. Distinct from every other label this
/// crate hashes, so a slot can never collide with an identity or a checksum.
const SLOT_DOMAIN: &[u8] = b"atom-live-rdv-slot-v1";

/// Label under which the rendezvous secret is derived from the pairing key.
pub(crate) const RENDEZVOUS_SECRET_LABEL: &[u8] = b"atom-live-rdv-root-v1";

/// How long one slot is valid, in seconds.
///
/// The tension: a **short** epoch rotates the label often, so a substrate sees
/// fewer requests under any one tag and has less to correlate; a **long** epoch
/// tolerates worse clock skew and costs fewer writes. One hour keeps the
/// unlinkability window tight while staying far above any plausible desync
/// between two consumer machines.
pub const EPOCH_SECS: u64 = 3600;

/// Size of a slot's public label.
pub const TAG_LEN: usize = 32;

/// Size of the symmetric key sealing a record in a slot.
pub const SLOT_KEY_LEN: usize = 32;

/// Which of the two per-epoch slots a record belongs in.
///
/// Each pair gets **two** slots per epoch, not one, so both peers can publish
/// their address in the same epoch without overwriting each other. Which peer
/// owns which is settled by the same identifier comparison that settles the
/// rendezvous roles (`crate::rendezvous::role_for`), so both sides agree with no
/// negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The slot written by the peer with the lexicographically smaller bundle id.
    LowToHigh,
    /// The slot written by the peer with the larger bundle id.
    HighToLow,
}

impl Direction {
    /// The direction *we* publish under, given both identifiers.
    pub fn publishing(local: &BundleId, peer: &BundleId) -> Self {
        if local.as_bytes() < peer.as_bytes() {
            Direction::LowToHigh
        } else {
            Direction::HighToLow
        }
    }

    /// The direction we read from — always the other one.
    pub fn flip(self) -> Self {
        match self {
            Direction::LowToHigh => Direction::HighToLow,
            Direction::HighToLow => Direction::LowToHigh,
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Direction::LowToHigh => 0,
            Direction::HighToLow => 1,
        }
    }
}

/// The long-term secret shared by exactly one pair of peers.
///
/// Established once at pairing and stored in the peer record. It is a
/// *discovery* secret only: it addresses and seals address records and grants
/// nothing else. See the module docs for what its compromise does and does not
/// permit.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RendezvousSecret([u8; 32]);

impl RendezvousSecret {
    /// Adopt raw secret bytes, e.g. when loading a stored peer record.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        RendezvousSecret(bytes)
    }

    /// Borrow the raw bytes, for writing into an encrypted peer record.
    ///
    /// Deliberately not `Display`/`Debug`: this must never reach a log line by
    /// accident. A caller that wants to persist it has to say so.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the slot for one epoch and direction.
    pub fn slot(&self, direction: Direction, epoch: u64) -> Slot {
        // Keyed BLAKE3: the secret is the key, not a hashed input, so a length
        // extension or a collision on the domain string cannot produce a usable
        // tag without the secret itself.
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(SLOT_DOMAIN);
        hasher.update(&[direction.to_byte()]);
        hasher.update(&epoch.to_be_bytes());

        let mut out = [0u8; TAG_LEN + SLOT_KEY_LEN];
        hasher.finalize_xof().fill(&mut out);

        let (tag, key) = out.split_at(TAG_LEN);
        let slot = Slot {
            tag: tag.try_into().expect("TAG_LEN bytes"),
            key: key.try_into().expect("SLOT_KEY_LEN bytes"),
        };
        out.zeroize();
        slot
    }

    /// The slots to write our current address into.
    ///
    /// Two epochs, the current and the next. Writing ahead means a peer whose
    /// clock runs fast still finds a record, without waiting for the boundary.
    pub fn publish_slots(&self, direction: Direction, now: u64) -> Vec<Slot> {
        let epoch = epoch_at(now);
        vec![self.slot(direction, epoch), self.slot(direction, epoch + 1)]
    }

    /// The slots to search for the peer's address.
    ///
    /// Three epochs — previous, current, next — so a clock skew of up to a full
    /// epoch in *either* direction still resolves. The count is fixed rather than
    /// adaptive: a lookup that queried a variable number of tags would leak the
    /// querier's uncertainty, and a constant three tells an observer nothing.
    pub fn lookup_slots(&self, direction: Direction, now: u64) -> Vec<Slot> {
        let epoch = epoch_at(now);
        vec![
            // `saturating_sub` rather than `epoch - 1`: a machine whose clock
            // sits at the Unix epoch must produce a wrong answer, not a panic.
            self.slot(direction, epoch.saturating_sub(1)),
            self.slot(direction, epoch),
            self.slot(direction, epoch + 1),
        ]
    }
}

impl fmt::Debug for RendezvousSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RendezvousSecret(redacted)")
    }
}

/// The epoch number containing `now` (Unix seconds).
pub fn epoch_at(now: u64) -> u64 {
    now / EPOCH_SECS
}

/// One epoch's addressing material: a public label and the key sealing what sits
/// under it.
///
/// The two are derived together but travel apart — the tag goes to the substrate
/// in the clear, the key never leaves the peer. Splitting them is what makes the
/// substrate blind: it can serve a slot without being able to read it.
#[derive(Clone)]
pub struct Slot {
    tag: [u8; TAG_LEN],
    key: [u8; SLOT_KEY_LEN],
}

impl Slot {
    /// The opaque label the substrate stores this record under.
    pub fn tag(&self) -> &[u8; TAG_LEN] {
        &self.tag
    }

    /// The tag in the form used on the wire to a blind endpoint: lowercase hex,
    /// which survives every URL path, filesystem and object-store key rule
    /// without escaping.
    pub fn tag_hex(&self) -> String {
        let mut s = String::with_capacity(TAG_LEN * 2);
        for b in &self.tag {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The key sealing this slot's record.
    pub(crate) fn key(&self) -> &[u8; SLOT_KEY_LEN] {
        &self.key
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The tag is public; the key is not, and must not appear even here.
        write!(f, "Slot({}…, key redacted)", &self.tag_hex()[..8])
    }
}

/// Current Unix seconds, or an error if the clock is nonsensical.
pub(crate) fn now_secs() -> Result<u64, Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Discovery("system clock is before the Unix epoch".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::LocalBundle;

    fn secret() -> RendezvousSecret {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        RendezvousSecret::from_bytes(b)
    }

    /// The core unlinkability claim: the same pair's slot label changes every
    /// epoch. If it did not, a substrate could follow one pair through time.
    #[test]
    fn tags_rotate_every_epoch() {
        let s = secret();
        let a = s.slot(Direction::LowToHigh, 100);
        let b = s.slot(Direction::LowToHigh, 101);
        assert_ne!(a.tag(), b.tag(), "the tag must not survive an epoch change");
        assert_ne!(a.key(), b.key(), "the sealing key must rotate with it");
    }

    /// Two peers must not write to the same label, or the second publisher
    /// silently destroys the first's address.
    #[test]
    fn the_two_directions_are_distinct_slots() {
        let s = secret();
        let up = s.slot(Direction::LowToHigh, 7);
        let down = s.slot(Direction::HighToLow, 7);
        assert_ne!(up.tag(), down.tag());
        assert_ne!(up.key(), down.key());
    }

    /// Different pairs must never collide, even in the same epoch — a collision
    /// would hand one pair's address record to another.
    #[test]
    fn different_secrets_give_different_slots() {
        let (a, b) = (secret(), secret());
        assert_ne!(
            a.slot(Direction::LowToHigh, 42).tag(),
            b.slot(Direction::LowToHigh, 42).tag()
        );
    }

    /// Both peers must independently agree on who writes which slot, from the
    /// identifiers alone and with nothing exchanged.
    #[test]
    fn directions_are_complementary() {
        for _ in 0..32 {
            let a = LocalBundle::generate().unwrap();
            let b = LocalBundle::generate().unwrap();
            let (ida, idb) = (a.id(), b.id());

            let a_writes = Direction::publishing(&ida, &idb);
            let b_writes = Direction::publishing(&idb, &ida);
            assert_ne!(a_writes, b_writes, "both peers claimed the same slot");

            // What A publishes under is what B must read from.
            assert_eq!(a_writes, b_writes.flip());
        }
    }

    /// The whole point of the skew allowance: peers whose clocks differ by up to
    /// an epoch still meet on at least one tag.
    #[test]
    fn publish_and_lookup_overlap_across_clock_skew() {
        let s = secret();
        let base = 1_800_000_000u64;

        for skew in [
            0i64,
            EPOCH_SECS as i64,
            -(EPOCH_SECS as i64),
            EPOCH_SECS as i64 - 1,
        ] {
            let publisher_now = (base as i64 + skew) as u64;
            let published: Vec<_> = s
                .publish_slots(Direction::LowToHigh, publisher_now)
                .iter()
                .map(|s| *s.tag())
                .collect();
            let sought: Vec<_> = s
                .lookup_slots(Direction::LowToHigh, base)
                .iter()
                .map(|s| *s.tag())
                .collect();

            assert!(
                published.iter().any(|t| sought.contains(t)),
                "a skew of {skew}s left the peers with no tag in common"
            );
        }
    }

    /// A lookup must always query the same number of tags, whatever the clock
    /// says: a variable count would leak the querier's state to the substrate.
    #[test]
    fn lookup_always_queries_three_tags() {
        let s = secret();
        for now in [0u64, 1, EPOCH_SECS, 1_800_000_000] {
            assert_eq!(s.lookup_slots(Direction::LowToHigh, now).len(), 3);
        }
    }

    /// A clock at the Unix epoch must not panic on the `epoch - 1` lookup.
    #[test]
    fn a_clock_at_zero_does_not_panic() {
        let s = secret();
        let slots = s.lookup_slots(Direction::LowToHigh, 0);
        assert_eq!(slots.len(), 3);
    }

    /// Derivation must be a pure function of (secret, direction, epoch) — both
    /// peers compute it independently and must land on the same bytes.
    #[test]
    fn derivation_is_deterministic() {
        let s = secret();
        assert_eq!(
            s.slot(Direction::HighToLow, 12345).tag(),
            s.slot(Direction::HighToLow, 12345).tag()
        );
    }

    /// The secret must not be printable by accident — a debug line that leaked it
    /// would hand an attacker the ability to forge address records.
    #[test]
    fn the_secret_never_debug_prints_itself() {
        let s = RendezvousSecret::from_bytes([0xAB; 32]);
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("ab"), "got: {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn tag_hex_is_lowercase_and_full_width() {
        let s = secret();
        let hex = s.slot(Direction::LowToHigh, 1).tag_hex();
        assert_eq!(hex.len(), TAG_LEN * 2);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }
}
