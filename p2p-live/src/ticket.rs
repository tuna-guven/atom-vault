//! L0 — the connection ticket (roadmap Phase 3).
//!
//! A ticket is what one peer hands the other out-of-band so a live session can
//! be established. It carries everything needed to *find* and *authenticate* the
//! peer, and deliberately nothing else:
//!
//! * the peer's **identity** as an RFC 7250 raw public key (what gets pinned),
//! * **transport hints** — the address(es) to try,
//! * a **suite** identifying the protocol and its security properties,
//! * an **expiry**, because a stale ticket points at an address that may since
//!   have been reassigned to someone else.
//!
//! # What a ticket is not
//!
//! A ticket carries **no key material and no capability**. Possessing one lets
//! you *attempt* a connection to a peer who has pinned you; it does not decrypt
//! anything and does not authorise anything. This is the deliberate inverse of
//! the Mode A read-cap that this design deletes: there is no bearer secret here
//! to steal, compel, or harvest.
//!
//! It is still not public information — a ticket links an identity to an IP
//! address, which is exactly the pairing metadata the threat model cares about.
//! Exchange it over the pairing channel ([`crate::pairing`]), not in the clear.
//!
//! # No broker
//!
//! Per `CLAUDE.md` §6, tickets are exchanged **by the humans**. There is no
//! directory, no rendezvous server, and nothing in this module contacts the
//! network. Addresses are entered manually by default; [`crate::stun`] is the
//! opt-in convenience path and comes with its own warning.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;

use crate::Error;
use crate::identity::PeerPublicKey;
use crate::tor::OnionAddress;

/// Human-visible prefix. Includes the format version so a future incompatible
/// ticket is rejected by name rather than misparsed.
pub const TICKET_PREFIX: &str = "atom-live-1:";

/// Ticket binary format version.
const FORMAT_VERSION: u8 = 1;

/// Bytes of BLAKE3 appended as a transcription checksum.
const CHECKSUM_LEN: usize = 4;

/// Domain separator for the checksum, so it can never collide with any other
/// hash this crate computes over the same bytes.
const CHECKSUM_DOMAIN: &[u8] = b"atom-live-ticket-checksum-v1";

/// Encoded width of a v3 onion host, including the `.onion` suffix.
const ONION_LABEL_BYTES: usize = 62;

/// A cap on hint count, keeping a decoded ticket bounded.
const MAX_HINTS: usize = 8;

/// Address-family tags inside the encoded hint list.
const TAG_V4: u8 = 4;
const TAG_V6: u8 = 6;
const TAG_ONION: u8 = 9;

/// A place the peer can be reached.
///
/// Both transports are expressible, and which one a ticket offers is the
/// recipient's choice of tradeoff — not something this layer decides. A direct
/// address is fast but tells both ISPs who is talking to whom; an onion address
/// hides that pairing at the cost of Tor's latency (`CLAUDE.md` §10).
///
/// A ticket may carry both, and a peer may then pick. Nothing here ranks them:
/// offering an onion at all is a deliberate act, and silently preferring the
/// fast path would quietly undo it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A routable UDP address for the QUIC rendezvous.
    Direct(SocketAddr),
    /// A v3 onion service reached over Tor.
    Onion(OnionAddress),
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Direct(a) => write!(f, "{a}"),
            Endpoint::Onion(a) => write!(f, "{a}"),
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(a: SocketAddr) -> Self {
        Endpoint::Direct(a)
    }
}

impl From<OnionAddress> for Endpoint {
    fn from(a: OnionAddress) -> Self {
        Endpoint::Onion(a)
    }
}

/// Default ticket lifetime. Short on purpose: a ticket names an address, and an
/// address that was yours last month may be someone else's today. Re-pairing is
/// cheap; connecting to a stranger's host is not.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// The protocol suite a ticket is for.
///
/// This is the hook for roadmap §6. The live suite's defining property is strict
/// forward secrecy; if a non-forward-secret async mode is ever reintroduced it
/// **must** take a new suite value rather than reusing this one, so a peer can
/// never silently reinterpret a live ticket as something with weaker
/// guarantees. Unknown suite values are rejected, not ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Suite {
    /// Live QUIC transfer: hybrid PQ key agreement (`X25519MLKEM768`), TLS 1.3
    /// only, raw-public-key mutual pinning, strict forward secrecy.
    LivePq1,
}

impl Suite {
    fn to_byte(self) -> u8 {
        match self {
            Suite::LivePq1 => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            1 => Ok(Suite::LivePq1),
            other => Err(Error::Ticket(format!(
                "unknown suite {other}: this ticket is for a protocol this build \
                 does not implement, and its security properties are unknown"
            ))),
        }
    }
}

/// A connection ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// The peer's identity — this is what the session pins.
    pub identity: PeerPublicKey,
    /// Places to try, in preference order. May be empty when the peer will be
    /// the one dialling.
    pub hints: Vec<Endpoint>,
    /// The protocol this ticket is for.
    pub suite: Suite,
    /// Unix seconds after which this ticket must be refused.
    pub not_after: u64,
}

impl Ticket {
    /// Build a ticket valid for [`DEFAULT_TTL_SECS`] from now.
    pub fn new(identity: PeerPublicKey, hints: Vec<Endpoint>) -> Result<Self, Error> {
        Ok(Ticket {
            identity,
            hints,
            suite: Suite::LivePq1,
            not_after: now_secs()?.saturating_add(DEFAULT_TTL_SECS),
        })
    }

    /// Override the expiry (absolute Unix seconds).
    pub fn expiring_at(mut self, not_after: u64) -> Self {
        self.not_after = not_after;
        self
    }

    /// Whether this ticket has expired as of `now` (Unix seconds).
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.not_after
    }

    /// Reject an expired ticket. Callers should run this before dialling.
    pub fn check_valid(&self) -> Result<(), Error> {
        if self.is_expired_at(now_secs()?) {
            return Err(Error::Ticket(
                "ticket has expired — ask the peer for a fresh one rather than \
                 dialling an address that may have been reassigned"
                    .into(),
            ));
        }
        Ok(())
    }

    /// The peer fingerprint humans compare out-of-band.
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Canonical binary encoding — the input to both the text form and the
    /// checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.push(FORMAT_VERSION);
        v.push(self.suite.to_byte());
        v.extend_from_slice(&self.not_after.to_be_bytes());

        let der = self.identity.as_der();
        v.push(der.len() as u8);
        v.extend_from_slice(der);

        v.push(self.hints.len() as u8);
        for hint in &self.hints {
            match hint {
                Endpoint::Direct(addr) => {
                    match addr.ip() {
                        IpAddr::V4(a) => {
                            v.push(TAG_V4);
                            v.extend_from_slice(&a.octets());
                        }
                        IpAddr::V6(a) => {
                            v.push(TAG_V6);
                            v.extend_from_slice(&a.octets());
                        }
                    }
                    v.extend_from_slice(&addr.port().to_be_bytes());
                }
                Endpoint::Onion(onion) => {
                    v.push(TAG_ONION);
                    // The label is a fixed 56 characters for every v3 address,
                    // so no length prefix is needed — and a fixed width means a
                    // malformed length cannot be used to desynchronise the parse.
                    v.extend_from_slice(onion.host().as_bytes());
                    v.extend_from_slice(&onion.port().to_be_bytes());
                }
            }
        }
        v
    }

    /// Only the direct addresses, for the QUIC rendezvous.
    pub fn direct_hints(&self) -> Vec<SocketAddr> {
        self.hints
            .iter()
            .filter_map(|h| match h {
                Endpoint::Direct(a) => Some(*a),
                Endpoint::Onion(_) => None,
            })
            .collect()
    }

    /// Only the onion addresses, for the Tor transport.
    pub fn onion_hints(&self) -> Vec<OnionAddress> {
        self.hints
            .iter()
            .filter_map(|h| match h {
                Endpoint::Onion(a) => Some(a.clone()),
                Endpoint::Direct(_) => None,
            })
            .collect()
    }

    /// Decode the canonical binary form.
    ///
    /// Every length is checked before it is used; a malformed ticket is an
    /// error, never a panic and never a partial parse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);

        let version = r.u8()?;
        if version != FORMAT_VERSION {
            return Err(Error::Ticket(format!(
                "ticket format version {version}, this build understands {FORMAT_VERSION}"
            )));
        }
        let suite = Suite::from_byte(r.u8()?)?;
        let not_after = r.u64()?;

        let id_len = r.u8()? as usize;
        if id_len == 0 {
            return Err(Error::Ticket("ticket carries no identity".into()));
        }
        let identity = PeerPublicKey::from_der(r.take(id_len)?.to_vec());

        let hint_count = r.u8()? as usize;
        if hint_count > MAX_HINTS {
            return Err(Error::Ticket(format!(
                "ticket lists {hint_count} address hints, more than the {MAX_HINTS} allowed"
            )));
        }
        let mut hints = Vec::with_capacity(hint_count);
        for _ in 0..hint_count {
            let hint = match r.u8()? {
                TAG_V4 => {
                    let o: [u8; 4] = r.take(4)?.try_into().expect("4 bytes taken");
                    let port = r.u16()?;
                    Endpoint::Direct(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port))
                }
                TAG_V6 => {
                    let o: [u8; 16] = r.take(16)?.try_into().expect("16 bytes taken");
                    let port = r.u16()?;
                    Endpoint::Direct(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
                }
                TAG_ONION => {
                    let label = r.take(ONION_LABEL_BYTES)?;
                    let host = std::str::from_utf8(label)
                        .map_err(|_| Error::Ticket("onion hint is not valid UTF-8".into()))?;
                    let port = r.u16()?;
                    // Validated on the way in, not merely copied: a ticket is
                    // attacker-influenced input, and an unvalidated host here
                    // would reach the SOCKS proxy.
                    Endpoint::Onion(OnionAddress::new(host, port).map_err(|e| {
                        Error::Ticket(format!("ticket carries a bad onion hint: {e}"))
                    })?)
                }
                tag => return Err(Error::Ticket(format!("unknown address family tag {tag}"))),
            };
            hints.push(hint);
        }

        if !r.is_empty() {
            return Err(Error::Ticket(
                "trailing bytes after ticket — refusing an ambiguous encoding".into(),
            ));
        }

        Ok(Ticket {
            identity,
            hints,
            suite,
            not_after,
        })
    }

    /// The pasteable text form: `atom-live-1:<base32>`.
    ///
    /// A 4-byte BLAKE3 checksum is appended before encoding. It catches
    /// transcription damage — a dropped character, a swapped pair — and is
    /// **not** a security control: anyone who can rewrite a ticket can rewrite
    /// its checksum too. Authenticity comes from the pairing channel that
    /// carried the ticket, not from this.
    pub fn to_text(&self) -> String {
        let mut payload = self.to_bytes();
        payload.extend_from_slice(&checksum(&payload));
        format!(
            "{TICKET_PREFIX}{}",
            BASE32_NOPAD.encode(&payload).to_lowercase()
        )
    }

    /// Parse the text form, tolerating case and surrounding whitespace — a
    /// ticket travels through chat clients and clipboards that mangle both.
    pub fn from_text(text: &str) -> Result<Self, Error> {
        let lowered = text.trim().to_lowercase();
        let body = lowered
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| Error::Ticket(format!("ticket must start with `{TICKET_PREFIX}`")))?;

        let decoded = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|e| Error::Ticket(format!("not valid base32: {e}")))?;

        if decoded.len() <= CHECKSUM_LEN {
            return Err(Error::Ticket("ticket is too short to be valid".into()));
        }
        let (payload, tail) = decoded.split_at(decoded.len() - CHECKSUM_LEN);
        if tail != checksum(payload) {
            return Err(Error::Ticket(
                "ticket checksum does not match — it was probably copied incompletely; \
                 ask for it again rather than editing it"
                    .into(),
            ));
        }

        Ticket::from_bytes(payload)
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(payload);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..CHECKSUM_LEN]);
    out
}

fn now_secs() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Ticket("system clock is before the Unix epoch".into()))
}

/// Bounds-checked cursor. Every read is length-checked before it indexes, so a
/// hostile or truncated ticket produces an error rather than a panic.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::Ticket("ticket length overflow".into()))?;
        if end > self.buf.len() {
            return Err(Error::Ticket(format!(
                "ticket truncated: wanted {n} bytes at offset {}, only {} remain",
                self.pos,
                self.buf.len() - self.pos
            )));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let b: [u8; 8] = self.take(8)?.try_into().expect("8 bytes taken");
        Ok(u64::from_be_bytes(b))
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn direct(s: &str) -> Endpoint {
        Endpoint::Direct(s.parse().unwrap())
    }

    fn sample() -> Ticket {
        let id = LocalIdentity::generate().unwrap();
        Ticket::new(
            id.public_key().clone(),
            vec![
                direct("203.0.113.7:4433"),
                direct("[2001:db8::1]:4433"),
                Endpoint::Onion(OnionAddress::new(ONION, 4433).unwrap()),
            ],
        )
        .unwrap()
    }

    #[test]
    fn text_form_round_trips() {
        let t = sample();
        let parsed = Ticket::from_text(&t.to_text()).unwrap();
        assert_eq!(parsed, t);
    }

    /// Tickets travel through chat clients and clipboards that helpfully
    /// capitalise and pad. Neither may break a paste.
    #[test]
    fn text_form_tolerates_case_and_whitespace() {
        let t = sample();
        let mangled = format!("\n  {}\t ", t.to_text().to_uppercase());
        assert_eq!(Ticket::from_text(&mangled).unwrap(), t);
    }

    #[test]
    fn a_damaged_ticket_is_refused_not_guessed() {
        let t = sample();
        let text = t.to_text();

        // Drop a character.
        let short = &text[..text.len() - 1];
        assert!(Ticket::from_text(short).is_err(), "truncated ticket");

        // Flip one base32 character in the body.
        let mut chars: Vec<char> = text.chars().collect();
        let i = TICKET_PREFIX.len() + 3;
        chars[i] = if chars[i] == 'a' { 'b' } else { 'a' };
        let flipped: String = chars.into_iter().collect();
        assert!(Ticket::from_text(&flipped).is_err(), "corrupted ticket");

        assert!(Ticket::from_text("not-a-ticket").is_err());
        assert!(Ticket::from_text(TICKET_PREFIX).is_err());
    }

    /// Truncation at every length must error rather than panic.
    #[test]
    fn truncated_binary_never_panics() {
        let bytes = sample().to_bytes();
        for n in 0..bytes.len() {
            assert!(
                Ticket::from_bytes(&bytes[..n]).is_err(),
                "prefix of length {n} must be rejected"
            );
        }
        assert!(Ticket::from_bytes(&bytes).is_ok());
    }

    /// Trailing bytes must be refused: two encodings decoding to one ticket is
    /// exactly the ambiguity that makes a checksum or signature meaningless.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = sample().to_bytes();
        bytes.push(0);
        assert!(Ticket::from_bytes(&bytes).is_err());
    }

    #[test]
    fn unknown_suite_is_rejected() {
        let mut bytes = sample().to_bytes();
        bytes[1] = 0xFE;
        let err = Ticket::from_bytes(&bytes).unwrap_err().to_string();
        assert!(err.contains("unknown suite"), "got: {err}");
    }

    #[test]
    fn too_many_hints_are_refused() {
        let id = LocalIdentity::generate().unwrap();
        let mut t = Ticket::new(id.public_key().clone(), vec![]).unwrap();
        t.hints = (0..=MAX_HINTS)
            .map(|i| {
                Endpoint::Direct(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                    443,
                ))
            })
            .collect();
        assert!(Ticket::from_bytes(&t.to_bytes()).is_err());
    }

    #[test]
    fn expiry_is_enforced() {
        let t = sample().expiring_at(0);
        assert!(t.is_expired_at(1));
        assert!(t.check_valid().is_err());

        let t = sample().expiring_at(u64::MAX);
        assert!(!t.is_expired_at(now_secs().unwrap()));
        assert!(t.check_valid().is_ok());
    }

    /// A ticket must expose the peer's real fingerprint — the thing a human
    /// compares before trusting it.
    #[test]
    fn fingerprint_comes_from_the_identity() {
        let t = sample();
        assert_eq!(t.fingerprint(), t.identity.fingerprint());
        assert_ne!(t.fingerprint(), sample().fingerprint());
    }

    /// A ticket contains no secret: everything in it is derivable from the
    /// peer's public key and address.
    #[test]
    fn ticket_carries_no_key_material() {
        let id = LocalIdentity::generate().unwrap();
        let t = Ticket::new(id.public_key().clone(), vec![]).unwrap();
        let bytes = t.to_bytes();
        // The only identity-derived bytes present are the public SPKI itself.
        let der = id.public_key().as_der();
        let occurrences = bytes.windows(der.len()).filter(|w| *w == der).count();
        assert_eq!(
            occurrences, 1,
            "the SPKI appears once and nothing else does"
        );
        assert_eq!(bytes.len(), 1 + 1 + 8 + 1 + der.len() + 1);
    }

    /// Both transports must survive the round trip, and each must be selectable
    /// on its own — the rendezvous needs direct addresses, the Tor path needs
    /// onions, and neither may silently see the other's.
    #[test]
    fn direct_and_onion_hints_round_trip_and_stay_separate() {
        let t = Ticket::from_text(&sample().to_text()).unwrap();
        assert_eq!(t.direct_hints().len(), 2);
        assert_eq!(t.onion_hints().len(), 1);
        assert_eq!(t.onion_hints()[0].host(), ONION);
        assert_eq!(t.onion_hints()[0].port(), 4433);
    }

    /// A ticket is attacker-influenced input. An onion hint that is not a valid
    /// v3 address must be rejected while decoding, not handed to a SOCKS proxy.
    #[test]
    fn a_malformed_onion_hint_is_rejected_while_decoding() {
        let id = LocalIdentity::generate().unwrap();
        let t = Ticket::new(
            id.public_key().clone(),
            vec![Endpoint::Onion(OnionAddress::new(ONION, 443).unwrap())],
        )
        .unwrap();
        let mut bytes = t.to_bytes();
        // Corrupt one character of the onion label into one outside base32.
        let idx = bytes.len() - ONION_LABEL_BYTES - 2 + 3;
        bytes[idx] = b'1';
        let err = Ticket::from_bytes(&bytes).unwrap_err().to_string();
        assert!(err.contains("onion"), "got: {err}");
    }
}
