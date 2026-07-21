//! The server link: one string that names a rendezvous endpoint and pins it
//! (roadmap Phase 8).
//!
//! # Why an address never reaches the user's hands
//!
//! A packet needs a route, so an address has to exist. What must not exist is a
//! **human handling it separately from the identity**. The moment a user is
//! asked for a host, a port, and a certificate fingerprint as three fields, two
//! things follow: the fingerprint is the one people skip, and a mistyped one is
//! indistinguishable from a correct one until it fails. So the address, the
//! path, and the pin travel together in a single checksummed blob, and the only
//! thing a user ever does is paste it.
//!
//! This is the same shape as [`crate::ticket::Ticket`] deliberately. A peer and a
//! rendezvous endpoint are both "somewhere to connect, plus the key that proves
//! it is the right somewhere", and giving them two different formats would mean
//! two chances to get the pinning wrong.
//!
//! # What the pin does, and what Syncthing actually does
//!
//! Syncthing configures a discovery server as
//! `https://discovery.syncthing.net/v2/?id=LYXKCHX-VI3NYZR-…` and a relay as
//! `relay://31.16.4.4:22067/?id=…`. Both carry a host **and** an ID — the ID
//! does not replace the address, it replaces the certificate authority. Those
//! strings feel invisible only because they ship compiled into the binary.
//!
//! The same division holds here: the address routes, the pin authenticates. A
//! hostile DNS answer, a hijacked IP, or a mis-issued certificate all fail,
//! because the endpoint that answers has to hold the key the link names.
//!
//! # Onion links, and the case with no address at all
//!
//! A link may carry an onion instead of (or as well as) a host. An onion address
//! is self-authenticating and routable at once, so an onion-only link is the one
//! form where no IP exists anywhere in the configuration — Tor resolves it, and
//! neither the user nor this machine ever handles a routable address. It costs
//! Tor's latency on a request made once per connection.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use rustls::pki_types::ServerName;

use crate::Error;
use crate::discovery::blind::CertPin;
use crate::ticket::Reader;
use crate::tor::OnionAddress;

/// Human-visible prefix, carrying the format version so a future incompatible
/// link is rejected by name rather than misparsed.
pub const LINK_PREFIX: &str = "atom-rdv-1:";

/// Link binary format version.
const FORMAT_VERSION: u8 = 1;

/// Bytes of BLAKE3 appended as a transcription checksum.
const CHECKSUM_LEN: usize = 4;

/// Domain separator, so this checksum can never collide with the ticket's over
/// the same bytes.
const CHECKSUM_DOMAIN: &[u8] = b"atom-live-rdv-link-checksum-v1";

/// Encoded width of a v3 onion host, including the `.onion` suffix.
const ONION_LABEL_BYTES: usize = 62;

/// Caps, so a decoded link is bounded whatever it claims.
const MAX_HOST_LEN: usize = 255;
const MAX_PREFIX_LEN: usize = 128;
const MAX_PINS: usize = 8;

/// What kind of server a link names.
///
/// Present from the first version so the relay (roadmap Phase 8, outstanding)
/// can share this format without a peer ever mistaking one for the other. An
/// unknown kind is refused, not ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerKind {
    /// A blind store holding sealed address records.
    Rendezvous,
    /// A byte pipe for peers that cannot hole-punch. Not yet implemented; the
    /// value exists so a relay link is refused clearly rather than misread as a
    /// rendezvous endpoint.
    Relay,
}

impl ServerKind {
    fn to_byte(self) -> u8 {
        match self {
            ServerKind::Rendezvous => 1,
            ServerKind::Relay => 2,
        }
    }

    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            1 => Ok(ServerKind::Rendezvous),
            2 => Ok(ServerKind::Relay),
            other => Err(Error::Discovery(format!(
                "unknown server kind {other}: this link is for something this build \
                 does not implement, and its security properties are unknown"
            ))),
        }
    }
}

/// Everything needed to reach and authenticate one server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerLink {
    pub kind: ServerKind,
    /// DNS name or IP literal. Empty when the link is onion-only.
    pub host: String,
    pub port: u16,
    /// Path the tags hang under.
    pub prefix: String,
    /// SHA-256 of the certificate(s) it may present. At least one.
    pub pins: Vec<CertPin>,
    /// An onion the server also answers on.
    pub onion: Option<OnionAddress>,
}

impl ServerLink {
    /// Build a link, validating everything a decoder would.
    ///
    /// Operators call this once to produce the string they publish; users never
    /// do, which is the point.
    pub fn new(
        kind: ServerKind,
        host: impl Into<String>,
        port: u16,
        prefix: impl Into<String>,
        pins: Vec<CertPin>,
        onion: Option<OnionAddress>,
    ) -> Result<Self, Error> {
        let link = ServerLink {
            kind,
            host: host.into(),
            port,
            prefix: prefix.into().trim_matches('/').to_string(),
            pins,
            onion,
        };
        link.validate()?;
        Ok(link)
    }

    /// The checks applied on construction *and* on decode, so a hand-built link
    /// and a pasted one cannot differ in what they permit.
    fn validate(&self) -> Result<(), Error> {
        if self.host.is_empty() && self.onion.is_none() {
            return Err(Error::Discovery(
                "a server link needs somewhere to connect: give it a host or an onion".into(),
            ));
        }
        if self.host.len() > MAX_HOST_LEN {
            return Err(Error::Discovery("server host is too long".into()));
        }
        if !self.host.is_empty() {
            // Rejected here rather than at connect time: a link is pasted once
            // and used for months, so a malformed host must fail on paste.
            ServerName::try_from(self.host.clone())
                .map_err(|_| Error::Discovery(format!("`{}` is not a usable host", self.host)))?;
        }
        if self.prefix.len() > MAX_PREFIX_LEN {
            return Err(Error::Discovery("server path prefix is too long".into()));
        }
        if self.pins.is_empty() {
            return Err(Error::Discovery(
                "a server link must pin at least one certificate: without a pin there \
                 is nothing distinguishing the real server from whoever answers, and \
                 this design has no CA to fall back on"
                    .into(),
            ));
        }
        if self.pins.len() > MAX_PINS {
            return Err(Error::Discovery(format!(
                "a server link may pin at most {MAX_PINS} certificates"
            )));
        }
        Ok(())
    }

    /// A short label for diagnostics, derived rather than carried.
    ///
    /// Deliberately not a field: a name inside the link would be attacker-chosen
    /// text rendered in the user's own UI, and it buys nothing a local nickname
    /// does not.
    pub fn label(&self) -> String {
        if !self.host.is_empty() {
            format!("{}:{}", self.host, self.port)
        } else if let Some(o) = &self.onion {
            format!("{}…onion", &o.host()[..8])
        } else {
            "server".to_string()
        }
    }

    /// Whether this link can be used without any routable address existing.
    pub fn is_onion_only(&self) -> bool {
        self.host.is_empty() && self.onion.is_some()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.push(FORMAT_VERSION);
        v.push(self.kind.to_byte());
        v.push(u8::from(self.onion.is_some()));

        v.push(self.host.len() as u8);
        v.extend_from_slice(self.host.as_bytes());
        v.extend_from_slice(&self.port.to_be_bytes());

        v.push(self.prefix.len() as u8);
        v.extend_from_slice(self.prefix.as_bytes());

        v.push(self.pins.len() as u8);
        for pin in &self.pins {
            v.extend_from_slice(pin);
        }

        if let Some(o) = &self.onion {
            // Fixed 56-character label plus suffix, so no length prefix is
            // needed and a bad length cannot desynchronise the parse.
            v.extend_from_slice(o.host().as_bytes());
            v.extend_from_slice(&o.port().to_be_bytes());
        }
        v
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::named(bytes, "server link");

        let version = r.u8()?;
        if version != FORMAT_VERSION {
            return Err(Error::Discovery(format!(
                "server link format version {version}, this build understands \
                 {FORMAT_VERSION}"
            )));
        }
        let kind = ServerKind::from_byte(r.u8()?)?;
        let has_onion = match r.u8()? {
            0 => false,
            1 => true,
            other => {
                return Err(Error::Discovery(format!(
                    "server link flag byte {other} is not a boolean"
                )));
            }
        };

        let host_len = r.u8()? as usize;
        let host = std::str::from_utf8(r.take(host_len)?)
            .map_err(|_| Error::Discovery("server host is not valid UTF-8".into()))?
            .to_string();
        let port = r.u16()?;

        let prefix_len = r.u8()? as usize;
        let prefix = std::str::from_utf8(r.take(prefix_len)?)
            .map_err(|_| Error::Discovery("server path prefix is not valid UTF-8".into()))?
            .to_string();

        let pin_count = r.u8()? as usize;
        if pin_count > MAX_PINS {
            return Err(Error::Discovery(format!(
                "server link pins {pin_count} certificates, more than the {MAX_PINS} allowed"
            )));
        }
        let mut pins = Vec::with_capacity(pin_count);
        for _ in 0..pin_count {
            let pin: CertPin = r.take(32)?.try_into().expect("32 bytes taken");
            pins.push(pin);
        }

        let onion = if has_onion {
            let label = std::str::from_utf8(r.take(ONION_LABEL_BYTES)?)
                .map_err(|_| Error::Discovery("onion host is not valid UTF-8".into()))?;
            let onion_port = r.u16()?;
            // Validated while decoding, not merely copied: a link is
            // attacker-influenced input and an unvalidated host reaches a SOCKS
            // proxy.
            Some(
                OnionAddress::new(label, onion_port)
                    .map_err(|e| Error::Discovery(format!("server link has a bad onion: {e}")))?,
            )
        } else {
            None
        };

        if !r.is_empty() {
            return Err(Error::Discovery(
                "trailing bytes after the server link — refusing an ambiguous encoding".into(),
            ));
        }

        let link = ServerLink {
            kind,
            host,
            port,
            prefix,
            pins,
            onion,
        };
        link.validate()?;
        Ok(link)
    }

    /// The pasteable form: `atom-rdv-1:<base32>`.
    ///
    /// The checksum catches transcription damage — a dropped character, a
    /// swapped pair — and is **not** a security control: anyone who can rewrite
    /// a link can rewrite its checksum. What makes a link safe to accept is that
    /// the pin inside it is checked against whoever answers.
    pub fn to_text(&self) -> String {
        let mut payload = self.to_bytes();
        payload.extend_from_slice(&checksum(&payload));
        format!(
            "{LINK_PREFIX}{}",
            BASE32_NOPAD.encode(&payload).to_lowercase()
        )
    }

    /// Parse the pasteable form, tolerating case and surrounding whitespace — a
    /// link travels through chat clients and clipboards that mangle both.
    pub fn from_text(text: &str) -> Result<Self, Error> {
        let lowered = text.trim().to_lowercase();
        let body = lowered.strip_prefix(LINK_PREFIX).ok_or_else(|| {
            Error::Discovery(format!("a server link must start with `{LINK_PREFIX}`"))
        })?;

        let decoded = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|e| Error::Discovery(format!("server link is not valid base32: {e}")))?;

        if decoded.len() <= CHECKSUM_LEN {
            return Err(Error::Discovery(
                "server link is too short to be valid".into(),
            ));
        }
        let (payload, tail) = decoded.split_at(decoded.len() - CHECKSUM_LEN);
        if tail != checksum(payload) {
            return Err(Error::Discovery(
                "server link checksum does not match — it was probably copied \
                 incompletely; ask for it again rather than editing it"
                    .into(),
            ));
        }

        ServerLink::from_bytes(payload)
    }
}

impl fmt::Display for ServerLink {
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

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn pins() -> Vec<CertPin> {
        vec![[1u8; 32], [2u8; 32]]
    }

    fn sample() -> ServerLink {
        ServerLink::new(
            ServerKind::Rendezvous,
            "rdv.example.org",
            8443,
            "records",
            pins(),
            Some(OnionAddress::new(ONION, 8443).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn text_form_round_trips() {
        let link = sample();
        assert_eq!(ServerLink::from_text(&link.to_text()).unwrap(), link);
    }

    /// Links travel through chat clients that capitalise and pad. Neither may
    /// break a paste.
    #[test]
    fn text_form_tolerates_case_and_whitespace() {
        let link = sample();
        let mangled = format!("\n  {}\t ", link.to_text().to_uppercase());
        assert_eq!(ServerLink::from_text(&mangled).unwrap(), link);
    }

    /// The whole reason the pin travels inside the link: it cannot be dropped
    /// while the rest still parses.
    #[test]
    fn a_link_without_a_pin_is_refused() {
        let err = ServerLink::new(
            ServerKind::Rendezvous,
            "rdv.example.org",
            8443,
            "",
            vec![],
            None,
        )
        .expect_err("an unpinned link must not be constructible");
        assert!(err.to_string().contains("pin"), "got: {err}");
    }

    /// A damaged link must be refused, never guessed at — a link with one
    /// flipped character in a pin would fail to connect for no visible reason.
    #[test]
    fn a_damaged_link_is_refused() {
        let text = sample().to_text();

        assert!(ServerLink::from_text(&text[..text.len() - 1]).is_err());

        let mut chars: Vec<char> = text.chars().collect();
        let i = LINK_PREFIX.len() + 5;
        chars[i] = if chars[i] == 'a' { 'b' } else { 'a' };
        let flipped: String = chars.into_iter().collect();
        assert!(ServerLink::from_text(&flipped).is_err());

        assert!(ServerLink::from_text("not-a-link").is_err());
        assert!(ServerLink::from_text(LINK_PREFIX).is_err());
    }

    /// Truncation at every length must error rather than panic.
    #[test]
    fn truncated_binary_never_panics() {
        let bytes = sample().to_bytes();
        for n in 0..bytes.len() {
            assert!(
                ServerLink::from_bytes(&bytes[..n]).is_err(),
                "prefix of length {n} must be rejected"
            );
        }
        assert!(ServerLink::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = sample().to_bytes();
        bytes.push(0);
        assert!(ServerLink::from_bytes(&bytes).is_err());
    }

    /// A relay link must not be silently usable as a rendezvous endpoint: the
    /// two do different jobs and expose different things.
    #[test]
    fn the_server_kind_survives_the_round_trip() {
        let relay = ServerLink::new(
            ServerKind::Relay,
            "relay.example.org",
            8443,
            "",
            pins(),
            None,
        )
        .unwrap();
        assert_eq!(
            ServerLink::from_text(&relay.to_text()).unwrap().kind,
            ServerKind::Relay
        );
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        let mut bytes = sample().to_bytes();
        bytes[1] = 0xFE;
        let err = ServerLink::from_bytes(&bytes).unwrap_err().to_string();
        assert!(err.contains("unknown server kind"), "got: {err}");
    }

    /// The form with no routable address anywhere in the configuration.
    #[test]
    fn an_onion_only_link_is_valid_and_says_so() {
        let link = ServerLink::new(
            ServerKind::Rendezvous,
            "",
            0,
            "records",
            pins(),
            Some(OnionAddress::new(ONION, 8443).unwrap()),
        )
        .unwrap();
        assert!(link.is_onion_only());
        assert_eq!(ServerLink::from_text(&link.to_text()).unwrap(), link);
    }

    /// A link that names nowhere at all is a configuration error, not an
    /// endpoint that silently never answers.
    #[test]
    fn a_link_with_nowhere_to_connect_is_refused() {
        assert!(ServerLink::new(ServerKind::Rendezvous, "", 0, "", pins(), None).is_err());
    }

    /// A malformed host must fail on paste, not months later mid-rendezvous.
    #[test]
    fn a_malformed_host_is_refused() {
        assert!(
            ServerLink::new(ServerKind::Rendezvous, "not a host", 443, "", pins(), None).is_err()
        );
    }

    /// A hostile link must not be able to smuggle an unvalidated onion host
    /// through to the SOCKS proxy.
    #[test]
    fn a_malformed_onion_is_rejected_while_decoding() {
        let link = ServerLink::new(
            ServerKind::Rendezvous,
            "rdv.example.org",
            8443,
            "",
            pins(),
            Some(OnionAddress::new(ONION, 8443).unwrap()),
        )
        .unwrap();
        let mut bytes = link.to_bytes();
        // Corrupt a character of the onion label into one outside base32.
        let idx = bytes.len() - ONION_LABEL_BYTES - 2 + 3;
        bytes[idx] = b'1';
        let err = ServerLink::from_bytes(&bytes).unwrap_err().to_string();
        assert!(err.contains("onion"), "got: {err}");
    }

    /// A label is for the user's own screen, so it must never be empty or carry
    /// text an operator chose.
    #[test]
    fn labels_are_derived_from_the_address() {
        assert_eq!(sample().label(), "rdv.example.org:8443");
        let onion_only = ServerLink::new(
            ServerKind::Rendezvous,
            "",
            0,
            "",
            pins(),
            Some(OnionAddress::new(ONION, 8443).unwrap()),
        )
        .unwrap();
        assert!(onion_only.label().ends_with("onion"));
    }
}
