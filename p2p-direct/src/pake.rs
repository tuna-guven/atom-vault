//! L4 — capability delivery via SPAKE2.
//!
//! The read-cap ([`crate::ReadCap`]) is never sent directly. Instead the two
//! humans share a **short** secret out-of-band (a few words / ~50 bits,
//! single-use). Both sides expand it via SPAKE2 into a strong ephemeral channel
//! key; an eavesdropper who lacks the exact short secret learns nothing, and
//! online guessing is limited to a single attempt per handshake.
//!
//! Over the resulting channel the sender seals the cap with XChaCha20-Poly1305.
//!
//! Protocol (one round trip, symmetric SPAKE2):
//! ```text
//!   sender:    (state, msg_s) = start(secret)
//!   recipient: (state, msg_r) = start(secret)
//!   -- exchange msg_s / msg_r out-of-band --
//!   sender:    key = state.finish(msg_r)   ; sealed = seal_cap(key, cap)
//!   recipient: key = state.finish(msg_s)   ; cap    = open_cap(key, sealed)
//! ```
//! Both sides derive the *same* `key` iff they used the same short secret.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::crypto::{self, NONCE_LEN};
use crate::{Error, ReadCap};

/// Shared SPAKE2 identity so both peers run the *symmetric* variant. This is a
/// context string, not a secret.
const PAKE_IDENTITY: &[u8] = b"atom-vault-cap-v1";

/// HKDF-ish label separating the cap-sealing key from the raw SPAKE2 output.
const SEAL_LABEL: &[u8] = b"atom-cap-seal-v1";

/// In-progress SPAKE2 handshake. Produced by [`start`]; consumed by
/// [`SpakeState::finish`].
pub struct SpakeState {
    inner: Spake2<Ed25519Group>,
}

/// The strong ephemeral key both peers agree on. Zeroized on drop.
pub struct SessionKey(Zeroizing<Vec<u8>>);

/// Begin a SPAKE2 handshake from a short secret. Returns our handshake state
/// and the outbound message to hand to the peer over the OOB channel.
pub fn start(short_secret: &[u8]) -> (SpakeState, Vec<u8>) {
    let (inner, outbound) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(short_secret),
        &Identity::new(PAKE_IDENTITY),
    );
    (SpakeState { inner }, outbound)
}

impl SpakeState {
    /// Complete the handshake with the peer's message, yielding the shared key.
    /// Fails if the peer used a different short secret or sent a bad message.
    pub fn finish(self, peer_message: &[u8]) -> Result<SessionKey, Error> {
        let key = self.inner.finish(peer_message).map_err(|_| Error::Pake)?;
        Ok(SessionKey(Zeroizing::new(key)))
    }
}

/// Seal a read-cap under the SPAKE2 session key. Output is `nonce || ciphertext`
/// and is safe to hand to the recipient over the (already authenticated) OOB
/// channel.
pub fn seal_cap(session: &SessionKey, cap: &ReadCap) -> Result<Vec<u8>, Error> {
    let key = derive_seal_key(session);
    let nonce = crypto::random_nonce();
    let plaintext = cap.to_bytes();
    let ciphertext = crypto::seal(&key, &nonce, &plaintext[..])?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed read-cap with the SPAKE2 session key.
pub fn open_cap(session: &SessionKey, sealed: &[u8]) -> Result<ReadCap, Error> {
    if sealed.len() < NONCE_LEN {
        return Err(Error::Malformed("sealed cap too short".into()));
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    let key = derive_seal_key(session);
    let plaintext = crypto::open(&key, &nonce, ciphertext)?;
    ReadCap::from_bytes(&plaintext)
}

fn derive_seal_key(session: &SessionKey) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, &session.0);
    let mut key = [0u8; 32];
    hk.expand(SEAL_LABEL, &mut key)
        .expect("32 is a valid HKDF-SHA256 length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RootKey;

    fn sample_cap() -> ReadCap {
        ReadCap {
            root_key: RootKey::from_bytes([0x7a; 32]),
            manifest_id: [0x9c; 32],
        }
    }

    #[test]
    fn matching_secret_delivers_cap() {
        let secret = b"correct horse battery staple";
        let (s_state, s_msg) = start(secret);
        let (r_state, r_msg) = start(secret);

        let s_key = s_state.finish(&r_msg).unwrap();
        let r_key = r_state.finish(&s_msg).unwrap();

        let cap = sample_cap();
        let sealed = seal_cap(&s_key, &cap).unwrap();
        let opened = open_cap(&r_key, &sealed).unwrap();

        assert_eq!(opened.root_key.as_bytes(), cap.root_key.as_bytes());
        assert_eq!(opened.manifest_id, cap.manifest_id);
    }

    #[test]
    fn wrong_secret_cannot_open_cap() {
        let (s_state, s_msg) = start(b"the real secret");
        let (r_state, r_msg) = start(b"a wrong guess");

        // SPAKE2 finish succeeds structurally but yields a *different* key.
        let s_key = s_state.finish(&r_msg).unwrap();
        let r_key = r_state.finish(&s_msg).unwrap();

        let sealed = seal_cap(&s_key, &sample_cap()).unwrap();
        // The AEAD open under the mismatched key must fail — no cap leaks.
        assert!(open_cap(&r_key, &sealed).is_err());
    }

    #[test]
    fn tampered_sealed_cap_rejected() {
        let secret = b"shared";
        let (s_state, s_msg) = start(secret);
        let (r_state, r_msg) = start(secret);
        let s_key = s_state.finish(&r_msg).unwrap();
        let r_key = r_state.finish(&s_msg).unwrap();

        let mut sealed = seal_cap(&s_key, &sample_cap()).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(open_cap(&r_key, &sealed).is_err());
    }
}
