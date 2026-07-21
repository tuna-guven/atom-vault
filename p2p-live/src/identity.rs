//! Peer identity as a raw public key (RFC 7250) — no CA, no X.509 chain.
//!
//! An identity is an Ed25519 keypair. Its *public* half, in SubjectPublicKeyInfo
//! (SPKI) DER form, is what a peer pins: it plays the role the ed25519 device ID
//! plays in the Tor path, and is what a manually-exchanged L0 ticket carries.

use std::sync::Arc;

use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

use crate::Error;

/// A peer's public identity: the SPKI DER of its Ed25519 key.
///
/// This is the value exchanged out-of-band in an L0 ticket and pinned by the
/// other side. Comparing these byte-for-byte *is* the authentication check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPublicKey(Vec<u8>);

impl PeerPublicKey {
    pub fn from_der(der: Vec<u8>) -> Self {
        PeerPublicKey(der)
    }

    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    /// Short fingerprint for display and for humans to compare out-of-band.
    ///
    /// This **must** be a hash of the whole SPKI, never a prefix of it: an
    /// Ed25519 SPKI DER begins with a fixed 12-byte algorithm identifier
    /// (`302a300506032b6570032100`), so any prefix-based fingerprint is
    /// identical for every key in existence and would let a swapped identity
    /// pass a human check unnoticed.
    ///
    /// 64 bits shown. Not a security boundary on its own — the full SPKI is what
    /// is pinned — but it is what a human actually compares, so it has to
    /// distinguish keys.
    pub fn fingerprint(&self) -> String {
        use std::fmt::Write;
        let digest = blake3::hash(&self.0);
        digest.as_bytes()[..8]
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }
}

/// A local peer identity — the private half stays here and never leaves.
///
/// The private key is held in `Zeroizing`, so its bytes are wiped when the
/// identity is dropped rather than lingering in freed heap memory. This is the
/// long-term *authentication* key, not a session key, so its lifetime does not
/// affect forward secrecy — but wiping it is the same discipline the rest of the
/// codebase applies to secret material, and it is cheap.
pub struct LocalIdentity {
    public: PeerPublicKey,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl LocalIdentity {
    /// Generate a fresh Ed25519 identity.
    ///
    /// Note this is the *long-term* identity used for authentication only. It is
    /// never used for key agreement, so its compromise cannot retroactively
    /// decrypt recorded sessions — that is what makes strict PFS possible.
    pub fn generate() -> Result<Self, Error> {
        let kp = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| Error::Identity(format!("key generation failed: {e}")))?;
        Ok(LocalIdentity {
            public: PeerPublicKey(kp.subject_public_key_info()),
            pkcs8: Zeroizing::new(kp.serialize_der()),
        })
    }

    pub fn public_key(&self) -> &PeerPublicKey {
        &self.public
    }

    /// Build the rustls `CertifiedKey` presenting this identity as a raw public
    /// key. For RPK the "certificate" entry carries the SPKI, not an X.509 cert.
    ///
    /// Public so tests (and future transports) can bind an identity to a
    /// provider other than the default hybrid one.
    pub fn certified_key(&self, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>, Error> {
        let spki_as_cert = CertificateDer::from(self.public.0.clone());
        // rustls takes ownership of the key bytes; we hand it a transient copy and
        // keep our own in `Zeroizing`. rustls manages its own copy's lifetime.
        let key = PrivateKeyDer::try_from(self.pkcs8.as_slice().to_vec())
            .map_err(|e| Error::Identity(format!("bad private key: {e}")))?;

        // Load the signing key directly and use `CertifiedKey::new` rather than
        // `from_der`: the latter runs `keys_match()`, which parses the entry as
        // an X.509 certificate. Under RFC 7250 the entry is a bare SPKI, so that
        // check would fail with `BadEncoding`.
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| Error::Identity(format!("load private key: {e}")))?;

        Ok(Arc::new(CertifiedKey::new(vec![spki_as_cert], signing_key)))
    }
}

impl std::fmt::Debug for LocalIdentity {
    // Never print the private half.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("public", &self.public.fingerprint())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for a real bug: `fingerprint` used to return the first
    /// bytes of the SPKI DER, which is a *constant* algorithm identifier for
    /// Ed25519. Every identity printed the same fingerprint, so a human
    /// comparing them out-of-band could not have detected a swapped key.
    #[test]
    fn fingerprints_distinguish_identities() {
        let a = LocalIdentity::generate().unwrap();
        let b = LocalIdentity::generate().unwrap();
        assert_ne!(
            a.public_key().fingerprint(),
            b.public_key().fingerprint(),
            "distinct identities must have distinct fingerprints"
        );
        assert_eq!(
            a.public_key().fingerprint(),
            a.public_key().fingerprint(),
            "fingerprints must be stable"
        );
        assert_eq!(a.public_key().fingerprint().len(), 16, "64 bits as hex");
    }
}
