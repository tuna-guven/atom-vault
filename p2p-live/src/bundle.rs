//! Hybrid identity: an Ed25519 key for the handshake, an ML-DSA-65 key for
//! post-quantum authentication (roadmap Phase 6).
//!
//! # Why a bundle rather than a bigger key
//!
//! Roadmap §3.2 requires key agreement to be hybrid — secure if *either* half
//! holds — and the same reasoning applies to authentication. ML-DSA is young;
//! replacing Ed25519 with it would trade a well-understood risk for a
//! poorly-understood one. So an identity is **both** keys, and impersonating a
//! peer requires breaking **both**.
//!
//! # Why the two keys are used in different places
//!
//! They cannot both sit in the TLS handshake. TLS 1.3's `CertificateVerify`
//! carries exactly one signature, and combining two into a composite scheme is
//! an unstandardised construction this project has no business inventing
//! (roadmap §3.1). So:
//!
//! * **Ed25519** authenticates the TLS handshake, exactly as before.
//! * **ML-DSA-65** authenticates the *channel* immediately afterwards, via a
//!   signature over the TLS exporter — see [`crate::pq_auth`].
//!
//! The result is the property that matters: an attacker must forge both to
//! impersonate. What it is not is a post-quantum TLS handshake; see
//! [`crate::pq_auth`] for exactly what is and is not covered.
//!
//! # Sizes, and why the URI had to change
//!
//! An ML-DSA-65 public key is ~1952 bytes against Ed25519's 32. The existing
//! `atom://` URI inlines a 32-byte key as 52 base32 characters; inlining a
//! bundle would produce a multi-kilobyte URI nobody can read aloud or paste.
//! Hence the split the roadmap anticipated (§3.4):
//!
//! * a **[`BundleId`]** — 32 bytes of BLAKE3 over the bundle — goes in the URI
//!   and is what humans compare, at the same 52 characters as today;
//! * the **full bundle** travels in a ticket, over the pairing channel, where a
//!   couple of kilobytes costs nothing.

use std::fmt;
use std::sync::Arc;

use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair};
use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

use crate::Error;
use crate::identity::{LocalIdentity, PeerPublicKey};

/// Domain separator for the bundle identifier, so the same bytes hashed for any
/// other purpose can never collide with an identity.
const BUNDLE_ID_DOMAIN: &[u8] = b"atom-live-identity-bundle-v1";

/// Bundle encoding version.
const BUNDLE_VERSION: u8 = 1;

/// ML-DSA-65 public key length, per FIPS 204.
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// An ML-DSA-65 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PqPublicKey(Vec<u8>);

impl PqPublicKey {
    /// Accept raw public key bytes, checking the length.
    ///
    /// The length check is the only structural validation available here;
    /// whether the key is well-formed is settled when a signature under it is
    /// verified, which is where a bad key produces a failure rather than a
    /// false success.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(Error::Identity(format!(
                "ML-DSA-65 public key must be {ML_DSA_65_PUBLIC_KEY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(PqPublicKey(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&ML_DSA_65, &self.0)
            .verify(message, signature)
            .map_err(|_| Error::Identity("ML-DSA signature did not verify".into()))
    }
}

impl fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PqPublicKey({} bytes)", self.0.len())
    }
}

/// A peer's full public identity.
///
/// `pq` is optional so a peer built before Phase 6, or one that deliberately
/// stays classical, is still expressible. Whether post-quantum authentication is
/// *required* is decided from the **pinned** bundle, never from what the peer
/// claims at connection time — so a missing key cannot be used to downgrade
/// someone whose pinned bundle has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBundle {
    classical: PeerPublicKey,
    pq: Option<PqPublicKey>,
}

impl IdentityBundle {
    pub fn new(classical: PeerPublicKey, pq: Option<PqPublicKey>) -> Self {
        IdentityBundle { classical, pq }
    }

    /// The Ed25519 identity that the TLS handshake pins.
    pub fn classical(&self) -> &PeerPublicKey {
        &self.classical
    }

    /// The ML-DSA-65 key, when this identity has one.
    pub fn pq(&self) -> Option<&PqPublicKey> {
        self.pq.as_ref()
    }

    /// Whether this identity carries post-quantum authentication.
    pub fn is_hybrid(&self) -> bool {
        self.pq.is_some()
    }

    /// Canonical encoding — the input to [`BundleId`] and to a ticket.
    pub fn to_bytes(&self) -> Vec<u8> {
        let der = self.classical.as_der();
        let pq = self.pq.as_ref().map(|k| k.as_bytes()).unwrap_or(&[]);

        let mut v = Vec::with_capacity(5 + der.len() + pq.len());
        v.push(BUNDLE_VERSION);
        v.extend_from_slice(&(der.len() as u16).to_be_bytes());
        v.extend_from_slice(der);
        v.extend_from_slice(&(pq.len() as u16).to_be_bytes());
        v.extend_from_slice(pq);
        v
    }

    /// Decode the canonical form, checking every length before it is used.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Error> {
            let end = pos
                .checked_add(n)
                .filter(|e| *e <= bytes.len())
                .ok_or_else(|| Error::Identity("identity bundle is truncated".into()))?;
            let out = &bytes[pos..end];
            pos = end;
            Ok(out)
        };

        let version = take(1)?[0];
        if version != BUNDLE_VERSION {
            return Err(Error::Identity(format!(
                "identity bundle version {version}, this build understands {BUNDLE_VERSION}"
            )));
        }

        let classical_len = u16::from_be_bytes(take(2)?.try_into().expect("2 bytes")) as usize;
        if classical_len == 0 {
            return Err(Error::Identity(
                "identity bundle has no classical key".into(),
            ));
        }
        let classical = PeerPublicKey::from_der(take(classical_len)?.to_vec());

        let pq_len = u16::from_be_bytes(take(2)?.try_into().expect("2 bytes")) as usize;
        let pq = if pq_len == 0 {
            None
        } else {
            Some(PqPublicKey::from_bytes(take(pq_len)?.to_vec())?)
        };

        if pos != bytes.len() {
            return Err(Error::Identity(
                "trailing bytes after identity bundle — refusing an ambiguous encoding".into(),
            ));
        }
        Ok(IdentityBundle { classical, pq })
    }

    /// The 32-byte identifier for this bundle.
    ///
    /// This is what an `atom://` URI carries and what a human compares. It
    /// covers **both** keys, so an identity whose post-quantum half was swapped
    /// has a different ID — a bundle hash that only covered the classical key
    /// would let the PQ key be replaced without anyone noticing.
    pub fn id(&self) -> BundleId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BUNDLE_ID_DOMAIN);
        hasher.update(&self.to_bytes());
        BundleId(*hasher.finalize().as_bytes())
    }
}

/// A 32-byte identity-bundle identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BundleId([u8; 32]);

impl BundleId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 52-character base32 form used in an `atom://` URI — the same length
    /// as the inline Ed25519 key it replaces, so the URI format is unchanged in
    /// shape even though what it names is now a hybrid identity.
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0).to_lowercase()
    }

    pub fn from_base32(s: &str) -> Result<Self, Error> {
        let raw = BASE32_NOPAD
            .decode(s.trim().to_uppercase().as_bytes())
            .map_err(|e| Error::Identity(format!("bundle id is not valid base32: {e}")))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error::Identity("bundle id must be 32 bytes".into()))?;
        Ok(BundleId(bytes))
    }

    /// Short form for humans to read aloud, as [`PeerPublicKey::fingerprint`]
    /// does for the classical key alone.
    pub fn fingerprint(&self) -> String {
        use fmt::Write;
        self.0[..8].iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}

impl fmt::Debug for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BundleId({})", self.fingerprint())
    }
}

impl fmt::Display for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base32())
    }
}

/// A local hybrid identity: both private keys.
///
/// The ML-DSA private key is held as PKCS#8 in [`Zeroizing`] and the key pair is
/// reconstructed for each signature. Keeping the parsed key alive would be
/// faster; keeping the bytes wiped matters more, and a transfer signs twice.
pub struct LocalBundle {
    classical: LocalIdentity,
    pq_pkcs8: Option<Zeroizing<Vec<u8>>>,
    pq_public: Option<PqPublicKey>,
}

impl LocalBundle {
    /// Generate a fresh hybrid identity.
    pub fn generate() -> Result<Self, Error> {
        let classical = LocalIdentity::generate()?;
        let keypair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map_err(|_| Error::Identity("ML-DSA-65 key generation failed".into()))?;
        let pkcs8 = keypair
            .to_pkcs8()
            .map_err(|_| Error::Identity("could not serialise the ML-DSA key".into()))?;
        let public = PqPublicKey::from_bytes(keypair.public_key().as_ref().to_vec())?;

        Ok(LocalBundle {
            classical,
            pq_pkcs8: Some(Zeroizing::new(pkcs8.as_ref().to_vec())),
            pq_public: Some(public),
        })
    }

    /// Wrap an existing classical identity with no post-quantum half.
    ///
    /// Sessions using this authenticate exactly as they did before Phase 6.
    pub fn classical_only(classical: LocalIdentity) -> Self {
        LocalBundle {
            classical,
            pq_pkcs8: None,
            pq_public: None,
        }
    }

    pub fn classical(&self) -> &LocalIdentity {
        &self.classical
    }

    /// This identity's public bundle — what goes in a ticket.
    pub fn bundle(&self) -> IdentityBundle {
        IdentityBundle::new(self.classical.public_key().clone(), self.pq_public.clone())
    }

    pub fn id(&self) -> BundleId {
        self.bundle().id()
    }

    /// Sign `message` with the ML-DSA-65 key.
    ///
    /// Errors when this identity has no post-quantum half — callers must treat
    /// that as "cannot prove", never as "proof not required".
    pub fn sign_pq(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let pkcs8 = self
            .pq_pkcs8
            .as_ref()
            .ok_or_else(|| Error::Identity("this identity has no post-quantum key".into()))?;

        let keypair = PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, pkcs8)
            .map_err(|_| Error::Identity("could not load the ML-DSA key".into()))?;

        let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let written = keypair
            .sign(message, &mut signature)
            .map_err(|_| Error::Identity("ML-DSA signing failed".into()))?;
        signature.truncate(written);
        Ok(signature)
    }
}

impl fmt::Debug for LocalBundle {
    /// Never print either private half.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalBundle")
            .field("id", &self.id().fingerprint())
            .field("hybrid", &self.pq_public.is_some())
            .finish_non_exhaustive()
    }
}

/// Shared handle, since a bundle is consulted by both ends of a rendezvous.
pub type SharedBundle = Arc<LocalBundle>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_bundle_is_hybrid() {
        let local = LocalBundle::generate().unwrap();
        let bundle = local.bundle();
        assert!(bundle.is_hybrid());
        assert_eq!(
            bundle.pq().unwrap().as_bytes().len(),
            ML_DSA_65_PUBLIC_KEY_LEN
        );
    }

    #[test]
    fn bundles_round_trip() {
        let local = LocalBundle::generate().unwrap();
        let bundle = local.bundle();
        assert_eq!(
            IdentityBundle::from_bytes(&bundle.to_bytes()).unwrap(),
            bundle
        );

        let classical = IdentityBundle::new(bundle.classical().clone(), None);
        assert_eq!(
            IdentityBundle::from_bytes(&classical.to_bytes()).unwrap(),
            classical
        );
        assert!(!classical.is_hybrid());
    }

    /// Truncation at every length must error rather than panic.
    #[test]
    fn truncated_bundles_never_panic() {
        let bytes = LocalBundle::generate().unwrap().bundle().to_bytes();
        for n in 0..bytes.len() {
            assert!(
                IdentityBundle::from_bytes(&bytes[..n]).is_err(),
                "prefix of length {n} must be rejected"
            );
        }
        assert!(IdentityBundle::from_bytes(&bytes).is_ok());

        let mut extra = bytes.clone();
        extra.push(0);
        assert!(
            IdentityBundle::from_bytes(&extra).is_err(),
            "trailing bytes must be refused"
        );
    }

    /// **The reason the ID covers both keys.** Swapping only the post-quantum
    /// half must change the identifier — otherwise an attacker could substitute
    /// their own PQ key under a victim's ID and the human check would pass.
    #[test]
    fn the_id_covers_the_post_quantum_key_too() {
        let a = LocalBundle::generate().unwrap();
        let b = LocalBundle::generate().unwrap();

        let mixed = IdentityBundle::new(a.bundle().classical().clone(), b.bundle().pq().cloned());

        assert_ne!(
            mixed.id(),
            a.id(),
            "substituting the PQ key must change the bundle id"
        );
        assert_ne!(mixed.id(), b.id());
    }

    #[test]
    fn ids_are_stable_distinct_and_url_shaped() {
        let a = LocalBundle::generate().unwrap();
        let b = LocalBundle::generate().unwrap();
        assert_eq!(a.id(), a.id());
        assert_ne!(a.id(), b.id());

        let text = a.id().to_base32();
        assert_eq!(text.len(), 52, "same shape as the Ed25519 URI it replaces");
        assert_eq!(BundleId::from_base32(&text).unwrap(), a.id());
        assert_eq!(
            BundleId::from_base32(&text.to_uppercase()).unwrap(),
            a.id(),
            "case must not matter when a human retypes it"
        );
        assert!(BundleId::from_base32("nonsense!").is_err());
    }

    #[test]
    fn signatures_verify_and_reject() {
        let local = LocalBundle::generate().unwrap();
        let pk = local.bundle().pq().unwrap().clone();

        let sig = local.sign_pq(b"a message").unwrap();
        pk.verify(b"a message", &sig).unwrap();

        assert!(pk.verify(b"a different message", &sig).is_err());

        let mut tampered = sig.clone();
        tampered[0] ^= 0x01;
        assert!(pk.verify(b"a message", &tampered).is_err());

        let other = LocalBundle::generate().unwrap();
        assert!(
            other
                .bundle()
                .pq()
                .unwrap()
                .verify(b"a message", &sig)
                .is_err(),
            "a signature must not verify under another identity's key"
        );
    }

    /// A classical-only identity must fail loudly when asked to prove, so a
    /// caller cannot mistake "cannot sign" for "no proof needed".
    #[test]
    fn a_classical_only_identity_cannot_sign() {
        let local = LocalBundle::classical_only(LocalIdentity::generate().unwrap());
        assert!(!local.bundle().is_hybrid());
        assert!(local.sign_pq(b"x").is_err());
    }

    #[test]
    fn malformed_pq_keys_are_refused() {
        assert!(PqPublicKey::from_bytes(vec![0u8; 32]).is_err());
        assert!(PqPublicKey::from_bytes(vec![]).is_err());
        assert!(PqPublicKey::from_bytes(vec![0u8; ML_DSA_65_PUBLIC_KEY_LEN]).is_ok());
    }
}
