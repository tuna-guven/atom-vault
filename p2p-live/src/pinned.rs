//! Raw-public-key pinning verifiers.
//!
//! There is no CA and no name validation. A peer is authentic iff the raw public
//! key it presents is byte-for-byte the one we were handed out-of-band in its L0
//! ticket. This is the Syncthing device-ID model, and it means a MITM needs the
//! peer's private key rather than a mis-issued certificate.
//!
//! Both directions are pinned: the client pins the server *and* the server pins
//! the client, so the connection is mutually authenticated.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};

use crate::identity::PeerPublicKey;

/// Constant-time-ish comparison of the presented key against the pin.
///
/// Public keys are not secret, so this is not a side-channel boundary; the
/// helper exists so both verifiers share one code path and one failure mode.
fn matches_pin(presented: &CertificateDer<'_>, pinned: &PeerPublicKey) -> bool {
    presented.as_ref() == pinned.as_der()
}

fn wrong_peer() -> TlsError {
    // Deliberately generic: do not tell a prober whether the key was
    // well-formed, only that it is not the peer we expect.
    TlsError::General("peer identity does not match the pinned key".into())
}

/// Client-side: pins the server's raw public key.
#[derive(Debug)]
pub(crate) struct PinnedServerVerifier {
    pub(crate) pinned: PeerPublicKey,
    pub(crate) provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // `end_entity` is the peer's SPKI (RFC 7250), not an X.509 certificate.
        // No chain building, no expiry, no name check — the pin is the identity.
        if matches_pin(end_entity, &self.pinned) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(wrong_peer())
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // QUIC is TLS 1.3 only, and we pin TLS13 in the config. Reaching here
        // would mean a downgrade, so refuse rather than implement it.
        Err(TlsError::General(
            "TLS 1.2 is not supported: this transport is TLS 1.3 only".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Server-side: pins the client's raw public key (mutual authentication).
#[derive(Debug)]
pub(crate) struct PinnedClientVerifier {
    pub(crate) pinned: PeerPublicKey,
    pub(crate) provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CAs exist in this model, so there are no subjects to hint.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if matches_pin(end_entity, &self.pinned) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(wrong_peer())
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General(
            "TLS 1.2 is not supported: this transport is TLS 1.3 only".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // Anonymous clients are never acceptable: both peers must prove identity.
        true
    }
}
