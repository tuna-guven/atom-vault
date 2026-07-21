//! A blind endpoint: the substrate you can host yourself (roadmap Phase 8).
//!
//! # What it has to be
//!
//! Almost nothing. `PUT /<prefix>/<tag>` stores a fixed-size blob, `GET
//! /<prefix>/<tag>` returns it, entries expire on their own. Any object store,
//! any static-file server with WebDAV, twenty lines of Caddy — the protocol is
//! deliberately this dull so that an operator has nothing interesting to log and
//! a user has no excuse not to self-host.
//!
//! The endpoint is given no identity, no account, and no authentication. It
//! cannot distinguish one client from another, cannot tell which of its blobs
//! belong together, and cannot read any of them.
//!
//! # Why the certificate is pinned instead of validated
//!
//! There is no CA anywhere else in this project ([`crate::pinned`]), and there is
//! no reason to introduce one here. An endpoint is configured as an address plus
//! the SHA-256 of the certificate it must present; chain building, name checking
//! and expiry are all skipped, because the pin *is* the identity. That also means
//! the recommended deployment — a self-signed certificate with a decade-long
//! lifetime — needs no PKI at all.
//!
//! The consequence to plan for: **replacing the certificate breaks the pin.**
//! Several pins can be configured at once so a rotation can be staged, and a
//! long-lived self-signed certificate avoids the problem entirely.
//!
//! # What the TLS is and is not protecting
//!
//! Not the record. The record is sealed under a key the endpoint never sees, and
//! stays sealed whatever happens to the transport. What TLS protects is the
//! **tag** — without it, a network observer between this machine and the endpoint
//! would see the same rotating label at both ends of a pair and could do the
//! correlation the endpoint itself is being denied.
//!
//! Because arbitrary servers are in scope, this connection uses rustls' default
//! groups rather than the strict hybrid post-quantum provider the peer transport
//! insists on. That is a deliberate and confined exception: nothing
//! confidentiality-critical rides this channel, and demanding
//! `X25519MLKEM768` would make every off-the-shelf store unusable. A future
//! adversary who records and breaks this traffic learns a rotating opaque tag and
//! a blob they still cannot open.
//!
//! # Routing the request away from your own IP
//!
//! [`BlindEndpoint::via_socks`] sends the request through a SOCKS5 proxy — a Tor
//! client, or a VPN's proxy. This is the one control that closes the residual
//! leak described in [`super`]: an endpoint that never sees either peer's real
//! address cannot pair them up at all. It costs latency on a request that happens
//! once per connection attempt, which is a good trade.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Error;
use crate::discovery::Substrate;
use crate::discovery::link::{ServerKind, ServerLink};
use crate::discovery::record::SEALED_LEN;

/// Whole-request budget. An endpoint slower than this is not usable for a
/// rendezvous a human is waiting on.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on response headers, so a hostile endpoint cannot exhaust memory by
/// never sending the blank line.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Cap on a response body. Records are a fixed width; anything beyond this is
/// either a broken endpoint or an attempt to make us read forever.
const MAX_BODY_BYTES: usize = SEALED_LEN * 2;

/// SHA-256 of a server certificate, in DER form.
pub type CertPin = [u8; 32];

/// One dumb, self-hostable store.
pub struct BlindEndpoint {
    name: String,
    host: String,
    port: u16,
    prefix: String,
    pins: Vec<CertPin>,
    via: Option<SocketAddr>,
    tls: Arc<rustls::ClientConfig>,
}

impl BlindEndpoint {
    /// Configure an endpoint.
    ///
    /// `prefix` is the path the tags hang under, with or without slashes.
    /// `pins` must be non-empty: an endpoint with nothing to pin against would
    /// fall back to trusting whoever answers, which is not a mode this design
    /// offers.
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        prefix: impl Into<String>,
        pins: Vec<CertPin>,
    ) -> Result<Self, Error> {
        let host = host.into();
        if host.is_empty() {
            return Err(Error::Discovery("endpoint host is empty".into()));
        }
        // Validated here rather than at connect time: a typo in a config file
        // should be an error when it is read, not an hour later mid-rendezvous.
        ServerName::try_from(host.clone())
            .map_err(|_| Error::Discovery(format!("`{host}` is not a usable host name")))?;

        if pins.is_empty() {
            return Err(Error::Discovery(
                "a rendezvous endpoint must be pinned to a certificate: without a pin \
                 there is nothing distinguishing the real endpoint from whoever \
                 answers, and this design has no CA to fall back on"
                    .into(),
            ));
        }

        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
            pins: pins.clone(),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }))
        .with_no_client_auth();

        Ok(BlindEndpoint {
            name: name.into(),
            host,
            port,
            prefix: prefix.into().trim_matches('/').to_string(),
            pins,
            via: None,
            tls: Arc::new(tls),
        })
    }

    /// Build from a pasted [`ServerLink`], which is how a user configures one.
    ///
    /// [`BlindEndpoint::new`] takes the pieces apart and is for tests and for the
    /// operator-side tool that *produces* a link. Everything user-facing goes
    /// through here, so a host and a pin are never two things a person handles
    /// separately — the pin is the field people skip, and a skipped pin is an
    /// endpoint that trusts whoever answers.
    ///
    /// An onion-only link requires a proxy: `.onion` is unreachable without one,
    /// and failing at the first request would be worse than refusing now.
    pub fn from_link(link: &ServerLink, socks: Option<SocketAddr>) -> Result<Self, Error> {
        if link.kind != ServerKind::Rendezvous {
            return Err(Error::Discovery(
                "this link names a different kind of server — a rendezvous endpoint \
                 and a relay do different jobs and are not interchangeable"
                    .into(),
            ));
        }

        // Prefer the onion whenever a proxy is available. This is the opposite
        // of the rule for a peer's ticket, where offering an onion is the peer's
        // decision and silently preferring it would undo a choice they made.
        // Here the choice is *ours*: the onion path is strictly less exposing —
        // the endpoint never learns this machine's address — and there is no
        // peer whose intent could be overridden.
        let (host, port) = match (&link.onion, socks) {
            (Some(onion), Some(_)) => (onion.host().to_string(), onion.port()),
            _ if link.is_onion_only() => {
                return Err(Error::Discovery(
                    "this endpoint is reachable only over Tor, so it needs a SOCKS \
                     proxy — pass one (usually 127.0.0.1:9050)"
                        .into(),
                ));
            }
            _ => (link.host.clone(), link.port),
        };

        let endpoint = Self::new(
            link.label(),
            host,
            port,
            link.prefix.clone(),
            link.pins.clone(),
        )?;
        Ok(match socks {
            Some(proxy) => endpoint.via_socks(proxy),
            None => endpoint,
        })
    }

    /// Route requests through a SOCKS5 proxy — a Tor client, or a VPN's.
    ///
    /// With this set the endpoint never learns this machine's address, which is
    /// what removes the "wrote tag `T`, read tag `T`" correlation entirely.
    pub fn via_socks(mut self, proxy: SocketAddr) -> Self {
        self.via = Some(proxy);
        self
    }

    /// The pins this endpoint accepts, for display in a config UI.
    pub fn pins(&self) -> &[CertPin] {
        &self.pins
    }

    fn path_for(&self, tag: &str) -> String {
        if self.prefix.is_empty() {
            format!("/{tag}")
        } else {
            format!("/{}/{tag}", self.prefix)
        }
    }

    /// Open a TLS connection to the endpoint, optionally through the proxy.
    async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
        let tcp = match self.via {
            Some(proxy) => {
                // The host goes to the proxy **unresolved**, so a Tor proxy does
                // the lookup. Resolving locally first would send a DNS query
                // that names the endpoint from this machine's own resolver — the
                // exact disclosure the proxy is here to prevent.
                tokio_socks::tcp::Socks5Stream::connect(proxy, (self.host.as_str(), self.port))
                    .await
                    .map_err(|e| {
                        Error::Discovery(format!(
                            "could not reach {}:{} through the SOCKS proxy at {proxy}: {e}",
                            self.host, self.port
                        ))
                    })?
                    .into_inner()
            }
            None => TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|e| {
                    Error::Discovery(format!("could not reach {}:{}: {e}", self.host, self.port))
                })?,
        };

        let name = ServerName::try_from(self.host.clone())
            .map_err(|_| Error::Discovery("endpoint host is not a usable name".into()))?;

        tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| {
                Error::Discovery(format!(
                    "TLS to {} failed: {e}. If the endpoint's certificate was replaced, \
                     its pin must be updated — this is refused rather than trusted.",
                    self.name
                ))
            })
    }

    /// One HTTP/1.1 request/response exchange.
    async fn request(
        &self,
        method: &str,
        tag: &str,
        body: Option<(&[u8], Duration)>,
    ) -> Result<(u16, Vec<u8>), Error> {
        let exchange = async {
            let mut stream = self.connect().await?;

            let mut head = format!(
                "{method} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n",
                self.path_for(tag),
                self.host,
                self.port
            );
            match body {
                Some((bytes, ttl)) => {
                    head.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
                    head.push_str("Content-Type: application/octet-stream\r\n");
                    // Advisory only. A store that understands it expires the
                    // record; a dumb one ignores it and the operator configures
                    // expiry themselves. Either way the record's own `not_after`
                    // is what a reader enforces.
                    head.push_str(&format!("X-Atom-Expire-Seconds: {}\r\n", ttl.as_secs()));
                }
                None => head.push_str("Accept: application/octet-stream\r\n"),
            }
            head.push_str("\r\n");

            stream.write_all(head.as_bytes()).await?;
            if let Some((bytes, _)) = body {
                stream.write_all(bytes).await?;
            }
            stream.flush().await?;

            read_response(&mut stream).await
        };

        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| {
                Error::Discovery(format!(
                    "{} did not answer within {REQUEST_TIMEOUT:?}",
                    self.name
                ))
            })?
    }
}

#[async_trait]
impl Substrate for BlindEndpoint {
    fn name(&self) -> &str {
        &self.name
    }

    async fn put(&self, tag: &str, sealed: &[u8], ttl: Duration) -> Result<(), Error> {
        let (status, _) = self.request("PUT", tag, Some((sealed, ttl))).await?;
        match status {
            200 | 201 | 202 | 204 => Ok(()),
            other => Err(Error::Discovery(format!(
                "{} refused the record with HTTP {other}",
                self.name
            ))),
        }
    }

    async fn get(&self, tag: &str) -> Result<Option<Vec<u8>>, Error> {
        let (status, body) = self.request("GET", tag, None).await?;
        match status {
            200 => Ok(Some(body)),
            // Nothing published, or it expired. Not an error: it is the normal
            // answer for two of the three slots a lookup always asks about.
            204 | 404 | 410 => Ok(None),
            other => Err(Error::Discovery(format!(
                "{} answered HTTP {other}",
                self.name
            ))),
        }
    }
}

/// Read a bounded HTTP/1.1 response: status code and body.
///
/// Everything here is length-checked against a cap before it is allocated. The
/// endpoint is not trusted — it is a dumb store that may also be hostile, and a
/// response is the one thing it fully controls.
async fn read_response<S>(stream: &mut S) -> Result<(u16, Vec<u8>), Error>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    // Headers, up to the blank line.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Error::Discovery(
                "response headers exceeded the size limit".into(),
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Discovery(
                "the endpoint closed the connection before sending a complete response".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = headers.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| Error::Discovery("empty response".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Discovery(format!("unintelligible status line: {status_line:?}")))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = value.trim().parse().ok();
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            _ => {}
        }
    }

    if chunked {
        // Not implemented on purpose rather than half-implemented: a chunked
        // parser is a decoding surface, and every store worth using can send a
        // Content-Length for a fixed-size blob.
        return Err(Error::Discovery(
            "the endpoint replied with chunked transfer encoding, which this client \
             does not accept — configure it to send a Content-Length"
                .into(),
        ));
    }

    let mut body = buf.split_off(header_end);
    match content_length {
        Some(len) => {
            if len > MAX_BODY_BYTES {
                return Err(Error::Discovery(format!(
                    "the endpoint declared a {len}-byte body, past the {MAX_BODY_BYTES}-byte limit"
                )));
            }
            while body.len() < len {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(Error::Discovery(
                        "the endpoint closed the connection mid-body".into(),
                    ));
                }
                body.extend_from_slice(&chunk[..n]);
                if body.len() > MAX_BODY_BYTES {
                    return Err(Error::Discovery("response body exceeded the limit".into()));
                }
            }
            body.truncate(len);
        }
        None if status == 200 => {
            return Err(Error::Discovery(
                "the endpoint returned a body with no Content-Length".into(),
            ));
        }
        None => body.clear(),
    }

    Ok((status, body))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Accepts exactly the certificates whose SHA-256 is one of the configured pins.
///
/// No chain, no name, no expiry — the same reasoning as [`crate::pinned`], which
/// pins raw public keys for peers. Here the presented certificate is a normal
/// X.509 one, so the whole DER is hashed rather than an extracted key.
#[derive(Debug)]
struct PinnedCertVerifier {
    pins: Vec<CertPin>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let presented = sha256(end_entity.as_ref());
        if self.pins.contains(&presented) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "the endpoint's certificate does not match any configured pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// SHA-256 of a certificate.
///
/// SHA-256 rather than the BLAKE3 this crate uses everywhere else, because a pin
/// has to be the digest operators can already produce
/// (`openssl x509 -fingerprint -sha256`). A hash nobody can compute for
/// themselves is a hash nobody configures correctly.
fn sha256(der: &[u8]) -> CertPin {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(der));
    out
}

/// Parse a pin written the way `openssl` prints one: 32 hex bytes, with or
/// without the colons.
pub fn parse_pin(text: &str) -> Result<CertPin, Error> {
    let hex: String = text
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if hex.len() != 64 {
        return Err(Error::Discovery(format!(
            "a certificate pin is 32 hex bytes (64 characters), got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Discovery("a certificate pin must be hexadecimal".into()))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_pin() -> CertPin {
        [7u8; 32]
    }

    /// An endpoint with no pin must be refused at construction: there is no CA
    /// here, so an unpinned endpoint trusts whoever answers.
    #[test]
    fn an_unpinned_endpoint_is_refused() {
        let err = BlindEndpoint::new("e", "example.org", 443, "rdv", vec![])
            .err()
            .expect("an unpinned endpoint must not be constructible");
        assert!(err.to_string().contains("pinned"), "got: {err}");
    }

    /// A bad host must fail when the config is read, not mid-rendezvous.
    #[test]
    fn a_malformed_host_is_refused_at_construction() {
        assert!(BlindEndpoint::new("e", "", 443, "rdv", vec![a_pin()]).is_err());
        assert!(BlindEndpoint::new("e", "not a host", 443, "rdv", vec![a_pin()]).is_err());
    }

    #[test]
    fn paths_are_built_without_double_slashes() {
        let with = BlindEndpoint::new("e", "example.org", 443, "/rdv/", vec![a_pin()]).unwrap();
        assert_eq!(with.path_for("abcd"), "/rdv/abcd");

        let without = BlindEndpoint::new("e", "example.org", 443, "", vec![a_pin()]).unwrap();
        assert_eq!(without.path_for("abcd"), "/abcd");
    }

    #[test]
    fn pins_parse_in_both_the_forms_openssl_prints() {
        let plain = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let colons = "01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:\
                      11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20";
        assert_eq!(parse_pin(plain).unwrap(), parse_pin(colons).unwrap());
        assert_eq!(parse_pin(plain).unwrap()[0], 1);
        assert_eq!(parse_pin(plain).unwrap()[31], 0x20);
    }

    #[test]
    fn a_malformed_pin_is_refused() {
        assert!(parse_pin("").is_err());
        assert!(parse_pin("0102").is_err());
        assert!(parse_pin(&"zz".repeat(32)).is_err());
    }

    fn link_with(host: &str, onion: bool) -> ServerLink {
        ServerLink::new(
            ServerKind::Rendezvous,
            host,
            8443,
            "records",
            vec![a_pin()],
            onion.then(|| {
                crate::tor::OnionAddress::new(
                    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
                    8443,
                )
                .unwrap()
            }),
        )
        .unwrap()
    }

    /// A pasted link must produce a usable endpoint with no other input — that
    /// is the entire point of the format.
    #[test]
    fn an_endpoint_is_built_from_a_link_alone() {
        let e = BlindEndpoint::from_link(&link_with("rdv.example.org", false), None).unwrap();
        assert_eq!(e.host, "rdv.example.org");
        assert_eq!(e.port, 8443);
        assert_eq!(e.path_for("ab"), "/records/ab");
        assert_eq!(e.pins(), &[a_pin()]);
        assert!(e.via.is_none());
    }

    /// When a proxy is available the onion is the better route and must be
    /// taken: it is the difference between the endpoint seeing our address and
    /// not.
    #[test]
    fn the_onion_is_preferred_when_a_proxy_exists() {
        let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let e = BlindEndpoint::from_link(&link_with("rdv.example.org", true), Some(proxy)).unwrap();
        assert!(e.host.ends_with(".onion"), "got {}", e.host);
        assert_eq!(e.via, Some(proxy));

        // Without a proxy the onion is unreachable, so the host is used instead.
        let direct = BlindEndpoint::from_link(&link_with("rdv.example.org", true), None).unwrap();
        assert_eq!(direct.host, "rdv.example.org");
    }

    /// An onion-only link with no proxy must fail on configuration, not on the
    /// first lookup an hour later.
    #[test]
    fn an_onion_only_link_without_a_proxy_is_refused() {
        let err = BlindEndpoint::from_link(&link_with("", true), None)
            .err()
            .expect("an onion needs a proxy");
        assert!(err.to_string().contains("SOCKS"), "got: {err}");
    }

    /// A relay link must not quietly become a rendezvous endpoint.
    #[test]
    fn a_link_for_another_kind_of_server_is_refused() {
        let relay = ServerLink::new(
            ServerKind::Relay,
            "relay.example.org",
            8443,
            "",
            vec![a_pin()],
            None,
        )
        .unwrap();
        assert!(BlindEndpoint::from_link(&relay, None).is_err());
    }

    /// A hostile endpoint must not be able to make this client read forever or
    /// allocate without bound.
    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let err = read_response(&mut response.as_bytes()).await.unwrap_err();
        assert!(err.to_string().contains("limit"), "got: {err}");
    }

    #[tokio::test]
    async fn endless_headers_are_refused() {
        let mut junk = b"HTTP/1.1 200 OK\r\n".to_vec();
        junk.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES + 16));
        let err = read_response(&mut junk.as_slice()).await.unwrap_err();
        assert!(err.to_string().contains("size limit"), "got: {err}");
    }

    #[tokio::test]
    async fn a_truncated_body_is_an_error_not_a_short_record() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nshort".to_vec();
        assert!(read_response(&mut response.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn chunked_responses_are_refused_rather_than_parsed() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n";
        let err = read_response(&mut response.as_slice()).await.unwrap_err();
        assert!(err.to_string().contains("chunked"), "got: {err}");
    }

    #[tokio::test]
    async fn a_body_and_status_are_read_back() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nServer: x\r\n\r\nhello".to_vec();
        let (status, body) = read_response(&mut response.as_slice()).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
    }

    /// The "nothing here" answers must be distinguishable from failures — a
    /// lookup asks about three slots and expects two of them to be empty.
    #[tokio::test]
    async fn a_404_carries_its_status_without_a_body() {
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (status, body) = read_response(&mut response.as_slice()).await.unwrap();
        assert_eq!(status, 404);
        assert!(body.is_empty());
    }
}
