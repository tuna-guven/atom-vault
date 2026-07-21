//! Optional external-address discovery via STUN (RFC 5389 / 8489).
//!
//! # This is off by default, and here is why
//!
//! `CLAUDE.md` §6 is explicit: STUN is *the only borderline third-party touch*
//! in the live path. **A STUN server learns your IP address**, and it learns it
//! moments before you start a transfer, which is exactly the correlation the
//! threat model cares about. Nothing in this crate calls it on your behalf. The
//! pure path is for the peer to enter their external `ip:port` manually — from a
//! router's port-forward or UPnP mapping, or a known static address — and that
//! remains the default everywhere in this crate.
//!
//! Surface the tradeoff to the user before enabling it; do not make it a silent
//! convenience.
//!
//! # Using it correctly
//!
//! A NAT mapping belongs to a **local port**, so a STUN query is only meaningful
//! for the port you will actually transfer from:
//!
//! 1. Bind a UDP socket on the port your ticket will advertise.
//! 2. [`discover`] against a STUN server using *that* socket.
//! 3. Drop the socket, bind the QUIC endpoint to the same local port, and put
//!    the discovered address in your ticket.
//!
//! Querying from a different port yields a different mapping and an address the
//! peer cannot reach. Under a symmetric NAT even the right port is not enough:
//! the mapping is per *destination*, so the address the STUN server reports is
//! not the one your peer will see. STUN cannot detect this for you; if
//! rendezvous fails with an address STUN supplied, symmetric NAT is the usual
//! reason.
//!
//! # What is validated
//!
//! Only a response carrying **our** 96-bit transaction ID is accepted, and only
//! from the address we queried. Without that check an off-path attacker could
//! race a forged reply and choose the address we publish in our own ticket.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::Error;

/// STUN Binding Request message type.
const BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Success Response message type.
const BINDING_SUCCESS: u16 = 0x0101;
/// The fixed magic cookie every STUN message carries (RFC 5389 §6).
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Attribute type for XOR-MAPPED-ADDRESS.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Attribute type for the legacy (unobfuscated) MAPPED-ADDRESS.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

const HEADER_LEN: usize = 20;
const TXID_LEN: usize = 12;

/// A generated request together with the transaction ID that must come back.
struct Request {
    bytes: [u8; HEADER_LEN],
    txid: [u8; TXID_LEN],
}

fn build_request() -> Result<Request, Error> {
    let mut txid = [0u8; TXID_LEN];
    getrandom::fill(&mut txid)
        .map_err(|e| Error::Connect(format!("OS random number generator unavailable: {e}")))?;

    let mut bytes = [0u8; HEADER_LEN];
    bytes[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    bytes[2..4].copy_from_slice(&0u16.to_be_bytes()); // no attributes
    bytes[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes[8..20].copy_from_slice(&txid);

    Ok(Request { bytes, txid })
}

/// Parse a Binding Success Response and extract the reflexive address.
///
/// Rejects anything that is not a success response for `txid`.
fn parse_response(msg: &[u8], txid: &[u8; TXID_LEN]) -> Result<SocketAddr, Error> {
    if msg.len() < HEADER_LEN {
        return Err(Error::Connect("STUN response is too short".into()));
    }

    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    if msg_type != BINDING_SUCCESS {
        return Err(Error::Connect(format!(
            "STUN server returned message type {msg_type:#06x}, not a binding success"
        )));
    }
    if u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]) != MAGIC_COOKIE {
        return Err(Error::Connect(
            "STUN response has a bad magic cookie".into(),
        ));
    }
    // The check that makes a forged reply useless.
    if &msg[8..20] != txid {
        return Err(Error::Connect(
            "STUN response transaction ID does not match our request — \
             discarding a possibly forged reply"
                .into(),
        ));
    }

    let declared = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let body = msg
        .get(HEADER_LEN..HEADER_LEN + declared)
        .ok_or_else(|| Error::Connect("STUN response is shorter than it claims".into()))?;

    let mut pos = 0usize;
    let mut fallback = None;
    while pos + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let attr_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start
            .checked_add(attr_len)
            .filter(|e| *e <= body.len())
            .ok_or_else(|| Error::Connect("STUN attribute runs past the message".into()))?;
        let value = &body[start..end];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => return decode_address(value, txid, true),
            // Kept only as a fallback for servers that omit the XOR form; the
            // XOR variant is preferred because middleboxes are known to rewrite
            // bare addresses they recognise inside packets.
            ATTR_MAPPED_ADDRESS if fallback.is_none() => {
                fallback = Some(decode_address(value, txid, false));
            }
            _ => {}
        }

        // Attributes are padded to a 4-byte boundary.
        pos = start + attr_len.next_multiple_of(4);
    }

    fallback.unwrap_or_else(|| {
        Err(Error::Connect(
            "STUN response carried no mapped address".into(),
        ))
    })
}

/// Decode a STUN address attribute, undoing the XOR obfuscation when present.
fn decode_address(value: &[u8], txid: &[u8; TXID_LEN], xored: bool) -> Result<SocketAddr, Error> {
    if value.len() < 4 {
        return Err(Error::Connect("STUN address attribute is too short".into()));
    }
    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let port = if xored {
        raw_port ^ (MAGIC_COOKIE >> 16) as u16
    } else {
        raw_port
    };

    // The XOR key is the magic cookie, extended with the transaction ID for IPv6.
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    key[4..].copy_from_slice(txid);

    let ip = match family {
        0x01 => {
            let bytes: [u8; 4] = value
                .get(4..8)
                .ok_or_else(|| Error::Connect("truncated IPv4 STUN address".into()))?
                .try_into()
                .expect("4 bytes");
            let mut out = bytes;
            if xored {
                for (o, k) in out.iter_mut().zip(key.iter()) {
                    *o ^= k;
                }
            }
            IpAddr::V4(Ipv4Addr::from(out))
        }
        0x02 => {
            let bytes: [u8; 16] = value
                .get(4..20)
                .ok_or_else(|| Error::Connect("truncated IPv6 STUN address".into()))?
                .try_into()
                .expect("16 bytes");
            let mut out = bytes;
            if xored {
                for (o, k) in out.iter_mut().zip(key.iter()) {
                    *o ^= k;
                }
            }
            IpAddr::V6(Ipv6Addr::from(out))
        }
        other => {
            return Err(Error::Connect(format!(
                "STUN response has unknown address family {other:#04x}"
            )));
        }
    };

    Ok(SocketAddr::new(ip, port))
}

/// Ask `server` what address it sees us coming from, using `socket`.
///
/// **This discloses your IP address to `server`.** Call it only when the user
/// has been told that and chosen it over entering their address manually.
///
/// `socket` must be bound to the port the ticket will advertise — see the module
/// documentation for why.
pub async fn discover(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, Error> {
    let request = build_request()?;
    socket
        .send_to(&request.bytes, server)
        .await
        .map_err(|e| Error::Connect(format!("sending STUN request to {server}: {e}")))?;

    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Connect(format!(
                "STUN server {server} did not reply"
            )));
        }

        let (n, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(Error::Connect(format!("STUN receive failed: {e}"))),
            Err(_) => {
                return Err(Error::Connect(format!(
                    "STUN server {server} did not reply"
                )));
            }
        };

        // Ignore anything not from the server we asked, then let the transaction
        // ID check inside `parse_response` reject the rest.
        if from != server {
            continue;
        }
        match parse_response(&buf[..n], &request.txid) {
            Ok(addr) => return Ok(addr),
            // A mismatched transaction ID is not fatal: it is a stale or forged
            // datagram, and the real reply may still be in flight.
            Err(_) if tokio::time::Instant::now() < deadline => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic Binding Success Response carrying XOR-MAPPED-ADDRESS.
    fn success_v4(txid: &[u8; TXID_LEN], addr: Ipv4Addr, port: u16) -> Vec<u8> {
        let x_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let mut x_addr = addr.octets();
        for (o, k) in x_addr.iter_mut().zip(cookie.iter()) {
            *o ^= k;
        }

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0);
        attr.push(0x01);
        attr.extend_from_slice(&x_port.to_be_bytes());
        attr.extend_from_slice(&x_addr);

        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&cookie);
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&attr);
        msg
    }

    #[test]
    fn decodes_a_xor_mapped_ipv4_address() {
        let txid = [7u8; TXID_LEN];
        let msg = success_v4(&txid, Ipv4Addr::new(203, 0, 113, 42), 51820);
        let got = parse_response(&msg, &txid).unwrap();
        assert_eq!(got, "203.0.113.42:51820".parse::<SocketAddr>().unwrap());
    }

    /// **The security-relevant check.** A reply that does not carry our
    /// transaction ID must be discarded: otherwise an off-path attacker who
    /// races the real server chooses the address we publish in our ticket.
    #[test]
    fn a_response_with_a_foreign_transaction_id_is_rejected() {
        let ours = [1u8; TXID_LEN];
        let theirs = [2u8; TXID_LEN];
        let forged = success_v4(&theirs, Ipv4Addr::new(198, 51, 100, 1), 1234);

        let err = parse_response(&forged, &ours).unwrap_err().to_string();
        assert!(err.contains("transaction ID"), "got: {err}");
    }

    #[test]
    fn malformed_responses_are_rejected_not_panicked_on() {
        let txid = [3u8; TXID_LEN];
        let good = success_v4(&txid, Ipv4Addr::new(192, 0, 2, 5), 443);

        for n in 0..good.len() {
            let _ = parse_response(&good[..n], &txid); // must not panic
        }

        // Wrong magic cookie.
        let mut bad = good.clone();
        bad[4] ^= 0xFF;
        assert!(parse_response(&bad, &txid).is_err());

        // An error response rather than a success.
        let mut bad = good.clone();
        bad[0..2].copy_from_slice(&0x0111u16.to_be_bytes());
        assert!(parse_response(&bad, &txid).is_err());

        // Declared length longer than the message.
        let mut bad = good.clone();
        bad[2..4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(parse_response(&bad, &txid).is_err());

        // Header only, no attributes.
        let mut bare = good[..HEADER_LEN].to_vec();
        bare[2..4].copy_from_slice(&0u16.to_be_bytes());
        assert!(parse_response(&bare, &txid).is_err());
    }

    #[test]
    fn requests_are_well_formed_and_use_fresh_transaction_ids() {
        let a = build_request().unwrap();
        let b = build_request().unwrap();
        assert_ne!(a.txid, b.txid, "transaction IDs must not repeat");
        assert_eq!(
            u16::from_be_bytes([a.bytes[0], a.bytes[1]]),
            BINDING_REQUEST
        );
        assert_eq!(u16::from_be_bytes([a.bytes[2], a.bytes[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([a.bytes[4], a.bytes[5], a.bytes[6], a.bytes[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&a.bytes[8..], &a.txid);
    }

    /// A server that swallows the request must time out rather than hang — a
    /// discovery step that wedges would wedge the whole pairing flow.
    #[tokio::test]
    async fn a_silent_server_times_out() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A real socket that receives and never answers.
        let black_hole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = black_hole.local_addr().unwrap();

        let started = std::time::Instant::now();
        let err = discover(&socket, server, Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not reply"), "got: {err}");
        assert!(started.elapsed() < Duration::from_secs(2), "must not hang");
    }

    /// The happy path over a real socket, against a server that replies
    /// correctly — proves `discover` wires the encoder, the socket and the
    /// parser together, not just that each works alone.
    #[tokio::test]
    async fn discovers_the_reflexive_address_from_a_real_reply() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = server_sock.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, from) = server_sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, HEADER_LEN, "a binding request is header-only");
            // Echo back the transaction ID we were sent, as a server must.
            let txid: [u8; TXID_LEN] = buf[8..20].try_into().unwrap();
            let reply = success_v4(&txid, Ipv4Addr::new(203, 0, 113, 9), 40404);
            server_sock.send_to(&reply, from).await.unwrap();
        });

        let got = discover(&client, server, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(got, "203.0.113.9:40404".parse::<SocketAddr>().unwrap());
    }
}
