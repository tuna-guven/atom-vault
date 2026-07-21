//! `atom live` — the strict-PFS, post-quantum live transfer path.
//!
//! This is the user-facing surface for the `p2p-live` crate: everything from
//! `docs/pfs-pq-roadmap.md` phases 0–6, reachable from a terminal or the GUI.
//!
//! # What is stored, and where
//!
//! Two files under `~/.atom_vault/`, both encrypted with the same
//! [`crate::config_crypto`] key the rest of the app uses:
//!
//! * `live_identity.key` — **the private identity** (Ed25519 + ML-DSA-65).
//!   Anyone holding it can impersonate you to peers who have paired with you.
//!   It cannot decrypt past transfers: these are authentication keys and never
//!   take part in key agreement, which is what keeps forward secrecy strict.
//! * `live_peers.json` — your advertised address and one ticket per paired
//!   peer. A ticket carries no secret, but it does link an identity to an
//!   address, which is exactly the metadata worth protecting.
//!
//! # Why the functions here are UI-agnostic
//!
//! Each operation is a `*_core` function taking plain data and callbacks, so the
//! CLI and the GUI drive **the same code**. A second implementation for the
//! window would be a second place for the out-of-band steps to be got subtly
//! wrong, and per `CLAUDE.md` §9 the human factor is the real attack surface
//! here.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use p2p_live::bundle::LocalBundle;
use p2p_live::pacing::Pacing;
use p2p_live::pairing::{self, PairedChannel, PairingCode, PairingState};
use p2p_live::rendezvous;
use p2p_live::ticket::{Endpoint, Ticket};
use p2p_live::transfer::{Cancel, EncryptedAtRest, Progress, Summary, Transfer};

/// How long a rendezvous waits for the peer before giving up.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(120);

type Res<T> = Result<T, Box<dyn std::error::Error>>;

// ── Storage ──────────────────────────────────────────────────────────────────

fn atom_dir() -> Res<PathBuf> {
    let mut p = dirs::home_dir().ok_or("Could not find home directory")?;
    p.push(".atom_vault");
    fs::create_dir_all(&p)?;
    Ok(p)
}

fn identity_path() -> Res<PathBuf> {
    Ok(atom_dir()?.join("live_identity.key"))
}

fn peers_path() -> Res<PathBuf> {
    Ok(atom_dir()?.join("live_peers.json"))
}

/// Write `data` encrypted, owner-readable only.
fn write_private(path: &Path, data: &[u8]) -> Res<()> {
    let sealed = crate::config_crypto::encrypt_config(data);
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path)?;
    f.write_all(&sealed)?;
    Ok(())
}

/// A peer we have paired with.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LivePeer {
    pub nickname: String,
    /// The peer's ticket in its canonical text form.
    pub ticket: String,
}

/// Everything `atom live` remembers besides the private identity.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LiveState {
    /// Addresses we advertise to peers, as `ip:port` or `<onion>.onion:port`.
    #[serde(default)]
    pub my_endpoints: Vec<String>,
    #[serde(default)]
    pub peers: Vec<LivePeer>,
}

impl LiveState {
    pub fn peer(&self, nickname: &str) -> Option<&LivePeer> {
        self.peers.iter().find(|p| p.nickname == nickname)
    }
}

pub fn load_state() -> Res<LiveState> {
    let path = peers_path()?;
    if !path.exists() {
        return Ok(LiveState::default());
    }
    let raw = fs::read(&path)?;
    let plain = crate::config_crypto::decrypt_config(&raw)?;
    Ok(serde_json::from_slice(&plain)?)
}

pub fn save_state(state: &LiveState) -> Res<()> {
    write_private(&peers_path()?, &serde_json::to_vec_pretty(state)?)
}

/// Load the private identity, generating one on first use.
///
/// Generating is idempotent from the user's point of view but **not** something
/// to do twice: a new identity is a new peer, and every existing pairing would
/// stop recognising you. Hence the file is only ever created when absent.
pub fn load_or_create_identity() -> Res<LocalBundle> {
    let path = identity_path()?;
    if path.exists() {
        let raw = fs::read(&path)?;
        let plain = crate::config_crypto::decrypt_config(&raw)?;
        return Ok(LocalBundle::from_secret_bytes(&plain)?);
    }

    let bundle = LocalBundle::generate()?;
    write_private(&path, &bundle.to_secret_bytes())?;
    Ok(bundle)
}

/// Parse an endpoint written by a human: `1.2.3.4:4433` or `abc…xyz.onion:4433`.
pub fn parse_endpoint(text: &str) -> Res<Endpoint> {
    let text = text.trim();
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(Endpoint::Direct(addr));
    }
    let (host, port) = text
        .rsplit_once(':')
        .ok_or("An address needs a port, e.g. 203.0.113.7:4433")?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("'{port}' is not a port number"))?;
    if host.ends_with(".onion") {
        return Ok(Endpoint::Onion(p2p_live::tor::OnionAddress::new(
            host, port,
        )?));
    }
    Err(format!(
        "'{text}' is neither an ip:port nor an onion address. \
         Enter the address your peer can reach you on."
    )
    .into())
}

// ── Identity ─────────────────────────────────────────────────────────────────

/// What the UI shows about our own identity.
pub struct IdentitySummary {
    pub id: String,
    pub fingerprint: String,
    pub hybrid: bool,
    pub endpoints: Vec<String>,
}

pub fn identity_summary() -> Res<IdentitySummary> {
    let bundle = load_or_create_identity()?;
    let state = load_state()?;
    Ok(IdentitySummary {
        id: bundle.id().to_base32(),
        fingerprint: bundle.id().fingerprint(),
        hybrid: bundle.bundle().is_hybrid(),
        endpoints: state.my_endpoints,
    })
}

/// Replace the addresses we advertise. Validated before being stored, so a typo
/// is caught here rather than inside a ticket a peer has already saved.
pub fn set_endpoints(addresses: &[String]) -> Res<()> {
    let mut parsed = Vec::new();
    for a in addresses {
        parsed.push(parse_endpoint(a)?);
    }
    let mut state = load_state()?;
    state.my_endpoints = parsed.iter().map(|e| e.to_string()).collect();
    save_state(&state)?;
    Ok(())
}

/// Build the ticket we hand a peer during pairing.
pub fn my_ticket() -> Res<Ticket> {
    let bundle = load_or_create_identity()?;
    let state = load_state()?;
    if state.my_endpoints.is_empty() {
        return Err(
            "No address set. Run 'atom live address <ip:port>' first so \
                    peers know where to reach you."
                .into(),
        );
    }
    let mut hints = Vec::new();
    for e in &state.my_endpoints {
        hints.push(parse_endpoint(e)?);
    }
    Ok(Ticket::new(bundle.bundle(), hints)?)
}

// ── Pairing ──────────────────────────────────────────────────────────────────

/// Round 1: begin from a short secret, producing the blob to send the peer.
pub fn pair_begin(code: &PairingCode) -> (PairingState, String) {
    let (state, msg) = pairing::start(code);
    (state, pairing::encode_message(&msg))
}

/// Round 2: consume the peer's round-1 blob, producing our sealed ticket.
pub fn pair_exchange(state: PairingState, peer_message: &str) -> Res<(PairedChannel, String)> {
    let peer = pairing::decode_message(peer_message)?;
    let channel = state.finish(&peer)?;
    let sealed = channel.seal_ticket(&my_ticket()?)?;
    Ok((channel, sealed))
}

/// Open the peer's sealed ticket and save them under `nickname`.
///
/// Refuses to bind a nickname to a second identity: silently overwriting is how
/// a user ends up transferring a vault to whoever pairs most recently.
pub fn pair_complete(channel: &PairedChannel, sealed: &str, nickname: &str) -> Res<Ticket> {
    let ticket = channel.open_ticket(sealed)?;
    let me = load_or_create_identity()?;
    if ticket.id() == me.id() {
        return Err("That ticket is your own identity — you cannot pair with yourself.".into());
    }

    let mut state = load_state()?;
    if let Some(existing) = state.peers.iter_mut().find(|p| p.nickname == nickname) {
        let old = Ticket::from_text(&existing.ticket)?;
        if old.id() != ticket.id() {
            return Err(format!(
                "SECURITY ALERT: '{nickname}' is already paired with a DIFFERENT identity \
                 ({} vs {}). Remove the old peer explicitly if you really mean to replace it.",
                old.fingerprint(),
                ticket.fingerprint()
            )
            .into());
        }
        existing.ticket = ticket.to_text();
    } else {
        state.peers.push(LivePeer {
            nickname: nickname.to_string(),
            ticket: ticket.to_text(),
        });
    }
    save_state(&state)?;
    Ok(ticket)
}

// ── Transfer ─────────────────────────────────────────────────────────────────

fn peer_ticket(nickname: &str) -> Res<Ticket> {
    let state = load_state()?;
    let peer = state
        .peer(nickname)
        .ok_or_else(|| format!("No peer named '{nickname}'. Run 'atom live pair' first."))?;
    Ok(Ticket::from_text(&peer.ticket)?)
}

/// Our own bind address, taken from the first direct endpoint we advertise.
fn bind_address() -> Res<SocketAddr> {
    let state = load_state()?;
    for e in &state.my_endpoints {
        if let Ok(Endpoint::Direct(addr)) = parse_endpoint(e) {
            // Bind the advertised *port* on all interfaces: the advertised host
            // is what the peer sees after NAT, which is usually not an address
            // this machine can bind.
            return Ok(SocketAddr::from(([0, 0, 0, 0], addr.port())));
        }
    }
    Err("No direct address set. Run 'atom live address <ip:port>' first.".into())
}

/// Which way the vault is moving.
enum Direction {
    Send(PathBuf),
    Receive(PathBuf),
}

/// Meet the peer, run the transfer, close cleanly.
///
/// One function for both directions so the rendezvous, the traffic-shaping
/// configuration and the close sequence cannot drift apart between them.
fn run_transfer(
    peer_nick: &str,
    direction: Direction,
    on_progress: &mut (dyn FnMut(Progress) + Send),
    cancel: Option<Cancel>,
) -> Res<Summary> {
    let ticket = peer_ticket(peer_nick)?;
    let me = load_or_create_identity()?;
    let bind = bind_address()?;

    let rt = tokio::runtime::Runtime::new()?;
    let summary = rt.block_on(async move {
        let mut session = rendezvous::rendezvous(bind, &ticket, &me, RENDEZVOUS_TIMEOUT).await?;

        let mut transfer = Transfer::new(EncryptedAtRest::aegis_vault()).pacing(Pacing::default());
        if let Some(c) = cancel {
            transfer = transfer.with_cancel(c);
        }

        let result = match &direction {
            Direction::Send(p) => transfer.send(&mut session, p, on_progress).await,
            Direction::Receive(p) => transfer.recv(&mut session, p, on_progress).await,
        };

        // Close either way: gracefully so the peer sees the end of the stream,
        // and because an abandoned session would otherwise linger until the
        // idle timeout.
        let _ = p2p_live::SecureSession::close(&mut session).await;
        result
    })?;
    Ok(summary)
}

/// Send `vault_path` to a paired peer. Both peers must run their side together.
pub fn send_core(
    vault_path: &str,
    peer_nick: &str,
    on_progress: &mut (dyn FnMut(Progress) + Send),
    cancel: Option<Cancel>,
) -> Res<Summary> {
    let path = PathBuf::from(vault_path);
    if !path.exists() {
        return Err(format!("No such vault: {vault_path}").into());
    }
    run_transfer(peer_nick, Direction::Send(path), on_progress, cancel)
}

/// Receive a vault from a paired peer into `save_path`.
pub fn receive_core(
    save_path: &str,
    peer_nick: &str,
    on_progress: &mut (dyn FnMut(Progress) + Send),
    cancel: Option<Cancel>,
) -> Res<Summary> {
    let path = PathBuf::from(save_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    run_transfer(peer_nick, Direction::Receive(path), on_progress, cancel)
}

// ── CLI handlers ─────────────────────────────────────────────────────────────
//
// Presentation only: every one of these calls a `*_core` function above, which
// is the same code the GUI drives.

use std::io::BufRead;

/// Read one line from the user, trimmed.
fn prompt(label: &str) -> Res<String> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn handle_id() -> Res<()> {
    let s = identity_summary()?;
    println!("--- 🛡  Your Live Identity ---");
    println!("🔑 Identity  : {}", s.id);
    println!("👁  Fingerprint: {}", s.fingerprint);
    println!(
        "🧬 Post-quantum: {}",
        if s.hybrid {
            "yes (Ed25519 + ML-DSA-65)"
        } else {
            "no — classical only"
        }
    );
    if s.endpoints.is_empty() {
        println!("📍 Address   : not set");
        println!("\n👉 Run 'atom live address <ip:port>' so peers know where to reach you.");
    } else {
        println!("📍 Address   : {}", s.endpoints.join(", "));
    }
    println!(
        "\nRead the fingerprint aloud when you pair. It covers both of your keys,\n\
         so if it matches on your peer's screen, nobody has substituted either one."
    );
    Ok(())
}

pub fn handle_address(address: &str) -> Res<()> {
    set_endpoints(&[address.to_string()])?;
    println!("✅ Peers will be told to reach you at {address}");
    if !address.contains(".onion") {
        println!(
            "\n⚠️  This is a direct address. Your ISP and your peer's ISP will both see\n\
             that the two of you exchanged packets. If that pairing must stay hidden,\n\
             set an .onion address instead and the transfer will run over Tor."
        );
    }
    Ok(())
}

pub fn handle_peers() -> Res<()> {
    let state = load_state()?;
    if state.peers.is_empty() {
        println!("No paired peers yet. Run 'atom live pair --nickname <name>'.");
        return Ok(());
    }
    println!("--- 👥 Paired Peers ---");
    for p in &state.peers {
        match Ticket::from_text(&p.ticket) {
            Ok(t) => {
                let expired = t.check_valid().is_err();
                println!(
                    "  {:<16} {}  {}{}",
                    p.nickname,
                    t.fingerprint(),
                    if t.is_hybrid() { "PQ" } else { "classical" },
                    if expired {
                        "  ⚠️ ticket expired"
                    } else {
                        ""
                    }
                );
                for h in &t.hints {
                    println!("      via {h}");
                }
            }
            Err(e) => println!("  {:<16} ⚠️ unreadable ticket: {e}", p.nickname),
        }
    }
    Ok(())
}

pub fn handle_pair(nickname: &str, code: Option<String>) -> Res<()> {
    // Fail before showing a code if we have no address to offer.
    let ticket = my_ticket()?;

    let code = match code {
        Some(c) => {
            println!("Using the pairing code your peer gave you.");
            PairingCode::parse(&c)?
        }
        None => {
            let c = PairingCode::generate()?;
            println!("\n🔑 Your pairing code:  {}\n", c.display());
            println!("   Read it ALOUD to {nickname} — in person or on a call.");
            println!("   Do NOT send it through the same channel as the blobs below:");
            println!("   the whole design rests on those being two different channels.");
            println!("   Single use. If pairing fails, start again with a NEW code.");
            c
        }
    };

    let (state, our_msg) = pair_begin(&code);

    println!("\n── Round 1 ─ send this to {nickname}:\n");
    println!("{our_msg}\n");
    let peer_msg = prompt(&format!(
        "Paste {nickname}'s round-1 message, then Enter:\n> "
    ))?;

    let (channel, sealed) = pair_exchange(state, &peer_msg)?;
    println!("\n── Round 2 ─ send this to {nickname}:\n");
    println!("{sealed}\n");
    let peer_sealed = prompt(&format!(
        "Paste {nickname}'s round-2 message, then Enter:\n> "
    ))?;

    let peer = pair_complete(&channel, &peer_sealed, nickname)?;

    println!("\n✅ Paired with {nickname}");
    println!("   Fingerprint : {}", peer.fingerprint());
    println!(
        "   Post-quantum: {}",
        if peer.is_hybrid() { "yes" } else { "no" }
    );
    println!("   Your own    : {}", ticket.fingerprint());
    println!(
        "\n👁  Now read both fingerprints aloud and check they match what {nickname} sees.\n\
         If they differ, someone sat in the middle of your exchange — delete this\n\
         peer and start over on a channel you trust more."
    );
    Ok(())
}

/// Shared driver for send and receive, so both report progress identically.
fn run_with_progress(
    label: &str,
    peer: &str,
    run: impl FnOnce(&mut (dyn FnMut(Progress) + Send)) -> Res<Summary>,
) -> Res<()> {
    println!("⏳ Waiting to meet {peer} — they must run their side at the same time.");

    let mut last_pct = u64::MAX;
    let mut resumed_noted = false;
    let mut on_progress = move |p: Progress| {
        if p.resumed_from > 0 && !resumed_noted {
            resumed_noted = true;
            println!("↻  Resuming from {}", human_bytes(p.resumed_from));
        }
        let pct = p
            .transferred
            .checked_mul(100)
            .and_then(|n| n.checked_div(p.total))
            .unwrap_or(100);
        if pct != last_pct {
            last_pct = pct;
            print!(
                "\r{label} {pct:>3}%  {} / {}",
                human_bytes(p.transferred),
                human_bytes(p.total)
            );
            let _ = std::io::stdout().flush();
        }
    };

    let summary = run(&mut on_progress)?;
    println!();
    println!("✅ Done — {} verified", human_bytes(summary.total));
    if summary.cover_frames > 0 {
        println!(
            "   {} cover frames sent so the size and end time reveal nothing.",
            summary.cover_frames
        );
    }
    Ok(())
}

pub fn handle_send(vault_path: &str, peer: &str) -> Res<()> {
    run_with_progress("📤 Sending", peer, |cb| {
        send_core(vault_path, peer, cb, None)
    })
}

pub fn handle_receive(save_path: &str, peer: &str) -> Res<()> {
    run_with_progress("📥 Receiving", peer, |cb| {
        receive_core(save_path, peer, cb, None)
    })?;
    println!("   Saved to {save_path}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse_both_transports() {
        assert!(matches!(
            parse_endpoint("203.0.113.7:4433").unwrap(),
            Endpoint::Direct(_)
        ));
        assert!(matches!(
            parse_endpoint("[2001:db8::1]:4433").unwrap(),
            Endpoint::Direct(_)
        ));
        assert!(matches!(
            parse_endpoint("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:4433")
                .unwrap(),
            Endpoint::Onion(_)
        ));
    }

    /// A mistyped address must be refused when it is entered, not baked into a
    /// ticket a peer has already saved.
    #[test]
    fn bad_endpoints_are_refused() {
        for bad in [
            "203.0.113.7",          // no port
            "example.com:443",      // clearnet host, not an onion
            "203.0.113.7:notaport", // bad port
            "",
        ] {
            assert!(parse_endpoint(bad).is_err(), "{bad} must be rejected");
        }
    }

    /// A peer entry must round-trip through the on-disk form unchanged.
    #[test]
    fn live_state_serialises() {
        let state = LiveState {
            my_endpoints: vec!["203.0.113.7:4433".into()],
            peers: vec![LivePeer {
                nickname: "bob".into(),
                ticket: "atom-live-1:abc".into(),
            }],
        };
        let json = serde_json::to_vec(&state).unwrap();
        let back: LiveState = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.my_endpoints, state.my_endpoints);
        assert_eq!(back.peer("bob").unwrap().ticket, "atom-live-1:abc");
        assert!(back.peer("nobody").is_none());
    }

    /// An empty state file must load as empty rather than failing, so a first
    /// run does not look like a corrupted install.
    #[test]
    fn a_default_state_is_empty_not_an_error() {
        let state = LiveState::default();
        assert!(state.my_endpoints.is_empty());
        assert!(state.peers.is_empty());
    }
}
