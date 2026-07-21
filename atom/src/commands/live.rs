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
//! * `live_peers.json` — your advertised address, your rendezvous endpoint
//!   configuration, and one entry per paired peer. A ticket carries no secret,
//!   but it does link an identity to an address, which is exactly the metadata
//!   worth protecting. **Since Phase 8 this file also holds one real secret per
//!   peer** — the pairwise rendezvous secret. It decrypts nothing and
//!   authenticates nobody (see `p2p_live::discovery::secret`), but someone
//!   holding it can read where a peer says it is and forge a record pointing
//!   elsewhere, so the file's encryption is now load-bearing rather than
//!   merely prudent.
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
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use data_encoding::BASE32_NOPAD;
use p2p_live::bundle::LocalBundle;
use p2p_live::discovery::{self, BlindEndpoint, Discovery, RendezvousSecret, ServerLink};
use p2p_live::pacing::Pacing;
use p2p_live::pairing::{self, PairedChannel, PairingCode, PairingState};
use p2p_live::reach::{self, PeerState};
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
///
/// Every Phase 8 field is `#[serde(default)]`, so a `live_peers.json` written
/// before this existed still loads — such a peer simply has no rendezvous
/// secret and stays on the manual-address path until re-paired.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LivePeer {
    pub nickname: String,
    /// The peer's ticket in its canonical text form.
    pub ticket: String,

    /// The pairwise rendezvous secret from pairing, base32.
    ///
    /// `None` for a peer paired before Phase 8. Its absence is what makes
    /// [`peer_state`] refuse to look them up rather than silently failing to.
    #[serde(default)]
    pub rendezvous_secret: Option<String>,

    /// Where this peer was last actually reached.
    ///
    /// Tried before any endpoint is contacted, so a peer who has not moved is
    /// reconnected with no third party involved at all.
    #[serde(default)]
    pub last_known: Vec<String>,

    /// Highest address-record sequence accepted from this peer.
    ///
    /// The replay floor: an endpoint that re-serves a record we have already
    /// used cannot pass it off as current.
    #[serde(default)]
    pub newest_seen: Option<u64>,
}

impl LivePeer {
    /// A newly paired peer, with the discovery secret and nothing learned yet.
    fn new(nickname: &str, ticket: &Ticket, secret: &RendezvousSecret) -> Self {
        LivePeer {
            nickname: nickname.to_string(),
            ticket: ticket.to_text(),
            rendezvous_secret: Some(encode_secret(secret)),
            last_known: Vec::new(),
            newest_seen: None,
        }
    }

    /// Whether this peer can be found by ID alone.
    pub fn is_reachable_by_id(&self) -> bool {
        self.rendezvous_secret.is_some()
    }
}

/// One dumb, self-hostable rendezvous endpoint.
///
/// Stored as **the link exactly as it was pasted**, plus two local choices: what
/// to call it, and whether to reach it through a proxy. Nothing about the
/// endpoint is stored in parts, because parts are what let a pin drift away from
/// the address it belongs to — and a pin that has drifted is one that silently
/// stops protecting anything.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RendezvousEndpoint {
    /// Local nickname. Ours, not the operator's: a name carried inside a link
    /// would be attacker-chosen text rendered in our own UI.
    pub name: String,
    /// The `atom-rdv-1:…` link.
    pub link: String,
    /// SOCKS5 proxy to route through, e.g. `127.0.0.1:9050` for Tor.
    ///
    /// Set this and the endpoint never learns this machine's address, which is
    /// the one control that closes the "wrote tag T, read tag T" correlation
    /// entirely. Required for an onion-only link.
    #[serde(default)]
    pub via_socks: Option<String>,
}

impl RendezvousEndpoint {
    fn parsed(&self) -> Res<ServerLink> {
        Ok(ServerLink::from_text(&self.link)?)
    }

    fn proxy(&self) -> Res<Option<SocketAddr>> {
        match &self.via_socks {
            None => Ok(None),
            Some(s) => {
                Ok(Some(s.parse().map_err(|_| {
                    format!("'{s}' is not a host:port for a SOCKS proxy")
                })?))
            }
        }
    }

    /// Build the client from the stored link.
    fn build(&self) -> Res<Arc<BlindEndpoint>> {
        Ok(Arc::new(BlindEndpoint::from_link(
            &self.parsed()?,
            self.proxy()?,
        )?))
    }
}

/// Everything `atom live` remembers besides the private identity.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LiveState {
    /// Addresses we advertise to peers, as `ip:port` or `<onion>.onion:port`.
    #[serde(default)]
    pub my_endpoints: Vec<String>,
    #[serde(default)]
    pub peers: Vec<LivePeer>,
    /// Where address records are published and looked up.
    #[serde(default)]
    pub rendezvous: Vec<RendezvousEndpoint>,
}

impl LiveState {
    pub fn peer(&self, nickname: &str) -> Option<&LivePeer> {
        self.peers.iter().find(|p| p.nickname == nickname)
    }
}

/// Base32 for a rendezvous secret, matching how every other identifier in this
/// project is written down.
fn encode_secret(secret: &RendezvousSecret) -> String {
    BASE32_NOPAD.encode(secret.expose()).to_lowercase()
}

fn decode_secret(text: &str) -> Res<RendezvousSecret> {
    let raw = BASE32_NOPAD
        .decode(text.trim().to_uppercase().as_bytes())
        .map_err(|e| format!("stored rendezvous secret is not valid base32: {e}"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "stored rendezvous secret is not 32 bytes")?;
    Ok(RendezvousSecret::from_bytes(bytes))
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

/// Ask a STUN server what our external `ip:port` is, and store it.
///
/// **This tells the STUN server our IP address.** `CLAUDE.md` §6 keeps STUN off
/// by default for exactly that reason, and nothing calls this on the user's
/// behalf — but the ID-only path needs an address to publish, and behind NAT
/// there is no other way to learn one. The caller must have shown the warning
/// before getting here.
///
/// `port` is the local UDP port we will transfer from. The mapping a NAT hands
/// out belongs to a port, so querying from any other one yields an address the
/// peer cannot reach.
pub fn discover_address(server: &str, port: u16) -> Res<String> {
    let server: SocketAddr = server
        .parse()
        .map_err(|_| format!("'{server}' is not a host:port — STUN needs e.g. 203.0.113.1:3478"))?;

    let rt = tokio::runtime::Runtime::new()?;
    let found = rt.block_on(async {
        // Bound to the port the transfer will use, then dropped before the QUIC
        // endpoint binds the same port.
        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
        p2p_live::stun::discover(&socket, server, Duration::from_secs(5)).await
    })?;

    set_endpoints(&[found.to_string()])?;
    Ok(found.to_string())
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

    // The one thing that outlives the pairing: the pairwise discovery secret,
    // which is what lets this peer be found by ID after their address changes.
    let secret = channel.rendezvous_secret();

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
        // Re-pairing is a fresh exchange, so it yields a fresh secret on both
        // sides. Keeping the old one would leave the two peers addressing
        // different slots and unable to find each other at all.
        existing.rendezvous_secret = Some(encode_secret(&secret));
    } else {
        state.peers.push(LivePeer::new(nickname, &ticket, &secret));
    }
    save_state(&state)?;
    Ok(ticket)
}

// ── Discovery ────────────────────────────────────────────────────────────────

/// Build the resolver from the configured endpoints.
///
/// An endpoint that will not build is reported rather than skipped: silently
/// dropping a misconfigured endpoint would leave a user believing they are
/// reachable when they are not.
pub fn discovery_from(state: &LiveState) -> Res<Discovery> {
    let mut substrates: Vec<Arc<dyn p2p_live::Substrate>> = Vec::new();
    for cfg in &state.rendezvous {
        substrates.push(cfg.build()?);
    }
    Ok(Discovery::new(substrates))
}

/// Assemble the in-memory peer state the reach layer works with.
fn peer_state(peer: &LivePeer) -> Res<PeerState> {
    let ticket = Ticket::from_text(&peer.ticket)?;
    let secret_text = peer.rendezvous_secret.as_ref().ok_or_else(|| {
        format!(
            "'{}' was paired before rendezvous existed, so they cannot be found by ID. \
             Re-pair with 'atom live pair --nickname {}' to enable it.",
            peer.nickname, peer.nickname
        )
    })?;

    // Prefer what we last actually reached them on; fall back to the ticket's
    // hints, which is all a freshly paired peer has.
    let mut last_known = Vec::new();
    for e in &peer.last_known {
        last_known.push(parse_endpoint(e)?);
    }
    if last_known.is_empty() {
        last_known = ticket.hints.clone();
    }

    Ok(PeerState {
        identity: ticket.identity,
        rendezvous: decode_secret(secret_text)?,
        last_known,
        newest_seen: peer.newest_seen,
    })
}

/// Write back what a connection attempt learned.
fn remember(nickname: &str, learned: &PeerState) -> Res<()> {
    let mut state = load_state()?;
    if let Some(p) = state.peers.iter_mut().find(|p| p.nickname == nickname) {
        p.last_known = learned.last_known.iter().map(|e| e.to_string()).collect();
        p.newest_seen = learned.newest_seen;
        save_state(&state)?;
    }
    Ok(())
}

/// What an announce achieved, for the UI to report.
pub struct AnnounceOutcome {
    pub peer: String,
    pub reached: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Publish our current address to every peer's slot.
///
/// One record per peer rather than one for everybody: the whole construction
/// rests on each pair having its own unlinkable slot, so a shared record would
/// hand an endpoint exactly the group membership the design denies it.
pub fn announce_core(only: Option<&str>) -> Res<Vec<AnnounceOutcome>> {
    let state = load_state()?;
    let me = load_or_create_identity()?;
    let discovery = discovery_from(&state)?;

    if discovery.is_empty() {
        return Err(
            "No rendezvous endpoint configured. Run 'atom live rendezvous add …' \
                    first, or keep exchanging addresses by hand."
                .into(),
        );
    }

    let mut hints = Vec::new();
    for e in &state.my_endpoints {
        hints.push(parse_endpoint(e)?);
    }
    if hints.is_empty() {
        return Err("No address set, so there is nothing to publish. Run \
                    'atom live address <ip:port>' (or --stun) first."
            .into());
    }

    let rt = tokio::runtime::Runtime::new()?;
    let mut outcomes = Vec::new();

    for peer in &state.peers {
        if only.is_some_and(|n| n != peer.nickname) {
            continue;
        }
        if !peer.is_reachable_by_id() {
            continue;
        }
        let ps = peer_state(peer)?;
        let report = rt.block_on(reach::announce(&me, &ps, &discovery, hints.clone()))?;
        outcomes.push(AnnounceOutcome {
            peer: peer.nickname.clone(),
            reached: report.succeeded,
            failed: report.failed,
        });
    }

    if outcomes.is_empty() {
        return Err(match only {
            Some(n) => format!("No peer named '{n}' that can be found by ID.").into(),
            None => "No peers to announce to.".to_string().into(),
        });
    }
    Ok(outcomes)
}

// ── Transfer ─────────────────────────────────────────────────────────────────

fn stored_peer(nickname: &str) -> Res<LivePeer> {
    let state = load_state()?;
    state
        .peer(nickname)
        .cloned()
        .ok_or_else(|| format!("No peer named '{nickname}'. Run 'atom live pair' first.").into())
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
    on_path: &mut (dyn FnMut(reach::Path) + Send),
) -> Res<Summary> {
    let state = load_state()?;
    let peer = stored_peer(peer_nick)?;
    let me = load_or_create_identity()?;
    let bind = bind_address()?;
    let discovery = discovery_from(&state)?;
    let mut ps = peer_state(&peer)?;

    let opts = reach::Options {
        timeout: RENDEZVOUS_TIMEOUT,
        socks: None,
        use_discovery: !discovery.is_empty(),
    };

    let rt = tokio::runtime::Runtime::new()?;
    let (summary, learned) = rt.block_on(async {
        let (mut session, path) = reach::connect(bind, &me, &mut ps, &discovery, &opts).await?;
        on_path(path);

        let mut transfer = Transfer::new(EncryptedAtRest::aegis_vault()).pacing(Pacing::default());
        if let Some(c) = cancel {
            transfer = transfer.with_cancel(c);
        }

        let result = match &direction {
            Direction::Send(p) => transfer.send(session.as_mut(), p, on_progress).await,
            Direction::Receive(p) => transfer.recv(session.as_mut(), p, on_progress).await,
        };

        // Close either way: gracefully so the peer sees the end of the stream,
        // and because an abandoned session would otherwise linger until the
        // idle timeout.
        let _ = session.close().await;
        result.map(|s| (s, ps))
    })?;

    // Persisted after the transfer, not during: a freshly resolved address is
    // only worth remembering once it has actually carried a session, and a
    // failed attempt must not overwrite an address that still works.
    remember(peer_nick, &learned)?;
    Ok(summary)
}

/// Send `vault_path` to a paired peer. Both peers must run their side together.
///
/// `on_path` reports which rung of the ladder reached them. It is a required
/// argument rather than an optional one because the rungs differ in who learns
/// about the connection, and a UI that quietly dropped that would be hiding the
/// only part of the tradeoff the user can act on.
pub fn send_core(
    vault_path: &str,
    peer_nick: &str,
    on_progress: &mut (dyn FnMut(Progress) + Send),
    cancel: Option<Cancel>,
    on_path: &mut (dyn FnMut(reach::Path) + Send),
) -> Res<Summary> {
    let path = PathBuf::from(vault_path);
    if !path.exists() {
        return Err(format!("No such vault: {vault_path}").into());
    }
    run_transfer(
        peer_nick,
        Direction::Send(path),
        on_progress,
        cancel,
        on_path,
    )
}

/// Receive a vault from a paired peer into `save_path`.
pub fn receive_core(
    save_path: &str,
    peer_nick: &str,
    on_progress: &mut (dyn FnMut(Progress) + Send),
    cancel: Option<Cancel>,
    on_path: &mut (dyn FnMut(reach::Path) + Send),
) -> Res<Summary> {
    let path = PathBuf::from(save_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    run_transfer(
        peer_nick,
        Direction::Receive(path),
        on_progress,
        cancel,
        on_path,
    )
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
        println!(
            "\n👉 Run 'atom live address <ip:port>' so peers know where to reach you,\n   \
             or 'atom live stun <server:port>' to discover it (tells that server your IP)."
        );
    } else {
        println!("📍 Address   : {}", s.endpoints.join(", "));
    }

    let state = load_state()?;
    if state.rendezvous.is_empty() {
        println!("📇 Rendezvous: none — peers must be given your address by hand");
    } else {
        println!(
            "📇 Rendezvous: {}",
            state
                .rendezvous
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("   Peers who paired with you can find you by ID after your address changes.");
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
                println!(
                    "  {:<16} {}  {}",
                    p.nickname,
                    t.fingerprint(),
                    if t.is_hybrid() { "PQ" } else { "classical" }
                );
                if p.is_reachable_by_id() {
                    // A ticket's expiry stops mattering once the peer can be
                    // looked up: the address in it is no longer what we dial.
                    println!("      findable by ID");
                } else {
                    println!(
                        "      ⚠️  paired before rendezvous — re-pair to be findable by ID{}",
                        if t.check_valid().is_err() {
                            ", and this ticket has expired"
                        } else {
                            ""
                        }
                    );
                }
                for h in &p.last_known {
                    println!("      last reached at {h}");
                }
                if p.last_known.is_empty() {
                    for h in &t.hints {
                        println!("      via {h} (from pairing)");
                    }
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

/// Print which rung of the ladder reached the peer.
///
/// Always printed, never only on the "worse" rungs: a user who sees the line
/// every time notices when it changes, whereas a warning that appears only
/// sometimes is read as noise.
fn report_path(p: reach::Path) {
    println!("\r🔗 Reached via {p}");
    if p == reach::Path::Discovered {
        println!(
            "   The endpoint saw an opaque tag, not who either of you are — but it did\n   \
             see both your addresses within the hour. Self-host it, or route through\n   \
             Tor with --via-socks, if that matters."
        );
    }
}

pub fn handle_send(vault_path: &str, peer: &str) -> Res<()> {
    run_with_progress("📤 Sending", peer, |cb| {
        send_core(vault_path, peer, cb, None, &mut report_path)
    })
}

pub fn handle_receive(save_path: &str, peer: &str) -> Res<()> {
    run_with_progress("📥 Receiving", peer, |cb| {
        receive_core(save_path, peer, cb, None, &mut report_path)
    })?;
    println!("   Saved to {save_path}");
    Ok(())
}

pub fn handle_announce(peer: Option<String>) -> Res<()> {
    let outcomes = announce_core(peer.as_deref())?;
    println!("--- 📡 Announced ---");
    for o in &outcomes {
        if o.reached.is_empty() {
            println!("  {:<16} ❌ published nowhere", o.peer);
        } else {
            println!("  {:<16} ✅ via {}", o.peer, o.reached.join(", "));
        }
        for (name, err) in &o.failed {
            println!("      ⚠️  {name}: {err}");
        }
    }
    println!(
        "\nEach peer got its own record under its own rotating tag, so no endpoint can\n\
         tell which of these belong together. Re-run this whenever your address changes."
    );
    Ok(())
}

pub fn handle_rendezvous_add(
    link: &str,
    name: Option<String>,
    via_socks: Option<String>,
) -> Res<()> {
    let parsed = ServerLink::from_text(link)?;
    // The label the operator's address implies, unless the user names it.
    let name = name.unwrap_or_else(|| parsed.label());

    let cfg = RendezvousEndpoint {
        name: name.clone(),
        // Stored re-serialised from the parsed form rather than as typed, so
        // whitespace and case a chat client introduced do not survive into the
        // config file.
        link: parsed.to_text(),
        via_socks,
    };
    // Built before it is saved, so a link that cannot work is refused now rather
    // than during a rendezvous someone is waiting on.
    cfg.build()?;

    let mut state = load_state()?;
    if let Some(existing) = state.rendezvous.iter_mut().find(|e| e.name == name) {
        *existing = cfg;
        println!("✅ Updated rendezvous endpoint '{name}'");
    } else {
        state.rendezvous.push(cfg);
        println!("✅ Added rendezvous endpoint '{name}'");
    }
    save_state(&state)?;

    println!(
        "   Pinned to {} certificate(s) from the link.",
        parsed.pins.len()
    );
    if state
        .rendezvous
        .iter()
        .find(|e| e.name == name)
        .is_some_and(|e| e.via_socks.is_none())
    {
        println!(
            "\n⚠️  This endpoint will see your IP address when you publish or look up.\n\
             It never learns who you are — the tag is opaque and rotates hourly — but\n\
             within that hour it can tell that your address and your peer's are a pair.\n\
             Host it yourself, or add --via-socks 127.0.0.1:9050 to reach it over Tor."
        );
    }
    Ok(())
}

/// Produce a link for an operator to publish.
///
/// The one place the pieces are still handled separately — by whoever runs the
/// server, once, for their own endpoint. Everybody else pastes the result.
pub fn handle_rendezvous_link(
    host: &str,
    port: u16,
    prefix: &str,
    pins: &[String],
    onion: Option<String>,
) -> Res<()> {
    let mut parsed_pins = Vec::with_capacity(pins.len());
    for p in pins {
        parsed_pins.push(discovery::parse_pin(p)?);
    }

    let onion = match onion {
        None => None,
        Some(text) => match parse_endpoint(&text)? {
            Endpoint::Onion(o) => Some(o),
            Endpoint::Direct(_) => {
                return Err("--onion needs an .onion address with a port".into());
            }
        },
    };

    let link = ServerLink::new(
        discovery::ServerKind::Rendezvous,
        host,
        port,
        prefix,
        parsed_pins,
        onion,
    )?;

    println!("--- 🔗 Rendezvous Link ---\n");
    println!("{link}\n");
    println!(
        "Give this to anyone who should use your endpoint. It carries the address and\n\
         the certificate pin together, so there is nothing for them to type by hand and\n\
         no pin for them to skip. They run:\n\n  \
         atom live rendezvous add <link>\n"
    );
    if link.is_onion_only() {
        println!(
            "This link is onion-only, so no routable address appears in it at all —\n\
             users of it will need --via-socks pointing at their Tor client."
        );
    }
    Ok(())
}

pub fn handle_rendezvous_list() -> Res<()> {
    let state = load_state()?;
    if state.rendezvous.is_empty() {
        println!(
            "No rendezvous endpoints configured — peers can only be reached at the\n\
             address you exchanged by hand. Add one with 'atom live rendezvous add <link>'."
        );
        return Ok(());
    }
    println!("--- 📇 Rendezvous Endpoints ---");
    for e in &state.rendezvous {
        let route = match &e.via_socks {
            Some(p) => format!("via {p}"),
            None => "direct (sees your IP)".to_string(),
        };
        match e.parsed() {
            Ok(link) => println!(
                "  {:<20} {:<28} {route}  [{} pin(s)]",
                e.name,
                link.label(),
                link.pins.len()
            ),
            Err(err) => println!("  {:<20} ⚠️ unreadable link: {err}", e.name),
        }
    }
    Ok(())
}

pub fn handle_rendezvous_remove(name: &str) -> Res<()> {
    let mut state = load_state()?;
    let before = state.rendezvous.len();
    state.rendezvous.retain(|e| e.name != name);
    if state.rendezvous.len() == before {
        return Err(format!("No rendezvous endpoint named '{name}'.").into());
    }
    save_state(&state)?;
    println!("✅ Removed rendezvous endpoint '{name}'");
    Ok(())
}

pub fn handle_stun(server: &str, port: u16) -> Res<()> {
    println!(
        "⚠️  A STUN query tells {server} your IP address, moments before you connect\n\
         to a peer. That is the one third-party touch the live path otherwise avoids.\n\
         If you have a forwarded port or a static address, use 'atom live address'\n\
         instead and skip this entirely.\n"
    );
    let found = discover_address(server, port)?;
    println!("✅ Your external address is {found} — saved and ready to announce.");
    println!("   Run 'atom live announce' to publish it to your peers.");
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

    fn a_secret() -> RendezvousSecret {
        RendezvousSecret::from_bytes([9u8; 32])
    }

    fn a_link() -> ServerLink {
        ServerLink::new(
            discovery::ServerKind::Rendezvous,
            "rdv.example.org",
            8443,
            "records",
            vec![[7u8; 32]],
            None,
        )
        .unwrap()
    }

    /// A peer entry must round-trip through the on-disk form unchanged.
    #[test]
    fn live_state_serialises() {
        let ticket = Ticket::new(LocalBundle::generate().unwrap().bundle(), vec![]).unwrap();
        let state = LiveState {
            my_endpoints: vec!["203.0.113.7:4433".into()],
            peers: vec![LivePeer::new("bob", &ticket, &a_secret())],
            rendezvous: vec![RendezvousEndpoint {
                name: "mine".into(),
                link: a_link().to_text(),
                via_socks: None,
            }],
        };
        let json = serde_json::to_vec(&state).unwrap();
        let back: LiveState = serde_json::from_slice(&json).unwrap();

        assert_eq!(back.my_endpoints, state.my_endpoints);
        assert_eq!(back.peer("bob").unwrap().ticket, ticket.to_text());
        assert!(back.peer("nobody").is_none());
        assert_eq!(back.rendezvous[0].name, "mine");
    }

    /// The rendezvous secret must survive the on-disk round trip exactly. A
    /// single flipped bit puts the two peers on different slots and they simply
    /// never find each other — with no error to explain why.
    #[test]
    fn a_rendezvous_secret_round_trips_through_storage() {
        let original = a_secret();
        let restored = decode_secret(&encode_secret(&original)).unwrap();
        assert_eq!(restored.expose(), original.expose());
    }

    #[test]
    fn a_corrupt_stored_secret_is_refused_rather_than_truncated() {
        assert!(decode_secret("").is_err());
        assert!(decode_secret("not base32 at all!").is_err());
        // Right alphabet, wrong length — must not be zero-padded into a key.
        assert!(decode_secret("aaaa").is_err());
    }

    /// A `live_peers.json` written before Phase 8 must still load, and the peer
    /// in it must be reported as not findable by ID rather than half-working.
    #[test]
    fn a_pre_phase8_state_file_still_loads() {
        let legacy = br#"{
            "my_endpoints": ["203.0.113.7:4433"],
            "peers": [{"nickname": "bob", "ticket": "atom-live-1:abc"}]
        }"#;
        let state: LiveState = serde_json::from_slice(legacy).unwrap();

        let bob = state.peer("bob").unwrap();
        assert_eq!(bob.ticket, "atom-live-1:abc");
        assert!(
            !bob.is_reachable_by_id(),
            "a peer with no stored secret must not claim to be findable"
        );
        assert!(state.rendezvous.is_empty());
    }

    /// Refusing to look up a peer paired before Phase 8 must say what to do
    /// about it, since the fix is a re-pair rather than anything automatic.
    #[test]
    fn a_peer_without_a_secret_cannot_be_resolved() {
        let peer = LivePeer {
            nickname: "bob".into(),
            ticket: Ticket::new(LocalBundle::generate().unwrap().bundle(), vec![])
                .unwrap()
                .to_text(),
            rendezvous_secret: None,
            last_known: vec![],
            newest_seen: None,
        };
        let err = peer_state(&peer)
            .expect_err("a peer with no secret cannot be resolved")
            .to_string();
        assert!(err.contains("Re-pair"), "got: {err}");
    }

    /// An endpoint must be rejected while it is being configured, not when
    /// somebody is waiting on a rendezvous.
    #[test]
    fn a_rendezvous_endpoint_validates_its_link_when_built() {
        let good = RendezvousEndpoint {
            name: "mine".into(),
            link: a_link().to_text(),
            via_socks: None,
        };
        assert!(good.build().is_ok());

        // A link damaged in transit must not be half-accepted.
        let mut damaged = a_link().to_text();
        damaged.truncate(damaged.len() - 3);
        assert!(
            RendezvousEndpoint {
                link: damaged,
                ..good.clone()
            }
            .build()
            .is_err()
        );

        // Anything that is not a link at all.
        assert!(
            RendezvousEndpoint {
                link: "example.org:443".into(),
                ..good.clone()
            }
            .build()
            .is_err()
        );

        // A SOCKS address that is not host:port must also be caught here.
        assert!(
            RendezvousEndpoint {
                via_socks: Some("localhost".into()),
                ..good.clone()
            }
            .build()
            .is_err()
        );
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
