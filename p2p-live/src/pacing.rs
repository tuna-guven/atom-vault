//! L3 traffic-analysis hardening — constant-rate pacing, cover traffic and a
//! quantised stream length (roadmap Phase 4, `CLAUDE.md` §2.2/§2.3, §6 step 4).
//!
//! # What an observer sees without this
//!
//! Everything below the payload is encrypted, but the *shape* of the flow is
//! not. An unpaced transfer tells anyone watching the link three things:
//!
//! 1. **Volume** — bytes on the wire ≈ bytes in the vault.
//! 2. **Duration** — the flow lasts exactly as long as the data takes.
//! 3. **The end** — the moment transmission stops is the moment the data ran
//!    out, which is also the moment the recipient has the whole vault.
//!
//! # What this module changes
//!
//! * **Fixed-size frames.** Every application frame is padded to the same
//!   length, control messages included, so no frame's size distinguishes it from
//!   any other. Without this the short final chunk alone reveals the payload
//!   length modulo the chunk size.
//! * **Constant rate.** Frames leave on a fixed schedule rather than as fast as
//!   the link allows, so throughput carries no information about the payload.
//! * **A quantised frame count.** The number of frames sent is rounded up a
//!   coarse ladder, so a 5.0 GB and a 6.3 GB vault present the same count. This
//!   is `CLAUDE.md` §4's decoy-block ladder applied to a live stream instead of
//!   a stored object set.
//! * **A randomised tail.** A few extra frames beyond the ladder, so the stop
//!   time does not land exactly on a ladder boundary — which would itself be a
//!   fingerprint of this tool.
//!
//! # The honest limits
//!
//! * **The rate must be sustainable or the guarantee degrades silently.** If the
//!   configured rate exceeds what the link or the source disk can sustain, the
//!   real bottleneck sets the pace again and throughput starts tracking
//!   conditions rather than the schedule. Set it below the slowest link.
//! * **Padding costs real bandwidth.** A power-of-two ladder bounds the overhead
//!   at under 2×, but under 2× of a 5 GB vault is still gigabytes of cover.
//! * **It hides the payload, not the conversation.** Constant-rate cover makes
//!   the transfer's *size* uninformative; it does nothing about the fact that
//!   two particular addresses exchanged packets. That is the peer-IP pairing
//!   exposure of `CLAUDE.md` §10, and only the Tor transport addresses it.

use std::time::Duration;

use tokio::time::Instant;

use crate::Error;

/// Default wire rate: 4 MiB/s (≈32 Mbit/s).
///
/// Chosen to be sustainable on a decent home uplink rather than to be fast — a
/// rate the link cannot hold is a rate that stops being constant. A 5 GiB vault
/// takes roughly 21 minutes before padding at this setting. Tune it to the
/// *slowest* leg of the path.
pub const DEFAULT_RATE_BYTES_PER_SEC: u64 = 4 * 1024 * 1024;

/// Smallest number of frames any transfer emits.
///
/// Without a floor, a very small payload announces that it is very small: a
/// three-frame flow is unmistakable however well padded each frame is.
pub const DEFAULT_MIN_FRAMES: u64 = 16;

/// Upper bound on the randomised tail, in frames.
pub const DEFAULT_JITTER_FRAMES: u64 = 64;

/// How the emitted frame count is rounded up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ladder {
    /// Round up to the next power of two. Overhead is bounded below 2× at any
    /// payload size, which is why this is the default: an absolute ladder pads a
    /// small vault by an enormous multiple.
    PowerOfTwo,
    /// Round up to the next multiple of `n` frames. Coarser for large payloads,
    /// but brutal for small ones — a 1 MiB vault padded to a 1 GiB multiple is
    /// a thousandfold overhead.
    Multiple(u64),
    /// No quantisation. The emitted count equals the real count (plus jitter),
    /// so the payload size is visible to within the jitter. Only sensible when
    /// bandwidth matters more than the size property.
    None,
}

/// Traffic-shaping configuration.
#[derive(Clone, Copy, Debug)]
pub struct Pacing {
    /// Wire rate in bytes per second, or `None` to send as fast as possible.
    pub rate_bytes_per_sec: Option<u64>,
    /// How the frame count is quantised.
    pub ladder: Ladder,
    /// Minimum frames emitted regardless of payload size.
    pub min_frames: u64,
    /// Maximum extra frames appended past the ladder, drawn uniformly.
    pub jitter_frames: u64,
}

impl Default for Pacing {
    fn default() -> Self {
        Pacing {
            rate_bytes_per_sec: Some(DEFAULT_RATE_BYTES_PER_SEC),
            ladder: Ladder::PowerOfTwo,
            min_frames: DEFAULT_MIN_FRAMES,
            jitter_frames: DEFAULT_JITTER_FRAMES,
        }
    }
}

impl Pacing {
    /// Every hardening feature off: no rate limit, no cover, no quantisation.
    ///
    /// The transfer is then as fast as the link allows and its shape reveals the
    /// payload size, duration and end time. Reasonable on a trusted LAN or when
    /// the metadata is already exposed by other means; never the safe default,
    /// which is why it has to be asked for by name.
    pub fn disabled() -> Self {
        Pacing {
            rate_bytes_per_sec: None,
            ladder: Ladder::None,
            min_frames: 0,
            jitter_frames: 0,
        }
    }

    /// Set the wire rate.
    pub fn at_rate(mut self, bytes_per_sec: u64) -> Self {
        self.rate_bytes_per_sec = Some(bytes_per_sec.max(1));
        self
    }

    /// Set the quantisation ladder.
    pub fn with_ladder(mut self, ladder: Ladder) -> Self {
        self.ladder = ladder;
        self
    }

    /// Set the floor and jitter, in frames.
    pub fn with_bounds(mut self, min_frames: u64, jitter_frames: u64) -> Self {
        self.min_frames = min_frames;
        self.jitter_frames = jitter_frames;
        self
    }

    /// Whether any shaping is active at all.
    pub fn is_shaped(&self) -> bool {
        self.rate_bytes_per_sec.is_some()
            || self.ladder != Ladder::None
            || self.min_frames > 0
            || self.jitter_frames > 0
    }

    /// Total frames to emit for a payload of `real_frames` data frames.
    ///
    /// Always at least `real_frames`: quantisation may only ever add cover, and
    /// a plan that dropped data would be a correctness bug disguised as a
    /// privacy feature.
    pub fn plan(&self, real_frames: u64) -> Result<u64, Error> {
        let quantised = match self.ladder {
            Ladder::PowerOfTwo => real_frames
                .checked_next_power_of_two()
                .unwrap_or(real_frames),
            Ladder::Multiple(n) if n > 0 => real_frames
                .div_ceil(n)
                .checked_mul(n)
                .unwrap_or(real_frames),
            _ => real_frames,
        };

        let floored = quantised.max(self.min_frames);
        let jitter = if self.jitter_frames > 0 {
            random_below(self.jitter_frames + 1)?
        } else {
            0
        };

        Ok(floored.saturating_add(jitter).max(real_frames))
    }

    /// A scheduler emitting frames of `frame_len` bytes at the configured rate.
    pub fn pacer(&self, frame_len: usize) -> Pacer {
        let interval = self.rate_bytes_per_sec.map(|rate| {
            // Nanoseconds per frame. Saturating, so an absurdly small rate
            // yields a long-but-finite interval rather than an overflow.
            let nanos = (frame_len as u128)
                .saturating_mul(1_000_000_000)
                .checked_div(rate as u128)
                .unwrap_or(0);
            Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
        });
        Pacer {
            interval,
            next: Instant::now(),
        }
    }
}

/// Emits one frame per slot at a fixed interval.
#[derive(Debug)]
pub struct Pacer {
    interval: Option<Duration>,
    next: Instant,
}

impl Pacer {
    /// Wait until this frame's slot is due.
    ///
    /// If the caller has fallen behind — a slow disk, a stalled link — the
    /// schedule is re-based on the present rather than accumulating debt and
    /// then bursting to catch up. A burst would be exactly the kind of
    /// rate variation the pacing exists to remove.
    pub async fn tick(&mut self) {
        let Some(interval) = self.interval else {
            return;
        };
        let now = Instant::now();
        if self.next > now {
            tokio::time::sleep_until(self.next).await;
            self.next += interval;
        } else {
            self.next = now + interval;
        }
    }
}

/// A uniform value in `[0, bound)` drawn from the OS CSPRNG.
///
/// Rejection-sampled rather than reduced modulo `bound`, which would bias the
/// low values — the bias is tiny here, but a biased "random" tail is a
/// predictable tail and this costs nothing.
fn random_below(bound: u64) -> Result<u64, Error> {
    if bound <= 1 {
        return Ok(0);
    }
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf)
            .map_err(|e| Error::Transfer(format!("OS random number generator unavailable: {e}")))?;
        let v = u64::from_be_bytes(buf);
        if v < zone {
            return Ok(v % bound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ladder behaviour in isolation: no floor, no jitter.
    fn ladder_only() -> Pacing {
        Pacing::default().with_bounds(0, 0)
    }

    #[test]
    fn the_ladder_rounds_up_and_never_down() {
        let p = ladder_only();
        for (real, want) in [(1, 1), (3, 4), (5, 8), (5120, 8192), (8192, 8192)] {
            assert_eq!(p.plan(real).unwrap(), want, "real={real}");
        }
    }

    /// Two very different payloads must present the same frame count, which is
    /// the entire point of quantising.
    #[test]
    fn different_payloads_collide_on_the_ladder() {
        let p = ladder_only();
        // 5.0 GiB and 6.3 GiB at 1 MiB frames.
        assert_eq!(p.plan(5120).unwrap(), p.plan(6451).unwrap());
    }

    #[test]
    fn the_multiple_ladder_rounds_to_multiples() {
        let p = ladder_only().with_ladder(Ladder::Multiple(1024));
        assert_eq!(p.plan(1).unwrap(), 1024);
        assert_eq!(p.plan(1024).unwrap(), 1024);
        assert_eq!(p.plan(1025).unwrap(), 2048);
    }

    /// A plan may only ever add frames. Emitting fewer than the payload needs
    /// would be data loss wearing a privacy costume.
    #[test]
    fn a_plan_never_drops_data_frames() {
        for ladder in [Ladder::PowerOfTwo, Ladder::Multiple(7), Ladder::None] {
            let p = Pacing::default().with_ladder(ladder);
            for real in [0u64, 1, 2, 17, 1000, 65_537] {
                assert!(
                    p.plan(real).unwrap() >= real,
                    "ladder {ladder:?} real={real}"
                );
            }
        }
    }

    /// A tiny payload must not announce that it is tiny.
    #[test]
    fn tiny_payloads_are_floored() {
        let p = Pacing::default().with_bounds(DEFAULT_MIN_FRAMES, 0);
        assert_eq!(p.plan(0).unwrap(), DEFAULT_MIN_FRAMES);
        assert_eq!(p.plan(1).unwrap(), DEFAULT_MIN_FRAMES);
        assert_eq!(p.plan(3).unwrap(), DEFAULT_MIN_FRAMES);
    }

    /// The tail must actually vary, or "randomised ramp-down" is a comment
    /// rather than a behaviour.
    #[test]
    fn the_tail_is_randomised() {
        let p = Pacing::default().with_bounds(0, 64);
        let seen: std::collections::HashSet<u64> = (0..40).map(|_| p.plan(100).unwrap()).collect();
        assert!(
            seen.len() > 1,
            "40 plans produced one identical length: the tail is not random"
        );
        assert!(seen.iter().all(|n| (128..=192).contains(n)), "got {seen:?}");
    }

    #[test]
    fn disabled_pacing_adds_nothing() {
        let p = Pacing::disabled();
        assert!(!p.is_shaped());
        assert_eq!(p.plan(37).unwrap(), 37);
        assert!(p.pacer(1024).interval.is_none());
    }

    #[test]
    fn the_frame_interval_follows_the_rate() {
        // 1 MiB frames at 4 MiB/s is one frame every 250 ms.
        let p = Pacing::default().at_rate(4 * 1024 * 1024);
        assert_eq!(
            p.pacer(1024 * 1024).interval,
            Some(Duration::from_millis(250))
        );
    }

    /// Rejection sampling must stay in range and not be stuck on one value.
    #[test]
    fn random_below_is_bounded_and_varied() {
        assert_eq!(random_below(0).unwrap(), 0);
        assert_eq!(random_below(1).unwrap(), 0);
        let seen: std::collections::HashSet<u64> =
            (0..200).map(|_| random_below(10).unwrap()).collect();
        assert!(seen.iter().all(|v| *v < 10));
        assert!(seen.len() > 5, "expected spread, got {seen:?}");
    }

    /// Falling behind must not produce a catch-up burst.
    #[tokio::test]
    async fn a_late_pacer_rebases_instead_of_bursting() {
        let mut pacer = Pacing::default().at_rate(1000).pacer(100); // 100 ms/frame
        pacer.tick().await;
        // Simulate a long stall.
        tokio::time::sleep(Duration::from_millis(350)).await;

        let start = Instant::now();
        pacer.tick().await; // due immediately, we are late
        pacer.tick().await; // must wait a full interval, not fire instantly
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(80),
            "second tick fired after {elapsed:?}; debt was repaid as a burst"
        );
    }
}
