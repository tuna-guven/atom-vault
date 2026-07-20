//! L3 — vault encoding: framing, the decoy ladder, and the manifest.
//!
//! This layer contains no secrets and no I/O. It answers two questions:
//!
//! 1. *How is a byte stream framed into fixed-size blocks?* — [`plan`] and
//!    [`block_bounds`]. The last real block is zero-padded to full size, so
//!    every block that reaches L1 is byte-for-byte the same length.
//! 2. *How many blocks appear on the wire?* — [`Ladder`]. The real block count
//!    is rounded **up** a coarse quantized ladder; the difference is made up of
//!    random decoy blocks (added later, in `store`). A 5.0 GB and a 6.3 GB vault
//!    can thus present the same on-store block count.
//!
//! The [`Manifest`] is the only artifact that knows the true length and which
//! blocks are decoys. It is itself encrypted (in `store`) before it is stored.

use serde::{Deserialize, Serialize};

use crate::crypto::DEFAULT_BLOCK_SIZE;

/// Quantization ladder for the on-store block count. Choosing a coarser ladder
/// leaks less about the true size at the cost of more decoy upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ladder {
    /// Round the real block count up to the next power of two. Good default:
    /// bounded ≤2× overhead, coarse buckets.
    NextPowerOfTwo,
    /// Round up to the next positive multiple of `n` blocks.
    MultipleOf(u32),
    /// No decoy padding — exactly the real block count. For tests and
    /// explicitly-lower-risk transfers only.
    Exact,
}

impl Ladder {
    /// Total block count (real + decoy) for `real_blocks` real blocks.
    ///
    /// Invariant relied on by callers and tests: the result is always
    /// `>= real_blocks`, and lands on the ladder's quantization.
    pub fn total_blocks(self, real_blocks: usize) -> usize {
        if real_blocks == 0 {
            return 0;
        }
        match self {
            Ladder::Exact => real_blocks,
            Ladder::NextPowerOfTwo => real_blocks.next_power_of_two(),
            Ladder::MultipleOf(n) => {
                let n = (n as usize).max(1);
                real_blocks.div_ceil(n) * n
            }
        }
    }
}

/// Parameters controlling how a stream is framed and padded.
#[derive(Clone, Copy, Debug)]
pub struct EncodeParams {
    /// Plaintext size of each block. All blocks are padded to exactly this.
    pub block_size: usize,
    /// How the block *count* is quantized with decoys.
    pub ladder: Ladder,
}

impl Default for EncodeParams {
    fn default() -> Self {
        EncodeParams {
            block_size: DEFAULT_BLOCK_SIZE,
            ladder: Ladder::NextPowerOfTwo,
        }
    }
}

impl EncodeParams {
    /// Number of real (non-decoy) blocks needed to hold `stream_len` bytes.
    pub fn real_blocks(&self, stream_len: u64) -> usize {
        if stream_len == 0 {
            return 0;
        }
        (stream_len as usize).div_ceil(self.block_size)
    }
}

/// A concrete framing plan for a stream of known length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPlan {
    pub real_len: u64,
    pub block_size: usize,
    pub real_blocks: usize,
    pub total_blocks: usize,
}

impl BlockPlan {
    pub fn decoy_blocks(&self) -> usize {
        self.total_blocks - self.real_blocks
    }
}

/// Compute the framing plan for a stream of `real_len` bytes.
pub fn plan(real_len: u64, params: &EncodeParams) -> BlockPlan {
    let real_blocks = params.real_blocks(real_len);
    let total_blocks = params.ladder.total_blocks(real_blocks);
    BlockPlan {
        real_len,
        block_size: params.block_size,
        real_blocks,
        total_blocks,
    }
}

/// The byte range `[start, end)` of real block `index` within the stream, and
/// how many of those bytes are real (the remainder up to `block_size` is
/// zero-padding). `end` is clamped to `real_len`.
pub fn block_bounds(plan: &BlockPlan, index: usize) -> (u64, u64) {
    let start = (index as u64) * (plan.block_size as u64);
    let end = (start + plan.block_size as u64).min(plan.real_len);
    (start, end)
}

/// One block's location and keying material as recorded in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRef {
    /// Opaque store object ID this block lives under.
    pub object_id: [u8; 32],
    /// AEAD nonce for this block (unused/random for decoys).
    pub nonce: [u8; 24],
    /// `Some(i)` for real block `i` (drives its HKDF key). `None` for a decoy.
    pub index: Option<u32>,
}

impl BlockRef {
    pub fn is_decoy(&self) -> bool {
        self.index.is_none()
    }
}

/// Current manifest format version.
pub const MANIFEST_VERSION: u16 = 1;

/// The encrypted-at-rest description of a transfer. Serialized, then sealed
/// under the manifest key before it is stored. The only thing that knows the
/// true length and the decoy set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u16,
    pub block_size: u32,
    /// True plaintext length of the source stream.
    pub real_len: u64,
    /// All blocks (real + decoy), in the order they were shuffled into. Order
    /// carries no information: object IDs are random and real blocks carry an
    /// explicit `index`, so recipients reassemble by `index`, not by position.
    pub blocks: Vec<BlockRef>,
}

impl Manifest {
    /// Real block refs, sorted by their stream index — reassembly order.
    pub fn real_blocks_ordered(&self) -> Vec<&BlockRef> {
        let mut reals: Vec<&BlockRef> = self.blocks.iter().filter(|b| !b.is_decoy()).collect();
        reals.sort_by_key(|b| b.index.unwrap());
        reals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_is_monotone_and_covering() {
        // total >= real, always, for every ladder.
        for real in 0..=5000usize {
            for ladder in [
                Ladder::Exact,
                Ladder::NextPowerOfTwo,
                Ladder::MultipleOf(1024),
                Ladder::MultipleOf(1),
            ] {
                let total = ladder.total_blocks(real);
                assert!(total >= real, "{ladder:?}: {total} < {real}");
                if real == 0 {
                    assert_eq!(total, 0);
                }
            }
        }
    }

    #[test]
    fn next_power_of_two_lands_on_ladder() {
        for real in 1..=5000usize {
            let total = Ladder::NextPowerOfTwo.total_blocks(real);
            assert!(total.is_power_of_two(), "{total} not a power of two");
            assert!(total < real * 2 + 1);
        }
        // Spec example: a 5.0 GB (5120 × 1 MiB) and a 6.3 GB (6451) vault both
        // land on 8192 blocks — indistinguishable by count.
        assert_eq!(Ladder::NextPowerOfTwo.total_blocks(5120), 8192);
        assert_eq!(Ladder::NextPowerOfTwo.total_blocks(6451), 8192);
    }

    #[test]
    fn multiple_of_lands_on_ladder() {
        for real in 1..=5000usize {
            let total = Ladder::MultipleOf(1024).total_blocks(real);
            assert_eq!(total % 1024, 0);
            assert!(total >= real);
        }
    }

    #[test]
    fn plan_covers_exact_and_partial_last_block() {
        let params = EncodeParams {
            block_size: 100,
            ladder: Ladder::Exact,
        };
        // Exactly 2 blocks.
        let p = plan(200, &params);
        assert_eq!(p.real_blocks, 2);
        assert_eq!(block_bounds(&p, 1), (100, 200));
        // Partial last block.
        let p = plan(250, &params);
        assert_eq!(p.real_blocks, 3);
        assert_eq!(block_bounds(&p, 2), (200, 250)); // 50 real bytes, 50 pad
        // Empty stream.
        let p = plan(0, &params);
        assert_eq!(p.real_blocks, 0);
        assert_eq!(p.total_blocks, 0);
    }
}
