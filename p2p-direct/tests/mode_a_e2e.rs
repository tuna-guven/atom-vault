//! End-to-end Mode A: encode → encrypt → PUT → (SPAKE2 cap delivery) → GET →
//! decrypt → decode, all through an in-memory blind store.

use std::io::Cursor;

use p2p_direct::encode::{EncodeParams, Ladder};
use p2p_direct::store::{download, upload, BlindStore, InMemoryStore};
use p2p_direct::{pake, RootKey};

/// Small block size so tests exercise many blocks + decoys cheaply.
fn params() -> EncodeParams {
    EncodeParams {
        block_size: 256,
        ladder: Ladder::NextPowerOfTwo,
    }
}

async fn roundtrip(payload: &[u8]) {
    let store = InMemoryStore::new();
    let root = RootKey::generate();
    let p = params();

    // Sender: upload.
    let mut reader = Cursor::new(payload.to_vec());
    let cap = upload(&mut reader, &p, &root, &store).await.unwrap();

    // On-store block count must land on the ladder (decoys included), and the
    // store must hold the manifest object too.
    let real_blocks = p.real_blocks(payload.len() as u64);
    let total_blocks = p.ladder.total_blocks(real_blocks);
    assert_eq!(
        store.len(),
        total_blocks + 1,
        "store should hold {total_blocks} blocks + 1 manifest"
    );

    // Recipient: download.
    let mut out = Vec::new();
    download(&cap, &store, &mut out).await.unwrap();
    assert_eq!(out, payload, "payload must round-trip losslessly");
}

#[tokio::test]
async fn roundtrip_various_sizes() {
    // Empty, sub-block, exact multiple, partial last block, many blocks.
    for len in [0usize, 1, 255, 256, 257, 512, 1000, 4096, 5000] {
        let payload: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        roundtrip(&payload).await;
    }
}

#[tokio::test]
async fn cap_delivered_over_pake_then_download() {
    let store = InMemoryStore::new();
    let root = RootKey::generate();
    let p = params();
    let payload: Vec<u8> = (0..3000u32).map(|i| (i ^ 0xa5) as u8).collect();

    let mut reader = Cursor::new(payload.clone());
    let cap = upload(&mut reader, &p, &root, &store).await.unwrap();
    let commitment = cap.commitment();

    // --- L4: deliver the cap via SPAKE2 over the short secret. ---
    let secret = b"seven-word diceware phrase goes here";
    let (s_state, s_msg) = pake::start(secret);
    let (r_state, r_msg) = pake::start(secret);
    let s_key = s_state.finish(&r_msg).unwrap();
    let r_key = r_state.finish(&s_msg).unwrap();

    let sealed = pake::seal_cap(&s_key, &cap).unwrap();
    let received_cap = pake::open_cap(&r_key, &sealed).unwrap();

    // Recipient binds the received cap to the out-of-band commitment.
    assert_eq!(received_cap.commitment(), commitment, "commitment must bind");

    let mut out = Vec::new();
    download(&received_cap, &store, &mut out).await.unwrap();
    assert_eq!(out, payload);
}

#[tokio::test]
async fn wrong_root_cannot_decrypt() {
    let store = InMemoryStore::new();
    let root = RootKey::generate();
    let p = params();
    let payload = vec![0x42u8; 900];

    let mut reader = Cursor::new(payload);
    let cap = upload(&mut reader, &p, &root, &store).await.unwrap();

    // A cap with the correct manifest_id but a wrong root must fail to open the
    // manifest (its key is derived from the root).
    let forged = p2p_direct::ReadCap {
        root_key: RootKey::from_bytes([0u8; 32]),
        manifest_id: cap.manifest_id,
    };
    let mut out = Vec::new();
    assert!(download(&forged, &store, &mut out).await.is_err());
}

#[tokio::test]
async fn decoys_are_indistinguishable_length() {
    // Every stored block object must be the same length, real or decoy, so the
    // store cannot fingerprint by size.
    let store = InMemoryStore::new();
    let root = RootKey::generate();
    let p = params();
    let payload = vec![7u8; 300]; // 2 real blocks, padded up to 4 with decoys.

    let mut reader = Cursor::new(payload);
    let cap = upload(&mut reader, &p, &root, &store).await.unwrap();

    let expected_ct_len = p.block_size + 16; // block plaintext + AEAD tag
    let manifest_obj_len = store.get(&cap.manifest_id).await.unwrap().len();

    // Every stored object except the manifest is a block of exactly one length.
    let block_lengths: Vec<usize> = store
        .object_lengths()
        .into_iter()
        .filter(|&l| l != manifest_obj_len)
        .collect();
    assert!(!block_lengths.is_empty());
    assert!(
        block_lengths.iter().all(|&l| l == expected_ct_len),
        "all block objects (real + decoy) must share one length"
    );
}
