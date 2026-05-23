use arti_client::{TorClient, TorClientConfig};
use ed25519_dalek::SigningKey;
use p2p_sync::{handshake, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;

#[tokio::main]
async fn main() {
    // Hardcoded keys for testing
    let alice_key = SigningKey::from_bytes(&[1u8; 32]);
    let bob_pub = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

    // TODO: Paste Bob's real .onion address here!
    let onion_addr = "ymrtnkalcr5m2sxflsm6ltgpi5c3hyflfu3d7wkhvmsnvwsxmf223oqd.onion";

    println!("🧅 Bootstrapping Arti Tor client (this takes ~10 seconds)...");

    // We explicitly enable .onion routing in the client configuration
    let mut config_builder = TorClientConfig::builder();
    config_builder.address_filter().allow_onion_addrs(true);
    let config = config_builder.build().unwrap();

    // Boot using our custom configuration
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();

    println!("🌐 Dialing {}...", onion_addr);
    let arti_stream = tor_client.connect((onion_addr, 80)).await.unwrap();
    let mut stream = arti_stream.compat();

    println!("🔐 Connected! Executing Noise handshake...");
    let session = handshake::execute_handshake(&mut stream, true, &alice_key, &bob_pub)
        .await
        .unwrap();

    let (control, _) = transport::start_multiplexer(stream, session.transport, true);

    println!("🚀 Opening Yamux stream and sending data...");
    let mut diff_stream = control.open_stream().await.unwrap().compat();
    diff_stream
        .write_all(b"HELLO BOB, THIS IS ALICE OVER THE LIVE INTERNET!")
        .await
        .unwrap();
    diff_stream.flush().await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = diff_stream.read(&mut buf).await.unwrap();
    println!("📩 Reply from Bob: {}", String::from_utf8_lossy(&buf[..n]));
}
