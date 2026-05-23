use ed25519_dalek::SigningKey;
use p2p_sync::{handshake, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::compat::FuturesAsyncReadCompatExt;

#[tokio::main]
async fn main() {
    // Hardcoded keys for testing
    let bob_key = SigningKey::from_bytes(&[2u8; 32]);
    let alice_pub = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

    // Bind to local port 8080. The Tor daemon will forward traffic here.
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("🛡️ Bob's vault is listening on 127.0.0.1:8080...");

    let (mut socket, _) = listener.accept().await.unwrap();
    println!("🔗 Connection received! Executing Noise handshake...");

    let session = handshake::execute_handshake(&mut socket, false, &bob_key, &alice_pub)
        .await
        .expect("Handshake failed");

    let (_control, mut inbound_rx) = transport::start_multiplexer(socket, session.transport, false);
    
    // Wait for Alice to open a multiplexed stream
    let mut sync_stream = inbound_rx.recv().await.unwrap().compat();
    
    let mut buf = vec![0u8; 1024];
    let n = sync_stream.read(&mut buf).await.unwrap();
    println!("📩 Received: {}", String::from_utf8_lossy(&buf[..n]));
    
    sync_stream.write_all(b"LOUD AND CLEAR FROM BOB").await.unwrap();
    sync_stream.flush().await.unwrap();
    println!("✅ Reply sent. Test complete.");
}