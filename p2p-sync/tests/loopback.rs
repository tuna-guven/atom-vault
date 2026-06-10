// tests/loopback.rs
use ed25519_dalek::SigningKey;
use p2p_sync::{handshake, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
// Bring in the Tokio <-> Futures bridge trait
use tokio_util::compat::FuturesAsyncReadCompatExt;

#[tokio::test]
async fn test_encrypted_multiplexer_loopback() {
    let alice_key = SigningKey::from_bytes(&[1u8; 32]);
    let bob_key = SigningKey::from_bytes(&[2u8; 32]);

    let alice_pub = alice_key.verifying_key();
    let bob_pub = bob_key.verifying_key();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // =========================================================================
    // BOB'S VAULT (The Responder / Listener)
    // =========================================================================
    let bob_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        let session = handshake::execute_handshake(&mut socket, false, &bob_key, &alice_pub)
            .await
            .expect("Bob handshake failed");

        let (_control, mut inbound_rx) =
            transport::start_multiplexer(socket, session.transport, false);

        // Append .compat() to convert the Futures stream into a Tokio stream!
        let mut sync_stream = inbound_rx
            .recv()
            .await
            .expect("Bob didn't get a stream")
            .compat();

        let mut buf = vec![0u8; 1024];
        let n = sync_stream.read(&mut buf).await.unwrap();
        let message = String::from_utf8_lossy(&buf[..n]);

        assert_eq!(message, "HELLO FROM ALICE'S VAULT!");

        sync_stream.write_all(b"BLOCKS RECEIVED").await.unwrap();
        sync_stream.flush().await.unwrap();
    });

    // =========================================================================
    // ALICE'S VAULT (The Initiator / Dialer)
    // =========================================================================
    let alice_task = tokio::spawn(async move {
        let mut socket = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        let session = handshake::execute_handshake(&mut socket, true, &alice_key, &bob_pub)
            .await
            .expect("Alice handshake failed");

        let (control, _inbound_rx) = transport::start_multiplexer(socket, session.transport, true);

        // Append .compat() here as well!
        let mut diff_stream = control
            .open_stream()
            .await
            .expect("Alice stream open failed")
            .compat();

        diff_stream
            .write_all(b"HELLO FROM ALICE'S VAULT!")
            .await
            .unwrap();
        diff_stream.flush().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = diff_stream.read(&mut buf).await.unwrap();
        let message = String::from_utf8_lossy(&buf[..n]);

        assert_eq!(message, "BLOCKS RECEIVED");
    });

    let (bob_result, alice_result) = tokio::join!(bob_task, alice_task);
    bob_result.unwrap();
    alice_result.unwrap();
}
