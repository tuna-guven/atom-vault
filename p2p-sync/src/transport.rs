use snow::TransportState;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::compat::TokioAsyncReadCompatExt;
use yamux::{Config, Connection, Mode, Stream};

/// A custom control handle replacing the deleted `yamux::Control`.
/// This allows us to safely open new Yamux streams concurrently from anywhere.
#[derive(Clone)]
pub struct Control {
    sender: mpsc::Sender<oneshot::Sender<Result<Stream, yamux::ConnectionError>>>,
}

impl Control {
    /// Opens a new multiplexed sub-stream over the encrypted connection.
    pub async fn open_stream(&self) -> Result<Stream, Box<dyn std::error::Error>> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(tx).await?;
        let stream = rx.await??;
        Ok(stream)
    }
}

/// Takes a raw connected stream and the Noise transport state,
/// and returns our custom Yamux controller.
pub fn start_multiplexer<S>(
    stream: S,
    transport: TransportState,
    is_initiator: bool,
) -> (Control, mpsc::Receiver<Stream>)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    // 1. Create the in-memory bridge (1MB buffer)
    let (yamux_io, router_io) = tokio::io::duplex(1024 * 1024);
    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(stream);
    let (mut router_rx, mut router_tx) = tokio::io::split(router_io);

    let transport_arc = Arc::new(Mutex::new(transport));
    let transport_inbound = transport_arc.clone();

    // =========================================================================
    // BACKGROUND TASK 1: OUTBOUND PUMP (Yamux -> Tor Network)
    // =========================================================================
    tokio::spawn(async move {
        let mut plain_buf = vec![0u8; 65535];
        let mut cipher_buf = vec![0u8; 65535];

        loop {
            let n = match router_rx.read(&mut plain_buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };

            let mut ts = transport_arc.lock().await;
            let cipher_len = ts.write_message(&plain_buf[..n], &mut cipher_buf).unwrap();
            drop(ts);

            if tcp_tx.write_u16(cipher_len as u16).await.is_err() {
                break;
            }
            if tcp_tx.write_all(&cipher_buf[..cipher_len]).await.is_err() {
                break;
            }
        }
    });

    // =========================================================================
    // BACKGROUND TASK 2: INBOUND PUMP (Tor Network -> Yamux)
    // =========================================================================
    tokio::spawn(async move {
        let mut cipher_buf = vec![0u8; 65535];
        let mut plain_buf = vec![0u8; 65535];

        loop {
            let cipher_len = match tcp_rx.read_u16().await {
                Ok(len) => len as usize,
                Err(_) => break,
            };

            if tcp_rx
                .read_exact(&mut cipher_buf[..cipher_len])
                .await
                .is_err()
            {
                break;
            }

            let mut ts = transport_inbound.lock().await;
            let plain_len = match ts.read_message(&cipher_buf[..cipher_len], &mut plain_buf) {
                Ok(len) => len,
                Err(_) => break,
            };
            drop(ts);

            if router_tx.write_all(&plain_buf[..plain_len]).await.is_err() {
                break;
            }
        }
    });

    // =========================================================================
    // PHASE 3: CONFIGURE YAMUX & SPAWN THE STATE MACHINE
    // =========================================================================
    let config = Config::default();

    let mode = if is_initiator {
        Mode::Client
    } else {
        Mode::Server
    };
    let mut connection = Connection::new(yamux_io.compat(), config, mode);

    // Channel for our custom Control handle to send requests into the state machine
    let (control_tx, mut control_rx) = mpsc::channel(32);
    let (inbound_tx, inbound_rx) = mpsc::channel(32);

    tokio::spawn(async move {
        let mut pending_opens: VecDeque<oneshot::Sender<Result<Stream, yamux::ConnectionError>>> =
            VecDeque::new();

        // poll_fn lets us write a custom Future that simultaneously polls channels and the network
        poll_fn(move |cx| {
            // 1. Ingest new stream requests from our Control handle
            while let Poll::Ready(Some(reply_tx)) = control_rx.poll_recv(cx) {
                pending_opens.push_back(reply_tx);
            }

            // 2. Attempt to open requested outbound streams
            while !pending_opens.is_empty() {
                match connection.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        let reply_tx = pending_opens.pop_front().unwrap();
                        let _ = reply_tx.send(Ok(stream));
                    }
                    Poll::Ready(Err(e)) => {
                        let reply_tx = pending_opens.pop_front().unwrap();
                        let _ = reply_tx.send(Err(e));
                    }
                    Poll::Pending => break, // Yamux flow control is blocking new streams for now
                }
            }

            // 3. Drive the connection forward and accept inbound streams
            loop {
                match connection.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(_inbound_stream))) => {
                        // TODO for diff.rs: Pass this inbound stream to the sync manager
                        let _ = inbound_tx.try_send(_inbound_stream);
                    }
                    Poll::Ready(Some(Err(e))) => {
                        eprintln!("Yamux connection error: {:?}", e);
                        return Poll::Ready(());
                    }
                    Poll::Ready(None) => return Poll::Ready(()), // Connection closed
                    Poll::Pending => break,
                }
            }

            Poll::Pending
        })
        .await;
    });

    // Return our custom, thread-safe handle
    (Control { sender: control_tx }, inbound_rx)
}
