use snow::TransportState;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::compat::TokioAsyncReadCompatExt;
use yamux::{Config, Connection, Mode, Stream};

#[derive(Clone)]
pub struct Control {
    sender: mpsc::Sender<oneshot::Sender<Result<Stream, yamux::ConnectionError>>>,
}

impl Control {
    pub async fn open_stream(&self) -> Result<Stream, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(tx).await.map_err(|_| {
            Box::<dyn std::error::Error + Send + Sync>::from("Control channel closed")
        })?;
        let stream = rx.await.map_err(|_| {
            Box::<dyn std::error::Error + Send + Sync>::from("Oneshot channel closed")
        })??;
        Ok(stream)
    }
}

pub fn start_multiplexer<S>(
    stream: S,
    transport: TransportState,
    is_initiator: bool,
) -> (Control, mpsc::Receiver<Stream>)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (yamux_io, router_io) = tokio::io::duplex(1024 * 1024);
    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(stream);
    let (mut router_rx, mut router_tx) = tokio::io::split(router_io);

    let transport_arc = Arc::new(Mutex::new(transport));
    let transport_inbound = transport_arc.clone();

    tokio::spawn(async move {
        let mut plain_buf = vec![0u8; 65000];
        let mut cipher_buf = vec![0u8; 65535];
        loop {
            let n = match router_rx.read(&mut plain_buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };

            let mut ts = transport_arc.lock().await;
            let cipher_len = match ts.write_message(&plain_buf[..n], &mut cipher_buf) {
                Ok(len) => len,
                Err(_) => break,
            };
            drop(ts);

            if tcp_tx.write_u16(cipher_len as u16).await.is_err() {
                break;
            }
            if tcp_tx.write_all(&cipher_buf[..cipher_len]).await.is_err() {
                break;
            }
            if tcp_tx.flush().await.is_err() {
                break;
            }
        }
    });

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

    let config = Config::default();

    let mode = if is_initiator {
        Mode::Client
    } else {
        Mode::Server
    };
    let mut connection = Connection::new(yamux_io.compat(), config, mode);

    let (control_tx, mut control_rx) = mpsc::channel(32);
    let (inbound_tx, inbound_rx) = mpsc::channel(32);

    tokio::spawn(async move {
        let mut pending_opens: VecDeque<oneshot::Sender<Result<Stream, yamux::ConnectionError>>> =
            VecDeque::new();

        // THE FIX: Pure, blocking poll_fn.
        // Wakers are perfectly preserved and Yamux will pull data instantly.
        poll_fn(|cx| {
            while let Poll::Ready(Some(reply_tx)) = control_rx.poll_recv(cx) {
                pending_opens.push_back(reply_tx);
            }

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
                    Poll::Pending => break,
                }
            }

            loop {
                match connection.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        let _ = inbound_tx.try_send(stream);
                    }
                    Poll::Ready(Some(Err(_))) => return Poll::Ready(()),
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }

            Poll::Pending
        })
        .await;

        println!("🛑 [Yamux] Multiplexer daemon shutdown cleanly.");
    });

    (Control { sender: control_tx }, inbound_rx)
}
