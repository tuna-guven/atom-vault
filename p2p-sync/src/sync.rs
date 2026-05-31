use crate::transport::Control;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::Stream;

type SyncResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ChunkEntry {
    pub cipher_len: usize,
    pub offset: u64,
    pub nonce: [u8; 24],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FileIndex {
    pub vfs_name: String,
    pub chunks: Vec<ChunkEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VaultMetadata {
    pub file_table: Vec<FileIndex>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SyncMessage {
    MetadataExchange(VaultMetadata),
    ChunkRequest {
        nonce: [u8; 24],
    },
    ChunkTransfer {
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
    },
}

#[derive(Clone)]
pub struct SyncManager {
    control: Control,
    local_metadata: Arc<VaultMetadata>,
    #[allow(dead_code)]
    local_storage: Arc<HashMap<[u8; 24], Vec<u8>>>,
}

impl SyncManager {
    pub fn new(
        control: Control,
        mut inbound_rx: mpsc::Receiver<Stream>,
        local_metadata: VaultMetadata,
        local_storage: HashMap<[u8; 24], Vec<u8>>,
    ) -> Self {
        let local_metadata = Arc::new(local_metadata);
        let local_storage = Arc::new(local_storage);
        let control_clone = control.clone();

        let meta_clone = local_metadata.clone();
        let storage_clone = local_storage.clone();

        tokio::spawn(async move {
            println!("🎧 [Listener] Background daemon active. Waiting for incoming streams...");

            while let Some(stream) = inbound_rx.recv().await {
                println!("🔌 [Listener] New inbound Yamux stream received from multiplexer!");
                let mut tokio_stream = stream.compat();
                let meta = meta_clone.clone();
                let storage = storage_clone.clone();
                let ctrl = control_clone.clone();

                tokio::spawn(async move {
                    println!("📥 [Listener] Waiting to read message on new stream...");

                    let msg_result = Self::recv_msg(&mut tokio_stream).await;

                    match msg_result {
                        Ok(msg) => {
                            println!("✅ [Listener] Message successfully decoded!");
                            match msg {
                                SyncMessage::MetadataExchange(remote_meta) => {
                                    println!(
                                        "🔄 [Listener] Remote metadata received! Sending local reply..."
                                    );
                                    let reply = SyncMessage::MetadataExchange((*meta).clone());

                                    if let Err(e) = Self::send_msg(&mut tokio_stream, &reply).await
                                    {
                                        println!(
                                            "❌ [Listener] Failed to send metadata reply: {}",
                                            e
                                        );
                                    } else {
                                        println!("✅ [Listener] Local metadata reply sent!");
                                    }

                                    let mut missing_nonces = Vec::new();
                                    for remote_file in &remote_meta.file_table {
                                        let local_file_opt = meta
                                            .file_table
                                            .iter()
                                            .find(|f| f.vfs_name == remote_file.vfs_name);
                                        for remote_chunk in &remote_file.chunks {
                                            let chunk_exists_locally =
                                                local_file_opt.map_or(false, |f| {
                                                    f.chunks
                                                        .iter()
                                                        .any(|c| c.nonce == remote_chunk.nonce)
                                                });
                                            if !chunk_exists_locally {
                                                missing_nonces.push(remote_chunk.nonce);
                                            }
                                        }
                                    }

                                    if !missing_nonces.is_empty() {
                                        println!(
                                            "📦 [Listener] Identified {} missing chunks. Requesting...",
                                            missing_nonces.len()
                                        );
                                        for nonce in missing_nonces {
                                            let c = ctrl.clone();
                                            tokio::spawn(async move {
                                                let chunk_stream = match c.open_stream().await {
                                                    Ok(s) => s,
                                                    Err(e) => {
                                                        println!(
                                                            "❌ [Listener] Failed to open sub-stream for chunk: {}",
                                                            e
                                                        );
                                                        return;
                                                    }
                                                };

                                                let mut chunk_stream = chunk_stream.compat();
                                                let _ = Self::send_msg(
                                                    &mut chunk_stream,
                                                    &SyncMessage::ChunkRequest { nonce },
                                                )
                                                .await;

                                                match Self::recv_msg(&mut chunk_stream).await {
                                                    Ok(SyncMessage::ChunkTransfer {
                                                        ciphertext,
                                                        ..
                                                    }) => {
                                                        println!(
                                                            "📥 [Listener] Received chunk ({} bytes)",
                                                            ciphertext.len()
                                                        );
                                                    }
                                                    Ok(_) => println!(
                                                        "❌ [Listener] Expected ChunkTransfer, got different message."
                                                    ),
                                                    Err(e) => println!(
                                                        "❌ [Listener] Failed to receive chunk transfer: {}",
                                                        e
                                                    ),
                                                }
                                            });
                                        }
                                    } else {
                                        println!(
                                            "🚀 [Listener] No missing chunks identified. Fully synced."
                                        );
                                    }
                                }
                                SyncMessage::ChunkRequest { nonce } => {
                                    println!(
                                        "📦 [Listener] Remote requested a chunk. Sending payload..."
                                    );
                                    if let Some(ciphertext) = storage.get(&nonce) {
                                        let reply = SyncMessage::ChunkTransfer {
                                            nonce,
                                            ciphertext: ciphertext.clone(),
                                        };
                                        if let Err(e) =
                                            Self::send_msg(&mut tokio_stream, &reply).await
                                        {
                                            println!("❌ [Listener] Failed to upload chunk: {}", e);
                                        }
                                    } else {
                                        println!(
                                            "❌ [Listener] Remote requested a chunk we don't have!"
                                        );
                                    }
                                }
                                _ => println!("⚠️ [Listener] Received unexpected message type"),
                            }
                        }
                        Err(e) => {
                            println!("❌ [Listener] Task died! Failed to receive message: {}", e);
                        }
                    }
                });
            }
            println!(
                "🛑 [Listener] CRITICAL: Multiplexer channel closed! The underlying Yamux connection crashed."
            );
        });

        Self {
            control,
            local_metadata,
            local_storage,
        }
    }

    pub async fn send_msg<S: AsyncWriteExt + Unpin>(
        stream: &mut S,
        msg: &SyncMessage,
    ) -> SyncResult<()> {
        let bytes = bincode::serialize(msg)
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
        let len = bytes.len() as u32;

        let mut payload = Vec::with_capacity(4 + bytes.len());
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(&bytes);

        stream.write_all(&payload).await?;
        stream.flush().await?;

        Ok(())
    }

    pub async fn recv_msg<S: AsyncReadExt + Unpin>(stream: &mut S) -> SyncResult<SyncMessage> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;

        let mut data_buf = vec![0u8; len];
        stream.read_exact(&mut data_buf).await?;

        let msg = bincode::deserialize(&data_buf)
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
        Ok(msg)
    }

    pub async fn synchronize(&self) -> SyncResult<()> {
        println!("🔄 [Dialer] Initiating metadata exchange...");
        let control = self.control.clone();

        println!("⏳ [Dialer] Requesting new Yamux stream allocation...");
        let mut meta_stream = match control.open_stream().await {
            Ok(s) => {
                println!("✅ [Dialer] Yamux stream successfully allocated!");
                s.compat()
            }
            Err(e) => {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "Yamux open_stream error: {}",
                    e
                )));
            }
        };

        println!("⏳ [Dialer] Sending local metadata payload...");
        Self::send_msg(
            &mut meta_stream,
            &SyncMessage::MetadataExchange((*self.local_metadata).clone()),
        )
        .await?;
        println!("✅ [Dialer] Local metadata sent! Awaiting Bob's reply (60s Tor wait limit)...");

        // The 60 second timeout accounts for Tor's multi-hop latency and circuit routing
        let remote_meta = match tokio::time::timeout(
            std::time::Duration::from_secs(60),
            Self::recv_msg(&mut meta_stream),
        )
        .await
        {
            Ok(Ok(SyncMessage::MetadataExchange(meta))) => {
                println!("✅ [Dialer] Bob's metadata reply received and decoded!");
                meta
            }
            Ok(Ok(_)) => {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "Expected MetadataExchange, got something else",
                ));
            }
            Ok(Err(e)) => {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "Failed to receive Bob's metadata: {}",
                    e
                )));
            }
            Err(_) => {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "Metadata exchange timed out after 60 seconds",
                ));
            }
        };

        println!("🔍 [Dialer] Computing missing chunks...");

        let mut missing_nonces = Vec::new();
        for remote_file in &remote_meta.file_table {
            let local_file_opt = self
                .local_metadata
                .file_table
                .iter()
                .find(|f| f.vfs_name == remote_file.vfs_name);
            for remote_chunk in &remote_file.chunks {
                let chunk_exists_locally = local_file_opt.map_or(false, |f| {
                    f.chunks.iter().any(|c| c.nonce == remote_chunk.nonce)
                });
                if !chunk_exists_locally {
                    missing_nonces.push(remote_chunk.nonce);
                }
            }
        }

        if missing_nonces.is_empty() {
            println!("🚀 [Dialer] Vaults are fully synchronized.");
            return Ok(());
        }

        println!(
            "📦 [Dialer] Identified {} missing chunks. Requesting concurrently...",
            missing_nonces.len()
        );

        let mut handles = Vec::new();
        for nonce in missing_nonces {
            let control = self.control.clone();
            let handle = tokio::spawn(async move {
                let stream = match control.open_stream().await {
                    Ok(s) => s,
                    Err(e) => {
                        println!("❌ [Dialer] Failed to open Yamux sub-stream: {}", e);
                        return;
                    }
                };

                let mut chunk_stream = stream.compat();
                let _ =
                    Self::send_msg(&mut chunk_stream, &SyncMessage::ChunkRequest { nonce }).await;

                match tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    Self::recv_msg(&mut chunk_stream),
                )
                .await
                {
                    Ok(Ok(SyncMessage::ChunkTransfer {
                        nonce: returned_nonce,
                        ciphertext,
                    })) => {
                        assert_eq!(nonce, returned_nonce);
                        println!(
                            "📥 [Dialer] Received and validated chunk ({} bytes)",
                            ciphertext.len()
                        );
                    }
                    Ok(Ok(_)) => {
                        println!("❌ [Dialer] Expected ChunkTransfer, got different message.")
                    }
                    Ok(Err(e)) => println!("❌ [Dialer] Failed to receive chunk transfer: {}", e),
                    Err(_) => println!("❌ [Dialer] TIMEOUT: Chunk stream stalled!"),
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        println!("🎉 [Dialer] Synchronization complete!");
        Ok(())
    }
}
