use crate::transport::Control;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::Stream;
use zeroize::Zeroizing;

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
    pub last_modified_unix: u64, // Vector clock for conflict resolution
    pub chunks: Vec<ChunkEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VaultMetadata {
    pub file_table: Vec<FileIndex>,
    pub cdc_salt: [u8; 32],
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
    pub local_metadata: Arc<RwLock<VaultMetadata>>,
    pub vault_path: PathBuf,
    pub write_lock: Arc<Mutex<()>>, // Crucial: Prevents concurrent downloads from corrupting SSD file appends
}

impl SyncManager {
    pub fn new(
        control: Control,
        mut inbound_rx: mpsc::Receiver<Stream>,
        local_metadata: VaultMetadata,
        vault_path: PathBuf,
    ) -> Self {
        let local_metadata = Arc::new(RwLock::new(local_metadata));
        let write_lock = Arc::new(Mutex::new(()));

        let control_clone = control.clone();
        let meta_clone = local_metadata.clone();
        let path_clone = vault_path.clone();
        let lock_clone = write_lock.clone();

        tokio::spawn(async move {
            println!("🎧 [Listener] Background daemon active. Waiting for incoming streams...");

            while let Some(stream) = inbound_rx.recv().await {
                println!("🔌 [Listener] New inbound Yamux stream received from multiplexer!");
                let mut tokio_stream = stream.compat();
                let meta = meta_clone.clone();
                let ctrl = control_clone.clone();
                let path = path_clone.clone();
                let w_lock = lock_clone.clone();

                tokio::spawn(async move {
                    if let Ok(msg) = Self::recv_msg(&mut tokio_stream).await {
                        match msg {
                            SyncMessage::MetadataExchange(remote_meta) => {
                                println!(
                                    "🔄 [Listener] Remote metadata received! Sending local reply..."
                                );

                                let meta_guard = meta.read().await;
                                let reply = SyncMessage::MetadataExchange((*meta_guard).clone());
                                let _ = Self::send_msg(&mut tokio_stream, &reply).await;

                                let mut missing_chunks_info = Vec::new();
                                for remote_file in &remote_meta.file_table {
                                    let local_file_opt = meta_guard
                                        .file_table
                                        .iter()
                                        .find(|f| f.vfs_name == remote_file.vfs_name);

                                    let is_newer = local_file_opt.map_or(true, |f| {
                                        remote_file.last_modified_unix > f.last_modified_unix
                                    });

                                    if is_newer {
                                        for remote_chunk in &remote_file.chunks {
                                            let chunk_exists = local_file_opt.map_or(false, |f| {
                                                f.chunks
                                                    .iter()
                                                    .any(|c| c.nonce == remote_chunk.nonce)
                                            });
                                            if !chunk_exists {
                                                missing_chunks_info.push((
                                                    remote_chunk.nonce,
                                                    remote_file.vfs_name.clone(),
                                                    remote_file.last_modified_unix,
                                                ));
                                            }
                                        }
                                    }
                                }
                                drop(meta_guard); // Free lock early so UI can keep using vault

                                if !missing_chunks_info.is_empty() {
                                    println!(
                                        "📦 [Listener] Identified {} missing chunks. Requesting...",
                                        missing_chunks_info.len()
                                    );
                                    let semaphore = Arc::new(Semaphore::new(50));

                                    for (nonce, vfs_name, last_mod) in missing_chunks_info {
                                        let c = ctrl.clone();
                                        let permit =
                                            semaphore.clone().acquire_owned().await.unwrap();
                                        let p = path.clone();
                                        let l = w_lock.clone();
                                        let m = meta.clone();

                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            if let Ok(s) = c.open_stream().await {
                                                let mut chunk_stream = s.compat();
                                                let _ = Self::send_msg(
                                                    &mut chunk_stream,
                                                    &SyncMessage::ChunkRequest { nonce },
                                                )
                                                .await;

                                                if let Ok(Ok(SyncMessage::ChunkTransfer {
                                                    ciphertext,
                                                    ..
                                                })) = tokio::time::timeout(
                                                    std::time::Duration::from_secs(60),
                                                    Self::recv_msg(&mut chunk_stream),
                                                )
                                                .await
                                                {
                                                    println!(
                                                        "📥 [Listener] Received chunk ({} bytes). Writing to disk...",
                                                        ciphertext.len()
                                                    );

                                                    // DISK I/O: Append securely to EOF
                                                    let _guard = l.lock().await;
                                                    if let Ok(mut file) = OpenOptions::new()
                                                        .write(true)
                                                        .append(true)
                                                        .create(true)
                                                        .open(&p)
                                                        .await
                                                    {
                                                        if let Ok(offset) = file
                                                            .seek(std::io::SeekFrom::End(0))
                                                            .await
                                                        {
                                                            if file
                                                                .write_all(&ciphertext)
                                                                .await
                                                                .is_ok()
                                                                && file.sync_all().await.is_ok()
                                                            {
                                                                // Update RAM Metadata
                                                                let mut mg = m.write().await;
                                                                if let Some(f) =
                                                                    mg.file_table.iter_mut().find(
                                                                        |f| f.vfs_name == vfs_name,
                                                                    )
                                                                {
                                                                    f.last_modified_unix = last_mod;
                                                                    f.chunks.push(ChunkEntry {
                                                                        cipher_len: ciphertext
                                                                            .len(),
                                                                        offset,
                                                                        nonce,
                                                                    });
                                                                } else {
                                                                    mg.file_table.push(FileIndex {
                                                                        vfs_name: vfs_name.clone(),
                                                                        last_modified_unix:
                                                                            last_mod,
                                                                        chunks: vec![ChunkEntry {
                                                                            cipher_len: ciphertext
                                                                                .len(),
                                                                            offset,
                                                                            nonce,
                                                                        }],
                                                                    });
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
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
                                // DISK I/O: Find chunk offset in metadata and stream directly from SSD
                                println!(
                                    "📦 [Listener] Remote requested chunk. Reading from disk..."
                                );
                                let meta_guard = meta.read().await;
                                let mut chunk_info = None;
                                for f in &meta_guard.file_table {
                                    for c in &f.chunks {
                                        if c.nonce == nonce {
                                            chunk_info = Some((c.offset, c.cipher_len));
                                            break;
                                        }
                                    }
                                    if chunk_info.is_some() {
                                        break;
                                    }
                                }
                                drop(meta_guard);

                                if let Some((offset, cipher_len)) = chunk_info {
                                    if let Ok(mut file) = File::open(&path).await {
                                        if file.seek(std::io::SeekFrom::Start(offset)).await.is_ok()
                                        {
                                            let mut buffer = vec![0u8; cipher_len];
                                            if file.read_exact(&mut buffer).await.is_ok() {
                                                let reply = SyncMessage::ChunkTransfer {
                                                    nonce,
                                                    ciphertext: buffer,
                                                };
                                                let _ =
                                                    Self::send_msg(&mut tokio_stream, &reply).await;
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
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
            vault_path,
            write_lock,
        }
    }

    pub async fn send_msg<S: AsyncWriteExt + Unpin>(
        stream: &mut S,
        msg: &SyncMessage,
    ) -> SyncResult<()> {
        let bytes = Zeroizing::new(
            bincode::serialize(msg)
                .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?,
        );
        let len = bytes.len() as u32;

        let mut payload = Zeroizing::new(Vec::with_capacity(4 + bytes.len()));
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(&bytes);

        stream.write_all(&*payload).await?;
        stream.flush().await?;

        Ok(())
    }

    pub async fn recv_msg<S: AsyncReadExt + Unpin>(stream: &mut S) -> SyncResult<SyncMessage> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;

        const MAX_PAYLOAD_SIZE: usize = 64 * 1024 * 1024;
        if len > MAX_PAYLOAD_SIZE {
            return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "Payload exceeds safe memory limits: {} bytes",
                len
            )));
        }

        let mut data_buf = Zeroizing::new(vec![0u8; len]);
        stream.read_exact(&mut *data_buf).await?;

        let msg = bincode::deserialize(&data_buf)
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
        Ok(msg)
    }

    pub async fn synchronize(&self) -> SyncResult<()> {
        println!("🔄 [Dialer] Initiating metadata exchange...");
        let control = self.control.clone();

        println!("⏳ [Dialer] Requesting new Yamux stream allocation...");
        let mut meta_stream = control.open_stream().await?.compat();

        println!("⏳ [Dialer] Sending local metadata payload...");
        let meta_guard = self.local_metadata.read().await;
        Self::send_msg(
            &mut meta_stream,
            &SyncMessage::MetadataExchange((*meta_guard).clone()),
        )
        .await?;
        drop(meta_guard);

        println!("✅ [Dialer] Local metadata sent! Awaiting Bob's reply (60s Tor wait limit)...");

        if let Ok(Ok(SyncMessage::MetadataExchange(remote_meta))) = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            Self::recv_msg(&mut meta_stream),
        )
        .await
        {
            println!("✅ [Dialer] Remote metadata reply received and decoded!");

            let mut missing_chunks_info = Vec::new();
            let meta_guard = self.local_metadata.read().await;

            for remote_file in &remote_meta.file_table {
                let local_file_opt = meta_guard
                    .file_table
                    .iter()
                    .find(|f| f.vfs_name == remote_file.vfs_name);

                let is_newer = local_file_opt.map_or(true, |f| {
                    remote_file.last_modified_unix > f.last_modified_unix
                });

                if is_newer {
                    for remote_chunk in &remote_file.chunks {
                        let chunk_exists = local_file_opt.map_or(false, |f| {
                            f.chunks.iter().any(|c| c.nonce == remote_chunk.nonce)
                        });
                        if !chunk_exists {
                            missing_chunks_info.push((
                                remote_chunk.nonce,
                                remote_file.vfs_name.clone(),
                                remote_file.last_modified_unix,
                            ));
                        }
                    }
                }
            }
            drop(meta_guard);

            if missing_chunks_info.is_empty() {
                println!("🚀 [Dialer] Vaults are fully synchronized.");
                return Ok(());
            }

            println!(
                "📦 [Dialer] Identified {} missing chunks. Requesting concurrently...",
                missing_chunks_info.len()
            );

            let mut handles = Vec::new();
            let semaphore = Arc::new(Semaphore::new(50));

            for (nonce, vfs_name, last_mod) in missing_chunks_info {
                let control = self.control.clone();
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let p = self.vault_path.clone();
                let l = self.write_lock.clone();
                let m = self.local_metadata.clone();

                let handle = tokio::spawn(async move {
                    let _permit = permit;

                    if let Ok(stream) = control.open_stream().await {
                        let mut chunk_stream = stream.compat();
                        let _ =
                            Self::send_msg(&mut chunk_stream, &SyncMessage::ChunkRequest { nonce })
                                .await;

                        if let Ok(Ok(SyncMessage::ChunkTransfer {
                            ciphertext,
                            nonce: returned_nonce,
                        })) = tokio::time::timeout(
                            std::time::Duration::from_secs(60),
                            Self::recv_msg(&mut chunk_stream),
                        )
                        .await
                        {
                            assert_eq!(nonce, returned_nonce);
                            println!(
                                "📥 [Dialer] Received and validated chunk ({} bytes). Writing to disk...",
                                ciphertext.len()
                            );

                            // DISK I/O: Append securely to EOF
                            let _guard = l.lock().await;
                            if let Ok(mut file) = OpenOptions::new()
                                .write(true)
                                .append(true)
                                .create(true)
                                .open(&p)
                                .await
                            {
                                if let Ok(offset) = file.seek(std::io::SeekFrom::End(0)).await {
                                    if file.write_all(&ciphertext).await.is_ok()
                                        && file.sync_all().await.is_ok()
                                    {
                                        // Update RAM Metadata
                                        let mut mg = m.write().await;
                                        if let Some(f) = mg
                                            .file_table
                                            .iter_mut()
                                            .find(|f| f.vfs_name == vfs_name)
                                        {
                                            f.last_modified_unix = last_mod;
                                            f.chunks.push(ChunkEntry {
                                                cipher_len: ciphertext.len(),
                                                offset,
                                                nonce,
                                            });
                                        } else {
                                            mg.file_table.push(FileIndex {
                                                vfs_name: vfs_name.clone(),
                                                last_modified_unix: last_mod,
                                                chunks: vec![ChunkEntry {
                                                    cipher_len: ciphertext.len(),
                                                    offset,
                                                    nonce,
                                                }],
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.await;
            }

            println!("🎉 [Dialer] Synchronization complete!");
        }

        Ok(())
    }
}
