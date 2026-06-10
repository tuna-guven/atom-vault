use crate::commands::p2p_utils::{load_vault_metadata, to_p2p_meta};
use crate::crypto;
use std::fs::OpenOptions;

pub fn handle_daemon() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ Starting Embedded Atom Vault Daemon...");

    // Because your old main.rs unlocked the hardcoded vault globally, we do it locally here
    let vault_file_path = "my_data.aegis";
    let mut physical_vault = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(vault_file_path)
        .unwrap();

    let salt = [0u8; 32];
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = [42u8; 32];
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();
    let (metadata, _) = load_vault_metadata(&mut physical_vault, &unlocked_vault).unwrap();

    let mut state_dir = dirs::home_dir().expect("Could not find home directory");
    state_dir.push(".atom_vault/arti_state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let config_json = serde_json::json!({
        "storage": {
            "state_dir": state_dir.to_str().unwrap()
        }
    });

    let default_builder = arti_client::TorClientConfig::builder();
    let config_builder = serde_json::from_value(config_json).unwrap_or(default_builder);
    let config = config_builder.build().expect("Failed to build Tor config");

    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        println!("🧅 Bootstrapping embedded Arti client (this takes ~10s)...");
        let client = arti_client::TorClient::create_bootstrapped(config)
            .await
            .expect("Failed to bootstrap Tor network");

        let svc_config = tor_hsservice::config::OnionServiceConfigBuilder::default()
            .nickname("atom_vault".parse().unwrap())
            .build()
            .expect("Failed to build Hidden Service Config");

        let (svc, mut stream_requests) = client
            .launch_onion_service(svc_config)
            .expect("Failed to configure Onion Service")
            .expect("Onion service was disabled and returned None!");

        let onion_name = svc.onion_address().expect("Service should have an address");
        let pubkey_bytes = onion_name.as_ref();

        use sha3::Digest;
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey_bytes);
        hasher.update(&[0x03u8]);
        let checksum = hasher.finalize();

        let mut v3_address = Vec::with_capacity(35);
        v3_address.extend_from_slice(pubkey_bytes);
        v3_address.extend_from_slice(&checksum[0..2]);
        v3_address.push(0x03);

        let clean_onion = format!(
            "{}.onion",
            data_encoding::BASE32_NOPAD
                .encode(&v3_address)
                .to_lowercase()
        );

        let mut onion_file_path = dirs::home_dir().unwrap();
        onion_file_path.push(".atom_vault/onion.txt");
        std::fs::write(&onion_file_path, &clean_onion).expect("Failed to save identity");

        println!("\n✅ Embedded Tor Hidden Service Active!");
        println!("🔗 Share this link with friends: atom://{}\n", clean_onion);
        println!("🎧 Listening for incoming P2P connections...");

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &raw_dek);
        let mut identity_bytes = zeroize::Zeroizing::new([0u8; 32]);
        hk.expand(b"atom-p2p-identity", &mut *identity_bytes)
            .unwrap();
        let local_identity = ed25519_dalek::SigningKey::from_bytes(&*identity_bytes);

        use futures::StreamExt;

        while let Some(rend_request) = stream_requests.next().await {
            println!("🔌 Incoming Tor circuit rendezvous request!");

            match rend_request.accept().await {
                Ok(mut data_stream_requests) => {
                    if let Some(data_stream_req) = data_stream_requests.next().await {
                        match data_stream_req
                            .accept(tor_cell::relaycell::msg::Connected::new_empty())
                            .await
                        {
                            Ok(arti_stream) => {
                                println!("🔐 Executing Post-Quantum Noise Handshake...");

                                use tokio_util::compat::FuturesAsyncReadCompatExt;
                                let mut stream = arti_stream.compat();
                                let expected_friend_pubkey = local_identity.verifying_key();

                                match p2p_sync::handshake::execute_handshake(
                                    &mut stream,
                                    false,
                                    &local_identity,
                                    &expected_friend_pubkey,
                                )
                                .await
                                {
                                    Ok(session) => {
                                        println!(
                                            "🎉 Handshake successful! Spawning SyncManager..."
                                        );

                                        let physical_vault_path =
                                            std::path::PathBuf::from(&vault_file_path);
                                        let p2p_meta = to_p2p_meta(&metadata);

                                        let (control, inbound_rx) =
                                            p2p_sync::transport::start_multiplexer(
                                                stream,
                                                session.transport,
                                                false,
                                            );

                                        let _sync_manager = p2p_sync::sync::SyncManager::new(
                                            control,
                                            inbound_rx,
                                            p2p_meta,
                                            physical_vault_path,
                                        );
                                    }
                                    Err(e) => println!("❌ Handshake rejected: {}", e),
                                }
                            }
                            Err(e) => println!("⚠️ Failed to accept data stream: {}", e),
                        }
                    }
                }
                Err(e) => println!("⚠️ Failed to accept Tor circuit: {}", e),
            }
        }
    });

    Ok(())
}
