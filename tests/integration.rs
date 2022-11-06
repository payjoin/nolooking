#[cfg(test)]
mod integration {
    use std::env;
    use std::process::Command;
    use std::str::FromStr;
    use std::thread::sleep;
    use std::time::Duration;

    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use ln_types::P2PAddress;
    use nolooking::http;
    use nolooking::lnd::LndClient;
    use nolooking::scheduler::{ChannelBatch, ScheduledChannel, Scheduler};
    use tempfile::tempdir;
    use tonic_lnd::lnrpc::{ConnectPeerRequest, LightningAddress};

    /*
    This tests the full integration of the scheduler, http server, and lnd client.
    It starts up two local lnd nodes, and then starts up the http server.

    The `merchant` hosts the receiver. The `peer` hosts the sender.
    The `peer` serves both as the Sender and Lightning Peer for the PayJoin.
    In the wild, Sender and Lightning peer are likely separate entities.

     ┌──────────────┐                ┌─────────────────┐                  ┌──────┐
     │Lightning Peer│                │    `merchant`   │                  │Sender│
     └──────┬───────┘                └───────┬─────────┘                  └───┬──┘
            │                                │                                │
            │            BOLT 2              ├─────── Bip21 with ?pj= ───────►│
            │     Channel Establishment      │                                │
            │                                │◄────── Original PSBT ──────────┤
            │                                │                                │
            │                                │                                │
            │◄──────── open_channel ─────────┤                                │
            │                                │                                │
            ├──────── accept_channel ───────►│                                │
            │                                │             BIP 78             │
            │                                │                                │
            │◄─────── funding_created ───────┤                                │
            │                                │                                │
            ├──────── funding_signed ───────►│                                │
            │                                │                                │
            │                                │        PayJoin Proposal        │
            │                                ├──────       PSBT       ───────►│
            │                                │                                │
            │                                │                                │
            │                                │    ┌─ PayJoin + Funding ───────┤
            │                                │    │     Transaction           │
            │                                │    │                           │
           x│xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx│xxx ▼ xxxxxxxxxxxxxxxxxxxxxxxxxx│x
           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx BITCOIN NETWORK xxxxxxxxxxxxxxxxxxxxx
           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
           x│xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx│xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx│x
            │                                │                                │
            │◄────────channel_ready ─────────┤                                │
            │                                │                                │
            ├──────── channel_ready ────────►│                                │
            │                                │                                │
    */
    #[tokio::test]
    async fn test() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let localhost = vec!["localhost".to_string()];
        let cert = rcgen::generate_simple_self_signed(localhost)?;
        let ssl_dir = format!("{}/tests/compose/nginx/ssl", env!("CARGO_MANIFEST_DIR"));
        std::fs::write(format!("{}/localhost-key.pem", ssl_dir), cert.serialize_private_key_pem())
            .expect("unable to write file");
        std::fs::write(format!("{}/localhost.pem", ssl_dir), cert.serialize_pem()?)
            .expect("unable to write file");

        let compose_dir = format!("{}/tests/compose", env!("CARGO_MANIFEST_DIR"));
        let mut fixture = Fixture::new(compose_dir);
        let tmp_path = fixture.tmp_path();

        // wait for bitcoind to start and for lnd to be fully initialized with secrets

        // sanity check
        let mut timeout = 6;
        let bitcoin_rpc = loop {
            if timeout < 0 {
                panic!("can't connect to bitcoin rpc");
            }
            sleep(Duration::from_secs(1));
            if let Ok(btcrpc) = Client::new(
                "http://localhost:43782",
                Auth::UserPass("ceiwHEbqWI83".to_string(), "DwubwWsoo3".to_string()),
            ) {
                match btcrpc.get_best_block_hash() {
                    Ok(_) => break btcrpc,
                    Err(e) => log::error!("Attempting to contact btcrpc: {}", e),
                }
            }
            timeout -= 1;
        };

        // merchant lnd nolooking configuration
        let address_str = "https://localhost:53281";
        let cert_file = format!("{}/merchant-tls.cert", &tmp_path).to_string();
        let macaroon_file = format!("{}/merchant-admin.macaroon", &tmp_path).to_string();

        timeout = 6;
        let mut merchant_client = loop {
            if timeout < 0 {
                panic!("can't connect to merchant_client");
            }
            sleep(Duration::from_secs(1));

            Command::new("docker")
                .arg("cp")
                .arg("compose-merchant_lnd-1:/root/.lnd/tls.cert")
                .arg(format!("{}/merchant-tls.cert", tmp_path))
                .output()
                .expect("failed to copy tls.cert");
            log::info!("copied merchant-tls.cert");

            Command::new("docker")
                .arg("cp")
                .arg("compose-merchant_lnd-1:/data/chain/bitcoin/regtest/admin.macaroon")
                .arg(format!("{}/merchant-admin.macaroon", &tmp_path))
                .output()
                .expect("failed to copy admin.macaroon");
            log::info!("copied merchant-admin.macaroon");

            // Connecting to LND requires only address, cert file, and macaroon file
            let client = tonic_lnd::connect(address_str, &cert_file, &macaroon_file).await;

            if let Ok(mut client) = client {
                match client.lightning().get_info(tonic_lnd::lnrpc::GetInfoRequest {}).await {
                    Ok(_) => break client,
                    Err(e) => log::error!("Attempting to connect lnd: {}", e),
                }
            }
            timeout -= 1;
        };

        // conf to merchant
        let endpoint: url::Url = "https://localhost:3010".parse().expect("not a valid Url");
        log::info!("{}", &endpoint.clone().to_string());
        let conf_string = format!(
            "bind_port=3000\nendpoint=\"{}\"\nlnd_address=\"{}\"\nlnd_cert_path=\"{}\"\nlnd_macaroon_path=\"{}\"",
            &endpoint.clone().to_string(), &address_str, &cert_file, &macaroon_file
        );
        let nolooking_conf = format!("{}/nolooking.conf", &tmp_path);
        std::fs::write(&nolooking_conf, conf_string).expect("Unable to write nolooking.conf");

        Command::new("docker")
            .arg("cp")
            .arg("compose-peer_lnd-1:/root/.lnd/tls.cert")
            .arg(format!("{}/peer-tls.cert", &tmp_path))
            .output()
            .expect("failed to copy tls.cert");
        log::info!("copied peer-tls-cert");

        Command::new("docker")
            .arg("cp")
            .arg("compose-peer_lnd-1:/data/chain/bitcoin/regtest/admin.macaroon")
            .arg(format!("{}/peer-admin.macaroon", &tmp_path))
            .output()
            .expect("failed to copy admin.macaroon");
        log::info!("copied peer-admin.macaroon");

        let address_str = "https://localhost:53283";
        let cert_file = format!("{}/peer-tls.cert", &tmp_path).to_string();
        let macaroon_file = format!("{}/peer-admin.macaroon", &tmp_path).to_string();

        // Connecting to LND requires only address, cert file, and macaroon file
        let mut peer_client =
            tonic_lnd::connect(address_str, &cert_file, &macaroon_file).await.unwrap();

        let info =
            peer_client.lightning().get_info(tonic_lnd::lnrpc::GetInfoRequest {}).await.unwrap();

        let peer_id_pubkey = info.into_inner().identity_pubkey;
        log::info!("peer_id_pubkey: {:#?}", peer_id_pubkey);

        // mine on-chain funds to peer_client
        let source_address = peer_client
            .lightning()
            .new_address(tonic_lnd::lnrpc::NewAddressRequest {
                r#type: 4, //taproot
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .address;
        let source_address = bitcoin::Address::from_str(&source_address).unwrap();
        bitcoin_rpc.generate_to_address(101, &source_address).unwrap();
        std::thread::sleep(Duration::from_secs(5));
        log::info!("SLEPT");
        // connect one to the next
        let connected = merchant_client
            .lightning()
            .connect_peer(ConnectPeerRequest {
                addr: Some(LightningAddress {
                    pubkey: peer_id_pubkey.clone(),
                    host: "peer_lnd:9735".to_string(),
                }),
                perm: false,
                timeout: 6,
            })
            .await
            .expect("failed to connect peers");
        log::info!("{:?}", connected);

        let peer_address = format!("{}@{}", peer_id_pubkey, "peer_lnd:9735");
        let peer_address = peer_address.parse::<P2PAddress>().expect("invalid ln P2PAddress");

        let channel_capacity = bitcoin::Amount::from_sat(250000);

        let fee_rate = 1;
        let mut channels = Vec::with_capacity(1);
        channels.push(ScheduledChannel::new(peer_address, channel_capacity));
        let batch = ChannelBatch::new(channels, false, fee_rate);
        let scheduler = Scheduler::new(LndClient::new(merchant_client).await.unwrap(), endpoint);
        let (bip21, _, _) = scheduler.schedule_payjoin(batch).await.unwrap();
        log::info!("{}", &bip21);

        let loop_til_open_channel = tokio::spawn(async move {
            let channel_update = peer_client
                .lightning()
                .subscribe_channel_events(tonic_lnd::lnrpc::ChannelEventSubscription {});
            let mut res = channel_update.await.unwrap().into_inner();
            loop {
                if let Ok(Some(channel_event)) = res.message().await {
                    if channel_event.r#type()
                        == tonic_lnd::lnrpc::channel_event_update::UpdateType::OpenChannel
                    {
                        break;
                    }
                }
            }
        });

        let bind_addr =
            (if env::consts::OS == "macos" { [127, 0, 0, 1] } else { [172, 17, 0, 1] }, 3000)
                .into();
        let nolooking_server = http::Server::new(scheduler, bind_addr);
        let dead_end: url::Url = "https://localhost:3011".parse().unwrap();

        // Connecting to LND requires only address, cert file, and macaroon file
        let peer_client =
            tonic_lnd::connect(address_str, &cert_file, &macaroon_file).await.unwrap();
        let peer_scheduler =
            Scheduler::new(LndClient::new(peer_client).await.unwrap(), dead_end.clone());
        // trigger payjoin-client
        let payjoin_channel_open = tokio::spawn(async move {
            // if we don't wait for nolooking server to run we'll make requests to a closed port
            std::thread::sleep(Duration::from_secs(2));
            // TODO loop on ping 3000 until it the server is live
            let bip21 = bip78::Uri::from_str(&bip21).unwrap();
            peer_scheduler.send_payjoin(bip21, true).await.unwrap();

            // Confirm the newly opene transaction in new blocks
            bitcoin_rpc.generate_to_address(8, &source_address).unwrap();
        });

        tokio::select! {
            _ = payjoin_channel_open => log::info!("payjoin-client completed first"),
            _ = nolooking_server.serve() => log::info!("nolooking server stopped first. This shouldn't happen"),
            _ = tokio::time::sleep(Duration::from_secs(20)) => log::info!("payjoin timed out after 20 seconds"),
        };

        tokio::select! {
            _ = loop_til_open_channel => {
                    fixture.test_succeeded = true;
                    log::info!("Channel opened!");
                },
            _ = tokio::time::sleep(Duration::from_secs(6)) => log::info!("Channel open upate listener timed out"),
        };

        Ok(())
    }
    struct Fixture {
        compose_dir: String,
        pub tmp_dir: tempfile::TempDir,
        pub test_succeeded: bool,
    }

    impl Fixture {
        fn new(compose_dir: String) -> Self {
            log::info!("Running docker-compose from {}", compose_dir);
            Command::new("docker-compose")
                .arg("--project-directory")
                .arg(&compose_dir)
                .arg("up")
                .arg("-d")
                .output()
                .expect("failed to docker-compose ... up");

            let tmp_dir = tempdir().expect("Couldn't open tmp_dir");

            Fixture { compose_dir, tmp_dir, test_succeeded: false }
        }

        fn tmp_path(&self) -> &str { self.tmp_dir.path().to_str().expect("Invalid tmp_dir path") }
    }

    impl Drop for Fixture {
        /// This runs on panic to clean up the test
        fn drop(&mut self) {
            log::info!("\nRunning `docker-compose down -v` to clean up");
            Command::new("docker-compose")
                .arg("--project-directory")
                .arg(self.compose_dir.as_str())
                .arg("down")
                .arg("-v")
                .output()
                .expect("failed to docker-compose ... down");
            if !self.test_succeeded {
                panic!("Cleanup successful. Panicking because this test failed.");
            }
        }
    }
}
