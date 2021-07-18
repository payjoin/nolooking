use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use bitcoin::util::address::Address;
use bitcoin::util::psbt::PartiallySignedTransaction;
use std::convert::TryInto;

#[derive(Clone)]
struct ScheduledChannel {
    node_pubkey: [u8; 33],
    node_network_addr: String,
    amount: bitcoin::Amount,
}

impl ScheduledChannel {
    fn from_args(addr: &str, amount: &str) -> Self {
        let mut node_pubkey = [0; 33];
        let mut node_addr_parts = addr.split('@');
        let node_pubkey_str = node_addr_parts.next().expect("split returned empty iterator");
        let node_addr = node_addr_parts.next().expect("missing host:port");
        assert!(node_addr_parts.next().is_none());

        hex::decode_to_slice(node_pubkey_str, &mut node_pubkey).expect("invalid node pubkey");
        let amount = bitcoin::Amount::from_str_in(&amount, bitcoin::Denomination::Satoshi).expect("invalid channel amount");

        ScheduledChannel {
            node_pubkey,
            node_network_addr: node_addr.to_owned(),
            amount,
        }
    }
}

#[derive(Clone)]
struct ScheduledPayJoin {
    fallback_address: Address,
    wallet_amount: bitcoin::Amount,
    client: tonic_lnd::Client,
    channels: Vec<ScheduledChannel>,
    fee_rate: u64,
}

async fn ensure_connected(client: &mut tonic_lnd::Client, node_pubkey: &[u8; 33], node_addr: &str) {
    let pubkey = hex::encode(node_pubkey);
    let peer_addr = tonic_lnd::rpc::LightningAddress {
        pubkey: pubkey.clone(),
        host: node_addr.to_owned(),
    };

    let connect_req = tonic_lnd::rpc::ConnectPeerRequest {
        addr: Some(peer_addr),
        perm: true,
        timeout: 60,
    };

    client.connect_peer(connect_req).await.map(drop).unwrap_or_else(|error| {
        if !error.message().starts_with("already connected to peer") {
            panic!("failed to connect to peer {}@{}: {:?}", pubkey, node_addr, error);
        }
    });
}

fn calculate_fees(channel_count: u64, fee_rate: u64, has_additional_output: bool) -> bitcoin::Amount {
    let additional_vsize = if has_additional_output {
        channel_count * (8 + 1 + 1 + 32)
    } else {
        (channel_count - 1) * (8 + 1 + 1 + 32) + 12
    };

    bitcoin::Amount::from_sat(fee_rate * additional_vsize)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 7 {
        println!("Usage: {} <bind_port> <address> <cert> <macaroon> <fee_rate_sat_per_vb> <dest_node_uri> <channel_amount> [<dest_node_uri> <channel_amount> ...] [<wallet_amount>]", args[0]);
        return Ok(());
    }
    let mut pairs = args[6..].chunks_exact(2);
    let scheduled_channels = pairs.by_ref().map(|args| ScheduledChannel::from_args(&args[0], &args[1])).collect::<Vec<_>>();

    let mut client = tonic_lnd::connect(args[2].clone(), &args[3], &args[4])
        .await
        .expect("failed to connect");
    let address = client.new_address(tonic_lnd::rpc::NewAddressRequest { r#type: 0, account: String::new(), }).await?.into_inner().address;
    let wallet_amount = pairs
        .remainder()
        .iter()
        .next()
        .map(|amount| bitcoin::Amount::from_str_in(amount, bitcoin::Denomination::Satoshi).expect("invalid wallet amount"))
        .unwrap_or(bitcoin::Amount::ZERO);

    let fee_rate = args[5].parse::<u64>().expect("invalid fee rate");

    let fees = calculate_fees(scheduled_channels.len() as u64, fee_rate, wallet_amount != bitcoin::Amount::ZERO);

    let total_channel_amount: bitcoin::Amount = scheduled_channels.iter().map(|channel| channel.amount).fold(bitcoin::Amount::ZERO, std::ops::Add::add);

    println!("Expected fee: {} sat", fees.as_sat());
    println!("bitcoin:{}?amount={}&pj=https://example.com/pj", address, (total_channel_amount + wallet_amount + fees).to_string_in(bitcoin::Denomination::Bitcoin));

    let address = address.parse::<Address>().expect("lnd returned invalid address");

    let addr = ([127, 0, 0, 1], args[1].parse().expect("invalid port number")).into();

    for channel in &scheduled_channels {
        ensure_connected(&mut client, &channel.node_pubkey, &channel.node_network_addr).await;
    }

    let scheduled_payjoin = ScheduledPayJoin {
        fallback_address: address,
        wallet_amount,
        channels: scheduled_channels,
        client,
        fee_rate,
    };

    let service = make_service_fn(move |_| {
        let scheduled_payjoin = scheduled_payjoin.clone();

        async move {

            Ok::<_, hyper::Error>(service_fn(move |request| handle_web_req(scheduled_payjoin.clone(), request)))
        }
    });

    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}

async fn handle_web_req(scheduled_payjoin: ScheduledPayJoin, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    use bitcoin::consensus::{Decodable, Encodable};

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Ok(Response::new(Body::from(
            "Check terminal output for payjoin link and use it in one of the supported wallets",
        ))),

        (&Method::POST, "/pj") => {
            dbg!(req.uri().query());

            let mut lnd = scheduled_payjoin.client;
            let query = req
                .uri()
                .query()
                .into_iter()
                .flat_map(|query| query.split('&'))
                .map(|kv| {
                    let eq_pos = kv.find('=').unwrap();
                    (&kv[..eq_pos], &kv[(eq_pos + 1)..])
                })
                .collect::<std::collections::HashMap<_, _>>();

            if query.get("disableoutputsubstitution") == Some(&"1") {
                panic!("Output substitution must be enabled");
            }
            let base64_bytes = hyper::body::to_bytes(req.into_body()).await?;
            let bytes = base64::decode(&base64_bytes).unwrap();
            let mut reader = &*bytes;
            let our_script = scheduled_payjoin.fallback_address.script_pubkey();
            let mut psbt = PartiallySignedTransaction::consensus_decode(&mut reader).unwrap();
            eprintln!("Received transaction: {:#?}", psbt);
            for input in &mut psbt.global.unsigned_tx.input {
                // clear signature
                input.script_sig = bitcoin::blockdata::script::Script::new();
            }
            let mut our_output = psbt.global.unsigned_tx.output.iter_mut().find(|output| output.script_pubkey == our_script).expect("the transaction doesn't contain our output");
            let total_channel_amount: bitcoin::Amount = scheduled_payjoin.channels.iter().map(|channel| channel.amount).fold(bitcoin::Amount::ZERO, std::ops::Add::add);
            let fees = calculate_fees(scheduled_payjoin.channels.len() as u64, scheduled_payjoin.fee_rate, scheduled_payjoin.wallet_amount != bitcoin::Amount::ZERO);

            assert_eq!(our_output.value, (total_channel_amount + scheduled_payjoin.wallet_amount + fees).as_sat());

            let chids = (0..scheduled_payjoin.channels.len()).into_iter().map(|_| rand::random::<[u8; 32]>()).collect::<Vec<_>>();

            // no collect() because of async
            let mut txouts = Vec::with_capacity(scheduled_payjoin.channels.len());

            for (channel, chid) in scheduled_payjoin.channels.iter().zip(&chids) {
                let psbt_shim = tonic_lnd::rpc::PsbtShim {
                    pending_chan_id: Vec::from(chid as &[_]),
                    base_psbt: Vec::new(),
                    no_publish: true,
                };

                let funding_shim = tonic_lnd::rpc::funding_shim::Shim::PsbtShim(psbt_shim);
                let funding_shim = tonic_lnd::rpc::FundingShim {
                    shim: Some(funding_shim),
                };

                ensure_connected(&mut lnd, &channel.node_pubkey, &channel.node_network_addr).await;

                let open_channel = tonic_lnd::rpc::OpenChannelRequest {
                    node_pubkey: Vec::from(&channel.node_pubkey as &[_]),
                    local_funding_amount: channel.amount.as_sat().try_into().expect("amount too large"),
                    push_sat: 0,
                    private: false,
                    min_htlc_msat: 0,
                    remote_csv_delay: 0,
                    spend_unconfirmed: false,
                    close_address: String::new(),
                    funding_shim: Some(funding_shim),
                    remote_max_value_in_flight_msat: channel.amount.as_sat() * 1000,
                    remote_max_htlcs: 10,
                    max_local_csv: 288,
                    ..Default::default()
                };
                let mut update_stream = lnd.open_channel(open_channel).await.expect("Failed to call open channel").into_inner();
                while let Some(message) = update_stream.message().await.expect("failed to receive update") {
                    assert_eq!(message.pending_chan_id, chid);
                    if let Some(update) = message.update {
                        use tonic_lnd::rpc::open_status_update::Update;
                        match update {
                            Update::PsbtFund(ready) => {
                                let mut bytes = &*ready.psbt;
                                let tx = PartiallySignedTransaction::consensus_decode(&mut bytes).unwrap();
                                eprintln!("PSBT received from LND: {:#?}", tx);
                                assert_eq!(tx.global.unsigned_tx.output.len(), 1);

                                txouts.extend(tx.global.unsigned_tx.output);
                                break;
                            },
                            // panic?
                            x => panic!("Unexpected update {:?}", x),
                        }
                    }
                }
            }

            let mut txouts = txouts.into_iter();
            let channel_output = txouts.next().expect("no channels");

            if scheduled_payjoin.wallet_amount == bitcoin::Amount::ZERO {
                assert_eq!(channel_output.value, scheduled_payjoin.channels[0].amount.as_sat());
                *our_output = channel_output;
            } else {
                our_output.value = scheduled_payjoin.wallet_amount.as_sat();
                psbt.global.unsigned_tx.output.push(channel_output)
            }

            psbt.global.unsigned_tx.output.extend(txouts);
            psbt.outputs.resize_with(psbt.global.unsigned_tx.output.len(), Default::default);

            eprintln!("PSBT to be given to LND: {:#?}", psbt);
            let mut psbt_bytes = Vec::new();
            psbt.consensus_encode(&mut psbt_bytes).unwrap();

            for chid in &chids {
                let psbt_verify = tonic_lnd::rpc::FundingPsbtVerify {
                    pending_chan_id: Vec::from(chid as &[_]),
                    funded_psbt: psbt_bytes.clone(),
                    skip_finalize: true,
                };

                let transition_msg = tonic_lnd::rpc::FundingTransitionMsg {
                    trigger: Some(tonic_lnd::rpc::funding_transition_msg::Trigger::PsbtVerify(psbt_verify)),
                };

                lnd.funding_state_step(transition_msg).await.expect("failed to execute funding state step");
            }

            // Reset transaction state to be non-finalized
            psbt = PartiallySignedTransaction::from_unsigned_tx(psbt.global.unsigned_tx).expect("resetting tx failed");
            let mut psbt_bytes = Vec::new();
            eprintln!("PSBT that will be returned: {:#?}", psbt);
            psbt.consensus_encode(&mut psbt_bytes).unwrap();
            let psbt_bytes = base64::encode(psbt_bytes);

            Ok(Response::new(Body::from(psbt_bytes)))
        },

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}
