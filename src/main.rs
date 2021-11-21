use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use bitcoin::util::address::Address;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{TxOut, Script};
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::fmt;

#[cfg(not(feature = "test_paths"))]
const STATIC_DIR: &str = "/usr/share/loptos/static";

#[cfg(feature = "test_paths")]
const STATIC_DIR: &str = "static";

#[derive(Copy, Clone, serde_derive::Deserialize)]
struct NodeId(#[serde(with = "hex::serde")][u8; 33]);

impl NodeId {
    fn to_vec(&self) -> Vec<u8> {
        Vec::from(&self.0 as &[_])
    }

    fn to_string(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::str::FromStr for NodeId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut node_pubkey = [0; 33];
        hex::decode_to_slice(s, &mut node_pubkey)?;
        Ok(NodeId(node_pubkey))
    }
}

impl std::convert::TryFrom<String> for NodeId {
    type Error = hex::FromHexError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[derive(Clone, serde_derive::Deserialize)]
struct ScheduledChannel {
    node_pubkey: NodeId,
    node_network_addr: String,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    amount: bitcoin::Amount,
}

impl ScheduledChannel {
    fn from_args(addr: &str, amount: &str) -> Self {
        let mut node_addr_parts = addr.split('@');
        let node_pubkey_str = node_addr_parts.next().expect("split returned empty iterator");
        let node_addr = node_addr_parts.next().expect("missing host:port");
        assert!(node_addr_parts.next().is_none());

        let node_pubkey = node_pubkey_str.parse().expect("invalid node pubkey");
        let amount = bitcoin::Amount::from_str_in(&amount, bitcoin::Denomination::Satoshi).expect("invalid channel amount");

        ScheduledChannel {
            node_pubkey,
            node_network_addr: node_addr.to_owned(),
            amount,
        }
    }
}

#[derive(Clone, serde_derive::Deserialize)]
struct ScheduledPayJoin {
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    wallet_amount: bitcoin::Amount,
    channels: Vec<ScheduledChannel>,
    fee_rate: u64,
}

impl ScheduledPayJoin {
    fn total_amount(&self) -> bitcoin::Amount {
        let fees = calculate_fees(self.channels.len() as u64, self.fee_rate, self.wallet_amount != bitcoin::Amount::ZERO);

        self.channels.iter().map(|channel| channel.amount).fold(bitcoin::Amount::ZERO, std::ops::Add::add) + self.wallet_amount + fees
    }

    async fn test_connections(&self, client: &mut tonic_lnd::Client) {
        for channel in &self.channels {
            ensure_connected(client, &channel.node_pubkey, &channel.node_network_addr).await;
        }
    }
}

#[derive(Clone, Default)]
struct PayJoins(Arc<Mutex<HashMap<Script, ScheduledPayJoin>>>);

impl PayJoins {
    fn insert(&self, address: &Address, payjoin: ScheduledPayJoin) -> Result<(), ()> {
        use std::collections::hash_map::Entry;

        match self.0.lock().expect("payjoins mutex poisoned").entry(address.script_pubkey()) {
            Entry::Vacant(place) => {
                place.insert(payjoin);
                Ok(())
            },
            Entry::Occupied(_) => Err(()),
        }
    }

    fn find<'a>(&self, txouts: &'a mut [TxOut]) -> Option<(&'a mut TxOut, ScheduledPayJoin)> {
        let mut payjoins = self.0.lock().expect("payjoins mutex poisoned");
        txouts
            .iter_mut()
            .find_map(|txout| payjoins.remove(&txout.script_pubkey).map(|payjoin| (txout, payjoin)))
    }
}

#[derive(Clone)]
struct Handler {
    client: tonic_lnd::Client,
    payjoins: PayJoins,
}

impl Handler {
    async fn new(mut client: tonic_lnd::Client) -> Result<Self, CheckError> {
        let version = client.get_info(tonic_lnd::rpc::GetInfoRequest {}).await?.into_inner().version;
        let mut iter = match version.find('-') {
            Some(pos) => &version[..pos],
            None => &version,
        }.split('.');
        let major = iter.next().expect("split returns non-empty iterator").parse::<u64>();
        let minor = iter.next().unwrap_or("0").parse::<u64>();
        match (major, minor) {
            (Ok(0), Ok(0..=13)) => return Err(CheckError::LNDTooOld(version)),
            (Ok(0), Ok(14..=u64::MAX)) => (),
            (Ok(1..=u64::MAX), Ok(_)) => (),
            (Err(error), _) => return  Err(CheckError::VersionNumber { version, error, }),
            (_, Err(error)) => return  Err(CheckError::VersionNumber { version, error, }),
        }
        Ok(Handler {
            client,
            payjoins: Default::default(),
        })
    }

}

#[derive(Debug)]
enum CheckError {
    RequestFailed(tonic_lnd::Error),
    VersionNumber { version: String, error: std::num::ParseIntError, },
    LNDTooOld(String),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CheckError::RequestFailed(_) => write!(f, "failed to get LND version"),
            CheckError::VersionNumber { version, error: _, } => write!(f, "Unparsable LND version '{}'", version),
            CheckError::LNDTooOld(version) => write!(f, "LND version {} is too old - it would cause GUARANTEED LOSS of sats!", version),
        }
    }
}

impl std::error::Error for CheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckError::RequestFailed(error) => Some(error),
            CheckError::VersionNumber { version: _, error, } => Some(error),
            CheckError::LNDTooOld(_) => None,
        }
    }
}

impl From<tonic_lnd::Error> for CheckError {
    fn from(value: tonic_lnd::Error) -> Self {
        CheckError::RequestFailed(value)
    }
}


async fn ensure_connected(client: &mut tonic_lnd::Client, node_pubkey: &NodeId, node_addr: &str) {
    let pubkey = node_pubkey.to_string();
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

async fn get_new_bech32_address(client: &mut tonic_lnd::Client) -> Address {
    client
        .new_address(tonic_lnd::rpc::NewAddressRequest { r#type: 0, account: String::new(), })
        .await
        .expect("failed to get chain address")
        .into_inner()
        .address
        .parse()
        .expect("lnd returned invalid address")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 || (args.len() > 5 && args.len() < 8) {
        println!("Usage: {} <bind_port> <address> <cert> <macaroon> [<fee_rate_sat_per_vb> (<dest_node_uri> <channel_amount> ...) [<wallet_amount>]]", args[0]);
        return Ok(());
    }

    let mut client = tonic_lnd::connect(args[2].clone(), &args[3], &args[4])
        .await
        .expect("failed to connect");
    let address = get_new_bech32_address(&mut client).await;

    let mut handler = Handler::new(client).await?;

    if args.len() > 5 {
        let fee_rate = args[5].parse::<u64>().expect("invalid fee rate");

        let mut pairs = args[6..].chunks_exact(2);
        let wallet_amount = pairs
            .remainder()
            .iter()
            .next()
            .map(|amount| bitcoin::Amount::from_str_in(amount, bitcoin::Denomination::Satoshi).expect("invalid wallet amount"))
            .unwrap_or(bitcoin::Amount::ZERO);
        let scheduled_channels = pairs.by_ref().map(|args| ScheduledChannel::from_args(&args[0], &args[1])).collect::<Vec<_>>();

        let scheduled_payjoin = ScheduledPayJoin {
            wallet_amount,
            channels: scheduled_channels,
            fee_rate,
        };

        scheduled_payjoin.test_connections(&mut handler.client).await;

        println!("bitcoin:{}?amount={}&pj=https://example.com/pj", address, scheduled_payjoin.total_amount().to_string_in(bitcoin::Denomination::Bitcoin));

        handler.payjoins.insert(&address, scheduled_payjoin).expect("New Handler is supposed to be empty");
    }

    let addr = ([127, 0, 0, 1], args[1].parse().expect("invalid port number")).into();

    let service = make_service_fn(move |_| {
        let handler = handler.clone();

        async move {

            Ok::<_, hyper::Error>(service_fn(move |request| handle_web_req(handler.clone(), request)))
        }
    });

    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}

async fn handle_web_req(mut handler: Handler, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    use bitcoin::consensus::{Decodable, Encodable};
    use std::path::Path;

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/pj") => {
            let index = std::fs::read(Path::new(STATIC_DIR).join("index.html")).expect("can't open index");
            Ok(Response::new(Body::from(index)))
        },

        (&Method::GET, path) if path.starts_with("/pj/static/") => {
            let directory_traversal_vulnerable_path = &path[("/pj/static/".len())..];
            let file = std::fs::read(Path::new(STATIC_DIR).join(directory_traversal_vulnerable_path)).expect("can't open static file");
            Ok(Response::new(Body::from(file)))
        },

        (&Method::POST, "/pj") => {
            dbg!(req.uri().query());

            let mut lnd = handler.client;
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
            let mut psbt = PartiallySignedTransaction::consensus_decode(&mut reader).unwrap();
            eprintln!("Received transaction: {:#?}", psbt);
            for input in &mut psbt.global.unsigned_tx.input {
                // clear signature
                input.script_sig = bitcoin::blockdata::script::Script::new();
            }
            let (our_output, scheduled_payjoin) = handler.payjoins.find(&mut psbt.global.unsigned_tx.output).expect("the transaction doesn't contain our output");
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
                    node_pubkey: channel.node_pubkey.to_vec(),
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

        (&Method::POST, "/pj/schedule") => {
            let bytes = hyper::body::to_bytes(req.into_body()).await?;
            let request = serde_json::from_slice::<ScheduledPayJoin>(&bytes).expect("invalid request");
            request.test_connections(&mut handler.client).await;
            let address = get_new_bech32_address(&mut handler.client).await;
            let total_amount = request.total_amount();
            handler.payjoins.insert(&address, request).expect("address reuse");

            let uri = format!("bitcoin:{}?amount={}&pj=https://example.com/pj", address, total_amount.to_string_in(bitcoin::Denomination::Bitcoin));
            let mut response = Response::new(Body::from(uri));
            response.headers_mut().insert(hyper::header::CONTENT_TYPE, "text/plain".parse().unwrap());
            Ok(response)
        },

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}
