mod args;
mod lnd;
pub mod scheduler;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bip78::receiver::*;
use bitcoin::util::address::Address;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Script, TxOut};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use scheduler::ScheduledPayJoin;

use crate::args::parse_args;
use crate::lnd::*;

#[macro_use]
extern crate serde_derive;
extern crate configure_me;

configure_me::include_config!();

#[cfg(not(feature = "test_paths"))]
const STATIC_DIR: &str = "/usr/share/loin/static";

#[cfg(feature = "test_paths")]
const STATIC_DIR: &str = "static";

#[derive(Clone, Default)]
struct PayJoins(Arc<Mutex<HashMap<Script, ScheduledPayJoin>>>);

impl PayJoins {
    fn insert(&self, address: &Address, payjoin: ScheduledPayJoin) -> Result<(), ()> {
        use std::collections::hash_map::Entry;

        match self.0.lock().expect("payjoins mutex poisoned").entry(address.script_pubkey()) {
            Entry::Vacant(place) => {
                place.insert(payjoin);
                Ok(())
            }
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
    client: LndClient,
    payjoins: PayJoins,
}

impl Handler {
    async fn new(client: LndClient) -> Self { Self { client, payjoins: Default::default() } }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (config, args) =
        Config::including_optional_config_files(std::iter::empty::<&str>()).unwrap_or_exit();

    let scheduled_pj = parse_args(args).expect("failed to parse remaining arguments");

    let client =
        tonic_lnd::connect(config.lnd_address, &config.lnd_cert_path, &config.lnd_macaroon_path)
            .await
            .expect("failed to connect");

    let client = LndClient::new(client).await?;
    let mut handler = Handler::new(client).await;

    if let Some(payjoin) = scheduled_pj {
        payjoin.test_connections(&mut handler.client).await;
        let address = handler.client.get_new_bech32_address().await?;

        println!(
            "bitcoin:{}?amount={}&pj=https://example.com/pj",
            address,
            payjoin.total_amount().to_string_in(bitcoin::Denomination::Bitcoin)
        );

        handler.payjoins.insert(&address, payjoin).expect("new handler should be empty");
    }

    let addr = ([127, 0, 0, 1], config.bind_port).into();

    let service = make_service_fn(move |_| {
        let handler = handler.clone();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |request| {
                handle_web_req(handler.clone(), request)
            }))
        }
    });

    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}

pub(crate) struct Headers(hyper::HeaderMap);
impl bip78::receiver::Headers for Headers {
    fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key)?.to_str().ok() }
}

async fn handle_web_req(
    handler: Handler,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    use std::path::Path;

    use bitcoin::consensus::Encodable;

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/pj") => {
            let index =
                std::fs::read(Path::new(STATIC_DIR).join("index.html")).expect("can't open index");
            Ok(Response::new(Body::from(index)))
        }

        (&Method::GET, path) if path.starts_with("/pj/static/") => {
            let directory_traversal_vulnerable_path = &path[("/pj/static/".len())..];
            let file =
                std::fs::read(Path::new(STATIC_DIR).join(directory_traversal_vulnerable_path))
                    .expect("can't open static file");
            Ok(Response::new(Body::from(file)))
        }

        (&Method::POST, "/pj") => {
            dbg!(req.uri().query());

            let lnd = handler.client;

            let headers = Headers(req.headers().to_owned());
            let query = {
                let uri = req.uri();
                if let Some(query) = uri.query() {
                    Some(&query.to_owned());
                }
                None
            };
            let body = req.into_body();
            let bytes = hyper::body::to_bytes(body).await?;
            dbg!(&bytes); // this is correct by my accounts
            let reader = &*bytes;
            let original_request = UncheckedProposal::from_request(reader, query, headers).unwrap();
            if original_request.is_output_substitution_disabled() {
                // TODO handle error for output substitution properly, don't panic
                panic!("Output substitution must be enabled");
            }

            let proposal = original_request
                // This is interactive, NOT a Payment Processor, so we don't save original tx.
                // Humans can solve the failure case out of band by trying again.
                .assume_interactive_receive_endpoint()
                .assume_no_inputs_owned() // TODO Check
                .assume_no_mixed_input_scripts() // This check is silly and could be ignored
                .assume_no_inputs_seen_before(); // TODO

            let mut psbt = proposal.psbt().clone();
            eprintln!("Received transaction: {:#?}", psbt);
            {
                for input in &mut psbt.unsigned_tx.input {
                    // clear signature
                    input.script_sig = bitcoin::blockdata::script::Script::new();
                }
            }
            // TODO: Handle with payjoin crate. Support multiple receiver outputs.
            let (our_output, scheduled_payjoin) = handler
                .payjoins
                .find(&mut psbt.unsigned_tx.output)
                .expect("the transaction doesn't contain our output");
            // TODO: replace with scheduled_payjoin.total_channel_amount()
            let total_channel_amount: bitcoin::Amount = scheduled_payjoin
                .channels
                .iter()
                .map(|channel| channel.amount)
                .fold(bitcoin::Amount::ZERO, std::ops::Add::add);
            // TODO: replace with sheduled_payjoin.fees()
            let fees = scheduler::calculate_fees(
                scheduled_payjoin.channels.len() as u64,
                scheduled_payjoin.fee_rate,
                scheduled_payjoin.wallet_amount != bitcoin::Amount::ZERO,
            );

            // FIXME we shouldn't have anything that panics when handling an http request
            assert_eq!(
                our_output.value,
                (total_channel_amount + scheduled_payjoin.wallet_amount + fees).as_sat()
            );
            // TODO handle error
            let open_chan_results = scheduled_payjoin.multi_open_channel(&lnd).await.unwrap();

            let mut txouts = open_chan_results.iter().map(|(_, txo)| txo.clone());
            let chids = open_chan_results.iter().map(|(id, _)| *id);

            let channel_output = txouts.next().expect("no channels");

            if scheduled_payjoin.wallet_amount == bitcoin::Amount::ZERO {
                assert_eq!(channel_output.value, scheduled_payjoin.channels[0].amount.as_sat());
                *our_output = channel_output;
            } else {
                our_output.value = scheduled_payjoin.wallet_amount.as_sat();
                psbt.unsigned_tx.output.push(channel_output)
            }

            psbt.unsigned_tx.output.extend(txouts);
            psbt.outputs.resize_with(psbt.unsigned_tx.output.len(), Default::default);

            eprintln!("PSBT to be given to LND: {:#?}", psbt);
            let mut psbt_bytes = Vec::new();
            psbt.consensus_encode(&mut psbt_bytes).unwrap();

            for chid in chids {
                let psbt_verify = tonic_lnd::rpc::FundingPsbtVerify {
                    pending_chan_id: Vec::from(&chid as &[_]),
                    funded_psbt: psbt_bytes.clone(),
                    skip_finalize: true,
                };

                let transition_msg = tonic_lnd::rpc::FundingTransitionMsg {
                    trigger: Some(tonic_lnd::rpc::funding_transition_msg::Trigger::PsbtVerify(
                        psbt_verify,
                    )),
                };

                lnd.funding_state_step(transition_msg)
                    .await
                    .expect("failed to execute funding state step");
            }

            // Reset transaction state to be non-finalized
            let psbt = PartiallySignedTransaction::from_unsigned_tx(psbt.unsigned_tx.clone())
                .expect("resetting tx failed");
            let mut psbt_bytes = Vec::new();
            eprintln!("PSBT that will be returned: {:#?}", psbt);
            psbt.consensus_encode(&mut psbt_bytes).unwrap();
            let psbt_bytes = base64::encode(psbt_bytes);

            Ok(Response::new(Body::from(psbt_bytes)))
        }

        (&Method::POST, "/pj/schedule") => {
            let bytes = hyper::body::to_bytes(req.into_body()).await?;
            let request =
                serde_json::from_slice::<ScheduledPayJoin>(&bytes).expect("invalid request");
            request.test_connections(&handler.client).await;
            let address = handler
                .client
                .get_new_bech32_address()
                .await
                .expect("lnd returned a bech32 address");
            let total_amount = request.total_amount();
            handler.payjoins.insert(&address, request).expect("address reuse");

            let uri = format!(
                "bitcoin:{}?amount={}&pj=https://example.com/pj",
                address,
                total_amount.to_string_in(bitcoin::Denomination::Bitcoin)
            );
            let mut response = Response::new(Body::from(uri));
            response
                .headers_mut()
                .insert(hyper::header::CONTENT_TYPE, "text/plain".parse().unwrap());
            Ok(response)
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}
