mod args;
mod lnd;
pub mod scheduler;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bip78::receiver::*;
use bitcoin::{Address, Script, TxOut};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use scheduler::ScheduledPayJoin;

use crate::args::parse_args;
use crate::lnd::*;
use crate::scheduler::Scheduler;

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

    let scheduler = Scheduler::new(LndClient::from_config(&config).await?);

    if let Some(payjoin) = scheduled_pj {
        let address = scheduler.schedule_payjoin(&payjoin).await?;

        // TODO: Don't hardcode pj endpoint
        // * Optional cli flag or ENV for pj endpoint (in the case of port forwarding), otherwise
        //      we should determine the bip21 string using `api::ServeOptions`
        println!(
            "bitcoin:{}?amount={}&pj=https://localhost:3010/pj",
            address,
            payjoin.total_amount().to_string_in(bitcoin::Denomination::Bitcoin)
        );
    }

    let addr = ([127, 0, 0, 1], config.bind_port).into();

    let service = make_service_fn(move |_| {
        let sched = scheduler.clone(); // TODO Review this double clone. Wataf is going on here, are we referencing the same scheduler or do we need a container?
        async move {
            Ok::<_, hyper::Error>(service_fn(move |request| handle_web_req(sched.clone(), request)))
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
    scheduler: Scheduler,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    use std::path::Path;

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

            let proposal_psbt = scheduler.propose_payjoin(original_request).await.unwrap();

            Ok(Response::new(Body::from(proposal_psbt)))
        }

        (&Method::POST, "/pj/schedule") => {
            let bytes = hyper::body::to_bytes(req.into_body()).await?;
            let request =
                serde_json::from_slice::<ScheduledPayJoin>(&bytes).expect("invalid request");

            let address = scheduler.schedule_payjoin(&request).await.unwrap();
            let total_amount = request.total_amount();

            // TODO: Don't hardcode pj endpoint
            // * Optional cli flag or ENV for pj endpoint (in the case of port forwarding), otherwise
            //      we should determine the bip21 string using `api::ServeOptions`
            let uri = format!(
                "bitcoin:{}?amount={}&pj=https://localhost:3010/pj",
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
