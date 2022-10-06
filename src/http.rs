use std::net::SocketAddr;

use bip78::receiver::*;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use crate::scheduler::{ScheduledPayJoin, Scheduler};

#[cfg(not(feature = "test_paths"))]
const STATIC_DIR: &str = "/usr/share/loin/static";

#[cfg(feature = "test_paths")]
const STATIC_DIR: &str = "static";

/// Serve requests to Schedule and execute PayJoins with given options.
pub async fn serve(sched: Scheduler, bind_addr: SocketAddr) -> Result<(), hyper::Error> {
    let new_service = make_service_fn(move |_| {
        let sched = sched.clone();
        async move {
            let handler = move |req| handle_web_req(sched.clone(), req);
            Ok::<_, hyper::Error>(service_fn(handler))
        }
    });

    let server = Server::bind(&bind_addr).serve(new_service);
    println!("Listening on: http://{}", bind_addr);
    server.await
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

pub(crate) struct Headers(hyper::HeaderMap);
impl bip78::receiver::Headers for Headers {
    fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key)?.to_str().ok() }
}
