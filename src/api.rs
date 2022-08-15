use std::net::SocketAddr;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use crate::scheduler::{ScheduledPayJoin, Scheduler, SchedulerError};

/// Serve API options.
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Whether to serve static files.
    pub serve_static: bool,
}

/// Serve [Scheduler] with given options.
pub async fn serve_http(sched: Scheduler, opts: ServeOptions) -> Result<(), hyper::Error> {
    let new_service = make_service_fn(move |_| {
        let sched = sched.clone();
        async move {
            let handler = move |req| handle_request(sched.clone(), opts, req);
            Ok::<_, hyper::Error>(service_fn(handler))
        }
    });

    let server = Server::bind(&opts.bind_addr).serve(new_service);
    println!("Listening on: http://{}", opts.bind_addr);
    server.await
}

async fn handle_request(
    sched: Scheduler,
    opts: ServeOptions,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    let result = match (req.method(), req.uri().path()) {
        (&Method::GET, _) =>
            if req.uri().path().starts_with("/pj") && opts.serve_static {
                handle_index_html().await
            } else {
                handle_404().await
            },
        (&Method::POST, "/pj") => handle_pj(sched, req).await,
        (&Method::POST, "/pj/schedule") => handle_pj_schedule(sched, opts, req).await,
        _ => handle_404().await,
    };

    match result {
        Ok(resp) => Ok(resp),
        Err(err) => err.into_response(),
    }
}

async fn handle_404() -> Result<Response<Body>, ApiError> {
    let mut not_found = Response::default();
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    Ok(not_found)
}

async fn handle_index_html() -> Result<Response<Body>, ApiError> {
    // TODO: What if we have multiple static files?
    let bytes = include_bytes!("../static/index.html");
    Ok(Response::new(Body::from(&bytes[..])))
}

async fn handle_pj(sched: Scheduler, req: Request<Body>) -> Result<Response<Body>, ApiError> {
    dbg!(req.uri().query());

    let headers = Bip78Headers(req.headers().to_owned());
    let query = req.uri().query().map(ToString::to_string);
    let body_bytes = dbg!(hyper::body::to_bytes(req.into_body()).await?);

    let original_req =
        bip78::receiver::UncheckedProposal::from_request(&*body_bytes, query.as_deref(), headers)?;

    let proposal_psbt = sched.satisfy_payjoin(original_req).await?;

    Ok(Response::new(Body::from(proposal_psbt)))
}

async fn handle_pj_schedule(
    sched: Scheduler,
    opts: ServeOptions,
    req: Request<Body>,
) -> Result<Response<Body>, ApiError> {
    let bytes = hyper::body::to_bytes(req.into_body()).await?;
    let pj = serde_json::from_slice::<ScheduledPayJoin>(&bytes).expect("invalid request");

    let bitcoin_addr = sched.schedule_payjoin(&pj).await?;
    let total_amount = pj.total_amount();

    let uri = format!(
        "bitcoin:{}?amount={}&pj=https://{}/pj",
        bitcoin_addr,
        total_amount.to_string_in(bitcoin::Denomination::Bitcoin),
        opts.bind_addr,
    );

    let mut response = Response::new(Body::from(uri));
    response.headers_mut().insert(hyper::header::CONTENT_TYPE, "text/plain".parse().unwrap());

    Ok(response)
}

pub struct Bip78Headers(hyper::HeaderMap);
impl bip78::receiver::Headers for Bip78Headers {
    fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key)?.to_str().ok() }
}

#[derive(Debug)]
pub enum ApiError {
    Hyper(hyper::Error),
    Scheduler(SchedulerError),
    Bip78Request(bip78::receiver::RequestError),
}

impl ApiError {
    /// Transforms an [ApiError] into a HTTP response
    pub fn into_response(self) -> Result<Response<Body>, hyper::Error> {
        if let Self::Hyper(err) = self {
            return Err(err);
        }

        let resp = Response::new(Body::from(self.to_string()));
        let (mut parts, body) = resp.into_parts();

        // TODO: Have a proper status
        parts.status = StatusCode::INTERNAL_SERVER_ERROR;

        // TODO: Avoid writing error directly to HTTP response (bad security)
        Ok(Response::from_parts(parts, body))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Have proper error printing
        write!(f, "api: {:?}", self)
    }
}

impl std::error::Error for ApiError {}

impl From<SchedulerError> for ApiError {
    fn from(e: SchedulerError) -> Self { Self::Scheduler(e) }
}

impl From<hyper::Error> for ApiError {
    fn from(e: hyper::Error) -> Self { Self::Hyper(e) }
}

impl From<bip78::receiver::RequestError> for ApiError {
    fn from(e: bip78::receiver::RequestError) -> Self { Self::Bip78Request(e) }
}
