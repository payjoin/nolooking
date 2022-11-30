use std::net::SocketAddr;
use std::path::Path;

use bip78::receiver::*;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{debug, info};
use qrcode_generator::QrCodeEcc;

use crate::lsp::Quote;
use crate::scheduler::{ChannelBatch, Scheduler, SchedulerError};

#[cfg(not(feature = "test_paths"))]
const PUBLIC_DIR: &str = "/usr/share/nolooking/public";

#[cfg(feature = "test_paths")]
const PUBLIC_DIR: &str = "public";

/// Create QR code and save to `PUBLIC_DIR/qr_codes/<name>.png`
fn create_qr_code(qr_string: &str, name: &str) {
    let filename = format!("{}/qr_codes/{}.png", PUBLIC_DIR, name);
    qrcode_generator::to_png_to_file(qr_string, QrCodeEcc::Low, 512, filename.clone())
        .expect(&format!("Saved QR code: {}", filename));
}

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
    info!("Listening on: http://{}", bind_addr);
    server.await
}

async fn handle_web_req(
    scheduler: Scheduler,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    let result = match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => handle_index().await,
        (&Method::POST, "/pj") => handle_pj(scheduler, req).await.map_err(HttpError::PayJoin),
        (&Method::POST, "/schedule") => handle_schedule(scheduler, req).await,
        (&Method::GET, path) => serve_public_file(path).await,
        _ => handle_404().await,
    };

    match result {
        Ok(resp) => Ok(resp),
        Err(err) => {
            match &err {
                HttpError::PayJoin(err) => {
                    log::debug!("PayJoin error: {:?}", &err);
                }
                _ => (),
            }
            err.into_response()
        }
    }
}

async fn handle_404() -> Result<Response<Body>, HttpError> {
    let mut not_found = Response::default();
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    Ok(not_found)
}

async fn handle_index() -> Result<Response<Body>, HttpError> {
    let index = std::fs::read(Path::new(PUBLIC_DIR).join("index.html")).expect("can't open index");
    Ok(Response::new(Body::from(index)))
}

async fn serve_public_file(path: &str) -> Result<Response<Body>, HttpError> {
    // A path argument to PathBuf::join(&self, path) with a leading slash
    // is treated as an absolute path, so we strip it in preparation.
    let directory_traversal_vulnerable_path = &path[("/".len())..];
    match std::fs::read(Path::new(PUBLIC_DIR).join(directory_traversal_vulnerable_path)) {
        Ok(file) => Response::builder()
            .status(200)
            .header("Cache-Control", "max-age=604800")
            .body(Body::from(file))
            .map_err(HttpError::Http),
        Err(_) => handle_404().await,
    }
}

async fn handle_pj(
    scheduler: Scheduler,
    req: Request<Body>,
) -> Result<Response<Body>, PayJoinError> {
    debug!("{:?}", req.uri().query());

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
    let reader = &*bytes;
    let original_request = UncheckedProposal::from_request(reader, query, headers)?;

    let proposal_psbt =
        scheduler.propose_payjoin(original_request).await.map_err(PayJoinError::Scheduler)?;
    Ok(Response::new(Body::from(proposal_psbt)))
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct ScheduleResponse {
    bip21: String,
    address: String,
    quote: Option<Quote>,
}

async fn handle_schedule(
    scheduler: Scheduler,
    req: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let bytes = hyper::body::to_bytes(req.into_body()).await.map_err(HttpError::Hyper)?;
    // deserialize x-www-form-urlencoded data with non-strict encoded "channel[arrayindex]"
    let conf = serde_qs::Config::new(5, false); // 5 is default max_depth
    let request: ChannelBatch = conf.deserialize_bytes(&bytes)?;

    let (uri, address, quote) = scheduler.schedule_payjoin(request).await?;

    let schedule_response =
        ScheduleResponse { bip21: uri.clone(), address: address.to_string(), quote };
    let mut response = Response::new(Body::from(
        serde_json::to_string(&schedule_response).map_err(HttpError::SerdeJson)?,
    ));
    create_qr_code(&uri, &address.to_string());
    response.headers_mut().insert(hyper::header::CONTENT_TYPE, "application/json".parse()?);
    Ok(response)
}

pub(crate) struct Headers(hyper::HeaderMap);
impl bip78::receiver::Headers for Headers {
    fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key)?.to_str().ok() }
}

#[derive(Debug)]
pub enum PayJoinError {
    Scheduler(SchedulerError),
    BadRequest(hyper::Error),
    Bip78Request(bip78::receiver::RequestError),
}

impl From<bip78::receiver::RequestError> for PayJoinError {
    fn from(e: bip78::receiver::RequestError) -> Self { Self::Bip78Request(e) }
}

impl From<hyper::Error> for PayJoinError {
    fn from(e: hyper::Error) -> Self { Self::BadRequest(e) }
}

#[derive(Debug)]
pub enum HttpError {
    PayJoin(PayJoinError),
    Hyper(hyper::Error),
    Http(hyper::http::Error),
    InvalidHeaderValue(hyper::header::InvalidHeaderValue),
    Scheduler(SchedulerError),
    SerdeQs(serde_qs::Error),
    SerdeJson(serde_json::Error),
}

impl HttpError {
    /// Transforms an [HttpError] into a HTTP response
    pub fn into_response(self) -> Result<Response<Body>, hyper::Error> {
        if let Self::Hyper(err) = self {
            return Err(err);
        }

        let resp = Response::new(Body::from(self.to_string()));
        let (mut parts, body) = resp.into_parts();

        // TODO respond with well known errors as defined in BIP-0078
        // https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#receivers-well-known-errors
        parts.status = match self {
            Self::PayJoin(_)
            | Self::Hyper(_)
            | Self::Http(_)
            | Self::InvalidHeaderValue(_)
            | Self::Scheduler(_)
            | Self::SerdeQs(_)
            | Self::SerdeJson(_) => StatusCode::BAD_REQUEST,
        };

        // TODO: Avoid writing error directly to HTTP response (bad security if public facing)
        // instead respond with the same format as well known errors
        Ok(Response::from_parts(parts, body))
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Have proper error printing
        write!(f, "api: {:?}", self)
    }
}

impl std::error::Error for HttpError {}

impl From<PayJoinError> for HttpError {
    fn from(e: PayJoinError) -> Self { Self::PayJoin(e) }
}

impl From<hyper::header::InvalidHeaderValue> for HttpError {
    fn from(e: hyper::header::InvalidHeaderValue) -> Self { Self::InvalidHeaderValue(e) }
}

impl From<SchedulerError> for HttpError {
    fn from(e: SchedulerError) -> Self { Self::Scheduler(e) }
}

impl From<serde_qs::Error> for HttpError {
    fn from(e: serde_qs::Error) -> Self { Self::SerdeQs(e) }
}
