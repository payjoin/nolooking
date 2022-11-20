use bitcoin::Address;
use hyper::{Body, Client, Uri};
use ln_types::P2PAddress;
use serde_derive::{Deserialize, Serialize};

async fn body_to_string(body: Body) -> Result<String, LspError> {
    let body_bytes = hyper::body::to_bytes(body).await.map_err(InternalLspError::Hyper)?;
    Ok(String::from_utf8(body_bytes.to_vec()).map_err(InternalLspError::FromUtf8)?)
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Quote {
    pub price: u32,
    size: u32,
    duration: u32,
    pub address: String,
}

pub async fn request_quote(
    p2p_address: &P2PAddress,
    refund_address: &Address,
    lsp_endpoint: &String,
) -> Result<Quote, LspError> {
    let https = hyper_tls::HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    // get address
    // suggest capacity
    let base_uri = format!(
        "{}/request-inbound?nodeid={}&capacity={}&duration={}&refund_address={}",
        lsp_endpoint, p2p_address, 1000000, 1, refund_address
    ); // TODO confirm p2p_address is urlencoded
    let url: Uri = base_uri.parse().map_err(InternalLspError::Uri)?;
    let req =
        hyper::Request::post(url).body(hyper::Body::empty()).map_err(InternalLspError::Http)?;
    let res = client.request(req).await.map_err(InternalLspError::Hyper)?;
    let body_str = body_to_string(res.into_body()).await?;
    let quote: Quote = serde_json::from_str(&body_str).map_err(InternalLspError::SerdeJson)?;
    Ok(quote)
}

#[derive(Debug)]
pub struct LspError(InternalLspError);

#[derive(Debug)]
pub(crate) enum InternalLspError {
    Uri(hyper::http::uri::InvalidUri),
    FromUtf8(std::string::FromUtf8Error),
    Hyper(hyper::Error),
    Http(hyper::http::Error),
    SerdeJson(serde_json::Error),
}

impl From<InternalLspError> for LspError {
    fn from(value: InternalLspError) -> Self { LspError(value) }
}
