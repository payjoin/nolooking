use bitcoin::Address;
use ln_types::P2PAddress;
use reqwest::Url;
use serde_derive::{Deserialize, Serialize};

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
) -> Result<Quote, LspError> {
    let base_uri = format!(
        "https://nolooking.chaincase.app/api/request-inbound?nodeid={}&capacity={}&duration={}&refund_address={}",
        p2p_address, 1000000, 1, refund_address
    );
    let url = Url::parse(&base_uri).map_err(InternalLspError::Url)?;
    let res = reqwest::Client::new().post(url).send().await?;
    let quote: Quote = res.json::<Quote>().await?;
    Ok(quote)
}

#[derive(Debug)]
pub struct LspError(InternalLspError);

#[derive(Debug)]
pub(crate) enum InternalLspError {
    Url(url::ParseError),
    Http(reqwest::Error),
}

impl From<InternalLspError> for LspError {
    fn from(value: InternalLspError) -> Self { LspError(value) }
}

impl From<reqwest::Error> for LspError {
    fn from(value: reqwest::Error) -> Self { LspError(InternalLspError::Http(value)) }
}
