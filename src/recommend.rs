use core::convert::TryFrom;
use std::convert::TryInto;
use std::num::ParseIntError;
use std::ops::Index;
use std::str::FromStr;

use bitcoin::util::amount::ParseAmountError;
use bitcoin::Amount;
use ln_types::P2PAddress;
use reqwest::Url;

type ConnectivityResponse = Vec<Nodes>;
#[derive(Clone, serde_derive::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Nodes {
    // TODO use ln:types::NodePubkey
    pub public_key: String,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub capacity: Amount,
}

#[derive(Debug, Clone, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    // TODO use ln_types pubkey
    #[serde(rename = "public_key")]
    pub public_key: String,
    pub alias: String,
    pub sockets: String,
    #[serde(rename = "active_channel_count")]
    pub active_channel_count: i64,
    pub capacity: String,
}

#[derive(Debug, Clone, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct NodeDTO {
    pub p2p_address: P2PAddress,
    pub alias: String,
    #[serde(rename = "active_channel_count")]
    pub active_channel_count: i64,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub capacity: Amount,
}

impl TryFrom<Node> for NodeDTO {
    type Error = RecommendedError;
    fn try_from(value: Node) -> Result<Self, RecommendedError> {
        // Sockets are comma delim'd. First option Tor hidden service, second is an ip
        let sockets: Vec<&str> = value.sockets.split(",").collect();
        let p2p_address = P2PAddress::try_from(format!("{}@{}", value.public_key, sockets[0]))
            .map_err(|_e| InternalRecommendedError::Parse("Could not parse P2PAddress"))
            .map_err(RecommendedError)?;
        let cap = u64::from_str(&value.capacity)?;

        Ok(Self {
            p2p_address,
            alias: value.alias,
            active_channel_count: value.active_channel_count,
            capacity: Amount::from_sat(cap),
        })
    }
}

#[derive(serde_derive::Deserialize, serde_derive::Serialize)]
pub struct Recommendations {
    pub routing_node: NodeDTO,
    pub edge_node: NodeDTO,
}

pub async fn get_recommended_channels() -> Result<Recommendations, RecommendedError> {
    let base_url = "https://mempool.space/api/v1/lightning/nodes/rankings/connectivity".to_string();
    let url = Url::parse(&base_url).map_err(InternalRecommendedError::Url)?;

    let res = reqwest::Client::new().get(url).send().await?;
    let high_channel_nodes = res.json::<ConnectivityResponse>().await?;
    let mut high_cap_nodes = high_channel_nodes.clone();
    high_cap_nodes.sort_by(|a, b| a.capacity.partial_cmp(&b.capacity).unwrap());

    let high_capacity_node = get_node(&high_cap_nodes.index(0).public_key).await?;
    let high_channel_node = get_node(&high_channel_nodes.index(0).public_key).await?;

    Ok(Recommendations { routing_node: high_capacity_node, edge_node: high_channel_node })
}

async fn get_node(pubkey: &str) -> Result<NodeDTO, RecommendedError> {
    let base_url = format!("https://mempool.space/api/v1/lightning/nodes/{}", pubkey);
    let url = Url::parse(&base_url).map_err(InternalRecommendedError::Url)?;

    let res = reqwest::Client::new().get(url).send().await?;
    let node: Node = res.json::<Node>().await?;
    let node_dto: NodeDTO = node.try_into()?;
    Ok(node_dto)
}

#[derive(Debug)]
pub struct RecommendedError(InternalRecommendedError);

#[derive(Debug)]
pub(crate) enum InternalRecommendedError {
    Url(url::ParseError),
    Http(reqwest::Error),
    Parse(&'static str),
    ParseAmountError(ParseAmountError),
    ParseIntError(ParseIntError),
}

impl From<InternalRecommendedError> for RecommendedError {
    fn from(value: InternalRecommendedError) -> Self { RecommendedError(value) }
}

impl From<reqwest::Error> for RecommendedError {
    fn from(value: reqwest::Error) -> Self {
        RecommendedError(InternalRecommendedError::Http(value))
    }
}

impl From<ParseAmountError> for RecommendedError {
    fn from(value: ParseAmountError) -> Self {
        RecommendedError(InternalRecommendedError::ParseAmountError(value))
    }
}

impl From<ParseIntError> for RecommendedError {
    fn from(value: ParseIntError) -> Self {
        RecommendedError(InternalRecommendedError::ParseIntError(value))
    }
}
