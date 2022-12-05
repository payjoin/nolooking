use core::convert::TryFrom;
use std::convert::TryInto;
use std::ops::Index;

use bitcoin::Amount;
use ln_types::P2PAddress;
use reqwest::Url;

type ConnectivityResponse = Vec<Nodes>;
#[derive(Clone, serde_derive::Deserialize, Debug)]
struct Nodes {
    pub public_key: P2PAddress,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub capacity: Amount,
}

#[derive(Debug, Clone, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct Node {
    // TODO use ln_types pubkey
    pub public_key: String,
    pub alias: String,
    #[serde(rename(serialize = "sockets", deserialize = "socket"))]
    pub sockets: String,
    pub active_channel_count: i64,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub capacity: Amount,
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
        // Sockets are comma delim'd. First option is ip, second is Tor hidden service
        // We always serve an ip P2P address to the user
        let sockets: Vec<&str> = value.sockets.split(",").collect();
        let p2p_address = P2PAddress::try_from(format!("{}@{}", sockets[0], value.public_key))
            .map_err(|_e| InternalRecommendedError::Parse("Could not parse P2PAddress"))
            .map_err(RecommendedError)?;
        Ok(Self {
            p2p_address,
            alias: value.alias,
            active_channel_count: value.active_channel_count,
            capacity: value.capacity,
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

async fn get_node(pubkey: &P2PAddress) -> Result<NodeDTO, RecommendedError> {
    let base_url = format!("https://mempool.space/api/v1/lightning/nodes/{}", pubkey);
    let url = Url::parse(&base_url).map_err(InternalRecommendedError::Url)?;

    let res = reqwest::Client::new().get(url).send().await?;
    let mut node: Node = res.json::<Node>().await?;

    // Sockets are comma delim'd. First option is ip, second is Tor hidden service
    // We always serve an ip P2P address to the user
    let sockets: Vec<&str> = node.sockets.split(",").collect();
    node.sockets = sockets[0].to_string();
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
}

impl From<InternalRecommendedError> for RecommendedError {
    fn from(value: InternalRecommendedError) -> Self { RecommendedError(value) }
}

impl From<reqwest::Error> for RecommendedError {
    fn from(value: reqwest::Error) -> Self {
        RecommendedError(InternalRecommendedError::Http(value))
    }
}
