use std::ops::Index;

use reqwest::Url;
use serde_derive::{Deserialize, Serialize};

type ConnectivityResponse = Vec<Nodes>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Nodes {
    pub public_key: String,
    pub channels: i64,
    pub capacity: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    #[serde(rename = "public_key")]
    pub public_key: String,
    pub alias: String,
    pub sockets: String,
    #[serde(rename = "active_channel_count")]
    pub active_channel_count: i64,
    pub capacity: String,
}

#[derive(Serialize, Deserialize)]
pub struct Recommendations {
    pub routing_node: Node,
    pub edge_node: Node,
}

pub async fn get_recommended_channels() -> Result<Recommendations, RecommendedError> {
    let base_url = "https://mempool.space/api/v1/lightning/nodes/rankings/connectivity".to_string();
    let url = Url::parse(&base_url).map_err(InternalRecommendedError::Url)?;

    let res = reqwest::Client::new().get(url).send().await?;
    let high_channel_nodes = res.json::<ConnectivityResponse>().await?;
    let mut high_cap_nodes = high_channel_nodes.clone();
    high_cap_nodes.sort_by(|a, b| a.capacity.partial_cmp(&b.capacity).unwrap());

    let routing_node = get_node(&high_cap_nodes.index(0).public_key).await?;
    let edge_node = get_node(&high_channel_nodes.index(0).public_key).await?;

    Ok(Recommendations { routing_node, edge_node })
}

async fn get_node(pubkey: &str) -> Result<Node, RecommendedError> {
    let base_url = format!("https://mempool.space/api/v1/lightning/nodes/{}", pubkey);
    let url = Url::parse(&base_url).map_err(InternalRecommendedError::Url)?;

    let res = reqwest::Client::new().get(url).send().await?;
    let node: Node = res.json::<Node>().await?;

    Ok(node)
}

#[derive(Debug)]
pub struct RecommendedError(InternalRecommendedError);

#[derive(Debug)]
pub(crate) enum InternalRecommendedError {
    Url(url::ParseError),
    Http(reqwest::Error),
}

impl From<InternalRecommendedError> for RecommendedError {
    fn from(value: InternalRecommendedError) -> Self { RecommendedError(value) }
}

impl From<reqwest::Error> for RecommendedError {
    fn from(value: reqwest::Error) -> Self {
        RecommendedError(InternalRecommendedError::Http(value))
    }
}
