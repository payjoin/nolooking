use std::ops::Index;

use hyper::{Body, Client, Uri};
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

// TODO return result here
async fn body_to_string(body: Body) -> String {
    let body_bytes = hyper::body::to_bytes(body).await.unwrap();
    String::from_utf8(body_bytes.to_vec()).unwrap()
}

pub async fn get_recommended_channels() -> Result<Recommendations, hyper::http::Error> {
    let https = hyper_tls::HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let uri: Uri =
        "https://mempool.space/api/v1/lightning/nodes/rankings/connectivity".parse().unwrap();
    let res = client.get(uri).await.unwrap();

    let body_str = body_to_string(res.into_body()).await;
    let high_channels: ConnectivityResponse = serde_json::from_str(&body_str).unwrap();
    let mut high_cap_nodes = high_channels.clone();
    high_cap_nodes.sort_by(|a, b| a.capacity.partial_cmp(&b.capacity).unwrap());

    let routing_node = get_node(&high_cap_nodes.index(0).public_key).await?;
    let edge_node = get_node(&high_channels.index(0).public_key).await?;

    Ok(Recommendations { routing_node, edge_node })
}

async fn get_node(pubkey: &str) -> Result<Node, hyper::http::Error> {
    let https = hyper_tls::HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let base_uri = "https://mempool.space/api/v1/lightning/nodes";
    let get_node_uri: Uri = format!("{}/{}", base_uri, pubkey).parse().unwrap();
    let res = client.get(get_node_uri).await.unwrap();
    let body_str = body_to_string(res.into_body()).await;
    let node: Node = serde_json::from_str(&body_str).unwrap();
    Ok(node)
}
