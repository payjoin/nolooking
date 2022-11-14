use std::ops::Index;

use hyper::{Body, Client, Uri};
use rand::seq::SliceRandom;
use serde_derive::{Deserialize, Serialize};

type ConnectivityResponse = Vec<Nodes>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Nodes {
    pub public_key: String,
    pub channels: i64,
    pub capacity: i64,
}

use serde_json::Value;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    #[serde(rename = "public_key")]
    pub public_key: String,
    pub alias: String,
    #[serde(rename = "first_seen")]
    pub first_seen: i64,
    #[serde(rename = "updated_at")]
    pub updated_at: i64,
    pub color: String,
    pub sockets: String,
    #[serde(rename = "as_number")]
    pub as_number: Option<i64>,
    #[serde(rename = "city_id")]
    pub city_id: Value,
    #[serde(rename = "country_id")]
    pub country_id: Option<i64>,
    #[serde(rename = "subdivision_id")]
    pub subdivision_id: Value,
    pub longitude: Option<f64>,
    pub latitude: Option<f64>,
    #[serde(rename = "iso_code")]
    pub iso_code: Option<String>,
    #[serde(rename = "as_organization")]
    pub as_organization: Option<String>,
    pub city: Option<Value>,
    pub country: Option<Country>,
    pub subdivision: Option<Value>,
    #[serde(rename = "active_channel_count")]
    pub active_channel_count: i64,
    pub capacity: String,
    #[serde(rename = "opened_channel_count")]
    pub opened_channel_count: i64,
    #[serde(rename = "closed_channel_count")]
    pub closed_channel_count: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Country {
    pub de: String,
    pub en: String,
    pub es: String,
    pub fr: String,
    pub ja: String,
    #[serde(rename = "pt-BR")]
    pub pt_br: String,
    pub ru: String,
    #[serde(rename = "zh-CN")]
    pub zh_cn: String,
}

#[derive(Serialize, Deserialize)]
pub struct Recommendations {
    pub routing_node: Node,
    pub edge_node: Node,
    pub nolooking_node: Node,
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
    let nolooking_node = get_wildcard_node().await?;

    Ok(Recommendations { routing_node, edge_node, nolooking_node })
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

async fn get_wildcard_node() -> Result<Node, hyper::http::Error> {
    let https = hyper_tls::HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let uri: Uri = "https://nolooking.chaincase.app/api/wildcard".parse().unwrap();
    let res = client.get(uri.clone()).await.unwrap();
    let body_str = body_to_string(res.into_body()).await;
    let nodes: Vec<_> = body_str.split("\n").filter(|s| *s != "").collect();

    let rand_pubkey = match nodes.choose(&mut rand::thread_rng()) {
        Some(node) => node,
        None => {
            eprintln!("Failed to fetch wildcard node from {}, using default.", uri);
            &"028624b5cb872511d8b23a25ec351f6201af7e6b640edc0888fce05a8dede2bc8a"
        }
    };

    let base_uri = "https://mempool.space/api/v1/lightning/nodes";
    let get_node_uri: Uri = format!("{}/{}", base_uri, rand_pubkey).parse().unwrap();
    let res = client.get(get_node_uri).await.unwrap();
    let body_str = body_to_string(res.into_body()).await;
    let node: Node = serde_json::from_str(&body_str).unwrap();
    Ok(node)
}
