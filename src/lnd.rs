use std::fmt;
use std::sync::Arc;

use bitcoin::consensus::Decodable;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use ln_types::P2PAddress;
use tokio::sync::Mutex as AsyncMutex;
use tonic_lnd::rpc::{FundingTransitionMsg, OpenChannelRequest, OpenStatusUpdate};

#[derive(Debug)]
pub enum CheckError {
    RequestFailed(tonic_lnd::Error),
    VersionNumber { version: String, error: std::num::ParseIntError },
    LNDTooOld(String),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CheckError::RequestFailed(_) => write!(f, "failed to get LND version"),
            CheckError::VersionNumber { version, error: _ } => {
                write!(f, "Unparsable LND version '{}'", version)
            }
            CheckError::LNDTooOld(version) => write!(
                f,
                "LND version {} is too old - it would cause GUARANTEED LOSS of sats!",
                version
            ),
        }
    }
}

impl std::error::Error for CheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckError::RequestFailed(error) => Some(error),
            CheckError::VersionNumber { version: _, error } => Some(error),
            CheckError::LNDTooOld(_) => None,
        }
    }
}

impl From<tonic_lnd::Error> for CheckError {
    fn from(value: tonic_lnd::Error) -> Self { CheckError::RequestFailed(value) }
}

#[derive(Clone)]
pub struct LndClient(Arc<AsyncMutex<tonic_lnd::Client>>);

impl LndClient {
    pub async fn new(mut client: tonic_lnd::Client) -> Result<Self, CheckError> {
        let version =
            client.get_info(tonic_lnd::rpc::GetInfoRequest {}).await?.into_inner().version;
        let (parsed_version, version) = Self::parse_lnd_version(version)?;

        if parsed_version < (0, 14, 0) {
            return Err(CheckError::LNDTooOld(version));
        } else if parsed_version < (0, 14, 2) {
            eprintln!(
                "WARNING: LND older than 0.14.2. Using with an empty LND wallet is impossible."
            );
        }

        Ok(Self(Arc::new(AsyncMutex::new(client))))
    }

    fn parse_lnd_version(version: String) -> Result<((u64, u64, u64), String), CheckError> {
        let mut iter = match version.find('-') {
            Some(pos) => &version[..pos],
            None => &version,
        }
        .split('.');

        let major = iter.next().expect("split returns non-empty iterator").parse::<u64>();
        let minor = iter.next().unwrap_or("0").parse::<u64>();
        let patch = iter.next().unwrap_or("0").parse::<u64>();

        match (major, minor, patch) {
            (Ok(major), Ok(minor), Ok(patch)) => Ok(((major, minor, patch), version)),
            (Err(error), _, _) => Err(CheckError::VersionNumber { version, error }),
            (_, Err(error), _) => Err(CheckError::VersionNumber { version, error }),
            (_, _, Err(error)) => Err(CheckError::VersionNumber { version, error }),
        }
    }

    /// Ensures that we are connected to the node of address.
    pub async fn ensure_connected(&self, node: P2PAddress) -> Result<(), CheckError> {
        let pubkey = node.node_id.to_string();
        let peer_addr =
            tonic_lnd::rpc::LightningAddress { pubkey, host: node.as_host_port().to_string() };
        let connect_req =
            tonic_lnd::rpc::ConnectPeerRequest { addr: Some(peer_addr), perm: true, timeout: 60 };

        let mut client = self.0.lock().await;
        match client.connect_peer(connect_req).await {
            Err(err) if err.message().starts_with("already connected to peer") => Ok(()),
            result => {
                result?;
                Ok(())
            }
        }
    }

    /// Obtains a new bitcoin bech32 address from the our lnd node.
    pub async fn get_new_bech32_address(&self) -> Address {
        self.0
            .lock()
            .await
            .new_address(tonic_lnd::rpc::NewAddressRequest { r#type: 0, account: String::new() })
            .await
            .expect("failed to get chain address")
            .into_inner()
            .address
            .parse()
            .expect("lnd returned invalid address")
    }

    /// Requests to open a channel with remote node, returning the psbt of the funding transaction.
    ///
    /// TODO: This should not panic, have proper error handling.
    pub async fn open_channel(
        &self,
        req: OpenChannelRequest,
    ) -> Result<Option<PartiallySignedTransaction>, CheckError> {
        let client = &mut *self.0.lock().await;
        let mut response = client.open_channel(req).await?;
        let stream = response.get_mut();

        while let Some(OpenStatusUpdate { pending_chan_id, update: Some(update) }) =
            stream.message().await?
        {
            use tonic_lnd::rpc::open_status_update::Update;
            match update {
                Update::PsbtFund(ready) => {
                    // TODO: Do not panic here
                    let psbt =
                        PartiallySignedTransaction::consensus_decode(&mut &*ready.psbt).unwrap();
                    eprintln!(
                        "PSBT received from LND for pending chan id {:?}: {:#?}",
                        pending_chan_id, psbt
                    );
                    assert_eq!(psbt.unsigned_tx.output.len(), 1);

                    return Ok(Some(psbt));
                }
                // TODO: do not panic
                x => panic!("Unexpected update {:?}", x),
            }
        }
        Ok(None)
    }

    pub async fn funding_state_step(&self, req: FundingTransitionMsg) -> Result<(), CheckError> {
        let client = &mut *self.0.lock().await;
        client.funding_state_step(req).await?;
        Ok(())
    }
}
