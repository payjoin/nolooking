use std::fmt;
use std::sync::Arc;

use bitcoin::consensus::Decodable;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use ln_types::P2PAddress;
use tokio::sync::Mutex as AsyncMutex;
use tonic_lnd::rpc::funding_transition_msg::Trigger;
use tonic_lnd::rpc::{
    FundingPsbtVerify, FundingTransitionMsg, OpenChannelRequest, OpenStatusUpdate,
};

use crate::scheduler::ChannelId;

#[derive(Clone)]
pub struct LndClient(Arc<AsyncMutex<tonic_lnd::Client>>);

impl LndClient {
    /// New [LndClient] from [Config].
    pub async fn from_config(config: &crate::config::Config) -> Result<Self, LndError> {
        let raw_client = tonic_lnd::connect(
            config.lnd_address.clone(),
            &config.lnd_cert_path,
            &config.lnd_macaroon_path,
        )
        .await?;

        Self::new(raw_client).await
    }

    pub async fn new(mut client: tonic_lnd::Client) -> Result<Self, LndError> {
        let response = client
            .get_info(tonic_lnd::rpc::GetInfoRequest {})
            .await
            .map_err(LndError::VersionRequestFailed)?;
        let version_str = &response.get_ref().version;
        let version = Self::parse_lnd_version(version_str)?;

        if version < (0, 14, 0) {
            return Err(LndError::LNDTooOld(version_str.clone()));
        } else if version < (0, 14, 2) {
            eprintln!(
                "WARNING: LND older than 0.14.2. Using with an empty LND wallet is impossible."
            );
        }

        Ok(Self(Arc::new(AsyncMutex::new(client))))
    }

    fn parse_lnd_version(version_str: &str) -> Result<(u64, u64, u64), LndError> {
        let trim_from = version_str.find('-').unwrap_or(version_str.len());
        let mut iter =
            version_str.get(..trim_from).expect("trim_from should always succeed").split('.');

        let mut parse_next = || {
            iter.next().map(|v| v.parse::<u64>()).transpose().map_err(|e| {
                LndError::ParseVersionFailed { version: version_str.to_string(), error: e }
            })
        };

        let major = parse_next()?.expect("split returned empty iterator");
        let minor = parse_next()?.unwrap_or(0);
        let patch = parse_next()?.unwrap_or(0);

        Ok((major, minor, patch))
    }

    /// Ensures that we are connected to the node of address.
    pub async fn ensure_connected(&self, node: P2PAddress) -> Result<(), LndError> {
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
    pub async fn get_new_bech32_address(&self) -> Result<Address, LndError> {
        let mut client = self.0.lock().await;
        let response = client
            .new_address(tonic_lnd::rpc::NewAddressRequest { r#type: 0, account: String::new() })
            .await?;
        response.get_ref().address.parse::<Address>().map_err(LndError::ParseBitcoinAddressFailed)
    }

    /// Requests to open a channel with remote node, returning the psbt of the funding transaction.
    pub async fn open_channel(
        &self,
        req: OpenChannelRequest,
    ) -> Result<Option<PartiallySignedTransaction>, LndError> {
        let client = &mut *self.0.lock().await;
        let mut response = client.open_channel(req).await?;
        let stream = response.get_mut();

        while let Some(OpenStatusUpdate { pending_chan_id, update: Some(update) }) =
            stream.message().await?
        {
            use tonic_lnd::rpc::open_status_update::Update;
            match update {
                Update::PsbtFund(ready) => {
                    let psbt = PartiallySignedTransaction::consensus_decode(&mut &*ready.psbt)
                        .map_err(LndError::Decode)?;
                    eprintln!(
                        "PSBT received from LND for pending chan id {:?}: {:#?}",
                        pending_chan_id, psbt
                    );
                    assert_eq!(psbt.unsigned_tx.output.len(), 1);

                    return Ok(Some(psbt));
                }
                x => return Err(LndError::UnexpectedUpdate(x)),
            }
        }
        Ok(None)
    }

    /// Sends the `FundingPsbtVerify` message to remote lnd nodes to finalize channels of given
    /// channel ids.
    pub async fn verify_funding<I>(&self, funded_psbt: &[u8], chan_ids: I) -> Result<(), LndError>
    where
        I: IntoIterator<Item = ChannelId>,
    {
        let handles = chan_ids
            .into_iter()
            .map(|chan_id| {
                let client = self.clone();
                let req = FundingTransitionMsg {
                    trigger: Some(Trigger::PsbtVerify(FundingPsbtVerify {
                        pending_chan_id: chan_id.into(),
                        funded_psbt: funded_psbt.to_vec(),
                        skip_finalize: true,
                    })),
                };
                tokio::spawn(async move { client.funding_state_step(req).await })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.await.unwrap()?;
        }

        Ok(())
    }

    pub async fn funding_state_step(&self, req: FundingTransitionMsg) -> Result<(), LndError> {
        let client = &mut *self.0.lock().await;
        client.funding_state_step(req).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum LndError {
    Generic(tonic_lnd::Error),
    ConnectError(tonic_lnd::ConnectError),
    Decode(bitcoin::consensus::encode::Error),
    ParseBitcoinAddressFailed(bitcoin::util::address::Error),
    VersionRequestFailed(tonic_lnd::Error),
    UnexpectedUpdate(tonic_lnd::rpc::open_status_update::Update),
    ParseVersionFailed { version: String, error: std::num::ParseIntError },
    LNDTooOld(String),
}

impl fmt::Display for LndError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LndError::Generic(e) => e.fmt(f),
            LndError::ConnectError(e) => e.fmt(f),
            LndError::Decode(e) => e.fmt(f),
            LndError::ParseBitcoinAddressFailed(e) => e.fmt(f),
            LndError::VersionRequestFailed(_) => write!(f, "failed to get LND version"),
            LndError::UnexpectedUpdate(e) => write!(f, "Unexpected channel update {:?}", e),
            LndError::ParseVersionFailed { version, error: _ } => {
                write!(f, "Unparsable LND version '{}'", version)
            }
            LndError::LNDTooOld(version) => write!(
                f,
                "LND version {} is too old - it would cause GUARANTEED LOSS of sats!",
                version
            ),
        }
    }
}

impl std::error::Error for LndError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LndError::Generic(e) => Some(e),
            LndError::ConnectError(e) => Some(e),
            LndError::Decode(e) => Some(e),
            LndError::ParseBitcoinAddressFailed(e) => Some(e),
            LndError::VersionRequestFailed(e) => Some(e),
            Self::UnexpectedUpdate(_) => None,
            LndError::ParseVersionFailed { version: _, error } => Some(error),
            LndError::LNDTooOld(_) => None,
        }
    }
}

impl From<tonic_lnd::Error> for LndError {
    fn from(value: tonic_lnd::Error) -> Self { LndError::Generic(value) }
}

impl From<tonic_lnd::ConnectError> for LndError {
    fn from(value: tonic_lnd::ConnectError) -> Self { LndError::ConnectError(value) }
}
