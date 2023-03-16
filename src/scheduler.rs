use std::collections::HashMap;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

use bip78::receiver::{Proposal, UncheckedProposal};
use bitcoin::consensus::Encodable;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{Address, Amount, Script, TxOut, Txid};
use ln_types::P2PAddress;
use log::{error, info};
use tonic_lnd::lnrpc::OpenChannelRequest;
use url::Url;

use crate::args::ArgError;
use crate::lnd::{LndClient, LndError};

#[derive(Clone, serde_derive::Deserialize, Debug)]
pub struct ScheduledChannel {
    pub(crate) node: P2PAddress,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub(crate) amount: bitcoin::Amount,
}

impl ScheduledChannel {
    pub fn new(node: P2PAddress, amount: bitcoin::Amount) -> Self { Self { node, amount } }

    pub(crate) fn from_args(addr: &str, amount: &str) -> Result<Self, ArgError> {
        let node = addr.parse::<P2PAddress>().map_err(ArgError::InvalidNodeAddress)?;

        let amount = bitcoin::Amount::from_str_in(amount, bitcoin::Denomination::Satoshi)
            .map_err(ArgError::InvalidBitcoinAmount)?;

        Ok(Self { node, amount })
    }
}

#[derive(Clone, serde_derive::Deserialize, Debug)]
pub struct ChannelBatch {
    channels: Vec<ScheduledChannel>,
    fee_rate: u64,
}

impl ChannelBatch {
    pub fn new(channels: Vec<ScheduledChannel>, fee_rate: u64) -> Self {
        Self { channels, fee_rate }
    }

    pub fn channels(&self) -> &Vec<ScheduledChannel> { &self.channels }
    pub fn fee_rate(&self) -> u64 { self.fee_rate }
}

/// A prepared channel batch.
///  reserve_deposit = RequiredReserve from LND set just before returning a bip21 uri.
#[derive(Clone, serde_derive::Deserialize, Debug)]
pub struct ScheduledPayJoin {
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    reserve_deposit: bitcoin::Amount,
    channels: Vec<ScheduledChannel>,
    fee_rate: u64,
}

impl ScheduledPayJoin {
    pub fn new(reserve_deposit: bitcoin::Amount, batch: ChannelBatch) -> Self {
        Self { reserve_deposit, channels: batch.channels().clone(), fee_rate: batch.fee_rate() }
    }

    fn total_amount(&self) -> bitcoin::Amount {
        self.channels
            .iter()
            .map(|channel| channel.amount)
            .fold(bitcoin::Amount::ZERO, std::ops::Add::add)
            + self.reserve_deposit
            + self.fees()
    }

    /// Check that amounts make sense for original(ish) psbt.
    /// We have to be paid what we're owed at a minimum.
    pub fn is_paying_us_enough(&self, our_output: &TxOut) -> bool {
        // TODO: replace with scheduled_payjoin.total_channel_amount()
        let total_channel_amount: bitcoin::Amount = self
            .channels
            .iter()
            .map(|channel| channel.amount)
            .fold(bitcoin::Amount::ZERO, std::ops::Add::add);
        let reserve_deposit = self.reserve_deposit();

        (total_channel_amount + reserve_deposit + self.fees()).as_sat() == our_output.value
    }

    /// This externally exposes [ScheduledPayJoin]::reserve_deposit.
    pub fn reserve_deposit(&self) -> bitcoin::Amount { self.reserve_deposit }

    /// Calculate the absolute miner fee this [ScheduledPayJoin] pays
    fn fees(&self) -> bitcoin::Amount {
        let channel_count = self.channels.len() as u64;
        let has_reserve_deposit = self.reserve_deposit != bitcoin::Amount::ZERO;

        let additional_vsize = if has_reserve_deposit {
            // <8 invariant bytes = 4 version + 4 locktime>
            //  + 2 variant bytes for input.len + output.len such that each len < 252
            //  + OP_0 OP_PUSHBYTES_32 <32 byte script>
            channel_count * (8 + 1 + 1 + 34)
        } else {
            // substitute 1 p2wsh channel (34 bytes) open for 1 p2wpkh reserve output (22 bytes)
            // that's + 12 bytes
            (channel_count - 1) * (8 + 1 + 1 + 34) + 12
        };

        bitcoin::Amount::from_sat(self.fee_rate * additional_vsize)
    }

    pub async fn multi_open_channel(
        &self,
        lnd: &LndClient,
    ) -> Result<Vec<(ChannelId, TxOut)>, SchedulerError> {
        let requests = self.generate_open_channel_requests();

        let handles = requests
            .iter()
            .cloned()
            .map(|(node, chan_id, req)| {
                let lnd = lnd.clone();
                let handle: tokio::task::JoinHandle<Result<Option<TxOut>, SchedulerError>> =
                    tokio::spawn(async move {
                        lnd.ensure_connected(node).await?;
                        let funding_txout = lnd
                            .open_channel(req)
                            .await?
                            .map(|psbt| psbt.unsigned_tx.output[0].clone());
                        Ok(funding_txout)
                    });
                (chan_id, handle)
            })
            .collect::<Vec<_>>();

        let mut funding_txos = Vec::<(ChannelId, TxOut)>::with_capacity(handles.len());
        for (chan_id, handle) in handles {
            match handle.await.unwrap()? {
                    Some(vout) => funding_txos.push((chan_id, vout)),
                    None => error!("failed to receive funding psbt after channel open request. !this case is not handled!"),
                };
        }

        if funding_txos.is_empty() {
            Err(SchedulerError::PayJoinCannotOpenAnyChannel)
        } else {
            Ok(funding_txos)
        }
    }

    pub fn generate_open_channel_requests(
        &self,
    ) -> Vec<(P2PAddress, ChannelId, OpenChannelRequest)> {
        self.channels
            .iter()
            .map(|chan| {
                let node_addr = chan.node.clone();
                let chan_id = temporary_channel_id();

                let psbt_shim = tonic_lnd::lnrpc::PsbtShim {
                    pending_chan_id: chan_id.into(),
                    base_psbt: Vec::new(),
                    no_publish: true,
                };
                let funding_shim = tonic_lnd::lnrpc::funding_shim::Shim::PsbtShim(psbt_shim);
                let funding_shim = tonic_lnd::lnrpc::FundingShim { shim: Some(funding_shim) };

                let req = OpenChannelRequest {
                    node_pubkey: chan.node.node_id.to_vec(),
                    local_funding_amount: chan
                        .amount
                        .as_sat()
                        .try_into()
                        .expect("amount too large"),
                    push_sat: 0,
                    private: false,
                    min_htlc_msat: 0,
                    remote_csv_delay: 0,
                    spend_unconfirmed: false,
                    close_address: String::new(),
                    funding_shim: Some(funding_shim),
                    remote_max_value_in_flight_msat: chan.amount.as_sat() * 1000,
                    remote_max_htlcs: 10,
                    max_local_csv: 288,
                    ..Default::default()
                };

                (node_addr, chan_id, req)
            })
            .collect()
    }

    // gen_funding_created AKA
    fn substitue_psbt_outputs<I>(
        &self,
        original_psbt: PartiallySignedTransaction,
        owned_vout: usize, // the original vout paying us. This is the one we can substitute
        funding_txos: I,
    ) -> PartiallySignedTransaction
    where
        I: IntoIterator<Item = TxOut>,
    {
        let mut iter = funding_txos.into_iter();
        let funding_txout = iter.next().unwrap(); // we assume there is at least 1.

        let mut proposal_psbt = original_psbt.clone();

        // determine whether we substitute channel opens for the original psbt's ownedoutput to us
        if self.reserve_deposit() == bitcoin::Amount::ZERO {
            assert_eq!(funding_txout.value, self.channels[0].amount.as_sat());
            proposal_psbt.unsigned_tx.output[owned_vout] = funding_txout;
        } else {
            // or keep it and adjust the amount for the on-chain reserve deposit
            proposal_psbt.unsigned_tx.output[owned_vout].value = self.reserve_deposit().as_sat();
            proposal_psbt.unsigned_tx.output.push(funding_txout)
        }

        // add remaining funding txouts
        proposal_psbt.unsigned_tx.output.extend(iter);

        // psbt should have outputs same length as contained unsigned tx
        proposal_psbt.outputs.resize_with(proposal_psbt.unsigned_tx.output.len(), Default::default);

        info!("channel funding Proposal PSBT created: {:#?}", proposal_psbt);

        proposal_psbt
    }
}

pub type ChannelId = [u8; 32];

fn temporary_channel_id() -> ChannelId { rand::random() }

/// [Scheduler] lets you pre-batch PayJoins, usually containing Channel Opens.
#[derive(Clone)]
pub struct Scheduler {
    lnd: LndClient,
    endpoint: Url,
    pjs: Arc<Mutex<HashMap<Script, ScheduledPayJoin>>>, // payjoins mapped by owned `scriptPubKey`s
    danger_accept_invalid_certs: bool,
    tor_proxy_address: SocketAddr,
}

impl Scheduler {
    /// New [Scheduler].
    pub fn new(
        lnd: LndClient,
        endpoint: Url,
        danger_accept_invalid_certs: bool,
        tor_proxy_address: SocketAddr,
    ) -> Self {
        Self {
            lnd,
            endpoint,
            danger_accept_invalid_certs,
            tor_proxy_address,
            pjs: Default::default(),
        }
    }

    pub async fn from_config(config: &crate::config::Config) -> Result<Self, SchedulerError> {
        Ok(Scheduler::new(LndClient::from_config(&config).await?, config.endpoint.parse().expect("Malformed secure endpoint from config file. Expecting a https or .onion URI to proxy payjoin requests"), 
        config.danger_accept_invalid_certs, config.tor_proxy_address))
    }

    /// Schedules a payjoin.
    pub async fn schedule_payjoin(
        &self,
        batch: ChannelBatch,
        // TODO return bip21::Url Seems broken or incompatible with bip78 now
    ) -> Result<(String, Address), SchedulerError> {
        self.test_connections(&batch.channels()).await?;
        let bitcoin_addr = self.lnd.get_new_bech32_address().await?;

        let required_reserve = self.lnd.required_reserve(batch.channels().len() as u32).await?;
        let wallet_balance = self.lnd.wallet_balance().await?;
        // Only add reserve if the wallet needs it
        let missing_reserve = required_reserve.checked_sub(wallet_balance).unwrap_or_default();

        let pj = &ScheduledPayJoin::new(missing_reserve, batch);

        if self.insert_payjoin(&bitcoin_addr, pj) {
            Ok((
                format_bip21(bitcoin_addr.clone(), pj.total_amount(), self.endpoint.clone()),
                bitcoin_addr,
            ))
        } else {
            Err(SchedulerError::Internal("lnd provided duplicate bitcoin addresses"))
        }
    }

    /// Given an Original PSBT request, respond with a PayJoin Proposal,
    /// returning a base64-encoded proposal PSBT (BIP-0078).
    /// Check the receiver PayJoin checklist as per spec (https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#receivers-original-psbt-checklist)
    pub async fn propose_payjoin(
        &self,
        original_req: UncheckedProposal,
    ) -> Result<String, SchedulerError> {
        if original_req.is_output_substitution_disabled() {
            return Err(SchedulerError::OutputSubstitutionDisabled);
        }
        let request = original_req
            // This is interactive, NOT a Payment Processor, so we don't save original tx.
            // Humans can solve the failure case out of band by trying again.
            .assume_interactive_receive_endpoint()
            .assume_no_inputs_owned() // TODO Check
            .assume_no_mixed_input_scripts() // This check is silly and could be ignored
            .assume_no_inputs_seen_before(); // TODO

        let mut original_psbt = request.psbt().clone();
        info!("Received psbt: {:#?}", original_psbt);

        // prepare proposal psbt (psbt, owned_vout, ScheduledPayJoin)
        let (owned_vout, pj) =
            self.find_matching_payjoin(&original_psbt).ok_or(SchedulerError::NoMatchingPayJoin)?;

        // FIXME does this need to go before find_matching_payjoin(...) ?
        // empty signatures because we won't broadcast the original psbt
        original_psbt
            .unsigned_tx
            .input
            .iter_mut()
            .for_each(|txin| txin.script_sig = bitcoin::Script::default());

        let our_output = &original_psbt.unsigned_tx.output[owned_vout];
        if !pj.is_paying_us_enough(our_output) {
            return Err(SchedulerError::OriginalPsbtInvalidAmount);
        }

        // initiate multiple `open_channel` requests and return the vector:
        // Vec<(temporary_channel_id:, funding_txout:)>
        let open_chan_results = pj.multi_open_channel(&self.lnd).await?;
        let txouts_to_substitute: Vec<TxOut> =
            open_chan_results.iter().map(|(_, txo)| txo.clone()).collect();
        let temporary_chan_ids = open_chan_results.iter().map(|(id, _)| *id);

        // TODO ensure privacy preserving txo ordering. should be responsibility of payjoin lib

        // create and send `funding_created` to all responding lightning nodes
        let proposal_psbt =
            pj.substitue_psbt_outputs(original_psbt, owned_vout, txouts_to_substitute);

        let mut raw_psbt = Vec::new();
        proposal_psbt.consensus_encode(&mut raw_psbt)?;
        self.lnd.verify_funding(&raw_psbt, temporary_chan_ids).await?;

        // Remove vestigial invalid signature data from the Original PSBT
        let proposal_psbt =
            PartiallySignedTransaction::from_unsigned_tx(proposal_psbt.unsigned_tx.clone())
                .expect("resetting tx failed");
        info!("Proposal PSBT that will be returned: {:#?}", proposal_psbt);

        let mut psbt_bytes = Vec::new();
        proposal_psbt.consensus_encode(&mut psbt_bytes)?;
        Ok(base64::encode(&mut psbt_bytes))
    }

    /// Insert payjoin associated with bitcoin address.
    fn insert_payjoin(&self, bitcoin_addr: &Address, pj: &ScheduledPayJoin) -> bool {
        let mut pj_by_spk = self.pjs.lock().unwrap();
        pj_by_spk.insert(bitcoin_addr.script_pubkey(), pj.clone()).is_none()
    }

    /// Get a prepared [ScheduledPayJoin] matching a PayJoin Request's Original PSBT
    fn find_matching_payjoin(
        &self,
        psbt: &PartiallySignedTransaction,
    ) -> Option<(usize, ScheduledPayJoin)> {
        let mut pj_by_script = self.pjs.lock().unwrap();

        // find vout of owned output, pop scheduled psbt
        let vout_pj_match = psbt.unsigned_tx.output.iter().enumerate().find_map(|(vout, txout)| {
            pj_by_script.remove(&txout.script_pubkey).map(|pj| (vout, pj))
        });

        vout_pj_match
    }

    fn init_pj_http_client(&self) -> Result<reqwest::Client, SchedulerError> {
        let tor_proxy_url = format!("socks5h://{}", self.tor_proxy_address);
        // the proxy can always be set and just fail if unavailable
        let proxy = reqwest::Proxy::custom(move |url| {
            // Proxy requests to .onion endpoints through Tor proxy
            if url.host_str().unwrap_or("").ends_with(".onion") {
                Some(tor_proxy_url.clone())
            } else {
                None
            }
        });

        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(self.danger_accept_invalid_certs)
            .proxy(proxy)
            .build()
            .map_err(|_| SchedulerError::Internal("Failed to build http client"))?;
        Ok(client)
    }

    /// Test that [ScheduledChannel] peer nodes are connected to ours
    pub async fn test_connections(&self, channels: &Vec<ScheduledChannel>) -> Result<(), LndError> {
        let handles = channels
            .iter()
            .map(|ch| (self.lnd.clone(), ch.node.clone()))
            .map(|(client, node)| tokio::spawn(async move { client.ensure_connected(node).await }))
            .collect::<Vec<_>>();

        for handle in handles {
            handle.await.unwrap()?;
        }
        Ok(())
    }

    /// Send a PayJoin from LND using automatic coin selection and
    /// automatic fee rate of 2 target confirmations.
    pub async fn send_payjoin<'a>(&self, uri: bip78::Uri<'_>) -> Result<Txid, SchedulerError> {
        log::debug!("get original_psbt");
        let pj_uri = bip78::UriExt::check_pj_supported(uri)
            .map_err(|e| SchedulerError::UriDoesNotSupportPayJoin(e.to_string()))?;
        let (original_psbt, leased_utxos) = if let Some(amount) = pj_uri.amount {
            log::debug!("funding original_psbt");
            self.lnd.fund_original_psbt(&pj_uri.address, amount).await?
        } else {
            return Err(SchedulerError::UriDoesNotSupportPayJoin(
                "Missing amount. Make sure the bip21 uri specifies an amount".to_string(),
            ));
        };

        log::debug!("sign original_psbt");
        let original_psbt = self.lnd.sign_psbt(original_psbt).await?;
        log::debug!("request_payjoin");
        let res = self.request_payjoin(pj_uri, original_psbt).await;
        if res.is_err() {
            self.lnd.release_utxos(leased_utxos).await?;
        } // else, those utxos are now spent and don't need to be released
        res
    }

    async fn request_payjoin(
        &self,
        pj_uri: bip78::PjUri<'_>,
        original_psbt: PartiallySignedTransaction,
    ) -> Result<Txid, SchedulerError> {
        use bip78::PjUriExt;

        let pj_params = bip78::sender::Configuration::non_incentivizing();
        let saved_inputs = original_psbt.inputs.clone();
        let (req, ctx) = pj_uri
            .create_pj_request(original_psbt.clone(), pj_params)
            .map_err(|_| SchedulerError::Internal("failed to make http pj request"))?;

        let http = self.init_pj_http_client()?;

        let response = http
            .post(req.url)
            .header("Content-Type", "text/plain")
            .body(reqwest::Body::from(req.body))
            .send()
            .await
            .map_err(|_| SchedulerError::Internal("PayJoin http request failed"))?;

        log::debug!("res: {:#?}", &response);
        let response =
            response.text().await.map_err(|_| SchedulerError::Internal("Bad response"))?;

        let mut payjoin_psbt = ctx
            .process_response(response.as_bytes())
            .map_err(|_| SchedulerError::Internal("bip78::sender ValidationError"))?;

        // fill in utxo info from original_psbt
        payjoin_psbt.inputs.splice(..saved_inputs.len(), saved_inputs);

        log::debug!("Proposed psbt: {:#?}", &payjoin_psbt);
        let tx = self.lnd.finalize_psbt(payjoin_psbt).await?;
        log::debug!("Finalized tx: {:#?}", &tx);
        let txid = self.lnd.broadcast(tx).await?;
        Ok(txid)
    }
}

pub fn format_bip21(address: Address, amount: Amount, endpoint: url::Url) -> String {
    let bip21_str = format!(
        "bitcoin:{}?amount={}&pj={}pj",
        address,
        amount.to_string_in(bitcoin::Denomination::Bitcoin),
        endpoint.to_string()
    );
    bip21_str
}

#[derive(Debug)]
pub enum SchedulerError {
    /// Error at the lightning node controller
    Lnd(LndError),
    /// Internal error that should not be shared
    Internal(&'static str),
    // Could not decode psbt
    Io(io::Error),
    /// Output Substitution is required to change the original output to a channel open
    OutputSubstitutionDisabled,
    /// No Original Psbt outputs match any [ScheduledPayJoin]
    NoMatchingPayJoin,
    /// Failed to open any channel for [ScheduledPayJoin]
    PayJoinCannotOpenAnyChannel,
    /// Original Psbt does not respect requested amount
    OriginalPsbtInvalidAmount,
    /// Bip21 has no valid `pj=` parameter
    UriDoesNotSupportPayJoin(String),
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Have proper printing
        write!(f, "scheduler error: {:?}", self)
    }
}

impl std::error::Error for SchedulerError {}

impl From<LndError> for SchedulerError {
    fn from(v: LndError) -> Self { Self::Lnd(v) }
}

impl From<io::Error> for SchedulerError {
    fn from(v: io::Error) -> Self { Self::Io(v) }
}
