use std::{
    collections::HashMap,
    convert::TryInto,
    fmt,
    sync::{Arc, Mutex},
};

use bip78::receiver::{Proposal, UncheckedProposal};
use bitcoin::consensus::Encodable;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{Address, Script, TxOut};
use ln_types::P2PAddress;
use tonic_lnd::rpc::OpenChannelRequest;

use crate::args::ArgError;
use crate::lnd::{LndClient, LndError};

#[derive(Clone, serde_derive::Deserialize)]
pub struct ScheduledChannel {
    pub(crate) node: P2PAddress,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub(crate) amount: bitcoin::Amount,
}

impl ScheduledChannel {
    pub(crate) fn from_args(addr: &str, amount: &str) -> Result<Self, ArgError> {
        let node = addr.parse::<P2PAddress>().map_err(ArgError::InvalidNodeAddress)?;

        let amount = bitcoin::Amount::from_str_in(amount, bitcoin::Denomination::Satoshi)
            .map_err(ArgError::InvalidBitcoinAmount)?;

        Ok(Self { node, amount })
    }
}

#[derive(Clone, serde_derive::Deserialize)]
pub struct ScheduledPayJoin {
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    wallet_amount: bitcoin::Amount,
    channels: Vec<ScheduledChannel>,
    fee_rate: u64,
}

impl ScheduledPayJoin {
    pub fn new(
        wallet_amount: bitcoin::Amount,
        channels: Vec<ScheduledChannel>,
        fee_rate: u64,
    ) -> Self {
        Self { wallet_amount, channels, fee_rate }
    }

    pub fn total_amount(&self) -> bitcoin::Amount {
        let fees = calculate_fees(
            self.channels.len() as u64,
            self.fee_rate,
            self.wallet_amount != bitcoin::Amount::ZERO,
        );

        self.channels
            .iter()
            .map(|channel| channel.amount)
            .fold(bitcoin::Amount::ZERO, std::ops::Add::add)
            + self.wallet_amount
            + fees
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
        // TODO: replace with sheduled_payjoin.fees()
        let fees = calculate_fees(
            self.channels.len() as u64,
            self.fee_rate,
            self.wallet_amount() != bitcoin::Amount::ZERO,
        );
        let wallet_amount = self.wallet_amount();

        let owned_txout_value = our_output.value;

        (total_channel_amount + fees + wallet_amount).as_sat() == owned_txout_value
    }

    /// This externally exposes [ScheduledPayJoin]::wallet_amount.
    pub fn wallet_amount(&self) -> bitcoin::Amount { self.wallet_amount }

    /// Test connections with remote lightning nodes that we are trying to create channels with as
    /// part of this [ScheduledPayJoin].
    pub async fn test_connections(&self, client: &LndClient) -> Result<(), LndError> {
        let handles = self
            .channels
            .iter()
            .map(|ch| (client.clone(), ch.node.clone()))
            .map(|(client, node)| tokio::spawn(async move { client.ensure_connected(node).await }))
            .collect::<Vec<_>>();

        for handle in handles {
            handle.await.unwrap()?;
        }
        Ok(())
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
                    None => eprintln!("failed to receive funding psbt after channel open request. !this case is not handled!"),
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

                let psbt_shim = tonic_lnd::rpc::PsbtShim {
                    pending_chan_id: chan_id.into(),
                    base_psbt: Vec::new(),
                    no_publish: true,
                };
                let funding_shim = tonic_lnd::rpc::funding_shim::Shim::PsbtShim(psbt_shim);
                let funding_shim = tonic_lnd::rpc::FundingShim { shim: Some(funding_shim) };

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
    fn add_channels_to_psbt<I>(
        &self,
        original_psbt: PartiallySignedTransaction,
        owned_vout: usize,
        funding_txos: I,
    ) -> PartiallySignedTransaction
    where
        I: IntoIterator<Item = TxOut>,
    {
        let mut iter = funding_txos.into_iter();
        let funding_txout = iter.next().unwrap(); // we assume there is at least 1.

        let mut proposal_psbt = original_psbt.clone();
        // determine whether we replace original psbt's owned output
        // or whether we change the value to be wallet amount
        if self.wallet_amount() == bitcoin::Amount::ZERO {
            assert_eq!(funding_txout.value, self.channels[0].amount.as_sat());
            proposal_psbt.unsigned_tx.output[owned_vout] = funding_txout;
        } else {
            proposal_psbt.unsigned_tx.output[owned_vout].value = self.wallet_amount().as_sat();
            proposal_psbt.unsigned_tx.output.push(funding_txout)
        }

        // add remaining funding txouts
        proposal_psbt.unsigned_tx.output.extend(iter);

        // psbt should have outputs same length as contained unsigned tx
        proposal_psbt.outputs.resize_with(proposal_psbt.unsigned_tx.output.len(), Default::default);

        eprintln!("channel funding Proposal PSBT created: {:#?}", proposal_psbt);

        proposal_psbt
    }
}

pub type ChannelId = [u8; 32];

fn temporary_channel_id() -> ChannelId { rand::random() }

/// [Scheduler] lets you pre-batch PayJoins, usually containing Channel Opens.
#[derive(Clone)]
pub struct Scheduler {
    lnd: LndClient,
    pjs: Arc<Mutex<HashMap<Script, ScheduledPayJoin>>>, // payjoins mapped by owned `scriptPubKey`s
}

impl Scheduler {
    /// New [Scheduler].
    pub fn new(lnd: LndClient) -> Self { Self { lnd, pjs: Default::default() } }

    pub async fn from_config(config: &crate::config::Config) -> Result<Self, SchedulerError> {
        Ok(Scheduler::new(LndClient::from_config(&config).await?))
    }

    /// Schedules a payjoin.
    pub async fn schedule_payjoin(
        &self,
        pj: &ScheduledPayJoin,
    ) -> Result<bitcoin::Address, SchedulerError> {
        pj.test_connections(&self.lnd).await?;
        let bitcoin_addr = self.lnd.get_new_bech32_address().await?;

        if self.insert_payjoin(&bitcoin_addr, pj) {
            Ok(bitcoin_addr)
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
        eprintln!("Received psbt: {:#?}", original_psbt);

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
        let funding_txouts = open_chan_results.iter().map(|(_, txo)| txo.clone());
        let temporary_chan_ids = open_chan_results.iter().map(|(id, _)| *id);

        // create and send `funding_created` to all responding lightning nodes
        let proposal_psbt = pj.add_channels_to_psbt(original_psbt, owned_vout, funding_txouts);

        let mut raw_psbt = Vec::new();
        proposal_psbt.consensus_encode(&mut raw_psbt).unwrap();
        self.lnd.verify_funding(&raw_psbt, temporary_chan_ids).await?;

        // TODO explain why we're doing this superfluous bit or remove it
        let proposal_psbt =
            PartiallySignedTransaction::from_unsigned_tx(proposal_psbt.unsigned_tx.clone())
                .expect("resetting tx failed");
        eprintln!("Proposal PSBT that will be returned: {:#?}", proposal_psbt);

        let mut psbt_bytes = Vec::new();
        proposal_psbt.consensus_encode(&mut psbt_bytes).unwrap();
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
}

pub fn calculate_fees(
    channel_count: u64,
    fee_rate: u64,
    has_additional_output: bool,
) -> bitcoin::Amount {
    let additional_vsize = if has_additional_output {
        channel_count * (8 + 1 + 1 + 32)
    } else {
        (channel_count - 1) * (8 + 1 + 1 + 32) + 12
    };

    bitcoin::Amount::from_sat(fee_rate * additional_vsize)
}

#[derive(Debug)]
pub enum SchedulerError {
    Lnd(LndError),
    /// Internal error that should not be shared
    Internal(&'static str),
    /// Output Substitution is required to change the original output to a channel open
    OutputSubstitutionDisabled,
    /// No Original Psbt outputs match any [ScheduledPayJoin]
    NoMatchingPayJoin,
    /// Failed to open any channel for [ScheduledPayJoin]
    PayJoinCannotOpenAnyChannel,
    /// Original Psbt does not respect requested amount
    OriginalPsbtInvalidAmount,
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
