use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::sync::{Arc, Mutex};

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
    pub(crate) channels: Vec<ScheduledChannel>,
    pub(crate) fee_rate: u64,
}

impl ScheduledPayJoin {
    pub(crate) fn new(
        wallet_amount: bitcoin::Amount,
        channels: Vec<ScheduledChannel>,
        fee_rate: u64,
    ) -> Self {
        Self { wallet_amount, channels, fee_rate }
    }

    pub fn calculate_fees(&self) -> bitcoin::Amount {
        let channel_count = self.channels.len() as u64;

        let additional_vsize = if self.wallet_amount == bitcoin::Amount::ZERO {
            (channel_count - 1) * (8 + 1 + 1 + 32) + 12
        } else {
            channel_count * (8 + 1 + 1 + 32)
        };

        bitcoin::Amount::from_sat(self.fee_rate * additional_vsize)
    }

    pub fn sum_channel_amounts(&self) -> bitcoin::Amount {
        self.channels.iter().map(|chan| chan.amount).fold(bitcoin::Amount::ZERO, std::ops::Add::add)
    }

    pub fn wallet_amount(&self) -> bitcoin::Amount { self.wallet_amount }

    /// Calculates the expected owned output value that this scheduled payjoin should have.
    pub fn total_amount(&self) -> bitcoin::Amount {
        let fees = self.calculate_fees();
        let channel_amounts_sum = self.sum_channel_amounts();

        fees + channel_amounts_sum + self.wallet_amount
    }

    /// Test connections with remote lightning nodes that we are trying to create channels with as
    /// part of this [ScheduledPayJoin].
    pub async fn test_connections(&self, client: &LndClient) -> Result<(), LndError> {
        let handles = self
            .channels
            .iter()
            .map(|ch| (client.clone(), ch.node.clone()))
            .map(|(client, node)| {
                tokio::spawn(async move { client.ensure_node_connected(node).await })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.await.unwrap()?;
        }
        Ok(())
    }

    /// Generates `open_channel` requests for each channel associated with the [ScheduledPayJoin].
    pub fn generate_open_channel_requests(
        &self,
    ) -> Vec<(P2PAddress, ChannelId, OpenChannelRequest)> {
        self.channels
            .iter()
            .map(|chan| {
                let node_addr = chan.node.clone();
                let chan_id = generate_channel_id();

                let psbt_shim = tonic_lnd::rpc::PsbtShim {
                    pending_chan_id: chan_id.into(),
                    base_psbt: Vec::new(),
                    no_publish: true,
                };
                let funding_shim = tonic_lnd::rpc::funding_shim::Shim::PsbtShim(psbt_shim);
                let funding_shim = tonic_lnd::rpc::FundingShim { shim: Some(funding_shim) };

                // TODO: Should these fields be configurable?
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
}

pub type ChannelId = [u8; 32];

fn generate_channel_id() -> ChannelId { rand::random() }

#[derive(Clone)]
pub struct Scheduler {
    lnd: LndClient,                                     // LND client
    pjs: Arc<Mutex<HashMap<Script, ScheduledPayJoin>>>, // payjoins mapped by owned `scriptPubKey`s
}

impl Scheduler {
    /// New [Scheduler].
    pub fn new(lnd: LndClient) -> Self { Self { lnd, pjs: Default::default() } }

    /// Schedules a payjoin.
    pub async fn schedule_payjoin(
        &self,
        pj: &ScheduledPayJoin,
    ) -> Result<bitcoin::Address, SchedulerError> {
        pj.test_connections(&self.lnd).await?;
        let bitcoin_addr = self.lnd.new_bech32_address().await?;

        if self.insert_payjoin(&bitcoin_addr, pj) {
            Ok(bitcoin_addr)
        } else {
            Err(SchedulerError::Internal("lnd provided duplicate bitcoin addresses"))
        }
    }

    /// Given the original PSBT request (which is checked), we attempt to satisfy the payjoin,
    /// returning a base64-encoded proposal PSBT (BIP-0078).
    pub async fn satisfy_payjoin(
        &self,
        original_req: UncheckedProposal,
    ) -> Result<String, SchedulerError> {
        if original_req.is_output_substitution_disabled() {
            // TODO handle error for output substitution properly, don't panic
            panic!("Output substitution must be enabled");
        }
        let proposal = original_req
            // This is interactive, NOT a Payment Processor, so we don't save original tx.
            // Humans can solve the failure case out of band by trying again.
            .assume_interactive_receive_endpoint()
            .assume_no_inputs_owned() // TODO Check
            .assume_no_mixed_input_scripts() // This check is silly and could be ignored
            .assume_no_inputs_seen_before(); // TODO

        let proposal_psbt = proposal.psbt().clone();
        eprintln!("Received psbt: {:#?}", proposal_psbt);

        // prepare proposal psbt
        let mut proposal_psbt =
            self.pop_payjoin(proposal_psbt)?.ok_or(SchedulerError::OriginalPsbtNotRecognized)?;

        // multi `open_channel` requests, return funding txouts
        let (funding_txouts, chan_ids) = proposal_psbt.multi_open_channel(&self.lnd).await?;

        // `funding_created` request
        let funding_created_psbt = proposal_psbt.generate_funding_created(funding_txouts)?;
        self.lnd.verify_funding(&funding_created_psbt, chan_ids).await?;

        // return proposal psbt
        let bip78_proposal_psbt = proposal_psbt.generate_from_unsigned_tx();
        Ok(base64::encode(bip78_proposal_psbt))
    }

    /// Insert payjoin associated with bitcoin address.
    fn insert_payjoin(&self, bitcoin_addr: &Address, pj: &ScheduledPayJoin) -> bool {
        let mut pj_by_spk = self.pjs.lock().unwrap();
        pj_by_spk.insert(bitcoin_addr.script_pubkey(), pj.clone()).is_none()
    }

    /// If an psbt output matches one of the scheduled payjoins, we pop the payjoin and create a
    /// [ProposalPsbt].
    fn pop_payjoin(
        &self,
        mut psbt: PartiallySignedTransaction,
    ) -> Result<Option<ProposalPsbt>, SchedulerError> {
        let mut pj_by_spk = self.pjs.lock().unwrap();

        // remove signatures from psbt
        psbt.unsigned_tx.input.iter_mut().for_each(|txin| txin.script_sig = bitcoin::Script::new());

        // find vout of owned output, pop scheduled psbt
        let proposed_psbt = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find_map(|(vout, txout)| pj_by_spk.remove(&txout.script_pubkey).map(|pj| (vout, pj)))
            .map(|(owned_vout, pj)| ProposalPsbt { psbt, owned_vout, pj });

        // check psbt amount
        // TODO: we still pop scheduled pj if this happens, is this okay?
        if let Some(psbt) = proposed_psbt.as_ref() {
            if !psbt.check_amounts() {
                return Err(SchedulerError::OriginalPsbtInvalidAmount);
            }
        }

        Ok(proposed_psbt)
    }
}

pub struct ProposalPsbt {
    psbt: PartiallySignedTransaction,
    owned_vout: usize,
    pj: ScheduledPayJoin,
}

impl ProposalPsbt {
    pub fn owned_output(&self) -> &TxOut { &self.psbt.unsigned_tx.output[self.owned_vout] }

    pub fn owned_output_mut(&mut self) -> &mut TxOut {
        &mut self.psbt.unsigned_tx.output[self.owned_vout]
    }

    pub fn check_amounts(&self) -> bool {
        let chan_amounts_sum = self.pj.sum_channel_amounts();
        let fees = self.pj.calculate_fees();
        let wallet_amount = self.pj.wallet_amount();

        let owned_txout_value = self.owned_output().value;

        (chan_amounts_sum + fees + wallet_amount).as_sat() == owned_txout_value
    }

    pub async fn multi_open_channel(
        &self,
        lnd: &LndClient,
    ) -> Result<(Vec<TxOut>, Vec<ChannelId>), SchedulerError> {
        let requests = self.pj.generate_open_channel_requests();

        let handles = requests
            .iter()
            .cloned()
            .map(|(node, _, req)| {
                let lnd = lnd.clone();
                tokio::spawn(async move { open_channel(lnd, node, req).await })
            })
            .collect::<Vec<_>>();

        let mut funding_vouts = Vec::<TxOut>::with_capacity(handles.len());
        for handle in handles {
            match handle.await.unwrap()? {
                Some(vout) => funding_vouts.push(vout),
                None => eprintln!("failed to receive funding psbt after channel open request - this is not handled"),
            };
        }

        if funding_vouts.is_empty() {
            Err(SchedulerError::PayJoinCannotOpenAnyChannel)
        } else {
            let chan_ids = requests.iter().map(|(_, id, _)| *id).collect::<Vec<_>>();
            Ok((funding_vouts, chan_ids))
        }
    }

    /// Creates a raw `funding_created` psbt.
    pub fn generate_funding_created<I>(
        &mut self,
        funding_txouts: I,
    ) -> Result<Vec<u8>, SchedulerError>
    where
        I: IntoIterator<Item = TxOut>,
    {
        let mut iter = funding_txouts.into_iter();
        let funding_txout = iter.next().unwrap(); // we assume there is at least 1.

        // determine whether we replace original psbt's owned output
        // or whether we change the value to be wallet amount
        if self.pj.wallet_amount() == bitcoin::Amount::ZERO {
            assert_eq!(funding_txout.value, self.pj.channels[0].amount.as_sat());
            *self.owned_output_mut() = funding_txout;
        } else {
            self.owned_output_mut().value = self.pj.wallet_amount().as_sat();
            self.psbt.unsigned_tx.output.push(funding_txout)
        }

        // add remaining funding txouts
        self.psbt.unsigned_tx.output.extend(iter);

        // psbt should have outputs same length as contained unsigned tx
        self.psbt.outputs.resize_with(self.psbt.unsigned_tx.output.len(), Default::default);

        eprintln!("channel funding PSBT created: {:#?}", self.psbt);

        // create `funding_created`
        let mut raw_psbt = Vec::new();
        self.psbt.consensus_encode(&mut raw_psbt).unwrap();

        Ok(raw_psbt)
    }

    pub fn generate_from_unsigned_tx(&self) -> Vec<u8> {
        // Reset transaction state to be non-finalized
        let psbt = PartiallySignedTransaction::from_unsigned_tx(self.psbt.unsigned_tx.clone())
            .expect("resetting tx failed");
        eprintln!("PSBT that will be returned: {:#?}", psbt);

        let mut psbt_bytes = Vec::new();
        psbt.consensus_encode(&mut psbt_bytes).unwrap();
        psbt_bytes
    }
}

/// Opens a channel with remote lnd node and returns the funding txout.
async fn open_channel(
    lnd: LndClient,
    node: P2PAddress,
    req: OpenChannelRequest,
) -> Result<Option<TxOut>, SchedulerError> {
    lnd.ensure_node_connected(node).await?;
    let funding_txout = lnd.open_channel(req).await?.map(|psbt| {
        assert_eq!(
            psbt.unsigned_tx.output.len(),
            1,
            "funding channel psbt should only have one output"
        );
        psbt.unsigned_tx.output[0].clone()
    });

    Ok(funding_txout)
}

#[derive(Debug)]
pub enum SchedulerError {
    Lnd(LndError),
    /// Internal error that should not be shared
    Internal(&'static str),
    /// Output substitution must be enabled
    OutputSubstitutionNotEnabled,
    /// Original Psbt does not have an associated payjoin that is scheduled
    OriginalPsbtNotRecognized,
    /// Original Psbt does not respect requested amount
    OriginalPsbtInvalidAmount,
    /// Failed to open any channel for [ScheduledPayJoin].
    PayJoinCannotOpenAnyChannel,
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
