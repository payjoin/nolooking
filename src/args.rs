use std::ffi::OsString;
use std::fmt;
use std::num::ParseIntError;

use crate::scheduler::{ChannelBatch, ScheduledChannel};

/// CLI argument errors.
#[derive(Debug)]
pub enum ArgError {
    /// Argument not UTF-8
    NotUTF8(OsString),
    /// Parse feerate error
    FeeRateError(ParseIntError),
    /// Parse node address error
    InvalidNodeAddress(ln_types::p2p_address::ParseError),
    /// Parse bitcoin amount error
    InvalidBitcoinAmount(bitcoin::util::amount::ParseAmountError),
    /// Wallet amount error
    HangingArgument(String),
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Do this properly.
        write!(f, "invalid arguments: {:?}", self)
    }
}

impl std::error::Error for ArgError {}

/// Parses arguments in `[fee_rate] [(<p2p_addr>, <sats_amount>)...]`
pub fn parse_args<A>(args: A) -> Result<Option<ChannelBatch>, ArgError>
where
    A: Iterator<Item = OsString>,
{
    // ensure all args are utf8
    let args = args
        .map(|arg| arg.into_string())
        .collect::<Result<Vec<_>, _>>()
        .map_err(ArgError::NotUTF8)?;

    // first argument is fee rate
    let fee_rate = match args.get(0) {
        Some(fee_rate_str) => fee_rate_str.parse::<u64>().map_err(ArgError::FeeRateError)?,
        None => return Ok(None),
    };

    // return None if no remaining args.
    let mut args = match args.get(1..) {
        Some(args) => args.iter(),
        None => return Ok(None),
    };

    // parse scheduled channel arguments: pairs of (addr, amount)
    let mut channels = Vec::with_capacity(args.len() / 2);

    while let (Some(addr), Some(amount)) = (args.next(), args.next()) {
        channels.push(ScheduledChannel::from_args(addr, amount)?);
    }

    // ignore a remaining arguments

    Ok(Some(ChannelBatch::new(channels, false, fee_rate)))
}
