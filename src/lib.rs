#[macro_use]
extern crate serde_derive;
extern crate configure_me;

pub mod scheduler;
pub mod http;
mod args;
pub mod lnd;
configure_me::include_config!();
