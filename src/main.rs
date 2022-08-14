mod api;
mod args;
mod lnd;
pub mod scheduler;

use lnd::LndClient;
use scheduler::ScheduledPayJoin;

use crate::args::parse_args;
use crate::scheduler::Scheduler;

#[macro_use]
extern crate serde_derive;
extern crate configure_me;

configure_me::include_config!();

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // parse config file and remaining cli args
    // * currently we parse only a single scheduled payjoin from CLI args
    let (config, args) =
        Config::including_optional_config_files(std::iter::empty::<&str>()).unwrap_or_exit();
    let scheduled_pj = parse_args(args).expect("failed to parse remaining arguments");

    // init scheduler
    let scheduler = Scheduler::new(LndClient::from_config(&config).await?);

    // prepare initial scheduled pj (if any)
    if let Some(payjoin) = scheduled_pj {
        let bitcoin_addr = scheduler.schedule_payjoin(&payjoin).await?;

        // TODO: This should not be hardcoded
        // * Optional cli flag or ENV for pj address (in the case of port forwarding), otherwise
        //      we should determine the bip21 string using `api::ServeOptions`
        println!(
            "bitcoin:{}?amount={}&pj=http://127.0.0.1:{}/pj",
            bitcoin_addr,
            payjoin.total_amount().to_string_in(bitcoin::Denomination::Bitcoin),
            config.bind_port,
        );
    }

    // serve HTTP endpoints
    let serve_opts = api::ServeOptions {
        bind_addr: ([127, 0, 0, 1], config.bind_port).into(),
        serve_static: true,
    };
    api::serve_http(scheduler, serve_opts).await?;

    Ok(())
}
