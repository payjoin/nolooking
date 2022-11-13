pub mod args;
mod http;
mod lnd;
mod recommend;
pub mod scheduler;

use scheduler::Scheduler;

use crate::args::parse_args;

#[macro_use]
extern crate serde_derive;
extern crate configure_me;

configure_me::include_config!();

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (config, args) =
        Config::including_optional_config_files(std::iter::empty::<&str>()).unwrap_or_exit();

    let scheduled_pj = parse_args(args).expect("failed to parse remaining arguments");
    let secure_endpoint: url::Url = config.endpoint.parse().expect("Malformed secure endpoint from config file. Expecting a https or .onion URI to proxy payjoin requests");

    let scheduler = Scheduler::from_config(&config).await?;

    if let Some(payjoin) = scheduled_pj {
        let address = scheduler.schedule_payjoin(&payjoin).await?;
        println!(
            "{}",
            scheduler::format_bip21(address, payjoin.total_amount(), secure_endpoint.clone())
        );
    }

    let bind_addr = (config.bind_ip, config.bind_port).into();
    http::serve(scheduler, bind_addr, secure_endpoint).await?;

    Ok(())
}
