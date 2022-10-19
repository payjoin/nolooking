pub mod args;
mod http;
mod lnd;
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

    let scheduler = Scheduler::from_config(&config).await?;

    if let Some(payjoin) = scheduled_pj {
        let address = scheduler.schedule_payjoin(&payjoin).await?;
        println!(
            "bitcoin:{}?amount={}&pj={}/pj",
            address,
            payjoin.total_amount().to_string_in(bitcoin::Denomination::Bitcoin),
            config.endpoint.unwrap_or("https://localhost:".to_string() + &config.bind_port.to_string())
        );
    }

    let bind_addr = ([127, 0, 0, 1], config.bind_port).into();
    http::serve(scheduler, bind_addr).await?;

    Ok(())
}
