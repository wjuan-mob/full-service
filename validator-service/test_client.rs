use std::{env, sync::Arc};

use grpcio::{CallOption, ChannelBuilder, EnvBuilder};
use mc_common::logger;
use mc_consensus_api::{consensus_common_grpc::BlockchainApiClient, empty::Empty};

fn main() {
    mc_common::setup_panic_handler();
    let args = env::args().collect::<Vec<_>>();
    let (logger, _global_logger_guard) = logger::create_app_logger(logger::o!());

    if args.len() != 2 {
        panic!("Expected exactly one argument, the port to connect to.")
    }
    let port = args[1]
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("{} is not a valid port number", args[1]));

    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(format!("localhost:{}", port).as_str());
    let blockchain_api_client = BlockchainApiClient::new(ch.clone());
    let (_, message, _) = blockchain_api_client
        .get_last_block_info_full(&Empty::new(), CallOption::default())
        .unwrap();
    logger::log::info!(logger, "Message: {:?}", message);
}
