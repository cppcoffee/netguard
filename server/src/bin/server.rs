use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use tikv_jemallocator::Jemalloc;
use tracing::{debug, info};

use server::{iptables, panic_hook, util, Config, ConntrackMap, ConntrackReclaim, Worker};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./netguard.toml", value_name = "FILE")]
    config: PathBuf,
}

fn setup_logger() {
    let env = tracing_subscriber::EnvFilter::from_env("CARGO_LOG");

    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::Uptime::default())
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .with_env_filter(env)
        .init();

    info!(start = humantime::format_rfc3339(std::time::SystemTime::now()).to_string());
}

fn main() -> Result<()> {
    panic_hook::set_panic_hook();

    let args = Args::parse();
    let config = Config::from_file(&args.config)?;

    setup_logger();

    util::set_process_priority(config.setting.worker_priority);

    let conntrack_map = Arc::new(ConntrackMap::new());

    for i in 0..config.setting.queue_count {
        let queue_id = config.setting.queue_start + i;

        let worker = Worker::new(config.clone(), queue_id, conntrack_map.clone())?;
        worker.start()?;
    }

    ConntrackReclaim::new(config.clone(), conntrack_map.clone()).start();

    iptables::rules_create(&config)?;

    wait_for_signal()?;

    iptables::rules_destroy(&config)?;

    info!("server exit...");

    Ok(())
}

fn wait_for_signal() -> Result<()> {
    let sigs = TERM_SIGNALS;
    let mut signals = Signals::new(sigs)?;

    for signal in &mut signals {
        debug!("Received a signal {:?}", signal);

        match signal {
            term_sig => {
                info!("Received a termination signal {:?}", term_sig);
                break;
            }
        }
    }

    Ok(())
}
