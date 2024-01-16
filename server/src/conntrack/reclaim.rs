use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tracing::{error, info};

use crate::{Config, ConntrackMap};

pub struct ConntrackReclaim {
    config: Arc<Config>,
    conntrack_map: Arc<ConntrackMap>,
}

impl ConntrackReclaim {
    pub fn new(config: Arc<Config>, conntrack_map: Arc<ConntrackMap>) -> Self {
        Self {
            config,
            conntrack_map,
        }
    }

    pub fn start(self) {
        let config = self.config;
        let conntrack_map = self.conntrack_map;

        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(config.filter.reclaim_interval));

            match conntrack_map.reclaim_expired_entries(config.filter.connection_timeout) {
                Ok((prev, len)) => {
                    info!("reclaim expired entries: {}, total: {}", prev - len, len);
                }
                Err(e) => {
                    error!("reclaim expired entries failed: {:?}", e)
                }
            }
        });
    }
}
