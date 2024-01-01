use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub setting: Setting,
    pub auth: Auth,
    pub filter: Filter,
}

#[derive(Debug, Deserialize)]
pub struct Setting {
    pub queue_start: u16,
    pub queue_count: u16,
    pub worker_priority: i32,
}

#[derive(Debug, Deserialize)]
pub struct Auth {
    pub port: u16,
    pub key: PathBuf,
    pub protocol: Protocol,
    pub allow_skew: u64,
}

#[derive(Debug, Deserialize, Hash, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Filter {
    //pub allow_ips: Vec<String>,
    pub reclaim_interval: u64,
    pub connection_timeout: u64,
    pub tcp: Rule,
    pub udp: Rule,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub ports: Vec<u16>,
    pub reject: bool,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Arc<Self>> {
        let s = fs::read_to_string(path).context(format!("can't read file: {}", path.display()))?;
        let config: Config = toml::from_str(&s)?;

        config.verify()?;

        Ok(Arc::new(config))
    }

    fn verify(&self) -> Result<()> {
        if self.setting.queue_count == 0 {
            bail!("queue_count must be greater than 0");
        }

        if !self.auth.key.exists() {
            bail!("auth key file not found: {}", self.auth.key.display());
        }

        if self.auth.allow_skew < 1 {
            bail!("auth allow_skew_seconds must be greater than 0");
        }

        if self.filter.reclaim_interval < 1 {
            bail!("filter reclaim_interval_seconds must be greater than 0");
        }

        if self.filter.connection_timeout < 1 {
            bail!("filter connect_timeout_seconds must be greater than 0");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_verify() {
        let config = Config {
            setting: Setting {
                queue_start: 0,
                queue_count: 0,
                worker_priority: 0,
            },
            auth: Auth {
                port: 0,
                key: PathBuf::from(""),
                protocol: Protocol::Tcp,
                allow_skew: 10,
            },
            filter: Filter {
                reclaim_interval: 60,
                connection_timeout: 300,
                tcp: Rule {
                    ports: vec![],
                    reject: false,
                },
                udp: Rule {
                    ports: vec![],
                    reject: false,
                },
            },
        };

        assert!(config.verify().is_err());
    }
}
