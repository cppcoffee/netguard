use std::fs::File;
use std::io::Read;
use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use pnet::datalink::NetworkInterface;

/// Route discovered via /proc
struct Route {
    destination: u64,
    gateway: u64,
    iface: String,
}

/// Discovered interface
#[derive(Debug)]
pub struct Interface {
    inner: NetworkInterface,
}

impl Route {
    /// The first few fields of the /proc/net/route table consist of:
    ///
    /// Iface   Destination Gateway
    /// eno1    00000000    0102A8C0
    ///
    /// Which tells us the
    fn from_line(line: &str) -> Result<Self> {
        let v: Vec<&str> = line.split('\t').collect();
        Ok(Self {
            iface: v.first().context("Index out of Bounds")?.to_string(),
            destination: u64::from_str_radix(v.get(1).context("Index out of Bounds")?, 16)?,
            gateway: u64::from_str_radix(v.get(2).context("Index out of Bounds")?, 16)?,
        })
    }
}

impl Interface {
    /// Use the interface name to initialize a new Interface
    pub fn from_name(name: &str) -> Result<Self> {
        let interfaces = pnet::datalink::interfaces();
        for i in interfaces {
            if i.name == name {
                return Ok(Self { inner: i });
            }
        }

        bail!("Invalid interface name: {}", name)
    }

    /// Grab an interface's source IP
    pub fn get_ip(&self) -> Result<IpAddr> {
        Ok(self
            .inner
            .ips
            .get(0)
            .context("Invalid interface name")?
            .ip())
    }

    /// Get the interface's name
    pub fn get_name(&self) -> &str {
        &self.inner.name
    }

    /// Get a Linux host's default gateway
    pub fn try_default() -> Result<Self> {
        let path = "/proc/net/route";
        let mut file = File::open(path).context(format!("fail to open file: {}", path))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .context(format!("fail to read file: {}", path))?;

        for line in contents.lines() {
            // Ignore bad lines
            let route = match Route::from_line(line) {
                Ok(r) => r,
                _ => continue,
            };

            // A destination address of 0.0.0.0 implies the default
            // gateway
            if route.destination == 0 && route.gateway != 0 {
                return Self::from_name(&route.iface);
            }
        }

        bail!("No default interface")
    }
}
