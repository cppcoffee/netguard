use std::process::Command;

use anyhow::{bail, Result};
use tracing::debug;

use crate::Config;

pub fn rules_create(config: &Config) -> Result<()> {
    let queue_opts = nfqueue_options_build(config);
    let protocol = config.auth.protocol.as_str();

    iptables_rule_add(protocol, config.auth.port, &queue_opts)?;

    for port in &config.filter.tcp.ports {
        iptables_rule_add("tcp", *port, &queue_opts)?;
    }

    for port in &config.filter.udp.ports {
        iptables_rule_add("udp", *port, &queue_opts)?;
    }

    Ok(())
}

pub fn rules_destroy(config: &Config) -> Result<()> {
    let queue_opts = nfqueue_options_build(config);
    let protocol = config.auth.protocol.as_str();

    iptables_rule_del(protocol, config.auth.port, &queue_opts)?;

    for port in &config.filter.tcp.ports {
        iptables_rule_del("tcp", *port, &queue_opts)?;
    }

    for port in &config.filter.udp.ports {
        iptables_rule_del("udp", *port, &queue_opts)?;
    }

    Ok(())
}

fn iptables_rule_add(protocol: &str, port: u16, queue_opts: &[String]) -> Result<()> {
    let port = port.to_string();

    let mut args = vec![
        "-I", "INPUT", "-p", protocol, "--dport", &port, "-j", "NFQUEUE",
    ];

    for opt in queue_opts {
        args.push(opt.as_str());
    }

    iptables_command(&args)?;

    Ok(())
}

fn iptables_rule_del(protocol: &str, port: u16, queue_opts: &[String]) -> Result<()> {
    let port = port.to_string();

    let mut args = vec![
        "-D", "INPUT", "-p", protocol, "--dport", &port, "-j", "NFQUEUE",
    ];

    for opt in queue_opts {
        args.push(opt.as_str());
    }

    iptables_command(&args)?;

    Ok(())
}

fn iptables_command(args: &[&str]) -> Result<()> {
    debug!("command: iptables {:?}", args);

    let output = Command::new("iptables").args(args).output()?;
    if !output.status.success() {
        bail!(
            "iptables command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn nfqueue_options_build(config: &Config) -> Vec<String> {
    let mut opts = Vec::new();

    if config.setting.queue_count > 1 {
        opts.push("--queue-balance".to_string());
        opts.push(format!(
            "{}:{}",
            config.setting.queue_start, config.setting.queue_count
        ));
    } else {
        opts.push("--queue-num".to_string());
        opts.push(config.setting.queue_start.to_string());
    };

    opts
}
