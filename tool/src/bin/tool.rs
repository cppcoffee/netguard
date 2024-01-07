use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportProtocol::Ipv6;

use tool::protocols::{PktWrapper, TcpBuilder, UdpBuilder};
use tool::route::Interface;

/// Supported algorithm types for keys/signing
#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
enum Algorithm {
    Rsa,
    // TODO: add support for ed25519
}

/// Supported layer 4 protocols
#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Parser, Debug)]
#[command(
    about = "NetGuard Client Tool",
    long_about = None
)]
enum Args {
    /// Generate NetGuard Keys
    #[command(name = "keygen")]
    KeyGen {
        /// Algorithm to use
        #[arg(value_enum, short, long, default_value_t = Algorithm::Rsa)]
        alg: Algorithm,

        /// Key size in bits
        #[arg(short, long, default_value_t = 4096)]
        bits: usize,

        /// Output file path
        #[arg(short, long, default_value = "./.netguard/rsa")]
        out: PathBuf,
    },

    /// Authenticate with a NetGuard server
    Auth {
        /// Address of server running NetGuard
        #[arg(short, long)]
        server: String,

        /// Specify the outgoing interface to use
        #[arg(short, long)]
        interface: Option<String>,

        /// Auth packet Layer 4 protocol
        #[arg(value_enum, short, long, default_value_t = Protocol::Udp)]
        protocol: Protocol,

        /// Auth packet destination port
        #[arg(short, long, default_value_t = 53)]
        dport: u16,

        /// Port to unlock
        #[arg(short, long)]
        unlock: u16,

        /// Private key for signing
        #[arg(short, long, default_value = "./.netguard/rsa")]
        key: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args {
        Args::KeyGen { alg, bits, out } => keygen(alg, bits, out)?,
        Args::Auth {
            server,
            interface,
            protocol,
            dport,
            unlock,
            key,
        } => auth(server, interface, protocol, dport, unlock, key)?,
    }

    Ok(())
}

fn keygen(alg: Algorithm, bits: usize, outfile: PathBuf) -> Result<()> {
    // Determine paths + directories
    let mut outfile_pub = outfile.clone();
    outfile_pub.set_extension("pub");

    let priv_path = Path::new(&outfile);
    let pub_path = Path::new(&outfile_pub);
    let parent = priv_path.parent().context("invalid parent path")?;

    // create the output directory if it doesn't exist
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    println!("[*] Generating {:?} keys...", alg);

    match alg {
        Algorithm::Rsa => {
            crypto::rsa_keygen(bits, priv_path, pub_path)?;
        }
    };

    println!("[+] Generated {:?} keys w/{} bits", alg, bits);

    Ok(())
}

fn auth(
    server: String,
    interface: Option<String>,
    proto: Protocol,
    dport: u16,
    uport: u16,
    key: PathBuf,
) -> Result<()> {
    // Check if a valid IpAddr was provided
    let target = server.parse::<IpAddr>().context("Invalid IP")?;

    // Determine which interface to use
    let iface = interface.map_or_else(Interface::try_default, |n| Interface::from_name(&n))?;

    // Determine the source IP of the interface
    let src_ip = iface.get_ip().context("Invalid interface")?;
    println!(
        "[+] Selected Interface {}, with address {}",
        iface.get_name(),
        src_ip
    );

    // Determine the layer 4 protocol
    let layer4 = match proto {
        Protocol::Tcp => IpNextHeaderProtocols::Tcp,
        Protocol::Udp => IpNextHeaderProtocols::Udp,
    };

    // Dynamically set the transport protocol, and calculate packet size
    // todo, see if the header size can be calculated and returned in tcp.rs & udp.rs
    let config: pnet::transport::TransportChannelType = match target.is_ipv4() {
        true => Layer4(Ipv4(layer4)),
        false => Layer4(Ipv6(layer4)),
    };

    // Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = transport_channel(crypto::MAX_PACKET_SIZE, config)
        .context("fail to create transport channel")?;

    // Build specific protocol data
    let data = crypto::build_knock_packet(uport, &key)?;

    // Create the packet
    let pkt: PktWrapper = match proto {
        Protocol::Tcp => TcpBuilder::new(src_ip, target, dport, &data)?.build()?,
        Protocol::Udp => UdpBuilder::new(src_ip, target, dport, &data)?.build()?,
    };

    println!(
        "[+] Sending {:?} packet to {}:{} to unlock port {}",
        proto, target, dport, uport
    );

    // Send it
    let n = tx.send_to(pkt, target)?;
    println!("[+] Sent {} bytes", n);

    Ok(())
}
