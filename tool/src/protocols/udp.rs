use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::{self, MutableUdpPacket};

use super::PktWrapper;

/// Builder abstraction to build a raw UDP packet
pub struct UdpBuilder<'a> {
    /// The packet being constructed
    pkt: MutableUdpPacket<'a>,

    /// The calculated total length
    length: usize,

    /// Source IP address
    src: IpAddr,

    /// Destination IP address
    dst: IpAddr,

    /// Destination port
    dport: u16,

    /// Pre-computed payload
    payload: &'a [u8],
}

impl<'a> UdpBuilder<'a> {
    /// Begin building a new UDP packet by providing the source and
    /// destination IP addresses, the destination port, and the
    /// appropriate payload.
    pub fn new(
        src: IpAddr,
        dst: IpAddr,
        dport: u16,
        payload: &'a [u8],
    ) -> Result<Self> {
        let length = Self::packet_size(payload.len(), dst.is_ipv4());
        Ok(Self {
            pkt: MutableUdpPacket::owned(vec![0; length]).context("The platform is out of memory")?,
            length,
            src,
            dst,
            dport,
            payload,
        })
    }

    /// Determine minimum packet size to allocate an appropriate backing
    /// store to construct the MutableUdpPacket.
    ///
    /// Adds the Ethernet Header + IP Header + UDP Header + Payload to
    /// determine the minimum length.
    fn packet_size(payload_len: usize, ipv4: bool) -> usize {
        // Layer 2 length
        let mut length: usize = EthernetPacket::minimum_packet_size();

        // Layer 3 length
        length += match ipv4 {
            true => Ipv4Packet::minimum_packet_size(),
            false => Ipv6Packet::minimum_packet_size(),
        };

        // Layer 4 length + payload
        length += MutableUdpPacket::minimum_packet_size();
        length += payload_len;
        length
    }

    /// Finalize the packet, providing a PktWrapper which can be sent
    /// out the raw socket opened via the pnet crate.
    ///
    /// Sets appropriate UDP header information, and computes the
    /// appropriate Layer 4 checksum.
    pub fn build(mut self) -> Result<PktWrapper<'a>> {
        self.pkt.set_source(rand::random::<u16>());
        self.pkt.set_destination(self.dport);
        self.pkt.set_length(self.length as u16);

        // Add the payload
        self.pkt.set_payload(self.payload);

        // Compute the checksum
        let checksum = match (self.src, self.dst) {
            (IpAddr::V4(src_ip4), IpAddr::V4(dst_ip4)) => {
                udp::ipv4_checksum(&self.pkt.to_immutable(), &src_ip4, &dst_ip4)
            }
            (IpAddr::V6(src_ip6), IpAddr::V6(dst_ip6)) => {
                udp::ipv6_checksum(&self.pkt.to_immutable(), &src_ip6, &dst_ip6)
            }
            _ => {
                println!("[-] Unknown IP Address type");
                return Err(anyhow!("IP address invalid, must be IPv4 or IPv6"));
            }
        };

        self.pkt.set_checksum(checksum);

        // Completed packet
        Ok(PktWrapper::Udp(self.pkt))
    }
}
