use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::ptr;

use anyhow::{bail, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};

use crate::util;

const ICMP_UNREACHABLE_HEADER_SIZE: usize = 8;
const UDP_CHECKSUM_OFFSET: usize = 6;

const BUFFER_SIZE: usize = 128;

pub struct Sender {
    icmp: TransportSender,
    tcp: TransportSender,
    icmpv6: TransportSender,
    tcp6: TransportSender,
}

impl Sender {
    pub fn new() -> Result<Self> {
        let (icmp, _) = transport_channel(
            0,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        )?;

        let (tcp, _) = transport_channel(
            0,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )?;

        let (icmpv6, _) = transport_channel(
            0,
            TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
        )?;

        let (tcp6, _) = transport_channel(
            0,
            TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
        )?;

        Ok(Self {
            icmp,
            tcp,
            icmpv6,
            tcp6,
        })
    }

    pub fn emit_icmp_unreachable(
        &mut self,
        source: &IpAddr,
        destination: &IpAddr,
        ip_packet: &[u8],
        udp_header: &UdpPacket,
    ) -> Result<()> {
        let udp_packet_header = util::packet_header(udp_header);

        let length = ICMP_UNREACHABLE_HEADER_SIZE + ip_packet.len() + udp_packet_header.len();
        if length >= BUFFER_SIZE {
            bail!("Packet too large")
        }

        let buffer = MaybeUninit::<[u8; BUFFER_SIZE]>::uninit();
        let mut buffer = unsafe { ptr::read(buffer.as_ptr() as *const [u8; BUFFER_SIZE]) };

        // ip header
        let ip_packet_len = ip_packet.len();
        let (_, right) = buffer.split_at_mut(ICMP_UNREACHABLE_HEADER_SIZE);
        right[..ip_packet_len].copy_from_slice(ip_packet);

        // udp header
        let udp_packet_len = udp_packet_header.len();
        let (_, right) = right.split_at_mut(ip_packet_len);
        right[..udp_packet_len].copy_from_slice(udp_packet_header);

        // zero out udp header checksum
        right[UDP_CHECKSUM_OFFSET..udp_packet_len].copy_from_slice(&[0, 0]);

        match (source, destination) {
            (IpAddr::V4(_), IpAddr::V4(_)) => {
                let icmp_packet = util::build_icmpv4_unreachable(&mut buffer[..length])?;
                self.icmp.send_to(icmp_packet, *destination)?;
            }
            (IpAddr::V6(src), IpAddr::V6(dest)) => {
                let icmp_packet = util::build_icmpv6_unreachable(&mut buffer[..length], src, dest)?;
                self.icmpv6.send_to(icmp_packet, *destination)?;
            }
            _ => bail!("IP version mismatch"),
        }

        Ok(())
    }

    pub fn emit_tcp_rst(
        &mut self,
        destination: &IpAddr,
        source: &IpAddr,
        tcp_header: &TcpPacket,
    ) -> Result<()> {
        let tcp_min_size = TcpPacket::minimum_packet_size();

        let buffer = MaybeUninit::<[u8; BUFFER_SIZE]>::uninit();
        let mut buffer = unsafe { ptr::read(buffer.as_ptr() as *const [u8; BUFFER_SIZE]) };

        let tcp_reset_packet =
            util::build_tcp_reset(&mut buffer[..tcp_min_size], destination, source, tcp_header)?;

        if destination.is_ipv4() {
            self.tcp.send_to(tcp_reset_packet, *destination)?;
        } else {
            self.tcp6.send_to(tcp_reset_packet, *destination)?;
        }

        Ok(())
    }
}
