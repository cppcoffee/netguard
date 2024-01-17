use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::sync::mpsc;
use std::{ptr, thread};

use anyhow::{anyhow, bail, Result};
use log::error;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};

use crate::reject::Message;
use crate::util;

const ICMP_UNREACHABLE_HEADER_SIZE: usize = 8;
const UDP_CHECKSUM_OFFSET: usize = 6;

const BUFFER_SIZE: usize = 128;

#[derive(Clone)]
pub struct RejectPacketSender {
    inner: mpsc::Sender<Message>,
}

impl RejectPacketSender {
    pub fn new() -> Result<Self> {
        let tx = Sender::new()?.start();

        Ok(Self { inner: tx })
    }

    pub fn emit_icmp_unreachable(
        &self,
        source: &IpAddr,
        destination: &IpAddr,
        ip_packet: &[u8],
        udp_packet_header: &[u8],
    ) -> Result<()> {
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
                let mut icmp_packet = MutableIcmpPacket::owned(buffer[..length].to_vec())
                    .ok_or(anyhow!("Failed to create ICMP packet"))?;

                util::build_icmpv4_unreachable(&mut icmp_packet);

                self.inner.send(Message::Icmp {
                    destination: *destination,
                    icmp_packet,
                })?;
            }
            (IpAddr::V6(src), IpAddr::V6(dest)) => {
                let mut icmp_packet = MutableIcmpv6Packet::owned(buffer[..length].to_vec())
                    .ok_or(anyhow!("Failed to create ICMP packet"))?;

                util::build_icmpv6_unreachable(&mut icmp_packet, src, dest);

                self.inner.send(Message::Icmpv6 {
                    destination: *destination,
                    icmp_packet,
                })?;
            }
            _ => bail!("IP version mismatch"),
        }

        Ok(())
    }

    pub fn emit_tcp_rst(
        &self,
        destination: &IpAddr,
        source: &IpAddr,
        tcp_header: &TcpPacket,
    ) -> Result<()> {
        let tcp_min_size = TcpPacket::minimum_packet_size();

        let buffer = MaybeUninit::<[u8; BUFFER_SIZE]>::uninit();
        let buffer = unsafe { ptr::read(buffer.as_ptr() as *const [u8; BUFFER_SIZE]) };

        let mut tcp_packet = MutableTcpPacket::owned(buffer[..tcp_min_size].to_vec())
            .ok_or(anyhow!("Failed to create TCP packet"))?;

        util::build_tcp_reset(&mut tcp_packet, destination, source, tcp_header)?;

        self.inner.send(Message::Tcp {
            destination: *destination,
            tcp_packet,
        })?;

        Ok(())
    }
}

struct Sender {
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
            icmpv6,
            tcp,
            tcp6,
        })
    }

    pub fn start(mut self) -> mpsc::Sender<Message> {
        let (tx, rx) = mpsc::channel::<Message>();

        thread::spawn(move || {
            for msg in rx {
                if let Err(e) = self.message_handler(msg) {
                    error!("Failed to handle message: {:?}", e);
                }
            }
        });

        tx
    }

    fn message_handler(&mut self, msg: Message) -> Result<()> {
        match msg {
            Message::Icmp {
                destination,
                icmp_packet,
            } => self
                .icmp
                .send_to(icmp_packet, destination)
                .context("send ICMP packet"),
            Message::Icmpv6 {
                destination,
                icmp_packet,
            } => self
                .icmpv6
                .send_to(icmp_packet, destination)
                .context("send ICMPv6 packet"),
            Message::Tcp {
                destination,
                tcp_packet,
            } => match destination {
                IpAddr::V4(_) => self
                    .tcp
                    .send_to(tcp_packet, destination)
                    .context("send TCP packet"),
                IpAddr::V6(_) => self
                    .tcp6
                    .send_to(tcp_packet, destination)
                    .context("send TCPv6 packet"),
            },
        }
    }
}
