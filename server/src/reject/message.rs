use std::net::IpAddr;

use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;

pub enum Message {
    Icmp {
        destination: IpAddr,
        icmp_packet: MutableIcmpPacket<'static>,
    },
    Icmpv6 {
        destination: IpAddr,
        icmp_packet: MutableIcmpv6Packet<'static>,
    },
    Tcp {
        destination: IpAddr,
        tcp_packet: MutableTcpPacket<'static>,
    },
}

