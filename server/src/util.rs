use std::net::{IpAddr, Ipv6Addr};

use anyhow::{bail, Result};
use pnet::packet::icmp::destination_unreachable::IcmpCodes;
use pnet::packet::icmp::{checksum as icmp_checksum, IcmpTypes, MutableIcmpPacket};
use pnet::packet::icmpv6::{
    checksum as icmp6_checksum, Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet,
};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;

const PORT_UNREACHABLE: u8 = 4;

pub fn build_icmpv4_unreachable(icmp_packet: &mut MutableIcmpPacket) {
    icmp_packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
    icmp_packet.set_icmp_code(IcmpCodes::DestinationPortUnreachable);
    icmp_packet.set_payload(&[]);

    let checksum = icmp_checksum(&icmp_packet.to_immutable());
    icmp_packet.set_checksum(checksum);
}

pub fn build_icmpv6_unreachable(
    icmp_packet: &mut MutableIcmpv6Packet,
    src: &Ipv6Addr,
    dest: &Ipv6Addr,
) {
    icmp_packet.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
    icmp_packet.set_icmpv6_code(Icmpv6Code(PORT_UNREACHABLE));
    icmp_packet.set_payload(&[]);

    let checksum = icmp6_checksum(&icmp_packet.to_immutable(), src, dest);
    icmp_packet.set_checksum(checksum);
}

pub fn build_tcp_reset(
    tcp_packet: &mut MutableTcpPacket,
    source: &IpAddr,
    destination: &IpAddr,
    tcp_header: &TcpPacket,
) -> Result<()> {
    let tcp_min_size = TcpPacket::minimum_packet_size();
    let header_length = (tcp_min_size / 4) as u8;

    tcp_packet.set_source(tcp_header.get_destination());
    tcp_packet.set_destination(tcp_header.get_source());
    tcp_packet.set_acknowledgement(tcp_header.get_sequence() + 1);
    tcp_packet.set_sequence(0);
    tcp_packet.set_flags(TcpFlags::RST);
    tcp_packet.set_window(0);
    tcp_packet.set_reserved(0);
    tcp_packet.set_data_offset(header_length);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_options(&[]);
    tcp_packet.set_payload(&[]);

    let checksum = match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src, &dst)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src, &dst)
        }
        _ => {
            bail!("Source and destination IP addresses must be both IPv4 or IPv6")
        }
    };

    tcp_packet.set_checksum(checksum);

    Ok(())
}

#[inline]
pub fn packet_header(p: &impl Packet) -> &[u8] {
    let packet = p.packet();
    let len = packet.len() - p.payload().len();
    &packet[..len]
}

pub fn set_thread_priority() -> Result<()> {
    let rc = unsafe {
        let handle = libc::pthread_self();
        let mut param: libc::sched_param = std::mem::zeroed();
        param.sched_priority = libc::sched_get_priority_max(libc::SCHED_FIFO);

        let policy = libc::SCHED_FIFO;
        libc::pthread_setschedparam(handle, policy, &param)
    };

    if rc != 0 {
        bail!("Failed to set thread priority: {}", rc);
    }

    Ok(())
}

#[inline]
pub fn set_process_priority(n: i32) {
    unsafe {
        libc::nice(n);
    }
}

#[inline]
pub fn set_rlimit_nofile(n: u64) -> Result<u64> {
    let value = rlimit::increase_nofile_limit(n)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::udp::UdpPacket;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_build_icmpv4_unreachable() {
        let mut data = vec![0u8; 128];
        let mut icmp_packet = MutableIcmpPacket::owned(data.clone()).unwrap();

        build_icmpv4_unreachable(&mut icmp_packet);

        assert_eq!(
            icmp_packet.get_icmp_type(),
            IcmpTypes::DestinationUnreachable
        );

        assert_eq!(
            icmp_packet.get_icmp_code(),
            IcmpCodes::DestinationPortUnreachable
        );

        assert_eq!(icmp_packet.get_checksum(), 0xfcfc);
    }

    #[test]
    fn test_build_icmpv6_unreachable() {
        let mut data = vec![0u8; 128];
        let src = Ipv6Addr::new(1, 1, 1, 1, 1, 1, 1, 1);
        let dest = Ipv6Addr::new(2, 2, 2, 2, 2, 2, 2, 2);

        let mut icmp_packet = MutableIcmpv6Packet::owned(data.clone()).unwrap();
        build_icmpv6_unreachable(&mut icmp_packet, &src, &dest);

        assert_eq!(
            icmp_packet.get_icmpv6_type(),
            Icmpv6Types::DestinationUnreachable
        );

        assert_eq!(icmp_packet.get_icmpv6_code(), Icmpv6Code(PORT_UNREACHABLE));
        assert_eq!(icmp_packet.get_checksum(), 0xFE29);
    }

    #[test]
    fn test_build_tcp_reset() {
        let incoming = TcpPacket::new(&[0u8; 40]).unwrap();

        let mut buffer = vec![0u8; 128];
        let mut tcp_reset = MutableTcpPacket::owned(buffer.clone()).unwrap();

        build_tcp_reset(
            &mut tcp_reset,
            &IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            &IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            &incoming,
        )
        .unwrap();

        assert_eq!(tcp_reset.get_source(), incoming.get_destination());
        assert_eq!(tcp_reset.get_destination(), incoming.get_source());
        assert_eq!(tcp_reset.get_acknowledgement(), incoming.get_sequence() + 1);
        assert_eq!(tcp_reset.get_sequence(), 0);
        assert_eq!(tcp_reset.get_flags(), TcpFlags::RST);
        assert_eq!(tcp_reset.get_window(), 0);
        assert_eq!(tcp_reset.get_reserved(), 0);
        assert_eq!(tcp_reset.get_urgent_ptr(), 0);
        assert_eq!(
            tcp_reset.get_data_offset(),
            (TcpPacket::minimum_packet_size() / 4) as u8
        );
        assert_eq!(tcp_reset.get_options().len(), 0);
        assert_eq!(tcp_reset.payload().len(), 0);
    }
}
