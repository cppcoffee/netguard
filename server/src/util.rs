use std::net::IpAddr;

use anyhow::{anyhow, bail, Result};
use pnet::packet::icmp::destination_unreachable::IcmpCodes;
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{util, Packet};

pub fn build_icmpv4_unreachable<'a>(data: &'a mut [u8]) -> Result<MutableIcmpPacket<'a>> {
    let mut icmp_packet =
        MutableIcmpPacket::new(&mut data[..]).ok_or(anyhow!("Failed to create ICMP packet"))?;

    icmp_packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
    icmp_packet.set_icmp_code(IcmpCodes::DestinationPortUnreachable);

    let checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);

    Ok(icmp_packet)
}

pub fn build_tcp_reset<'a>(
    data: &'a mut [u8],
    source: &IpAddr,
    destination: &IpAddr,
    tcp_header: &TcpPacket,
) -> Result<MutableTcpPacket<'a>> {
    let header_length = (data.len() / 4) as u8;

    let mut tcp_packet =
        MutableTcpPacket::new(&mut data[..]).ok_or(anyhow!("Failed to create TCP packet"))?;

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

    Ok(tcp_packet)
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
        let mut icmp_packet = build_icmpv4_unreachable(&mut data).unwrap();

        assert_eq!(
            icmp_packet.get_icmp_type(),
            IcmpTypes::DestinationUnreachable
        );

        assert_eq!(
            icmp_packet.get_icmp_code(),
            IcmpCodes::DestinationPortUnreachable
        );

        assert_eq!(
            icmp_packet.get_checksum(),
            util::checksum(icmp_packet.packet(), 1)
        );

        let checksum = util::checksum(icmp_packet.packet(), 1);
        icmp_packet.set_checksum(checksum);
        assert_eq!(icmp_packet.get_checksum(), checksum);
    }

    #[test]
    fn test_packet_header() {
        let udp_packet = UdpPacket::new(&[0u8; 20]).unwrap();
        assert_eq!(packet_header(&udp_packet), &[0u8; 8]);

        let tcp_packet = TcpPacket::new(&[0u8; 40]).unwrap();
        assert_eq!(packet_header(&tcp_packet), &[0u8; 20]);
    }

    #[test]
    fn test_build_tcp_reset() {
        let tcp_min_size = TcpPacket::minimum_packet_size();

        let incoming = TcpPacket::new(&[0u8; 40]).unwrap();

        let mut buffer = vec![0u8; 128];
        let tcp_reset = build_tcp_reset(
            &mut buffer[..tcp_min_size],
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
        assert_eq!(tcp_reset.get_data_offset(), (tcp_min_size / 4) as u8);
        assert_eq!(tcp_reset.get_options().len(), 0);
        assert_eq!(tcp_reset.payload().len(), 0);
    }
}
