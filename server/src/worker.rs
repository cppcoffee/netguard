use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use nfq::{Queue, Verdict};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::VerifyingKey;
use rsa::sha2::Sha256;
use rsa::RsaPublicKey;
use tracing::{debug, error, info};

use crate::{util, Config, ConntrackEntry, ConntrackMap, Protocol, Sender};

const IPV4_ADDR_BITS: u8 = 32;
const IPV6_ADDR_BITS: u8 = 128;

pub struct Worker {
    queue_num: u16,
    config: Arc<Config>,
    conntrack_map: Arc<ConntrackMap>,
    verifying_key: VerifyingKey<Sha256>,
    sender: Sender,
}

impl Worker {
    pub fn new(
        config: Arc<Config>,
        queue_num: u16,
        conntrack_map: Arc<ConntrackMap>,
    ) -> Result<Worker> {
        let public_key = RsaPublicKey::read_pkcs1_pem_file(&config.auth.key)?;
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let sender = Sender::new()?;

        Ok(Worker {
            config,
            queue_num,
            conntrack_map,
            verifying_key,
            sender,
        })
    }

    pub fn start(mut self) -> Result<()> {
        let queue_num = self.queue_num;

        let mut queue = Queue::open()?;
        queue.bind(queue_num)?;
        queue.set_fail_open(queue_num, false)?;
        queue.set_recv_conntrack(queue_num, true)?;

        queue.set_recv_security_context(queue_num, true)?;
        queue.set_recv_uid_gid(queue_num, true)?;

        thread::spawn(move || {
            if let Err(e) = util::set_thread_priority() {
                error!("nfq {queue_num} failed to set thread priority: {e}");
                return;
            }

            info!("nfq {queue_num} worker started");

            loop {
                if let Err(e) = self.event_handler(&mut queue) {
                    error!("nfq {queue_num} failed handle event: {e}");
                    continue;
                }
            }
        });

        Ok(())
    }

    fn event_handler(&mut self, queue: &mut Queue) -> Result<()> {
        let mut verdict = Verdict::Drop;
        let mut msg = queue.recv()?;
        let payload = msg.get_payload();
        let version = (payload[0] >> 4) & 0xF;

        match version {
            4 => verdict = self.ipv4_packet_handler(payload)?,
            6 => verdict = self.ipv6_packet_handler(payload)?,
            x => error!("nfq {} received unknown IP version: {x}", self.queue_num),
        }

        msg.set_verdict(verdict);
        queue.verdict(msg)?;

        Ok(())
    }

    fn ipv4_packet_handler(&mut self, payload: &[u8]) -> Result<Verdict> {
        let ip_header = Ipv4Packet::new(payload).ok_or(anyhow!("Malformed IPv4 packet"))?;

        let source = IpAddr::V4(ip_header.get_source());

        if self.is_allow_ip(&source)? {
            return Ok(Verdict::Accept);
        }

        let destination = IpAddr::V4(ip_header.get_destination());
        let protocol = ip_header.get_next_level_protocol();

        let ip_packet = util::packet_header(&ip_header);

        let verdict = self.transport_protocol_handler(
            source,
            destination,
            protocol,
            ip_packet,
            ip_header.payload(),
        )?;

        Ok(verdict)
    }

    fn ipv6_packet_handler(&mut self, payload: &[u8]) -> Result<Verdict> {
        let ip_header = Ipv6Packet::new(payload).ok_or(anyhow!("Malformed IPv6 packet"))?;

        let source = IpAddr::V6(ip_header.get_source());

        if self.is_allow_ip(&source)? {
            return Ok(Verdict::Accept);
        }

        let destination = IpAddr::V6(ip_header.get_destination());
        let protocol = ip_header.get_next_header();

        let ip_packet = util::packet_header(&ip_header);

        let verdict = self.transport_protocol_handler(
            source,
            destination,
            protocol,
            ip_packet,
            ip_header.payload(),
        )?;

        Ok(verdict)
    }

    fn transport_protocol_handler(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: IpNextHeaderProtocol,
        ip_packet: &[u8],
        payload: &[u8],
    ) -> Result<Verdict> {
        let mut verdict = Verdict::Drop;

        match protocol {
            IpNextHeaderProtocols::Udp => {
                verdict = self.udp_packet_handler(src_ip, dst_ip, ip_packet, payload)?;
            }
            IpNextHeaderProtocols::Tcp => {
                verdict = self.tcp_packet_handler(src_ip, dst_ip, payload)?;
            }
            _ => {
                debug!(
                    "nfq {} unknown transport protocol: {protocol}, skip it",
                    self.queue_num
                );
            }
        }

        Ok(verdict)
    }

    fn udp_packet_handler(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        ip_packet: &[u8],
        payload: &[u8],
    ) -> Result<Verdict> {
        let queue_num = self.queue_num;
        let udp_header = UdpPacket::new(payload).ok_or(anyhow!("Malformed UDP packet"))?;
        let src_port = udp_header.get_source();
        let dst_port = udp_header.get_destination();
        let payload = udp_header.payload();

        debug!("nfq {queue_num} UDP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}");

        let verdict =
            self.verify_packet(src_ip, src_port, dst_ip, dst_port, Protocol::Udp, payload)?;

        if verdict != Verdict::Accept {
            self.sender
                .emit_icmp_unreachable(&dst_ip, &src_ip, ip_packet, &udp_header)?;
        }

        Ok(verdict)
    }

    fn tcp_packet_handler(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        payload: &[u8],
    ) -> Result<Verdict> {
        let queue_num = self.queue_num;
        let tcp_header = TcpPacket::new(payload).ok_or(anyhow!("Malformed TCP packet"))?;
        let src_port = tcp_header.get_source();
        let dst_port = tcp_header.get_destination();
        let payload = tcp_header.payload();

        debug!("nfq {queue_num} TCP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}");

        let verdict =
            self.verify_packet(src_ip, src_port, dst_ip, dst_port, Protocol::Tcp, payload)?;

        if verdict != Verdict::Accept {
            self.sender.emit_tcp_rst(&src_ip, &dst_ip, &tcp_header)?;
        }

        Ok(verdict)
    }

    fn verify_packet(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: Protocol,
        payload: &[u8],
    ) -> Result<Verdict> {
        let queue_num = self.queue_num;
        let mut entry = ConntrackEntry::new(src_ip, dst_ip, dst_port, protocol.clone());

        if self.is_auth_port(protocol, dst_port) {
            match crypto::verify_knock_packet(
                payload,
                &self.verifying_key,
                self.config.auth.allow_skew,
            ) {
                Ok(knock_info) => {
                    entry.dst_port = knock_info.unlock_port;

                    info!(
                        "nfq {queue_num} allow {:?}, timestamp: {}",
                        entry, knock_info.timestamp
                    );

                    self.conntrack_map.add_entry(entry)?;
                }
                Err(e) => {
                    debug!("nfq {queue_num} malformed auth packet from {src_ip}:{src_port}: {e}")
                }
            }
        } else if let Some(inst) = self.conntrack_map.get_timestamp(&entry)? {
            // avoid updating timestamp every time
            if Instant::now().duration_since(inst).as_secs() > 0 {
                self.conntrack_map.update_timestamp(entry)?;
            }

            return Ok(Verdict::Accept);
        }

        Ok(Verdict::Drop)
    }

    fn is_allow_ip(&self, source: &IpAddr) -> Result<bool> {
        if self.config.filter.allow_ips.is_empty() {
            return Ok(false);
        }

        let bits = match source {
            IpAddr::V4(_) => IPV4_ADDR_BITS,
            IpAddr::V6(_) => IPV6_ADDR_BITS,
        };

        let src_ip =
            IpNet::new(*source, bits).context(format!("IpNet::new({}, {}) fail", source, bits))?;

        Ok(self.config.filter.allow_ips.contains(&src_ip))
    }

    fn is_auth_port(&self, protocol: Protocol, dst_port: u16) -> bool {
        self.config.auth.protocol == protocol && self.config.auth.port == dst_port
    }
}
