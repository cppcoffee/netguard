use std::net::IpAddr;

use crate::Protocol;

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct ConntrackEntry {
    pub src_ip: IpAddr,
    //pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl ConntrackEntry {
    pub fn new(
        src_ip: IpAddr,
        //src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: Protocol,
    ) -> ConntrackEntry {
        ConntrackEntry {
            src_ip,
            //src_port,
            dst_ip,
            dst_port,
            protocol,
        }
    }
}
