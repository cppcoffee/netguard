use std::mem::{size_of, size_of_val};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;

use crate::builder::sha256_digest;
use crate::{NetGuardData, MAX_PACKET_SIZE};

pub fn verify_packet(
    payload: &[u8],
    verifying_key: &VerifyingKey<Sha256>,
    allow_skew_seconds: u64,
) -> Result<NetGuardData> {
    if payload.len() >= MAX_PACKET_SIZE {
        bail!("Packet len={} is too large", payload.len());
    }

    let (knock_info, meta, payload) = parse_knock_packet(payload)?;
    let (signature, payload) = parse_length_packet(payload)?;
    let (digest, _payload) = parse_length_packet(payload)?;

    if !verify_digest(meta, digest) {
        bail!("Digest verify failed");
    }

    // Verify the signature
    let signature = Signature::try_from(signature)?;
    if let Err(e) = verifying_key.verify(meta, &signature) {
        bail!("Signature verification failed: {:?}", e);
    }

    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if now_secs > knock_info.timestamp + allow_skew_seconds {
        bail!(
            "Timestamp is too old, now_secs={now_secs}, knock timestamp={}",
            knock_info.timestamp
        );
    }

    Ok(knock_info)
}

fn parse_knock_packet(payload: &[u8]) -> Result<(NetGuardData, &[u8], &[u8])> {
    let mut timestamp = 0_u64;
    let mut port = 0_u16;
    let size = size_of_val(&timestamp) + size_of_val(&port);

    if payload.len() < size {
        bail!("Payload is too small")
    }

    let (meta, payload) = payload.split_at(size);

    let (left, right) = meta.split_at(size_of::<u64>());
    timestamp = u64::from_be_bytes(left.try_into()?);
    port = u16::from_be_bytes(right.try_into()?);

    let knock_info = NetGuardData::new(timestamp, port);

    Ok((knock_info, meta, payload))
}

fn parse_length_packet(payload: &[u8]) -> Result<(&[u8], &[u8])> {
    let sz = size_of::<u16>();

    if payload.len() < sz {
        bail!("Packet is too small")
    }

    let (data, payload) = payload.split_at(sz);

    let n = u16::from_be_bytes(data.try_into()?);
    if n as usize > payload.len() {
        bail!("Invalid length packet n={n}")
    }

    Ok(payload.split_at(n as usize))
}

#[inline]
fn verify_digest(data: &[u8], digest: &[u8]) -> bool {
    sha256_digest(data) == digest
}
