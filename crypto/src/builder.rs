use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};

use crate::NetGuardData;

#[inline]
pub fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// NetGuard protocol payload will result in the following structure:
///
/// data: NetGuardData
/// sig_size: u16     (must be network byte order)
/// signature: [u8]
/// digest_size: u16  (must be network byte order)
/// digest: [u8]
pub fn build_packet(unlock_port: u16, private_key_path: &Path) -> Result<Vec<u8>> {
    if !private_key_path.exists() {
        bail!("Private key not exists: {:?}", private_key_path);
    }

    let private_key = RsaPrivateKey::read_pkcs1_pem_file(private_key_path)?;

    let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // Initialize the NetGuardData protocol data
    let mut data = NetGuardData::new(secs, unlock_port).to_network_vec();

    // Sign the data
    let signature = sign_rsa(private_key, &data);

    // Hash the data
    let digest = sha256_digest(&data);

    data.extend(&(signature.len() as u16).to_be_bytes());
    data.extend(signature);
    data.extend(&(digest.len() as u16).to_be_bytes());
    data.extend(digest);

    Ok(data)
}

fn sign_rsa(private_key: RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut rng, &data);

    signature.to_vec()
}
