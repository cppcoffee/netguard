use std::path::Path;

use anyhow::Result;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

pub fn rsa_keygen(bits: usize, priv_path: &Path, pub_path: &Path) -> Result<()> {
    let mut rng = rand::thread_rng();

    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    private_key.write_pkcs1_pem_file(&priv_path, LineEnding::LF)?;
    public_key.write_pkcs1_pem_file(&pub_path, LineEnding::LF)?;

    Ok(())
}
