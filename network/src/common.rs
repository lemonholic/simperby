use libp2p::identity::{ed25519, Keypair};
use simperby_common::crypto::*;

/// Converts simperby pub/priv keys into a libp2p keypair.
pub fn convert_keypair(
    public_key: &PublicKey,
    private_key: &PrivateKey,
) -> Result<Keypair, String> {
    let mut keypair_bytes = private_key.as_ref().to_vec();
    keypair_bytes.extend(public_key.as_ref());
    if let Ok(keypair_inner) = ed25519::Keypair::decode(&mut keypair_bytes) {
        Ok(Keypair::Ed25519(keypair_inner))
    } else {
        Err("invalid public/private keypair was given.".to_string())
    }
}
