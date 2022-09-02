use std::collections::BTreeSet;

use libp2p::{
    identity::{self, ed25519, Keypair},
    PeerId,
};
use serde::{Deserialize, Serialize};
use simperby_common::crypto::*;
use tokio::task;

use crate::BroadcastToken;

/// Stores a mapping between libp2p PeerId and simberby PublicKey.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KnownPeer {
    pub id: PeerId,
    pub pubkey: PublicKey,
}

/// Stores a set of known peers.
pub(crate) struct KnownPeers {
    peers: BTreeSet<KnownPeer>,
}

/// A struct for managing broadcast message.
pub(crate) struct BroadcastMessageInfo {
    pub(crate) _token: BroadcastToken,
    pub(crate) _message: Vec<u8>,
    pub(crate) _relayed_nodes: BTreeSet<PublicKey>,
    /// The background task that regularly broadcasts related message.
    pub(crate) task: task::JoinHandle<()>,
}

/// A network message type.
#[derive(Serialize, Deserialize)]
pub(crate) enum NetworkMessage {
    Alive(PublicKey),
    Ack(PublicKey, BroadcastToken),
    Message(BroadcastToken, Vec<u8>),
}

impl KnownPeer {
    fn check_consistency(&self) -> Result<(), String> {
        if convert_public_key(&self.pubkey)?.to_peer_id() == self.id {
            Ok(())
        } else {
            Err("unmatched peer id and public key.".to_string())
        }
    }
}

impl KnownPeers {
    pub fn new() -> Self {
        Self {
            peers: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, pubkey: PublicKey) -> Result<(), String> {
        let id = convert_public_key(&pubkey)?.to_peer_id();
        let peer = KnownPeer { id, pubkey };
        peer.check_consistency()
            .map_err(|e| format!("malformed public key: {}", e))?;
        self.peers.insert(peer);
        Ok(())
    }

    pub fn _get_public_key(&self, id: &PeerId) -> Result<PublicKey, String> {
        self.peers
            .iter()
            .find(|peer| peer.id == *id)
            .ok_or(format!("no such id: {}", id))
            .map(|peer| peer.pubkey.to_owned())
    }

    pub fn _get_peer_id(&self, pubkey: &PublicKey) -> Result<PeerId, String> {
        self.peers
            .iter()
            .find(|peer| peer.pubkey == *pubkey)
            .ok_or(format!("no such public key: {}", pubkey))
            .map(|peer| peer.id.to_owned())
    }
}

/// Converts simperby public key into a libp2p public key.
pub fn convert_public_key(public_key: &PublicKey) -> Result<identity::PublicKey, String> {
    Ok(identity::PublicKey::Ed25519(
        ed25519::PublicKey::decode(public_key.as_ref())
            .map_err(|e| format!("invalid public key: {}", e))?,
    ))
}

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
