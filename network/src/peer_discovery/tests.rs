use super::primitive::PeerDiscoveryPrimitiveImpl;
use crate::{primitives::PeerDiscoveryPrimitive, *};
use simperby_common::crypto::*;

use chrono::Utc;
use rand::{thread_rng, Rng};
use std::{collections::HashMap, ops::Range};
use tokio::{
    sync::{Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration},
};

const MAX_NODES: u64 = 300;
const AVAILABLE_PORT_RANGE: Range<u16> = 55000..56000;
const MAX_INITIALLY_KNOWN_PEERS: u64 = 2;
/// A prime number used in RNG.
const LCG_MULTIPLIER: u64 = 16536801242360453141;
/// An allowed amount of difference between real timestamp and discovered timestamp, in milliseconds.
const PERMITTED_ERROR_FOR_PEER_DISCOVERY: u64 = 30_000;

type Keypair = (PublicKey, PrivateKey);

/// A simple RNG controlled only by its seed.
struct DeterministicRng {
    seed: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { seed }
    }

    fn get_u64(&self) -> u64 {
        LCG_MULTIPLIER.wrapping_mul(self.seed)
    }

    fn get_bytes(&self, length: u64) -> Vec<u8> {
        let num_blocks = length.rem_euclid(8) + 1;
        (0..num_blocks)
            .flat_map(|_| self.get_u64().to_be_bytes())
            .collect()
    }
}

struct KeyStore {
    store: Vec<Keypair>,
}

impl KeyStore {
    fn new() -> Self {
        let store = Vec::from_iter(
            (0..MAX_NODES)
                .map(|index| DeterministicRng::new(index).get_bytes(8))
                .map(generate_keypair),
        );
        Self { store }
    }

    fn generate_keypair(&mut self) -> Keypair {
        self.store.pop().expect("exceeded maximum number of nodes")
    }
}

static AVAILABLE_PORTS: OnceCell<Mutex<Vec<u16>>> = OnceCell::const_new();

async fn init_available_ports() -> Mutex<Vec<u16>> {
    Mutex::new(Vec::from_iter(AVAILABLE_PORT_RANGE))
}

async fn get_port() -> u16 {
    let available_ports = AVAILABLE_PORTS.get_or_init(init_available_ports).await;
    available_ports
        .lock()
        .await
        .pop()
        .expect("exceeded port range")
}

async fn wait_ms(millis: u64) {
    time::sleep(Duration::from_millis(millis)).await;
}

/// A peer discovery node.
struct TestNetNode {
    shared_known_peers: SharedKnownPeers,
    handle: JoinHandle<Result<(), Error>>,
    network_config: NetworkConfig,
}

impl Drop for TestNetNode {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A network model of peer discovery nodes.
struct TestNet {
    keystore: KeyStore,
    default_network_config: NetworkConfig,
    nodes: Vec<TestNetNode>,
}

#[allow(dead_code)]
/// The set of methods that will be directly called by test functions.
impl TestNet {
    fn new() -> Self {
        let keystore = KeyStore::new();
        let (dummy_pubkey, dummy_privkey) = generate_keypair(DeterministicRng::new(0).get_bytes(1));
        let dummy_port = Some(1);
        let default_network_config = NetworkConfig {
            network_id: format!("test-{}", thread_rng().gen::<u32>()),
            port: dummy_port,
            members: keystore
                .store
                .iter()
                .cloned()
                .map(|(pubkey, _)| pubkey)
                .collect(),
            public_key: dummy_pubkey,
            private_key: dummy_privkey,
        };
        Self {
            keystore,
            default_network_config,
            nodes: Vec::new(),
        }
    }

    async fn add_members(&mut self, n: u64) {
        for _ in 0..n {
            self.add_member().await;
        }
    }

    fn remove_members(&mut self, mut indices: Vec<usize>) {
        indices.sort();
        indices.reverse();
        for index in indices {
            self.nodes.remove(index);
        }
    }

    async fn panic_if_discovery_failed(&self) {
        for node in &self.nodes {
            let known_peers = node.shared_known_peers.read().await;
            self.panic_if_known_peers_is_incorrect(known_peers.to_owned());
            let recently_seen_peers = known_peers
                .iter()
                .filter(|peer| self.is_peer_recently_seen(peer))
                .collect();
            self.panic_if_recently_seen_peers_incorrect(recently_seen_peers);
        }
    }
}

/// The set of methods that won't be directly called by test functions.
impl TestNet {
    async fn add_member(&mut self) {
        let port = get_port().await;
        let (public_key, private_key) = self.keystore.generate_keypair();
        let network_config = NetworkConfig {
            port: Some(port),
            public_key,
            private_key,
            ..self.default_network_config.to_owned()
        };
        let initially_known_peers = self.get_initially_known_peers();
        let (shared_known_peers, handle) = PeerDiscoveryPrimitiveImpl::serve(
            network_config.clone(),
            "".to_owned(),
            Default::default(),
            initially_known_peers,
        )
        .await
        .unwrap();
        self.nodes.push(TestNetNode {
            shared_known_peers,
            handle,
            network_config,
        });
    }

    fn get_initially_known_peers(&self) -> Vec<Peer> {
        if self.nodes.is_empty() {
            return Vec::new();
        }
        (0..MAX_INITIALLY_KNOWN_PEERS.min(self.nodes.len() as u64))
            .map(|i| {
                DeterministicRng::new(i)
                    .get_u64()
                    .rem_euclid(self.nodes.len() as u64)
            })
            .map(|peer_index| self.nodes[peer_index as usize].network_config.to_owned())
            .map(|network_config| {
                (
                    network_config.public_key,
                    network_config.port.expect("binding port was not provided"),
                )
            })
            .map(|(pubkey, port)| Peer {
                public_key: pubkey,
                address: format!("127.0.0.1:{}", port).parse().unwrap(),
                message: String::new(),
                ports: HashMap::new(),
                recently_seen_timestamp: 0,
            })
            .collect()
    }

    fn panic_if_known_peers_is_incorrect(&self, known_peers: Vec<Peer>) {
        for peer in &known_peers {
            assert!(self.is_peer_a_member(peer));
        }
    }

    fn is_peer_a_member(&self, peer: &Peer) -> bool {
        self.default_network_config
            .members
            .contains(&peer.public_key)
    }

    fn is_peer_recently_seen(&self, peer: &Peer) -> bool {
        let recent = Utc::now()
            .timestamp_millis()
            .checked_sub(PERMITTED_ERROR_FOR_PEER_DISCOVERY as i64)
            .unwrap();
        recent <= peer.recently_seen_timestamp as i64
    }

    fn panic_if_recently_seen_peers_incorrect(&self, recently_seen_peers: Vec<&Peer>) {
        let online_peers = &self.nodes;
        let pubkeys_of_oneline_peers = online_peers
            .iter()
            .map(|node| node.network_config.public_key.to_owned());
        for peer in &recently_seen_peers {
            assert!(pubkeys_of_oneline_peers
                .clone()
                .any(|pubkey| pubkey == peer.public_key));
        }
        // A node will not count itself, so the difference should be 1.
        assert!(online_peers.len() - recently_seen_peers.len() == 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sequential_join_1() {
    let mut testnet = TestNet::new();
    for _ in 0..5 {
        testnet.add_members(1).await;
        wait_ms(2_000).await;
    }
    wait_ms(3_000).await;
    testnet.panic_if_discovery_failed().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sequential_join_2() {
    let mut testnet = TestNet::new();
    for _ in 0..10 {
        testnet.add_members(1).await;
        wait_ms(1_000).await;
    }
    wait_ms(3_000).await;
    testnet.panic_if_discovery_failed().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sequential_join_3() {
    let mut testnet = TestNet::new();
    for _ in 0..30 {
        testnet.add_members(1).await;
        wait_ms(200).await;
    }
    wait_ms(3_000).await;
    testnet.panic_if_discovery_failed().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_join_1() {
    let mut testnet = TestNet::new();
    testnet.add_members(10).await;
    wait_ms(3_000).await;
    testnet.panic_if_discovery_failed().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_join_2() {
    let mut testnet = TestNet::new();
    testnet.add_members(30).await;
    wait_ms(3_000).await;
    testnet.panic_if_discovery_failed().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn arbitrary_join_1() {
    // 20 nodes
    let mut testnet = TestNet::new();
    testnet.add_members(3).await;
    for _ in 0..5 {
        testnet.add_members(1).await;
        wait_ms(200).await;
    }
    testnet.add_members(3).await;
    testnet.add_members(5).await;
    for _ in 0..4 {
        testnet.add_members(1).await;
        wait_ms(500).await;
    }
    wait_ms(3_000).await;
    testnet.panic_if_discovery_failed().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn arbitrary_join_2() {
    // 15 nodes
    let mut testnet = TestNet::new();
    testnet.add_members(4).await;
    for _ in 0..3 {
        testnet.add_members(1).await;
        wait_ms(1_000).await;
    }
    testnet.add_members(4).await;
    wait_ms(5_000).await;
    testnet.add_members(4).await;
    wait_ms(3_000).await;
    testnet.panic_if_discovery_failed().await;
}
