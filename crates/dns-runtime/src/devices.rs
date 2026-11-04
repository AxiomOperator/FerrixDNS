//! What this node knows about the devices around it, kept fresh in the background.
//!
//! The DNS path only reads a published table. When it meets an address it doesn't know, it asks
//! the monitor task to find out, and it only waits for the answer if policy depends on it.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use dns_policy::{DomainName, LocalData, LocalQuery, MacAddress, reverse_name};
use dns_upstreams::UpstreamRequest;
use hickory_server::proto::op::{Query, ResponseCode};
use hickory_server::proto::rr::rdata::PTR;
use hickory_server::proto::rr::{Name, RData, RecordType};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tracing::{debug, warn};

use crate::forward::ConditionalPools;
use crate::neighbors::{Neighbor, NeighborSource};
use crate::policy::PolicyHandle;

/// How long a query from an unknown device can wait to learn who it is.
const IDENTIFY_WAIT: Duration = Duration::from_millis(200);
const NEIGHBOR_INTERVAL: Duration = Duration::from_secs(30);
const HOSTNAME_INTERVAL: Duration = Duration::from_secs(300);
/// How long to remember an address that has dropped out of the neighbor table.
const FORGET_AFTER: Duration = Duration::from_secs(3600);
const MAX_DEVICES: usize = 4096;
const MAX_CONCURRENT_LOOKUPS: usize = 8;
const LOOKUP_QUEUE: usize = 1024;

/// What's known about one address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub address: IpAddr,
    pub mac: Option<MacAddress>,
    pub hostname: Option<DomainName>,
    /// Whether the kernel's neighbor table currently lists this address.
    pub on_network: bool,
    /// When this device was last known to be active, in milliseconds since the epoch.
    pub last_active_ms: i64,
}

struct Lookup {
    address: IpAddr,
    done: Option<oneshot::Sender<()>>,
}

type DeviceTable = HashMap<IpAddr, Arc<DeviceInfo>>;

/// The answer to a reverse lookup. `Unavailable` means nobody could say, so a name that's already
/// known is kept, and a brief router outage doesn't change which rules a device gets.
#[derive(Debug, PartialEq, Eq)]
enum HostnameLookup {
    Found(DomainName),
    NoName,
    Unavailable,
}

/// The published device table.
pub struct DeviceDirectory {
    table: Arc<ArcSwap<DeviceTable>>,
    lookups: mpsc::Sender<Lookup>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

impl DeviceDirectory {
    /// A directory holding fixed entries with nothing updating it, for tests.
    pub fn fixed(devices: Vec<DeviceInfo>) -> Self {
        let table = devices
            .into_iter()
            .map(|device| (device.address, Arc::new(device)))
            .collect();
        let (lookups, _) = mpsc::channel(1);
        Self {
            table: Arc::new(ArcSwap::from_pointee(table)),
            lookups,
        }
    }

    /// Starts the monitor task. It stops once the directory is dropped.
    pub(crate) fn start(
        neighbors: NeighborSource,
        policy: PolicyHandle,
        pools: Arc<ConditionalPools>,
    ) -> Arc<Self> {
        let (lookups, requests) = mpsc::channel(LOOKUP_QUEUE);
        let table: Arc<ArcSwap<DeviceTable>> = Arc::default();
        let monitor = Monitor {
            table: Arc::clone(&table),
            entries: HashMap::new(),
            neighbors,
            policy,
            pools,
            limit: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
            in_flight: HashSet::new(),
            waiters: HashMap::new(),
            read_failed: false,
        };
        tokio::spawn(monitor.run(requests));
        Arc::new(Self { table, lookups })
    }

    /// What's known about an address right now.
    pub fn get(&self, address: IpAddr) -> Option<Arc<DeviceInfo>> {
        self.table.load().get(&address).cloned()
    }

    /// Every known device.
    pub fn snapshot(&self) -> Vec<Arc<DeviceInfo>> {
        self.table.load().values().cloned().collect()
    }

    /// Asks the monitor about a new address, without waiting. A full queue just means it's asked
    /// again on the address's next query.
    pub(crate) fn observe(&self, address: IpAddr) {
        let _ = self.lookups.try_send(Lookup {
            address,
            done: None,
        });
    }

    /// Asks about a new address, and waits a moment for the answer.
    pub(crate) async fn identify(&self, address: IpAddr) -> Option<Arc<DeviceInfo>> {
        let (done, finished) = oneshot::channel();
        let lookup = Lookup {
            address,
            done: Some(done),
        };
        if self.lookups.try_send(lookup).is_ok() {
            let _ = timeout(IDENTIFY_WAIT, finished).await;
        }
        self.get(address)
    }
}

struct Entry {
    mac: Option<MacAddress>,
    hostname: Option<DomainName>,
    on_network: bool,
    last_active_ms: i64,
    /// When this entry last changed sides of the neighbor table, or was last seen in it.
    last_listed_ms: i64,
}

struct Monitor {
    table: Arc<ArcSwap<DeviceTable>>,
    entries: HashMap<IpAddr, Entry>,
    neighbors: NeighborSource,
    policy: PolicyHandle,
    pools: Arc<ConditionalPools>,
    limit: Arc<Semaphore>,
    in_flight: HashSet<IpAddr>,
    waiters: HashMap<IpAddr, Vec<oneshot::Sender<()>>>,
    read_failed: bool,
}

impl Monitor {
    async fn run(mut self, mut requests: mpsc::Receiver<Lookup>) {
        let (results, mut finished) = mpsc::channel(MAX_CONCURRENT_LOOKUPS * 2);
        let mut neighbor_timer = interval(NEIGHBOR_INTERVAL);
        let mut hostname_timer = interval(HOSTNAME_INTERVAL);
        neighbor_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        hostname_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                request = requests.recv() => {
                    let Some(request) = request else { return };
                    let mut batch = vec![request];
                    while batch.len() < LOOKUP_QUEUE {
                        match requests.try_recv() {
                            Ok(next) => batch.push(next),
                            Err(_) => break,
                        }
                    }
                    self.handle_lookups(batch, &results).await;
                }
                Some((address, hostname)) = finished.recv() => {
                    self.finish_hostname(address, hostname);
                    self.publish();
                }
                _ = neighbor_timer.tick() => {
                    self.read_neighbors(&results).await;
                    self.forget_old();
                    self.publish();
                }
                _ = hostname_timer.tick() => {
                    let addresses: Vec<IpAddr> = self.entries.keys().copied().collect();
                    for address in addresses {
                        self.start_hostname_lookup(address, &results);
                    }
                }
            }
        }
    }

    async fn handle_lookups(
        &mut self,
        batch: Vec<Lookup>,
        results: &mpsc::Sender<(IpAddr, HostnameLookup)>,
    ) {
        let now = now_ms();
        let mut new = false;
        for lookup in batch {
            if let Some(done) = lookup.done {
                self.waiters.entry(lookup.address).or_default().push(done);
            }
            if !self.entries.contains_key(&lookup.address) {
                new = true;
                self.make_room();
                self.entries.insert(
                    lookup.address,
                    Entry {
                        mac: None,
                        hostname: None,
                        on_network: false,
                        last_active_ms: now,
                        last_listed_ms: now,
                    },
                );
            }
        }
        // A device that just sent a query is usually in the neighbor table by now. Lookups arrive
        // in batches while this runs, so a flood only costs one read at a time.
        if new {
            self.read_neighbors(results).await;
        }
        let pending: Vec<IpAddr> = self.waiters.keys().copied().collect();
        for address in pending {
            self.start_hostname_lookup(address, results);
        }
        let known: Vec<IpAddr> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.hostname.is_none() && entry.last_active_ms == now)
            .map(|(address, _)| *address)
            .collect();
        for address in known {
            self.start_hostname_lookup(address, results);
        }
        self.publish();
    }

    /// Sources can be spoofed, so a flood of made-up addresses mustn't crowd out real devices.
    /// When full, this forgets the older half of the addresses that aren't on the network.
    fn make_room(&mut self) {
        if self.entries.len() < MAX_DEVICES {
            return;
        }
        let mut absent: Vec<(i64, IpAddr)> = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.on_network)
            .map(|(address, entry)| (entry.last_listed_ms, *address))
            .collect();
        absent.sort_unstable();
        for (_, address) in absent.iter().take(absent.len().div_ceil(2)) {
            self.entries.remove(address);
        }
        // Everything is genuinely on the network, which needs a very large one.
        if absent.is_empty()
            && let Some(address) = self.entries.keys().next().copied()
        {
            self.entries.remove(&address);
        }
    }

    async fn read_neighbors(&mut self, results: &mpsc::Sender<(IpAddr, HostnameLookup)>) {
        let source = self.neighbors.clone();
        let table = match tokio::task::spawn_blocking(move || source.read()).await {
            Ok(Ok(table)) => {
                self.read_failed = false;
                table
            }
            Ok(Err(error)) => {
                if !self.read_failed {
                    warn!(%error, "cannot read the neighbor table, so MAC addresses are unavailable");
                }
                self.read_failed = true;
                return;
            }
            Err(error) => {
                warn!(%error, "the neighbor table reader failed");
                return;
            }
        };
        let changed = self.apply_neighbors(&table, now_ms());
        for address in changed {
            self.start_hostname_lookup(address, results);
        }
    }

    /// Updates entries from the table, returning the addresses that need a new host name.
    fn apply_neighbors(&mut self, table: &[Neighbor], now: i64) -> Vec<IpAddr> {
        let listed: HashSet<IpAddr> = table.iter().map(|neighbor| neighbor.address).collect();
        for (address, entry) in &mut self.entries {
            if !listed.contains(address) {
                entry.on_network = false;
            }
        }
        let mut changed = Vec::new();
        for neighbor in table {
            if !self.entries.contains_key(&neighbor.address) {
                self.make_room();
            }
            let entry = self.entries.entry(neighbor.address).or_insert_with(|| {
                changed.push(neighbor.address);
                Entry {
                    mac: None,
                    hostname: None,
                    on_network: false,
                    last_active_ms: now,
                    last_listed_ms: now,
                }
            });
            // A different MAC means a different device now has this address.
            if entry.mac.is_some_and(|mac| mac != neighbor.mac) {
                entry.hostname = None;
                changed.push(neighbor.address);
            }
            entry.mac = Some(neighbor.mac);
            entry.on_network = true;
            entry.last_listed_ms = now;
            if neighbor.active {
                entry.last_active_ms = now;
            }
        }
        changed
    }

    fn forget_old(&mut self) {
        let cutoff = now_ms() - i64::try_from(FORGET_AFTER.as_millis()).unwrap_or(i64::MAX);
        self.entries
            .retain(|_, entry| entry.on_network || entry.last_listed_ms >= cutoff);
    }

    fn start_hostname_lookup(
        &mut self,
        address: IpAddr,
        results: &mpsc::Sender<(IpAddr, HostnameLookup)>,
    ) {
        if !self.in_flight.insert(address) {
            return;
        }
        let results = results.clone();
        let policy = Arc::clone(&self.policy);
        let pools = Arc::clone(&self.pools);
        let limit = Arc::clone(&self.limit);
        tokio::spawn(async move {
            let _permit = limit.acquire().await;
            let hostname = find_hostname(address, &policy, &pools).await;
            let _ = results.send((address, hostname)).await;
        });
    }

    fn finish_hostname(&mut self, address: IpAddr, hostname: HostnameLookup) {
        self.in_flight.remove(&address);
        if let Some(entry) = self.entries.get_mut(&address) {
            match hostname {
                HostnameLookup::Found(name) => entry.hostname = Some(name),
                HostnameLookup::NoName => entry.hostname = None,
                HostnameLookup::Unavailable => {}
            }
        }
        if let Some(waiters) = self.waiters.remove(&address) {
            // These run after the table is published, so they see this result.
            let table = Arc::clone(&self.table);
            let published = self.published();
            table.store(Arc::new(published));
            for done in waiters {
                let _ = done.send(());
            }
        }
    }

    fn published(&self) -> DeviceTable {
        self.entries
            .iter()
            .map(|(address, entry)| {
                (
                    *address,
                    Arc::new(DeviceInfo {
                        address: *address,
                        mac: entry.mac,
                        hostname: entry.hostname.clone(),
                        on_network: entry.on_network,
                        last_active_ms: entry.last_active_ms,
                    }),
                )
            })
            .collect()
    }

    fn publish(&self) {
        self.table.store(Arc::new(self.published()));
    }
}

/// Finds an address's name without ever asking the default upstreams, which would tell them about
/// private addresses and couldn't answer anyway.
async fn find_hostname(
    address: IpAddr,
    policy: &PolicyHandle,
    pools: &ConditionalPools,
) -> HostnameLookup {
    let address = address.to_canonical();
    if address.is_loopback() {
        return DomainName::parse("localhost")
            .map_or(HostnameLookup::NoName, HostnameLookup::Found);
    }
    let reverse = reverse_name(address);
    let Ok(name) = DomainName::parse(&reverse) else {
        return HostnameLookup::NoName;
    };

    let (servers, load_balance) = {
        let policy = policy.load();
        if let Some(answer) = policy.local_answer(&name, LocalQuery::Ptr)
            && answer.policy_applies
        {
            return answer
                .records
                .iter()
                .find_map(|record| match &record.data {
                    LocalData::Ptr(target) => Some(HostnameLookup::Found(target.clone())),
                    _ => None,
                })
                .unwrap_or(HostnameLookup::NoName);
        }
        match policy.forward_route(&name) {
            Some(route) => (Arc::clone(&route.servers), route.load_balance),
            None => return HostnameLookup::NoName,
        }
    };
    let pool = match pools.pool(&servers, load_balance) {
        Ok(pool) => pool,
        Err(error) => {
            warn!(%error, "cannot reach a forward zone's servers");
            return HostnameLookup::Unavailable;
        }
    };
    let Ok(wire_name) = Name::from_ascii(format!("{reverse}.")) else {
        return HostnameLookup::NoName;
    };
    let request = UpstreamRequest {
        query: Query::query(wire_name, RecordType::PTR),
        recursion_desired: true,
        checking_disabled: false,
        edns: None,
    };
    let forwarded = match pool.forward(&request).await {
        Ok(forwarded) => forwarded,
        Err(error) => {
            debug!(%error, "reverse lookup failed");
            return HostnameLookup::Unavailable;
        }
    };
    if matches!(
        forwarded.message.metadata.response_code,
        ResponseCode::ServFail | ResponseCode::Refused
    ) {
        return HostnameLookup::Unavailable;
    }
    forwarded
        .message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::PTR(PTR(target)) => DomainName::parse(&target.to_string())
                .ok()
                .map(HostnameLookup::Found),
            _ => None,
        })
        .unwrap_or(HostnameLookup::NoName)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use arc_swap::ArcSwap;
    use dns_policy::{CompiledPolicy, PolicyDocument};
    use dns_upstreams::PoolConfig;

    use super::*;

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0, 0, 1];

    fn policy(source: &str) -> PolicyHandle {
        let document = PolicyDocument::parse(source).unwrap();
        let compiled = CompiledPolicy::compile("r", &document, SystemTime::now(), None).unwrap();
        Arc::new(ArcSwap::from_pointee(compiled))
    }

    fn pools() -> Arc<ConditionalPools> {
        Arc::new(ConditionalPools::new(PoolConfig {
            servers: vec![],
            load_balance: false,
            attempt_timeout: Duration::from_millis(50),
            total_timeout: Duration::from_millis(100),
            rounds: 1,
            trust_roots: None,
        }))
    }

    fn directory(neighbors: Vec<Neighbor>, source: &str) -> Arc<DeviceDirectory> {
        DeviceDirectory::start(NeighborSource::fixed(neighbors), policy(source), pools())
    }

    const LOCAL: &str = r#"
schema_version = 1
[[local_zones]]
name = "home.arpa"
[[local_records]]
id = "1"
name = "nas.home.arpa"
type = "a"
value = "192.168.1.10"
"#;

    #[tokio::test]
    async fn identifying_learns_the_mac_and_the_local_host_name() {
        let address: IpAddr = "192.168.1.10".parse().unwrap();
        let devices = directory(
            vec![Neighbor {
                address,
                mac: MacAddress::new(MAC),
                active: true,
            }],
            LOCAL,
        );
        assert!(devices.get(address).is_none());

        let device = devices.identify(address).await.unwrap();
        assert_eq!(device.mac, Some(MacAddress::new(MAC)));
        assert_eq!(device.hostname.as_ref().unwrap().as_str(), "nas.home.arpa");
        assert!(device.on_network);
    }

    #[tokio::test]
    async fn an_unlisted_address_is_still_remembered() {
        let address: IpAddr = "192.168.1.77".parse().unwrap();
        let devices = directory(vec![], LOCAL);
        let device = devices.identify(address).await.unwrap();
        assert_eq!(device.mac, None);
        assert_eq!(device.hostname, None);
        assert!(!device.on_network);
    }

    #[tokio::test]
    async fn loopback_is_this_machine() {
        let address: IpAddr = "127.0.0.1".parse().unwrap();
        let devices = directory(vec![], "schema_version = 1\n");
        let device = devices.identify(address).await.unwrap();
        assert_eq!(device.hostname.as_ref().unwrap().as_str(), "localhost");
    }

    #[tokio::test]
    async fn the_neighbor_table_also_lists_devices_that_never_asked() {
        let address: IpAddr = "192.168.1.20".parse().unwrap();
        let devices = directory(
            vec![Neighbor {
                address,
                mac: MacAddress::new(MAC),
                active: false,
            }],
            LOCAL,
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while devices.get(address).is_none() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(devices.snapshot().len(), 1);
    }

    /// A DNS server that answers every question with one PTR record, like a router would.
    async fn start_router(host: &str) -> std::net::SocketAddr {
        use hickory_server::proto::op::{Message, MessageType};
        use hickory_server::proto::rr::Record;

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let host = Name::from_ascii(host).unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let query = Message::from_vec(&buffer[..length]).unwrap();
                let question = query.queries[0].clone();
                let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
                reply.metadata.message_type = MessageType::Response;
                reply.add_query(question.clone());
                reply.add_answer(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::PTR(PTR(host.clone())),
                ));
                socket
                    .send_to(&reply.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        address
    }

    #[tokio::test]
    async fn a_forwarded_network_supplies_host_names_that_identify_clients() {
        let router = start_router("tablet.lan.").await;
        let source = format!(
            "schema_version = 1\n\
             [[forward_zones]]\nid = \"r\"\nzones = [\"192.168.1.0/24\"]\nservers = [\"{router}\"]\n\
             [[clients]]\nid = \"tablet\"\nhostnames = [\"tablet\"]\n"
        );
        let handle = policy(&source);
        let devices =
            DeviceDirectory::start(NeighborSource::fixed(vec![]), Arc::clone(&handle), pools());

        let address: IpAddr = "192.168.1.5".parse().unwrap();
        let device = devices.identify(address).await.unwrap();
        let hostname = device.hostname.clone().unwrap();
        assert_eq!(hostname.as_str(), "tablet.lan");

        let found = handle.load();
        let identity = found.identity(dns_policy::ClientSource {
            address,
            mac: None,
            hostname: Some(&hostname),
        });
        assert_eq!(identity.unwrap().id.as_ref(), "tablet");
    }

    #[tokio::test]
    async fn private_addresses_never_reach_the_default_upstreams_for_a_name() {
        // No forward zone covers this, so there's nothing to ask and nothing is learned.
        let devices = directory(vec![], "schema_version = 1\n");
        let address: IpAddr = "192.168.1.6".parse().unwrap();
        assert_eq!(devices.identify(address).await.unwrap().hostname, None);
    }

    #[test]
    fn a_new_mac_on_an_address_clears_its_host_name() {
        let address: IpAddr = "192.168.1.30".parse().unwrap();
        let mut monitor = empty_monitor();
        let neighbor = |last: u8| Neighbor {
            address,
            mac: MacAddress::new([0, 0, 0, 0, 0, last]),
            active: true,
        };
        assert_eq!(monitor.apply_neighbors(&[neighbor(1)], 1000), [address]);
        monitor.entries.get_mut(&address).unwrap().hostname =
            Some(DomainName::parse("old.lan").unwrap());

        assert!(monitor.apply_neighbors(&[neighbor(1)], 2000).is_empty());
        assert!(monitor.entries[&address].hostname.is_some());

        assert_eq!(monitor.apply_neighbors(&[neighbor(2)], 3000), [address]);
        assert_eq!(monitor.entries[&address].hostname, None);
        assert_eq!(monitor.entries[&address].last_active_ms, 3000);

        assert!(monitor.apply_neighbors(&[], 4000).is_empty());
        assert!(!monitor.entries[&address].on_network);
        assert_eq!(monitor.entries[&address].last_active_ms, 3000);
    }

    fn empty_monitor() -> Monitor {
        Monitor {
            table: Arc::default(),
            entries: HashMap::new(),
            neighbors: NeighborSource::fixed(vec![]),
            policy: policy("schema_version = 1\n"),
            pools: pools(),
            limit: Arc::new(Semaphore::new(1)),
            in_flight: HashSet::new(),
            waiters: HashMap::new(),
            read_failed: false,
        }
    }

    fn entry(on_network: bool, last_listed_ms: i64) -> Entry {
        Entry {
            mac: None,
            hostname: None,
            on_network,
            last_active_ms: last_listed_ms,
            last_listed_ms,
        }
    }

    #[test]
    fn a_brief_outage_keeps_a_known_host_name_but_a_real_answer_replaces_it() {
        let mut monitor = empty_monitor();
        let address: IpAddr = "192.168.1.40".parse().unwrap();
        monitor.entries.insert(address, entry(true, 1));
        let name = DomainName::parse("tablet.lan").unwrap();

        monitor.finish_hostname(address, HostnameLookup::Found(name.clone()));
        monitor.finish_hostname(address, HostnameLookup::Unavailable);
        assert_eq!(monitor.entries[&address].hostname, Some(name));

        monitor.finish_hostname(address, HostnameLookup::NoName);
        assert_eq!(monitor.entries[&address].hostname, None);
    }

    #[test]
    fn a_full_table_forgets_old_absent_addresses_before_anything_on_the_network() {
        let mut monitor = empty_monitor();
        let real: IpAddr = "192.168.1.1".parse().unwrap();
        monitor.entries.insert(real, entry(true, 0));
        let mut spoofed = 0_u32;
        while monitor.entries.len() < MAX_DEVICES {
            spoofed += 1;
            let address = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + spoofed));
            monitor
                .entries
                .insert(address, entry(false, i64::from(spoofed)));
        }
        monitor.make_room();
        assert!(monitor.entries.len() < MAX_DEVICES);
        assert!(monitor.entries.contains_key(&real));
        let oldest = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0001_u32));
        let newest = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + spoofed));
        assert!(!monitor.entries.contains_key(&oldest));
        assert!(monitor.entries.contains_key(&newest));
    }
}
