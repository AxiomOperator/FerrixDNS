//! A bounded cache of upstream DNS answers.
//!
//! Entries are upstream answers and never contain policy decisions, so changing policy needs no
//! flush. The DNS path checks policy on every hit, including each CNAME target (ADR-003).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use moka::Expiry;
use moka::sync::Cache;

/// Bytes counted per entry beyond its wire size, for the key and bookkeeping.
const ENTRY_OVERHEAD: u32 = 256;

/// Limits for the cache.
#[derive(Clone, Copy, Debug)]
pub struct CacheConfig {
    /// Approximate memory limit, in bytes.
    pub max_bytes: u64,
    pub max_ttl: Duration,
    /// Longest time to keep NXDOMAIN and empty answers.
    pub negative_ttl_cap: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_ttl: Duration::from_secs(86_400),
            negative_ttl_cap: Duration::from_secs(300),
        }
    }
}

/// What makes two queries interchangeable.
///
/// The DNSSEC flags are part of the key because they change what upstream returns.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The query name in lowercase.
    pub name: String,
    pub record_type: RecordType,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
    /// Which servers this came from: 0 for the default upstreams, or a forward zone's number.
    pub route: u32,
}

#[derive(Debug)]
struct Entry {
    message: Message,
    validated: bool,
    stored_at: Instant,
    ttl: Duration,
    size: u32,
}

struct PerEntryTtl;

impl Expiry<CacheKey, std::sync::Arc<Entry>> for PerEntryTtl {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &std::sync::Arc<Entry>,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// A cached answer with its TTLs reduced by the time spent in the cache.
#[derive(Clone, Debug)]
pub struct CachedAnswer {
    pub message: Message,
    /// Whether this node validated the answer with DNSSEC when it was stored.
    pub validated: bool,
}

/// Counters and size, for reporting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub bytes: u64,
    pub max_bytes: u64,
}

/// A bounded, thread-safe cache of upstream answers.
pub struct DnsCache {
    entries: Cache<CacheKey, std::sync::Arc<Entry>>,
    config: CacheConfig,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// How long an answer may be cached, or `None` if it shouldn't be.
fn cache_ttl(message: &Message, config: &CacheConfig) -> Option<Duration> {
    if message.metadata.truncation {
        return None;
    }
    let code = message.metadata.response_code;
    let has_answers = !message.answers.is_empty();
    match code {
        ResponseCode::NoError if has_answers => {
            let seconds = message.answers.iter().map(|record| record.ttl).min()?;
            positive(Duration::from_secs(u64::from(seconds)), config.max_ttl)
        }
        // RFC 2308: negative answers are cached using the SOA in the authority section, and
        // without one they aren't cached at all.
        ResponseCode::NoError | ResponseCode::NXDomain => {
            let seconds = message
                .authorities
                .iter()
                .find_map(|record| match &record.data {
                    RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
                    _ => None,
                })?;
            positive(
                Duration::from_secs(u64::from(seconds)),
                config.negative_ttl_cap,
            )
        }
        // Failures are often transient and must not be repeated from the cache.
        _ => None,
    }
}

fn positive(ttl: Duration, cap: Duration) -> Option<Duration> {
    (!ttl.is_zero()).then(|| ttl.min(cap))
}

fn age_records(records: &mut [hickory_proto::rr::Record], elapsed_seconds: u32) {
    for record in records {
        record.ttl = record.ttl.saturating_sub(elapsed_seconds);
    }
}

impl DnsCache {
    pub fn new(config: CacheConfig) -> Self {
        let entries = Cache::builder()
            .max_capacity(config.max_bytes)
            .weigher(|_key: &CacheKey, entry: &std::sync::Arc<Entry>| entry.size)
            .expire_after(PerEntryTtl)
            .build();
        Self {
            entries,
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Looks up an answer, reducing its TTLs by its age.
    pub fn get(&self, key: &CacheKey) -> Option<CachedAnswer> {
        let Some(entry) = self.entries.get(key) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let elapsed = entry.stored_at.elapsed();
        if elapsed >= entry.ttl {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.hits.fetch_add(1, Ordering::Relaxed);

        let elapsed_seconds = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
        let mut message = entry.message.clone();
        age_records(&mut message.answers, elapsed_seconds);
        age_records(&mut message.authorities, elapsed_seconds);
        age_records(&mut message.additionals, elapsed_seconds);
        Some(CachedAnswer {
            message,
            validated: entry.validated,
        })
    }

    /// Stores an upstream answer if it's cacheable. Returns whether it was stored.
    pub fn insert(&self, key: CacheKey, message: &Message, validated: bool) -> bool {
        let Some(ttl) = cache_ttl(message, &self.config) else {
            return false;
        };
        let Ok(wire) = message.to_vec() else {
            return false;
        };
        let wire_size = u32::try_from(wire.len()).unwrap_or(u32::MAX);

        let mut stored = message.clone();
        // Records can outlive their original TTL only up to the cap, so clients see the cap too.
        let cap = u32::try_from(self.config.max_ttl.as_secs()).unwrap_or(u32::MAX);
        for record in stored
            .answers
            .iter_mut()
            .chain(&mut stored.authorities)
            .chain(&mut stored.additionals)
        {
            record.ttl = record.ttl.min(cap);
        }
        self.entries.insert(
            key,
            std::sync::Arc::new(Entry {
                message: stored,
                validated,
                stored_at: Instant::now(),
                ttl,
                size: wire_size.saturating_add(ENTRY_OVERHEAD),
            }),
        );
        true
    }

    /// Removes everything.
    pub fn flush(&self) {
        self.entries.invalidate_all();
        self.entries.run_pending_tasks();
    }

    pub fn stats(&self) -> CacheStats {
        self.entries.run_pending_tasks();
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries: self.entries.entry_count(),
            bytes: self.entries.weighted_size(),
            max_bytes: self.config.max_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, Record};

    use super::*;

    fn name(value: &str) -> Name {
        Name::from_str(value).unwrap()
    }

    fn key(value: &str) -> CacheKey {
        CacheKey {
            name: value.to_owned(),
            record_type: RecordType::A,
            dnssec_ok: false,
            checking_disabled: false,
            route: 0,
        }
    }

    fn response(code: ResponseCode) -> Message {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.response_code = code;
        message
    }

    fn answer(ttl: u32) -> Message {
        let mut message = response(ResponseCode::NoError);
        message.add_answer(Record::from_rdata(
            name("a.example."),
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        message
    }

    fn negative(code: ResponseCode, soa_ttl: u32, minimum: u32) -> Message {
        let mut message = response(code);
        message.add_authority(Record::from_rdata(
            name("example."),
            soa_ttl,
            RData::SOA(SOA::new(
                name("ns.example."),
                name("h.example."),
                1,
                1,
                1,
                1,
                minimum,
            )),
        ));
        message
    }

    fn cache() -> DnsCache {
        DnsCache::new(CacheConfig::default())
    }

    #[test]
    fn stores_and_returns_positive_answers() {
        let cache = cache();
        assert!(cache.get(&key("a.example")).is_none());
        assert!(cache.insert(key("a.example"), &answer(60), false));
        let hit = cache.get(&key("a.example")).unwrap();
        assert_eq!(hit.message.answers.len(), 1);
        assert!(!hit.validated);
        let stats = cache.stats();
        assert_eq!((stats.hits, stats.misses, stats.entries), (1, 1, 1));
    }

    #[test]
    fn answers_expire_and_ttls_count_down() {
        let cache = cache();
        cache.insert(key("a.example"), &answer(2), false);
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(
            cache.get(&key("a.example")).unwrap().message.answers[0].ttl,
            1
        );
        std::thread::sleep(Duration::from_millis(1000));
        assert!(cache.get(&key("a.example")).is_none());
    }

    #[test]
    fn the_shortest_answer_ttl_applies() {
        let cache = cache();
        let mut message = answer(300);
        message.add_answer(Record::from_rdata(
            name("a.example."),
            1,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ));
        cache.insert(key("a.example"), &message, false);
        std::thread::sleep(Duration::from_millis(1050));
        assert!(cache.get(&key("a.example")).is_none());
    }

    #[test]
    fn long_ttls_are_capped() {
        let cache = DnsCache::new(CacheConfig {
            max_ttl: Duration::from_secs(1),
            ..CacheConfig::default()
        });
        cache.insert(key("a.example"), &answer(86_400), false);
        assert_eq!(
            cache.get(&key("a.example")).unwrap().message.answers[0].ttl,
            1
        );
        std::thread::sleep(Duration::from_millis(1050));
        assert!(cache.get(&key("a.example")).is_none());
    }

    #[test]
    fn negative_answers_use_the_soa_and_their_own_cap() {
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            let cache = DnsCache::new(CacheConfig {
                negative_ttl_cap: Duration::from_secs(1),
                ..CacheConfig::default()
            });
            assert!(cache.insert(key("n.example"), &negative(code, 3600, 3600), false));
            assert!(cache.get(&key("n.example")).is_some());
            std::thread::sleep(Duration::from_millis(1050));
            assert!(cache.get(&key("n.example")).is_none(), "{code:?}");
        }
        // RFC 2308: the lower of the SOA's TTL and its minimum field.
        let cache = cache();
        assert!(!cache.insert(
            key("z.example"),
            &negative(ResponseCode::NXDomain, 0, 60),
            false
        ));
    }

    #[test]
    fn uncacheable_answers_are_refused() {
        let cache = cache();
        let mut truncated = answer(60);
        truncated.metadata.truncation = true;
        let uncacheable = [
            response(ResponseCode::ServFail),
            response(ResponseCode::Refused),
            response(ResponseCode::NXDomain),
            response(ResponseCode::NoError),
            answer(0),
            truncated,
        ];
        for message in uncacheable {
            assert!(
                !cache.insert(key("a.example"), &message, false),
                "{message:?}"
            );
        }
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn dnssec_flags_and_record_types_are_separate_entries() {
        let cache = cache();
        cache.insert(key("a.example"), &answer(60), false);
        assert!(
            cache
                .get(&CacheKey {
                    dnssec_ok: true,
                    ..key("a.example")
                })
                .is_none()
        );
        assert!(
            cache
                .get(&CacheKey {
                    checking_disabled: true,
                    ..key("a.example")
                })
                .is_none()
        );
        assert!(
            cache
                .get(&CacheKey {
                    record_type: RecordType::AAAA,
                    ..key("a.example")
                })
                .is_none()
        );
    }

    #[test]
    fn the_validated_flag_is_kept() {
        let cache = cache();
        cache.insert(key("a.example"), &answer(60), true);
        assert!(cache.get(&key("a.example")).unwrap().validated);
    }

    #[test]
    fn memory_is_bounded() {
        let cache = DnsCache::new(CacheConfig {
            max_bytes: 64 * 1024,
            ..CacheConfig::default()
        });
        for index in 0..10_000 {
            cache.insert(key(&format!("host{index}.example")), &answer(60), false);
        }
        let stats = cache.stats();
        assert!(stats.bytes <= 64 * 1024, "{stats:?}");
        assert!(stats.entries > 0 && stats.entries < 1000, "{stats:?}");
    }

    #[test]
    fn flush_removes_everything() {
        let cache = cache();
        cache.insert(key("a.example"), &answer(60), false);
        cache.flush();
        assert!(cache.get(&key("a.example")).is_none());
        assert_eq!(cache.stats().entries, 0);
    }
}
