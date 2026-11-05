//! A bounded cache of upstream DNS answers.
//!
//! Entries are upstream answers and never contain policy decisions, so changing policy needs no
//! flush. The DNS path checks policy on every hit, including each CNAME target (ADR-003).

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use moka::Expiry;
use moka::sync::Cache;

/// Bytes counted per entry beyond its wire size, for the key and bookkeeping.
const ENTRY_OVERHEAD: u32 = 256;
/// The TTL clients get on an expired answer, so they ask again soon (RFC 8767 section 4).
pub const STALE_ANSWER_TTL: u32 = 30;
/// Answers shorter-lived than this are deliberately short, so refreshing them early gains little.
const MIN_PREFETCH_TTL: Duration = Duration::from_secs(20);
/// An answer is refreshed in its last tenth of life, if it's been asked for at least this often.
const PREFETCH_MIN_HITS: u32 = 2;
const PREFETCH_REMAINING_DIVISOR: u32 = 10;

/// Limits for the cache.
#[derive(Clone, Copy, Debug)]
pub struct CacheConfig {
    /// Approximate memory limit, in bytes.
    pub max_bytes: u64,
    pub max_ttl: Duration,
    /// Longest time to keep NXDOMAIN and empty answers.
    pub negative_ttl_cap: Duration,
    /// How long an expired answer is kept, to use when upstreams can't answer. Zero turns this off.
    pub stale_window: Duration,
    /// Refreshes popular answers shortly before they expire.
    pub prefetch: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_ttl: Duration::from_secs(86_400),
            negative_ttl_cap: Duration::from_secs(300),
            stale_window: Duration::from_secs(86_400),
            prefetch: true,
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
    hits: AtomicU32,
    refreshing: AtomicBool,
}

struct PerEntryTtl {
    stale_window: Duration,
}

impl Expiry<CacheKey, std::sync::Arc<Entry>> for PerEntryTtl {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &std::sync::Arc<Entry>,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl.saturating_add(self.stale_window))
    }
}

/// A cached answer with its TTLs reduced by the time spent in the cache.
#[derive(Clone, Debug)]
pub struct CachedAnswer {
    pub message: Message,
    /// Whether this node validated the answer with DNSSEC when it was stored.
    pub validated: bool,
    /// This caller should refresh the answer in the background. Only one caller is told to.
    pub refresh_due: bool,
}

/// What the cache holds for a question, without counting as a lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheState {
    /// Seconds until it expires. Zero if it already has.
    pub remaining_seconds: u64,
    /// It has expired, and is only kept to use if upstreams can't answer.
    pub stale: bool,
}

/// Counters and size, for reporting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub bytes: u64,
    pub max_bytes: u64,
    /// Expired answers given out because upstreams couldn't answer.
    pub stale_served: u64,
    /// Answers refreshed before they expired.
    pub prefetches: u64,
}

/// A bounded, thread-safe cache of upstream answers.
pub struct DnsCache {
    entries: Cache<CacheKey, std::sync::Arc<Entry>>,
    config: CacheConfig,
    hits: AtomicU64,
    misses: AtomicU64,
    stale_served: AtomicU64,
    prefetches: AtomicU64,
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
            .expire_after(PerEntryTtl {
                stale_window: config.stale_window,
            })
            .build();
        Self {
            entries,
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stale_served: AtomicU64::new(0),
            prefetches: AtomicU64::new(0),
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
        let refresh_due = self.claim_refresh(&entry, elapsed);

        let elapsed_seconds = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
        let mut message = entry.message.clone();
        age_records(&mut message.answers, elapsed_seconds);
        age_records(&mut message.authorities, elapsed_seconds);
        age_records(&mut message.additionals, elapsed_seconds);
        Some(CachedAnswer {
            message,
            validated: entry.validated,
            refresh_due,
        })
    }

    /// Whether a hit on an answer should refresh it. At most one hit per stored answer gets a yes.
    fn claim_refresh(&self, entry: &Entry, elapsed: Duration) -> bool {
        let hits = entry.hits.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let remaining = entry.ttl.saturating_sub(elapsed);
        let claimed = self.config.prefetch
            && entry.ttl >= MIN_PREFETCH_TTL
            && hits >= PREFETCH_MIN_HITS
            && remaining <= entry.ttl / PREFETCH_REMAINING_DIVISOR
            && !entry.refreshing.swap(true, Ordering::Relaxed);
        if claimed {
            self.prefetches.fetch_add(1, Ordering::Relaxed);
        }
        claimed
    }

    /// Reports on an entry, for diagnostics. This doesn't change any counts.
    pub fn peek(&self, key: &CacheKey) -> Option<CacheState> {
        let entry = self.entries.get(key)?;
        let elapsed = entry.stored_at.elapsed();
        Some(CacheState {
            remaining_seconds: entry.ttl.saturating_sub(elapsed).as_secs(),
            stale: elapsed >= entry.ttl,
        })
    }

    /// An expired answer, for when upstreams can't give a fresh one (RFC 8767).
    ///
    /// DNSSEC signatures may have lapsed since this was validated, so it doesn't count as validated.
    pub fn get_stale(&self, key: &CacheKey) -> Option<CachedAnswer> {
        if self.config.stale_window.is_zero() {
            return None;
        }
        let entry = self.entries.get(key)?;
        self.stale_served.fetch_add(1, Ordering::Relaxed);
        let mut message = entry.message.clone();
        for record in message
            .answers
            .iter_mut()
            .chain(&mut message.authorities)
            .chain(&mut message.additionals)
        {
            record.ttl = STALE_ANSWER_TTL;
        }
        Some(CachedAnswer {
            message,
            validated: false,
            refresh_due: false,
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
                hits: AtomicU32::new(0),
                refreshing: AtomicBool::new(false),
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
            stale_served: self.stale_served.load(Ordering::Relaxed),
            prefetches: self.prefetches.load(Ordering::Relaxed),
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
    fn expired_answers_are_kept_for_the_stale_window() {
        let cache = cache();
        cache.insert(key("a.example"), &answer(1), true);
        std::thread::sleep(Duration::from_millis(1050));
        assert!(cache.get(&key("a.example")).is_none());
        let stale = cache.get_stale(&key("a.example")).unwrap();
        assert_eq!(stale.message.answers[0].ttl, STALE_ANSWER_TTL);
        assert!(
            !stale.validated,
            "a stale answer isn't claimed as validated"
        );
        assert_eq!(cache.stats().stale_served, 1);
    }

    #[test]
    fn nothing_stale_is_served_past_the_window_or_when_off() {
        let off = DnsCache::new(CacheConfig {
            stale_window: Duration::ZERO,
            ..CacheConfig::default()
        });
        off.insert(key("a.example"), &answer(60), false);
        assert!(off.get_stale(&key("a.example")).is_none());

        let short = DnsCache::new(CacheConfig {
            stale_window: Duration::from_millis(100),
            ..CacheConfig::default()
        });
        short.insert(key("a.example"), &answer(1), false);
        std::thread::sleep(Duration::from_millis(1200));
        assert!(short.get_stale(&key("a.example")).is_none());
    }

    #[test]
    fn popular_answers_near_expiry_are_refreshed_once() {
        let cache = cache();
        // A 20 second answer is due in its last 2 seconds, so age it past that.
        let mut entry_message = answer(20);
        entry_message.answers[0].ttl = 20;
        cache.entries.insert(
            key("a.example"),
            std::sync::Arc::new(Entry {
                message: entry_message,
                validated: false,
                stored_at: Instant::now() - Duration::from_secs(19),
                ttl: Duration::from_secs(20),
                size: 300,
                hits: AtomicU32::new(0),
                refreshing: AtomicBool::new(false),
            }),
        );
        assert!(
            !cache.get(&key("a.example")).unwrap().refresh_due,
            "one hit isn't popular"
        );
        assert!(cache.get(&key("a.example")).unwrap().refresh_due);
        assert!(
            !cache.get(&key("a.example")).unwrap().refresh_due,
            "only one caller refreshes"
        );
        assert_eq!(cache.stats().prefetches, 1);
    }

    #[test]
    fn fresh_short_lived_or_disabled_answers_are_not_refreshed() {
        let cache = cache();
        cache.insert(key("fresh.example"), &answer(3600), false);
        for _ in 0..5 {
            assert!(!cache.get(&key("fresh.example")).unwrap().refresh_due);
        }
        cache.insert(key("short.example"), &answer(5), false);
        for _ in 0..5 {
            assert!(!cache.get(&key("short.example")).unwrap().refresh_due);
        }
        assert_eq!(cache.stats().prefetches, 0);
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
