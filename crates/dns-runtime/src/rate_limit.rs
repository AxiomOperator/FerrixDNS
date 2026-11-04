//! Per-client rate limiting with token buckets.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const SHARDS: usize = 16;
/// Addresses tracked per shard. Sources can be spoofed, so this bounds memory during a flood.
const SHARD_CAPACITY: usize = 4096;
/// How often one client's excess is reported, so a flood can't fill the query log.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// What to do with a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    /// Over the limit. `report` is true for the first such query in a while.
    Limited {
        report: bool,
    },
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
    last_report: Option<Instant>,
}

/// Token buckets for each client address.
///
/// A bucket holds a minute's allowance and refills continuously, so a client can burst up to its
/// limit but can't sustain more than that per minute.
#[derive(Debug)]
pub struct RateLimiter {
    shards: Vec<Mutex<HashMap<IpAddr, Bucket>>>,
    limited: AtomicU64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            limited: AtomicU64::new(0),
        }
    }
}

fn shard_of(address: IpAddr) -> usize {
    let last = match address {
        IpAddr::V4(ip) => ip.octets()[3],
        IpAddr::V6(ip) => ip.octets()[15],
    };
    usize::from(last) % SHARDS
}

fn refill(bucket: &mut Bucket, per_minute: u32, now: Instant) {
    let capacity = f64::from(per_minute);
    let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * capacity / 60.0).min(capacity);
    bucket.updated = now;
}

impl RateLimiter {
    /// Counts a query from an address against a limit per minute.
    pub fn check(&self, address: IpAddr, per_minute: u32) -> RateDecision {
        self.check_at(address, per_minute, Instant::now())
    }

    fn check_at(&self, address: IpAddr, per_minute: u32, now: Instant) -> RateDecision {
        let Some(shard) = self.shards.get(shard_of(address)) else {
            return RateDecision::Allow;
        };
        let mut buckets = shard.lock().unwrap_or_else(PoisonError::into_inner);
        if buckets.len() >= SHARD_CAPACITY && !buckets.contains_key(&address) {
            // A full bucket holds no information, so forgetting it changes nothing.
            let capacity = f64::from(per_minute);
            buckets.retain(|_, bucket| {
                refill(bucket, per_minute, now);
                bucket.tokens < capacity
            });
            if buckets.len() >= SHARD_CAPACITY {
                // Dropping real clients' buckets would reset them, so an excess of new sources
                // goes unlimited. They're still confined to the allowed networks.
                return RateDecision::Allow;
            }
        }
        let bucket = buckets.entry(address).or_insert_with(|| Bucket {
            tokens: f64::from(per_minute),
            updated: now,
            last_report: None,
        });
        refill(bucket, per_minute, now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return RateDecision::Allow;
        }
        self.limited.fetch_add(1, Ordering::Relaxed);
        let report = bucket
            .last_report
            .is_none_or(|last| now.saturating_duration_since(last) >= REPORT_INTERVAL);
        if report {
            bucket.last_report = Some(now);
        }
        RateDecision::Limited { report }
    }

    /// Queries refused since the node started.
    pub fn limited_total(&self) -> u64 {
        self.limited.load(Ordering::Relaxed)
    }

    /// Addresses that were refused in the last minute and haven't earned a query back since.
    pub fn currently_limited(&self) -> HashSet<IpAddr> {
        let now = Instant::now();
        let mut addresses = HashSet::new();
        for shard in &self.shards {
            let buckets = shard.lock().unwrap_or_else(PoisonError::into_inner);
            addresses.extend(
                buckets
                    .iter()
                    .filter(|(_, bucket)| {
                        bucket.last_report.is_some_and(|last| {
                            now.saturating_duration_since(last) < REPORT_INTERVAL
                        })
                    })
                    .map(|(address, _)| *address),
            );
        }
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2));
    const OTHER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 3));

    #[test]
    fn clients_can_burst_to_the_limit_then_refill_steadily() {
        let limiter = RateLimiter::default();
        let start = Instant::now();
        for _ in 0..60 {
            assert_eq!(limiter.check_at(CLIENT, 60, start), RateDecision::Allow);
        }
        assert!(matches!(
            limiter.check_at(CLIENT, 60, start),
            RateDecision::Limited { .. }
        ));

        // 60 per minute earns one query a second.
        let later = start + Duration::from_millis(1100);
        assert_eq!(limiter.check_at(CLIENT, 60, later), RateDecision::Allow);
        assert!(matches!(
            limiter.check_at(CLIENT, 60, later),
            RateDecision::Limited { .. }
        ));

        // Refilling never saves up more than a minute's allowance.
        let idle = later + Duration::from_secs(3600);
        for _ in 0..60 {
            assert_eq!(limiter.check_at(CLIENT, 60, idle), RateDecision::Allow);
        }
        assert!(matches!(
            limiter.check_at(CLIENT, 60, idle),
            RateDecision::Limited { .. }
        ));
    }

    #[test]
    fn each_address_has_its_own_allowance() {
        let limiter = RateLimiter::default();
        let now = Instant::now();
        assert_eq!(limiter.check_at(CLIENT, 1, now), RateDecision::Allow);
        assert!(matches!(
            limiter.check_at(CLIENT, 1, now),
            RateDecision::Limited { .. }
        ));
        assert_eq!(limiter.check_at(OTHER, 1, now), RateDecision::Allow);
    }

    #[test]
    fn a_flood_is_reported_once_a_minute_but_counted_in_full() {
        let limiter = RateLimiter::default();
        let now = Instant::now();
        assert_eq!(limiter.check_at(CLIENT, 1, now), RateDecision::Allow);
        assert_eq!(
            limiter.check_at(CLIENT, 1, now),
            RateDecision::Limited { report: true }
        );
        assert_eq!(
            limiter.check_at(CLIENT, 1, now),
            RateDecision::Limited { report: false }
        );
        assert_eq!(limiter.limited_total(), 2);
        assert!(limiter.currently_limited().contains(&CLIENT));
        assert!(!limiter.currently_limited().contains(&OTHER));

        let later = now + REPORT_INTERVAL;
        assert_eq!(limiter.check_at(CLIENT, 1, later), RateDecision::Allow);
        assert_eq!(
            limiter.check_at(CLIENT, 1, later),
            RateDecision::Limited { report: true }
        );
    }

    #[test]
    fn memory_stays_bounded_when_sources_are_spoofed() {
        let limiter = RateLimiter::default();
        let now = Instant::now();
        // All of these land in one shard, because they share a last octet.
        for high in 0..=255_u8 {
            for middle in 0..=255_u8 {
                let address = IpAddr::V4(std::net::Ipv4Addr::new(10, high, middle, 16));
                // Each is left with no tokens, so none can be forgotten.
                limiter.check_at(address, 1, now);
            }
        }
        let tracked = limiter.shards[0].lock().unwrap().len();
        assert_eq!(tracked, SHARD_CAPACITY);
        let new = IpAddr::V4(std::net::Ipv4Addr::new(11, 0, 0, 16));
        assert_eq!(limiter.check_at(new, 1, now), RateDecision::Allow);
        assert_eq!(limiter.check_at(new, 1, now), RateDecision::Allow);
    }

    #[test]
    fn full_buckets_are_forgotten_when_space_is_needed() {
        let limiter = RateLimiter::default();
        let now = Instant::now();
        for high in 0..=255_u8 {
            for middle in 0..=255_u8 {
                let address = IpAddr::V4(std::net::Ipv4Addr::new(10, high, middle, 16));
                limiter.check_at(address, 1, now);
            }
        }
        let later = now + Duration::from_secs(120);
        let new = IpAddr::V4(std::net::Ipv4Addr::new(11, 0, 0, 16));
        assert_eq!(limiter.check_at(new, 1, later), RateDecision::Allow);
        assert_eq!(limiter.shards[0].lock().unwrap().len(), 1);
    }
}
