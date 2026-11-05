use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection};
use tracing::warn;

use crate::store;
use crate::{Outcome, QueryEvent, Shared, Telemetry, TelemetryError};

/// The most segments a top-domains query reads, to keep dashboards cheap.
const TOP_DOMAIN_SEGMENTS: usize = 2;
const TOP_LIMIT: i64 = 10;
/// A range ending this close to now is what a live dashboard asks for.
const RECENT_RANGE_MS: i64 = 60_000;
/// The least time between recounts of a recent range's top domains.
const TOP_DOMAINS_MIN_WAIT: Duration = Duration::from_secs(2);
/// Waiting this many times as long as a recount took keeps it to a small share of one CPU core,
/// however much history there is and however many dashboards are open.
const TOP_DOMAINS_WAIT_FACTOR: u32 = 10;
const MAX_CACHED_RANGES: usize = 8;
/// The largest page read at once for an export.
const EXPORT_BATCH: u32 = 5_000;
const ALLOWED_OUTCOMES: &[&str] = &["forwarded", "cached", "stale", "local"];

#[derive(Clone, Default)]
struct TopDomains {
    blocked: Vec<DomainCount>,
    allowed: Vec<DomainCount>,
}

pub(crate) struct CachedTopDomains {
    value: TopDomains,
    refresh_after: Instant,
    refreshing: bool,
}

/// Top domains of recent ranges, by the range's length in minutes.
pub(crate) type TopDomainsCache = HashMap<i64, CachedTopDomains>;

/// Filters for a query log page.
#[derive(Clone, Debug, Default)]
pub struct QueryFilter {
    /// Return events older than this sequence number.
    pub before_seq: Option<i64>,
    pub limit: u32,
    /// Matches anywhere in the query name.
    pub qname: Option<String>,
    /// Matches the client ID or address exactly.
    pub client: Option<String>,
    pub outcome: Option<String>,
    pub qtype: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
}

/// One page of the query log, newest first.
#[derive(Clone, Debug, Serialize)]
pub struct QueryPage {
    pub events: Vec<QueryEvent>,
    /// Pass as `before_seq` for the next page.
    pub next_before_seq: Option<i64>,
}

/// Queries with one outcome in one minute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinuteCount {
    pub bucket_start_ms: i64,
    pub outcome: String,
    pub count: i64,
    pub latency_sum_us: i64,
}

/// Counts for one time bucket.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct BucketCounts {
    pub start_ms: i64,
    pub forwarded: i64,
    pub blocked: i64,
    pub rejected: i64,
    pub failed: i64,
}

/// A client's query count.
#[derive(Clone, Debug, Serialize)]
pub struct ClientCount {
    pub client: String,
    pub count: i64,
}

/// A domain's query count.
#[derive(Clone, Debug, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: i64,
}

/// Dashboard totals for a time range.
#[derive(Clone, Debug, Serialize)]
pub struct Overview {
    pub from_ms: i64,
    pub to_ms: i64,
    pub bucket_ms: i64,
    pub total: i64,
    /// Answered queries, including those from the cache and local zones.
    pub forwarded: i64,
    pub cached: i64,
    pub local: i64,
    pub blocked: i64,
    pub rejected: i64,
    pub failed: i64,
    pub average_latency_us: i64,
    pub buckets: Vec<BucketCounts>,
    pub top_clients: Vec<ClientCount>,
    pub top_blocked_domains: Vec<DomainCount>,
    pub top_domains: Vec<DomainCount>,
}

/// The state of the telemetry store.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TelemetryStats {
    pub recorded: u64,
    pub dropped: u64,
    pub write_errors: u64,
    pub retained_bytes: u64,
    /// Seconds of history actually retained, which may be less than the configured days.
    pub retained_seconds: u64,
}

fn parse_outcome(value: &str) -> Outcome {
    match value {
        "forwarded" => Outcome::Forwarded,
        "cached" => Outcome::Cached,
        "stale" => Outcome::Stale,
        "local" => Outcome::Local,
        "blocked" => Outcome::Blocked,
        "rejected" => Outcome::Rejected,
        "rate_limited" => Outcome::RateLimited,
        _ => Outcome::Failed,
    }
}

fn event_from_row(row: &SqliteRow) -> Result<QueryEvent, sqlx::Error> {
    let outcome: String = row.try_get("outcome")?;
    Ok(QueryEvent {
        seq: row.try_get("seq")?,
        occurred_at_ms: row.try_get("occurred_at_ms")?,
        client_id: row.try_get("client_id")?,
        client_ip: row.try_get("client_ip")?,
        qname: row.try_get("qname")?,
        matched_name: row.try_get("matched_name")?,
        qtype: row.try_get("qtype")?,
        outcome: parse_outcome(&outcome),
        rcode: row.try_get("rcode")?,
        rule_id: row.try_get("rule_id")?,
        source_list_id: row.try_get("source_list_id")?,
        upstream: row.try_get("upstream")?,
        duration_us: u64::try_from(row.try_get::<i64, _>("duration_us")?).unwrap_or(0),
        revision_id: row.try_get("revision_id")?,
    })
}

fn like_pattern(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

async fn query_segment(
    connection: &mut SqliteConnection,
    filter: &QueryFilter,
    limit: i64,
) -> Result<Vec<QueryEvent>, sqlx::Error> {
    // NULL filters disable themselves, and values are always bound, never interpolated.
    let qname = filter.qname.as_deref().map(like_pattern);
    let rows = sqlx::query(
        "SELECT * FROM query_events WHERE \
         (?1 IS NULL OR seq < ?1) AND \
         (?2 IS NULL OR qname LIKE ?2 ESCAPE '\\') AND \
         (?3 IS NULL OR client_id = ?3 OR client_ip = ?3) AND \
         (?4 IS NULL OR outcome = ?4) AND \
         (?5 IS NULL OR qtype = ?5) AND \
         (?6 IS NULL OR occurred_at_ms >= ?6) AND \
         (?7 IS NULL OR occurred_at_ms <= ?7) \
         ORDER BY seq DESC LIMIT ?8",
    )
    .bind(filter.before_seq)
    .bind(qname)
    .bind(filter.client.as_deref())
    .bind(filter.outcome.as_deref())
    .bind(filter.qtype.as_deref())
    .bind(filter.from_ms)
    .bind(filter.to_ms)
    .bind(limit)
    .fetch_all(connection)
    .await?;
    rows.iter().map(event_from_row).collect()
}

impl Telemetry {
    /// Reads a page of the query log, newest first, across daily segments.
    pub async fn query_log(&self, filter: &QueryFilter) -> QueryPage {
        self.read_log(filter, 200).await
    }

    /// Reads a larger page than [`Self::query_log`] allows, for exports.
    pub async fn query_log_batch(&self, filter: &QueryFilter) -> QueryPage {
        self.read_log(filter, EXPORT_BATCH).await
    }

    async fn read_log(&self, filter: &QueryFilter, largest: u32) -> QueryPage {
        let limit = i64::from(filter.limit.clamp(1, largest));
        let directory = &self.shared.directory;
        let mut events = Vec::new();

        for day in store::segment_days(directory) {
            let remaining = limit + 1 - i64::try_from(events.len()).unwrap_or(limit);
            if remaining <= 0 {
                break;
            }
            let Some(start) = store::day_start_ms(&day) else {
                continue;
            };
            if filter.to_ms.is_some_and(|to| start > to)
                || filter
                    .from_ms
                    .is_some_and(|from| start + 86_400_000 <= from)
            {
                continue;
            }
            let found = match store::open_segment_for_read(directory, &day).await {
                Ok(mut connection) => query_segment(&mut connection, filter, remaining).await,
                Err(error) => Err(error),
            };
            match found {
                Ok(found) => events.extend(found),
                // One unreadable day shouldn't hide the rest of the log.
                Err(error) => warn!(%error, %day, "skipping an unreadable query log segment"),
            }
        }

        let limit = usize::try_from(limit).unwrap_or(200);
        let has_more = events.len() > limit;
        events.truncate(limit);
        let next_before_seq = if has_more {
            events.last().map(|event| event.seq)
        } else {
            None
        };
        QueryPage {
            events,
            next_before_seq,
        }
    }

    /// Builds dashboard totals from rollups, including counts not yet written to disk.
    pub async fn overview(&self, from_ms: i64, to_ms: i64) -> Result<Overview, TelemetryError> {
        let span = (to_ms - from_ms).max(60_000);
        let bucket_ms = bucket_size(span);

        let rows = sqlx::query(
            "SELECT bucket_start_ms, client_key, outcome, qtype, count, latency_sum_us \
             FROM query_rollups_1m WHERE bucket_start_ms >= ? AND bucket_start_ms <= ?",
        )
        .bind(from_ms - from_ms % 60_000)
        .bind(to_ms)
        .fetch_all(&self.shared.rollups_pool)
        .await?;

        let mut totals = Totals::new(from_ms, bucket_ms);
        for row in &rows {
            totals.add(
                row.try_get("bucket_start_ms")?,
                row.try_get("client_key")?,
                &row.try_get::<String, _>("outcome")?,
                row.try_get("count")?,
                row.try_get("latency_sum_us")?,
            );
        }
        for (key, value) in self.shared.pending().iter() {
            if key.bucket_start_ms >= from_ms - from_ms % 60_000 && key.bucket_start_ms <= to_ms {
                totals.add(
                    key.bucket_start_ms,
                    key.client_key.clone(),
                    key.outcome.as_str(),
                    value.count,
                    value.latency_sum_us,
                );
            }
        }

        let top = recent_top_domains(&self.shared, from_ms, to_ms).await;
        Ok(totals.finish(from_ms, to_ms, top.blocked, top.allowed))
    }

    /// Query counts per minute and outcome, for reporting to a controller. Client names and
    /// addresses aren't included.
    pub async fn minute_counts(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<MinuteCount>, TelemetryError> {
        let rows = sqlx::query(
            "SELECT bucket_start_ms, outcome, SUM(count) AS total, SUM(latency_sum_us) AS latency \
             FROM query_rollups_1m WHERE bucket_start_ms >= ? AND bucket_start_ms < ? \
             GROUP BY bucket_start_ms, outcome ORDER BY bucket_start_ms",
        )
        .bind(from_ms)
        .bind(to_ms)
        .fetch_all(&self.shared.rollups_pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(MinuteCount {
                    bucket_start_ms: row.try_get("bucket_start_ms")?,
                    outcome: row.try_get("outcome")?,
                    count: row.try_get("total")?,
                    latency_sum_us: row.try_get("latency")?,
                })
            })
            .collect()
    }

    /// Query counts by client key since a time, for the client inventory.
    pub async fn client_activity(
        &self,
        from_ms: i64,
    ) -> Result<HashMap<String, (i64, i64)>, TelemetryError> {
        let rows = sqlx::query(
            "SELECT client_key, SUM(count) AS total, MAX(bucket_start_ms) AS last_seen \
             FROM query_rollups_1m WHERE bucket_start_ms >= ? AND client_key <> '' \
             GROUP BY client_key",
        )
        .bind(from_ms)
        .fetch_all(&self.shared.rollups_pool)
        .await?;

        let mut activity = HashMap::new();
        for row in rows {
            let total: i64 = row.try_get("total")?;
            let last_seen: i64 = row.try_get("last_seen")?;
            activity.insert(row.try_get("client_key")?, (total, last_seen));
        }
        for (key, value) in self.shared.pending().iter() {
            if key.client_key.is_empty() || key.bucket_start_ms < from_ms {
                continue;
            }
            let entry = activity.entry(key.client_key.clone()).or_insert((0, 0));
            entry.0 += value.count;
            entry.1 = entry.1.max(key.bucket_start_ms);
        }
        Ok(activity)
    }

    /// Current counters and how much history is on disk.
    pub async fn stats(&self, now_ms: i64) -> TelemetryStats {
        let directory = &self.shared.directory;
        let days = store::segment_days(directory);
        let retained_bytes = days
            .iter()
            .map(|day| store::segment_bytes(directory, day))
            .sum();

        let mut oldest = None;
        for day in days.iter().rev() {
            let Ok(mut connection) = store::open_segment_for_read(directory, day).await else {
                continue;
            };
            let row = sqlx::query("SELECT MIN(occurred_at_ms) AS oldest FROM query_events")
                .fetch_one(&mut connection)
                .await
                .ok();
            oldest = row.and_then(|row| row.try_get::<Option<i64>, _>("oldest").ok().flatten());
            if oldest.is_some() {
                break;
            }
        }
        let retained_seconds = oldest.map_or(0, |oldest| {
            u64::try_from((now_ms - oldest).max(0) / 1000).unwrap_or(0)
        });

        TelemetryStats {
            recorded: self.shared.recorded.load(Ordering::Relaxed),
            dropped: self.shared.dropped.load(Ordering::Relaxed),
            write_errors: self.shared.write_errors.load(Ordering::Relaxed),
            retained_bytes,
            retained_seconds,
        }
    }

    /// Writes pending rollups now, for tests and shutdown.
    pub async fn flush(&self) {
        crate::writer::flush_rollups(&self.shared).await;
    }
}

/// Picks a bucket size giving at most about 120 points.
fn bucket_size(span_ms: i64) -> i64 {
    const SIZES_MIN: [i64; 8] = [1, 5, 10, 15, 30, 60, 180, 1440];
    for minutes in SIZES_MIN {
        let size = minutes * 60_000;
        if span_ms / size <= 120 {
            return size;
        }
    }
    1440 * 60_000
}

/// Totals and charts read rollups, which stay cheap, but top domains have to count the query log,
/// which can take seconds. So a live dashboard gets the last count at once, and a new one is made in
/// the background when it's due. Older ranges don't change, so they're just counted.
async fn recent_top_domains(shared: &Arc<Shared>, from_ms: i64, to_ms: i64) -> TopDomains {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0);
    if (now_ms - to_ms).abs() > RECENT_RANGE_MS {
        return count_top_domains(shared, from_ms, to_ms).await;
    }
    let range = (to_ms - from_ms) / 60_000;

    {
        let mut cache = shared
            .top_domains
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(cached) = cache.get_mut(&range) {
            if !cached.refreshing && Instant::now() >= cached.refresh_after {
                cached.refreshing = true;
                let shared = Arc::clone(shared);
                tokio::spawn(async move {
                    let started = Instant::now();
                    let value = count_top_domains(&shared, from_ms, to_ms).await;
                    remember_top_domains(&shared, range, value, started.elapsed());
                });
            }
            return cached.value.clone();
        }
    }

    let started = Instant::now();
    let value = count_top_domains(shared, from_ms, to_ms).await;
    remember_top_domains(shared, range, value.clone(), started.elapsed());
    value
}

fn remember_top_domains(shared: &Shared, range: i64, value: TopDomains, took: Duration) {
    let mut cache = shared
        .top_domains
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if cache.len() >= MAX_CACHED_RANGES && !cache.contains_key(&range) {
        cache.clear();
    }
    cache.insert(
        range,
        CachedTopDomains {
            value,
            refresh_after: Instant::now()
                + TOP_DOMAINS_MIN_WAIT.max(took * TOP_DOMAINS_WAIT_FACTOR),
            refreshing: false,
        },
    );
}

async fn count_top_domains(shared: &Shared, from_ms: i64, to_ms: i64) -> TopDomains {
    TopDomains {
        blocked: top_domains(shared, from_ms, to_ms, &["blocked"]).await,
        allowed: top_domains(shared, from_ms, to_ms, ALLOWED_OUTCOMES).await,
    }
}

/// Counts domains in recent segments. Only per-query logging modes can provide these.
async fn top_domains(
    shared: &Shared,
    from_ms: i64,
    to_ms: i64,
    outcomes: &[&str],
) -> Vec<DomainCount> {
    // The list is ours and fixed, and each value is still bound.
    let placeholders = vec!["?"; outcomes.len()].join(", ");
    let statement = format!(
        "SELECT qname, COUNT(*) AS total FROM query_events WHERE qname IS NOT NULL \
         AND occurred_at_ms >= ? AND occurred_at_ms <= ? AND outcome IN ({placeholders}) \
         GROUP BY qname ORDER BY total DESC LIMIT 200"
    );
    let directory = &shared.directory;
    let mut counts: HashMap<String, i64> = HashMap::new();
    for day in store::segment_days(directory)
        .into_iter()
        .take(TOP_DOMAIN_SEGMENTS)
    {
        let Ok(mut connection) = store::open_segment_for_read(directory, &day).await else {
            continue;
        };
        let mut query = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(from_ms)
            .bind(to_ms);
        for outcome in outcomes {
            query = query.bind(*outcome);
        }
        let rows = query.fetch_all(&mut connection).await;
        let Ok(rows) = rows else {
            continue;
        };
        for row in rows {
            if let (Ok(domain), Ok(total)) = (
                row.try_get::<String, _>("qname"),
                row.try_get::<i64, _>("total"),
            ) {
                *counts.entry(domain).or_default() += total;
            }
        }
    }
    let mut sorted: Vec<DomainCount> = counts
        .into_iter()
        .map(|(domain, count)| DomainCount { domain, count })
        .collect();
    sorted.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.domain.cmp(&right.domain))
    });
    sorted.truncate(usize::try_from(TOP_LIMIT).unwrap_or(10));
    sorted
}

struct Totals {
    origin_ms: i64,
    bucket_ms: i64,
    forwarded: i64,
    cached: i64,
    local: i64,
    blocked: i64,
    rejected: i64,
    failed: i64,
    latency_sum_us: i64,
    buckets: HashMap<i64, BucketCounts>,
    clients: HashMap<String, i64>,
}

impl Totals {
    fn new(origin_ms: i64, bucket_ms: i64) -> Self {
        Self {
            origin_ms: origin_ms - origin_ms % bucket_ms,
            bucket_ms,
            forwarded: 0,
            cached: 0,
            local: 0,
            blocked: 0,
            rejected: 0,
            failed: 0,
            latency_sum_us: 0,
            buckets: HashMap::new(),
            clients: HashMap::new(),
        }
    }

    fn add(&mut self, start_ms: i64, client: String, outcome: &str, count: i64, latency_us: i64) {
        let offset = (start_ms - self.origin_ms).max(0) / self.bucket_ms;
        let bucket_start = self.origin_ms + offset * self.bucket_ms;
        let bucket = self.buckets.entry(bucket_start).or_default();
        bucket.start_ms = bucket_start;
        match outcome {
            "forwarded" => {
                bucket.forwarded += count;
                self.forwarded += count;
            }
            "cached" | "stale" => {
                bucket.forwarded += count;
                self.forwarded += count;
                self.cached += count;
            }
            "local" => {
                bucket.forwarded += count;
                self.forwarded += count;
                self.local += count;
            }
            "blocked" => {
                bucket.blocked += count;
                self.blocked += count;
            }
            "rejected" | "rate_limited" => {
                bucket.rejected += count;
                self.rejected += count;
            }
            _ => {
                bucket.failed += count;
                self.failed += count;
            }
        }
        self.latency_sum_us += latency_us;
        if !client.is_empty() {
            *self.clients.entry(client).or_default() += count;
        }
    }

    fn finish(
        self,
        from_ms: i64,
        to_ms: i64,
        top_blocked_domains: Vec<DomainCount>,
        top_domains: Vec<DomainCount>,
    ) -> Overview {
        let total = self.forwarded + self.blocked + self.rejected + self.failed;

        // Fill empty buckets so charts show quiet periods instead of joining across them.
        let mut buckets = Vec::new();
        let mut start = self.origin_ms;
        while start <= to_ms {
            buckets.push(self.buckets.get(&start).copied().unwrap_or(BucketCounts {
                start_ms: start,
                ..BucketCounts::default()
            }));
            start += self.bucket_ms;
        }

        let mut top_clients: Vec<ClientCount> = self
            .clients
            .into_iter()
            .map(|(client, count)| ClientCount { client, count })
            .collect();
        top_clients.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.client.cmp(&right.client))
        });
        top_clients.truncate(usize::try_from(TOP_LIMIT).unwrap_or(10));

        Overview {
            from_ms,
            to_ms,
            bucket_ms: self.bucket_ms,
            total,
            forwarded: self.forwarded,
            cached: self.cached,
            local: self.local,
            blocked: self.blocked,
            rejected: self.rejected,
            failed: self.failed,
            average_latency_us: if total > 0 {
                self.latency_sum_us / total
            } else {
                0
            },
            buckets,
            top_clients,
            top_blocked_domains,
            top_domains,
        }
    }
}
