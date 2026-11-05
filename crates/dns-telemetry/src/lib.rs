//! Query telemetry that the DNS path never waits for.
//!
//! [`Telemetry::record`] only updates in-memory counters and tries to enqueue an event. A writer
//! task persists events to daily SQLite segment files and rollups to `rollups.db`. If storage
//! fails or falls behind, DNS keeps serving and events are counted as dropped. See ADR-002.

mod read;
mod store;
mod writer;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use dns_policy::{QueryLogMode, TelemetryConfig};
use serde::Serialize;
use sqlx::SqlitePool;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};

pub use read::{
    BucketCounts, ClientCount, DomainCount, MinuteCount, Overview, QueryFilter, QueryPage,
    TelemetryStats,
};

/// Events waiting for the writer. At 10,000 QPS this covers about 5 seconds (spec section 4.5).
pub const DEFAULT_EVENT_QUEUE: usize = 50_000;
const LIVE_STREAM_CAPACITY: usize = 1024;
const MILLIS_PER_MINUTE: i64 = 60_000;

/// Why the telemetry store could not be opened.
#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("telemetry storage failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("telemetry database failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("telemetry migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

/// How a query ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Answered from upstream.
    Forwarded,
    /// Answered from the cache.
    Cached,
    /// Answered from a local zone.
    Local,
    /// Answered with an expired answer from the cache, because upstreams couldn't answer.
    Stale,
    /// Answered with the configured block response.
    Blocked,
    /// Rejected by this node, for example an unsupported query.
    Rejected,
    /// No usable answer could be produced.
    Failed,
    /// Refused because the client is over its query limit.
    RateLimited,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Cached => "cached",
            Self::Stale => "stale",
            Self::Local => "local",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::RateLimited => "rate_limited",
        }
    }
}

/// One answered query.
#[derive(Clone, Debug, Serialize)]
pub struct QueryEvent {
    /// Assigned by the writer. Live events sent before that have `0`.
    pub seq: i64,
    pub occurred_at_ms: i64,
    pub client_id: Option<String>,
    pub client_ip: Option<String>,
    pub qname: Option<String>,
    /// The name that caused a block, which differs from `qname` for a CNAME target.
    pub matched_name: Option<String>,
    pub qtype: String,
    pub outcome: Outcome,
    pub rcode: String,
    pub rule_id: Option<String>,
    pub source_list_id: Option<String>,
    pub upstream: Option<String>,
    pub duration_us: u64,
    pub revision_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RollupKey {
    pub(crate) bucket_start_ms: i64,
    pub(crate) client_key: String,
    pub(crate) outcome: Outcome,
    pub(crate) qtype: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RollupValue {
    pub(crate) count: i64,
    pub(crate) latency_sum_us: i64,
}

pub(crate) type RollupMap = HashMap<RollupKey, RollupValue>;

pub(crate) struct Shared {
    pub(crate) directory: PathBuf,
    pub(crate) rollups_pool: SqlitePool,
    pub(crate) pending_rollups: Mutex<RollupMap>,
    pub(crate) top_domains: Mutex<read::TopDomainsCache>,
    pub(crate) dropped: AtomicU64,
    pub(crate) write_errors: AtomicU64,
    pub(crate) recorded: AtomicU64,
    pub(crate) next_seq: std::sync::atomic::AtomicI64,
}

impl Shared {
    pub(crate) fn pending(&self) -> MutexGuard<'_, RollupMap> {
        self.pending_rollups
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Runs the writer on its own thread, so slow disks can't take time from DNS worker threads.
fn spawn_writer(
    shared: Arc<Shared>,
    receiver: mpsc::Receiver<QueryEvent>,
    settings: Arc<dyn Fn() -> TelemetryConfig + Send + Sync>,
) -> Result<(), TelemetryError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()?;
    std::thread::Builder::new()
        .name("telemetry-writer".to_owned())
        .spawn(move || runtime.block_on(writer::run(shared, receiver, settings)))?;
    Ok(())
}

/// The handle used by the DNS path and the API.
pub struct Telemetry {
    pub(crate) shared: Arc<Shared>,
    events: mpsc::Sender<QueryEvent>,
    live: broadcast::Sender<QueryEvent>,
}

impl Telemetry {
    /// Opens the store in `directory` and starts its writer task.
    ///
    /// `settings` supplies the current retention limits each time they're applied.
    pub async fn open(
        directory: impl Into<PathBuf>,
        settings: Arc<dyn Fn() -> TelemetryConfig + Send + Sync>,
    ) -> Result<Self, TelemetryError> {
        Self::open_with_queue(directory, settings, DEFAULT_EVENT_QUEUE).await
    }

    /// Like [`Self::open`], with a specific event queue capacity.
    pub async fn open_with_queue(
        directory: impl Into<PathBuf>,
        settings: Arc<dyn Fn() -> TelemetryConfig + Send + Sync>,
        queue: usize,
    ) -> Result<Self, TelemetryError> {
        let directory = directory.into();
        std::fs::create_dir_all(&directory)?;
        let rollups_pool = store::open_rollups(&directory).await?;
        let next_seq = store::recover_next_seq(&directory, &rollups_pool).await;

        let shared = Arc::new(Shared {
            directory,
            rollups_pool,
            pending_rollups: Mutex::default(),
            top_domains: Mutex::default(),
            dropped: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            recorded: AtomicU64::new(0),
            next_seq: std::sync::atomic::AtomicI64::new(next_seq),
        });
        let (events, receiver) = mpsc::channel(queue.max(1));
        let (live, _) = broadcast::channel(LIVE_STREAM_CAPACITY);
        spawn_writer(Arc::clone(&shared), receiver, settings)?;
        Ok(Self {
            shared,
            events,
            live,
        })
    }

    /// Records a query according to the logging mode. This never waits.
    ///
    /// Rollups are updated first, so counts stay accurate when detailed events are dropped.
    pub fn record(&self, mut event: QueryEvent, mode: QueryLogMode) {
        if mode == QueryLogMode::Disabled {
            return;
        }
        if mode != QueryLogMode::Full {
            event.client_id = None;
            event.client_ip = None;
        }
        self.add_to_rollups(&event);
        self.shared.recorded.fetch_add(1, Ordering::Relaxed);
        if mode == QueryLogMode::AggregateOnly {
            return;
        }

        // Having no live subscribers isn't an error.
        let _ = self.live.send(event.clone());
        if self.events.try_send(event).is_err() {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn add_to_rollups(&self, event: &QueryEvent) {
        let client_key = event
            .client_id
            .as_deref()
            .or(event.client_ip.as_deref())
            .unwrap_or_default()
            .to_owned();
        let key = RollupKey {
            bucket_start_ms: event.occurred_at_ms - event.occurred_at_ms % MILLIS_PER_MINUTE,
            client_key,
            outcome: event.outcome,
            qtype: event.qtype.clone(),
        };
        let mut pending = self.shared.pending();
        let value = pending.entry(key).or_default();
        value.count += 1;
        value.latency_sum_us += i64::try_from(event.duration_us).unwrap_or(i64::MAX);
    }

    /// Subscribes to live events. Slow subscribers miss events rather than delaying anything.
    pub fn subscribe(&self) -> broadcast::Receiver<QueryEvent> {
        self.live.subscribe()
    }
}

#[cfg(test)]
mod tests;
