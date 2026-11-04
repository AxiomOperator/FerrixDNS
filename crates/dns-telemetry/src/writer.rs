use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};

use dns_policy::TelemetryConfig;
use sqlx::{Connection, SqliteConnection};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{error, info};

use crate::store::{self, META_NEXT_SEQ};
use crate::{QueryEvent, RollupKey, RollupMap, RollupValue, Shared, TelemetryError};

const MAX_BATCH: usize = 2000;
const BATCH_WINDOW: Duration = Duration::from_millis(250);
const ROLLUP_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const RETENTION_INTERVAL: Duration = Duration::from_secs(60);
const ROLLUP_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

struct Segment {
    day: String,
    connection: SqliteConnection,
}

/// Runs until every [`crate::Telemetry`] handle is gone.
pub(crate) async fn run(
    shared: Arc<Shared>,
    mut events: mpsc::Receiver<QueryEvent>,
    settings: Arc<dyn Fn() -> TelemetryConfig + Send + Sync>,
) {
    let mut segment = None;
    let mut last_rollup_flush = Instant::now();
    let mut last_retention = Instant::now() - RETENTION_INTERVAL;
    let mut batch = Vec::with_capacity(MAX_BATCH);

    loop {
        let closed = match timeout(BATCH_WINDOW, events.recv_many(&mut batch, MAX_BATCH)).await {
            Ok(0) => true,
            Ok(_) | Err(_) => false,
        };

        let lost = u64::try_from(batch.len()).unwrap_or(u64::MAX);
        if !batch.is_empty()
            && let Err(write_error) =
                write_batch(&shared, &mut segment, std::mem::take(&mut batch)).await
        {
            shared.dropped.fetch_add(lost, Ordering::Relaxed);
            shared.write_errors.fetch_add(1, Ordering::Relaxed);
            error!(error = %write_error, lost, "failed to write query events");
            // Reopen on the next batch, which also recreates a corrupt segment.
            segment = None;
        }

        if closed || last_rollup_flush.elapsed() >= ROLLUP_FLUSH_INTERVAL {
            flush_rollups(&shared).await;
            last_rollup_flush = Instant::now();
        }
        if closed {
            return;
        }
        if last_retention.elapsed() >= RETENTION_INTERVAL {
            let config = settings();
            let current = segment
                .as_ref()
                .map(|segment: &Segment| segment.day.clone());
            let now = now_ms();
            remove_old_segments(&shared, &config, current.as_deref(), now);
            prune_rollups(&shared, now).await;
            last_retention = Instant::now();
        }
    }
}

async fn write_batch(
    shared: &Shared,
    segment: &mut Option<Segment>,
    mut batch: Vec<QueryEvent>,
) -> Result<(), TelemetryError> {
    // A batch can span midnight, in which case each run of days goes to its own file.
    while let Some(first) = batch.first() {
        let day = store::day_of(first.occurred_at_ms);
        let end = batch
            .iter()
            .position(|event| store::day_of(event.occurred_at_ms) != day)
            .unwrap_or(batch.len());
        let run: Vec<QueryEvent> = batch.drain(..end).collect();

        if segment.as_ref().is_none_or(|current| current.day != day) {
            let connection = store::open_segment_for_write(&shared.directory, &day).await?;
            *segment = Some(Segment { day, connection });
        }
        if let Some(current) = segment.as_mut() {
            insert_events(shared, &mut current.connection, run).await?;
        }
    }
    Ok(())
}

async fn insert_events(
    shared: &Shared,
    connection: &mut SqliteConnection,
    events: Vec<QueryEvent>,
) -> Result<(), TelemetryError> {
    let mut transaction = connection.begin().await?;
    for event in events {
        let seq = shared.next_seq.fetch_add(1, Ordering::Relaxed);
        sqlx::query(
            "INSERT INTO query_events (seq, occurred_at_ms, client_id, client_ip, qname, \
             matched_name, qtype, outcome, rcode, rule_id, source_list_id, upstream, duration_us, \
             revision_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(seq)
        .bind(event.occurred_at_ms)
        .bind(event.client_id)
        .bind(event.client_ip)
        .bind(event.qname)
        .bind(event.matched_name)
        .bind(event.qtype)
        .bind(event.outcome.as_str())
        .bind(event.rcode)
        .bind(event.rule_id)
        .bind(event.source_list_id)
        .bind(event.upstream)
        .bind(i64::try_from(event.duration_us).unwrap_or(i64::MAX))
        .bind(event.revision_id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// Writes pending rollups, keeping them in memory if the write fails.
pub(crate) async fn flush_rollups(shared: &Shared) {
    let taken: RollupMap = std::mem::take(&mut *shared.pending());
    let next_seq = shared.next_seq.load(Ordering::Relaxed);
    let rows: Vec<(RollupKey, RollupValue)> = taken
        .iter()
        .map(|(key, value)| (key.clone(), *value))
        .collect();
    if let Err(write_error) = write_rollups(shared, rows, next_seq).await {
        shared.write_errors.fetch_add(1, Ordering::Relaxed);
        error!(error = %write_error, "failed to write query rollups");
        let mut pending = shared.pending();
        for (key, value) in taken {
            let merged = pending.entry(key).or_default();
            merged.count += value.count;
            merged.latency_sum_us += value.latency_sum_us;
        }
    }
}

async fn write_rollups(
    shared: &Shared,
    rollups: Vec<(RollupKey, RollupValue)>,
    next_seq: i64,
) -> Result<(), TelemetryError> {
    let mut transaction = shared.rollups_pool.begin().await?;
    for (key, value) in rollups {
        sqlx::query(
            "INSERT INTO query_rollups_1m (bucket_start_ms, client_key, outcome, qtype, count, \
             latency_sum_us) VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT (bucket_start_ms, client_key, outcome, qtype) DO UPDATE SET \
             count = count + excluded.count, \
             latency_sum_us = latency_sum_us + excluded.latency_sum_us",
        )
        .bind(key.bucket_start_ms)
        .bind(key.client_key)
        .bind(key.outcome.as_str())
        .bind(key.qtype)
        .bind(value.count)
        .bind(value.latency_sum_us)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO telemetry_meta (key, value) VALUES (?, ?) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(META_NEXT_SEQ)
    .bind(next_seq.to_string())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// Deletes whole segments past the age or byte limit, oldest first.
pub(crate) fn remove_old_segments(
    shared: &Shared,
    config: &TelemetryConfig,
    current_day: Option<&str>,
    now_ms: i64,
) {
    let days = store::segment_days(&shared.directory);
    let age_limit_ms = i64::from(config.query_history_days) * 24 * 60 * 60 * 1000;
    let cutoff = now_ms - age_limit_ms;

    let mut total_bytes = 0_u64;
    // Newest first, so the newest data counts against the byte limit first.
    for day in &days {
        total_bytes += store::segment_bytes(&shared.directory, day);
        let is_current = current_day == Some(day.as_str());
        // A day's segment holds data up to the end of that day.
        let day_end = store::day_start_ms(day).map_or(i64::MAX, |start| start + 86_400_000);
        let too_old = day_end <= cutoff;
        let too_big = total_bytes > config.query_history_max_bytes;
        if !is_current && (too_old || too_big) {
            info!(%day, too_old, too_big, "removing an old query log segment");
            store::remove_database(&store::segment_path(&shared.directory, day));
        }
    }
}

/// Deletes rollups past their retention.
pub(crate) async fn prune_rollups(shared: &Shared, now_ms: i64) {
    let rollup_cutoff = now_ms - ROLLUP_RETENTION_MS;
    if let Err(delete_error) = sqlx::query("DELETE FROM query_rollups_1m WHERE bucket_start_ms < ?")
        .bind(rollup_cutoff)
        .execute(&shared.rollups_pool)
        .await
    {
        error!(error = %delete_error, "failed to prune query rollups");
    }
}
