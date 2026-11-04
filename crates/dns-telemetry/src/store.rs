use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Row, SqliteConnection, SqlitePool};
use tracing::{error, warn};

use crate::TelemetryError;

static ROLLUPS_MIGRATOR: Migrator = sqlx::migrate!("../../migrations/node-telemetry-rollups");
static SEGMENT_MIGRATOR: Migrator = sqlx::migrate!("../../migrations/node-telemetry-segment");

const ROLLUPS_FILE: &str = "rollups.db";
const SEGMENT_PREFIX: &str = "queries-";
const SEGMENT_SUFFIX: &str = ".db";
pub(crate) const META_NEXT_SEQ: &str = "next_seq";

fn options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        // Telemetry is disposable, so it trades a little durability for far fewer fsyncs.
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
}

async fn connect_rollups(path: &Path) -> Result<SqlitePool, TelemetryError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options(path))
        .await?;
    ROLLUPS_MIGRATOR.run(&pool).await?;
    Ok(pool)
}

pub(crate) fn remove_database(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        if let Err(remove_error) = std::fs::remove_file(&name)
            && remove_error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(error = %remove_error, "failed to remove a telemetry file");
        }
    }
}

/// Opens the rollups database. Telemetry is disposable, so a corrupt one is recreated.
pub(crate) async fn open_rollups(directory: &Path) -> Result<SqlitePool, TelemetryError> {
    let path = directory.join(ROLLUPS_FILE);
    match connect_rollups(&path).await {
        Ok(pool) => Ok(pool),
        Err(open_error) => {
            error!(error = %open_error, "recreating an unusable telemetry rollups database");
            remove_database(&path);
            connect_rollups(&path).await
        }
    }
}

/// The UTC day of a timestamp as `YYYY-MM-DD`.
pub(crate) fn day_of(timestamp_ms: i64) -> String {
    let millis = u64::try_from(timestamp_ms).unwrap_or(0);
    let time = SystemTime::UNIX_EPOCH + Duration::from_millis(millis);
    let formatted = humantime::format_rfc3339_seconds(time).to_string();
    formatted.get(..10).unwrap_or("1970-01-01").to_owned()
}

/// The start of a `YYYY-MM-DD` day in milliseconds, for window checks.
pub(crate) fn day_start_ms(day: &str) -> Option<i64> {
    let time = humantime::parse_rfc3339(&format!("{day}T00:00:00Z")).ok()?;
    let millis = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

pub(crate) fn segment_path(directory: &Path, day: &str) -> PathBuf {
    directory.join(format!("{SEGMENT_PREFIX}{day}{SEGMENT_SUFFIX}"))
}

/// Segment days on disk, newest first.
pub(crate) fn segment_days(directory: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut days: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let day = name
                .strip_prefix(SEGMENT_PREFIX)?
                .strip_suffix(SEGMENT_SUFFIX)?;
            day_start_ms(day).map(|_| day.to_owned())
        })
        .collect();
    days.sort_unstable_by(|left, right| right.cmp(left));
    days
}

/// Bytes used by a segment, including its write-ahead log.
pub(crate) fn segment_bytes(directory: &Path, day: &str) -> u64 {
    let path = segment_path(directory, day);
    ["", "-wal", "-shm"]
        .iter()
        .map(|suffix| {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            std::fs::metadata(&name).map_or(0, |metadata| metadata.len())
        })
        .sum()
}

/// Opens a segment for writing, creating and migrating it if needed.
pub(crate) async fn open_segment_for_write(
    directory: &Path,
    day: &str,
) -> Result<SqliteConnection, TelemetryError> {
    let path = segment_path(directory, day);
    match connect_segment(&path).await {
        Ok(connection) => Ok(connection),
        Err(open_error) => {
            error!(error = %open_error, %day, "recreating an unusable query log segment");
            remove_database(&path);
            connect_segment(&path).await
        }
    }
}

async fn connect_segment(path: &Path) -> Result<SqliteConnection, TelemetryError> {
    let mut connection = SqliteConnection::connect_with(&options(path)).await?;
    SEGMENT_MIGRATOR.run(&mut connection).await?;
    Ok(connection)
}

/// Opens a segment for reading. A failure skips just that day.
pub(crate) async fn open_segment_for_read(
    directory: &Path,
    day: &str,
) -> Result<SqliteConnection, sqlx::Error> {
    let options = SqliteConnectOptions::from_str("sqlite://")?
        .filename(segment_path(directory, day))
        .read_only(true)
        .busy_timeout(Duration::from_secs(5));
    SqliteConnection::connect_with(&options).await
}

async fn stored_next_seq(pool: &SqlitePool) -> Option<i64> {
    let row = sqlx::query("SELECT value FROM telemetry_meta WHERE key = ?")
        .bind(META_NEXT_SEQ)
        .fetch_optional(pool)
        .await
        .ok()??;
    row.try_get::<String, _>("value").ok()?.parse().ok()
}

async fn newest_segment_seq(directory: &Path) -> Option<i64> {
    for day in segment_days(directory) {
        let Ok(mut connection) = open_segment_for_read(directory, &day).await else {
            continue;
        };
        let row = sqlx::query("SELECT MAX(seq) AS seq FROM query_events")
            .fetch_one(&mut connection)
            .await
            .ok();
        if let Some(seq) = row.and_then(|row| row.try_get::<Option<i64>, _>("seq").ok().flatten()) {
            return Some(seq);
        }
    }
    None
}

/// Finds the next sequence number, so it stays monotonic across restarts and segment files.
pub(crate) async fn recover_next_seq(directory: &Path, pool: &SqlitePool) -> i64 {
    let stored = stored_next_seq(pool).await.unwrap_or(1);
    let on_disk = newest_segment_seq(directory).await.map_or(1, |seq| seq + 1);
    stored.max(on_disk)
}
