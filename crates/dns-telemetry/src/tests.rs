use std::sync::Arc;
use std::time::Duration;

use dns_policy::{QueryLogMode, TelemetryConfig};

use crate::store;
use crate::writer;
use crate::{Outcome, QueryEvent, QueryFilter, Telemetry};

const DAY_MS: i64 = 86_400_000;
/// 2026-11-03T12:00:00Z.
const NOON: i64 = 1_793_707_200_000;

fn settings() -> Arc<dyn Fn() -> TelemetryConfig + Send + Sync> {
    Arc::new(TelemetryConfig::default)
}

async fn open() -> (tempfile::TempDir, Telemetry) {
    let directory = tempfile::tempdir().unwrap();
    let telemetry = Telemetry::open(directory.path().join("telemetry"), settings())
        .await
        .unwrap();
    (directory, telemetry)
}

fn event(at: i64, qname: &str, outcome: Outcome) -> QueryEvent {
    QueryEvent {
        seq: 0,
        occurred_at_ms: at,
        client_id: Some("laptop".into()),
        client_ip: Some("192.168.1.20".into()),
        qname: Some(qname.into()),
        matched_name: None,
        qtype: "A".into(),
        outcome,
        rcode: "NOERROR".into(),
        rule_id: None,
        source_list_id: None,
        upstream: Some("1.1.1.1:53".into()),
        duration_us: 1000,
        revision_id: Some("rev".into()),
    }
}

async fn wait_for_events(telemetry: &Telemetry, expected: usize) -> Vec<QueryEvent> {
    let filter = QueryFilter {
        limit: 200,
        ..QueryFilter::default()
    };
    for _ in 0..100 {
        let page = telemetry.query_log(&filter).await;
        if page.events.len() >= expected {
            return page.events;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("expected {expected} events to be written");
}

#[tokio::test]
async fn writes_events_and_reads_them_newest_first() {
    let (_directory, telemetry) = open().await;
    for index in 0..3 {
        telemetry.record(
            event(
                NOON + index,
                &format!("q{index}.example"),
                Outcome::Forwarded,
            ),
            QueryLogMode::Full,
        );
    }
    let events = wait_for_events(&telemetry, 3).await;
    assert_eq!(events[0].qname.as_deref(), Some("q2.example"));
    assert_eq!(events[2].qname.as_deref(), Some("q0.example"));
    assert!(events[0].seq > events[1].seq);
    assert_eq!(events[0].client_id.as_deref(), Some("laptop"));
    assert_eq!(events[0].outcome, Outcome::Forwarded);
}

#[tokio::test]
async fn paginates_and_filters_across_daily_segments() {
    let (_directory, telemetry) = open().await;
    for index in 0..5 {
        telemetry.record(
            event(NOON - DAY_MS + index, "old.example", Outcome::Blocked),
            QueryLogMode::Full,
        );
    }
    for index in 0..5 {
        telemetry.record(
            event(NOON + index, "new.example", Outcome::Forwarded),
            QueryLogMode::Full,
        );
    }
    wait_for_events(&telemetry, 10).await;

    let first = telemetry
        .query_log(&QueryFilter {
            limit: 7,
            ..QueryFilter::default()
        })
        .await;
    assert_eq!(first.events.len(), 7);
    assert_eq!(first.events[0].qname.as_deref(), Some("new.example"));
    assert_eq!(first.events[6].qname.as_deref(), Some("old.example"));

    let second = telemetry
        .query_log(&QueryFilter {
            limit: 7,
            before_seq: first.next_before_seq,
            ..QueryFilter::default()
        })
        .await;
    assert_eq!(second.events.len(), 3);
    assert_eq!(second.next_before_seq, None);

    let filtered = |filter| {
        let telemetry = &telemetry;
        async move { telemetry.query_log(&filter).await.events.len() }
    };
    let base = QueryFilter {
        limit: 200,
        ..QueryFilter::default()
    };
    assert_eq!(
        filtered(QueryFilter {
            outcome: Some("blocked".into()),
            ..base.clone()
        })
        .await,
        5
    );
    assert_eq!(
        filtered(QueryFilter {
            qname: Some("new".into()),
            ..base.clone()
        })
        .await,
        5
    );
    assert_eq!(
        filtered(QueryFilter {
            client: Some("192.168.1.20".into()),
            ..base.clone()
        })
        .await,
        10
    );
    assert_eq!(
        filtered(QueryFilter {
            from_ms: Some(NOON),
            ..base.clone()
        })
        .await,
        5
    );
    assert_eq!(
        filtered(QueryFilter {
            qtype: Some("AAAA".into()),
            ..base.clone()
        })
        .await,
        0
    );
    // LIKE wildcards in a search are literal text.
    assert_eq!(
        filtered(QueryFilter {
            qname: Some("%".into()),
            ..base
        })
        .await,
        0
    );
}

#[tokio::test]
async fn logging_modes_control_what_is_kept() {
    let (_directory, telemetry) = open().await;

    telemetry.record(
        event(NOON, "off.example", Outcome::Forwarded),
        QueryLogMode::Disabled,
    );
    let overview = telemetry
        .overview(NOON - 1000, NOON + 60_000)
        .await
        .unwrap();
    assert_eq!(overview.total, 0, "disabled records nothing");

    telemetry.record(
        event(NOON, "counted.example", Outcome::Blocked),
        QueryLogMode::AggregateOnly,
    );
    let overview = telemetry
        .overview(NOON - 1000, NOON + 60_000)
        .await
        .unwrap();
    assert_eq!(overview.blocked, 1);
    assert!(
        overview.top_clients.is_empty(),
        "aggregate-only drops clients"
    );

    telemetry.record(
        event(NOON + 1, "anon.example", Outcome::Forwarded),
        QueryLogMode::Anonymized,
    );
    let events = wait_for_events(&telemetry, 1).await;
    assert_eq!(events.len(), 1, "aggregate-only keeps no per-query history");
    assert_eq!(events[0].qname.as_deref(), Some("anon.example"));
    assert_eq!(events[0].client_id, None);
    assert_eq!(events[0].client_ip, None);
}

#[tokio::test]
async fn a_live_overview_reuses_top_domains_until_a_recount_is_due() {
    let (_directory, telemetry) = open().await;
    let now_ms = || {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    };
    let top = |overview: crate::Overview| {
        let mut domains: Vec<String> = overview
            .top_domains
            .into_iter()
            .map(|domain| domain.domain)
            .collect();
        domains.sort();
        domains
    };
    let hour_ago = now_ms() - 3_600_000;
    telemetry.record(
        event(now_ms(), "first.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    wait_for_events(&telemetry, 1).await;
    let first = telemetry.overview(hour_ago, now_ms()).await.unwrap();
    assert_eq!(top(first), ["first.example"]);

    telemetry.record(
        event(now_ms(), "second.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    wait_for_events(&telemetry, 2).await;
    let cached = telemetry.overview(hour_ago, now_ms()).await.unwrap();
    assert_eq!(cached.total, 2, "totals stay live");
    assert_eq!(top(cached), ["first.example"], "the last count is reused");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let overview = telemetry.overview(hour_ago, now_ms()).await.unwrap();
        if top(overview).len() == 2 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "never recounted");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn overview_totals_include_pending_and_flushed_rollups() {
    let (_directory, telemetry) = open().await;
    telemetry.record(
        event(NOON, "a.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    telemetry.record(
        event(NOON + 1, "a.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    telemetry.record(
        event(NOON + 2, "ads.example", Outcome::Blocked),
        QueryLogMode::Full,
    );
    telemetry.flush().await;
    telemetry.record(
        event(NOON + 3, "x.example", Outcome::Failed),
        QueryLogMode::Full,
    );
    wait_for_events(&telemetry, 4).await;

    let overview = telemetry
        .overview(NOON - 60_000, NOON + 60_000)
        .await
        .unwrap();
    assert_eq!(overview.total, 4);
    assert_eq!(overview.forwarded, 2);
    assert_eq!(overview.blocked, 1);
    assert_eq!(overview.failed, 1);
    assert_eq!(overview.average_latency_us, 1000);
    assert_eq!(overview.top_clients[0].client, "laptop");
    assert_eq!(overview.top_clients[0].count, 4);
    assert_eq!(overview.top_blocked_domains[0].domain, "ads.example");
    assert_eq!(overview.top_domains[0].domain, "a.example");
    assert_eq!(overview.buckets.iter().map(|b| b.forwarded).sum::<i64>(), 2);
    assert!(overview.buckets.len() >= 2, "empty buckets are filled");
}

#[tokio::test]
async fn a_full_queue_drops_events_but_counters_stay_accurate() {
    let directory = tempfile::tempdir().unwrap();
    let telemetry = Telemetry::open_with_queue(directory.path().join("t"), settings(), 1)
        .await
        .unwrap();
    // Far faster than the writer can drain a queue of one.
    for index in 0..100_000 {
        telemetry.record(
            event(NOON + index, "a.example", Outcome::Forwarded),
            QueryLogMode::Full,
        );
    }
    let stats = telemetry.stats(NOON).await;
    assert_eq!(stats.recorded, 100_000);
    assert!(stats.dropped > 0, "dropped {}", stats.dropped);

    let overview = telemetry
        .overview(NOON - 1000, NOON + 120_000)
        .await
        .unwrap();
    assert_eq!(overview.forwarded, 100_000);
}

#[tokio::test]
async fn sequence_numbers_stay_monotonic_after_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("telemetry");
    let last_seq = {
        let telemetry = Telemetry::open(&path, settings()).await.unwrap();
        telemetry.record(
            event(NOON, "a.example", Outcome::Forwarded),
            QueryLogMode::Full,
        );
        wait_for_events(&telemetry, 1).await[0].seq
    };
    let reopened = Telemetry::open(&path, settings()).await.unwrap();
    reopened.record(
        event(NOON + 1, "b.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    let events = wait_for_events(&reopened, 2).await;
    assert_eq!(events[0].qname.as_deref(), Some("b.example"));
    assert!(events[0].seq > last_seq);
}

#[tokio::test]
async fn retention_removes_old_and_oversized_segments_but_not_the_current_one() {
    let (_directory, telemetry) = open().await;
    for days_ago in [0, 1, 2, 10] {
        telemetry.record(
            event(NOON - days_ago * DAY_MS, "a.example", Outcome::Forwarded),
            QueryLogMode::Full,
        );
    }
    wait_for_events(&telemetry, 4).await;
    let directory = telemetry.shared.directory.clone();
    assert_eq!(store::segment_days(&directory).len(), 4);

    let today = store::day_of(NOON);
    let by_age = TelemetryConfig::default();
    writer::remove_old_segments(&telemetry.shared, &by_age, Some(&today), NOON);
    let days = store::segment_days(&directory);
    assert_eq!(
        days.len(),
        3,
        "the 10-day-old segment is past 7 days: {days:?}"
    );

    let by_size = TelemetryConfig {
        query_history_max_bytes: 1,
        ..TelemetryConfig::default()
    };
    writer::remove_old_segments(&telemetry.shared, &by_size, Some(&today), NOON);
    assert_eq!(
        store::segment_days(&directory),
        [today],
        "the current day is always kept"
    );
}

#[tokio::test]
async fn a_corrupt_segment_does_not_stop_writes_or_other_days() {
    let (_directory, telemetry) = open().await;
    telemetry.record(
        event(NOON - DAY_MS, "yesterday.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    wait_for_events(&telemetry, 1).await;

    let directory = telemetry.shared.directory.clone();
    let corrupt_day = store::day_of(NOON - 2 * DAY_MS);
    std::fs::write(
        store::segment_path(&directory, &corrupt_day),
        b"not a database",
    )
    .unwrap();

    // Reads skip the bad day.
    assert_eq!(wait_for_events(&telemetry, 1).await.len(), 1);

    // Writes to that day recreate it.
    telemetry.record(
        event(NOON - 2 * DAY_MS, "recovered.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    let events = wait_for_events(&telemetry, 2).await;
    assert!(
        events
            .iter()
            .any(|e| e.qname.as_deref() == Some("recovered.example"))
    );
}

#[tokio::test]
async fn a_corrupt_rollups_database_is_recreated_on_open() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("telemetry");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("rollups.db"), b"this is not a database at all").unwrap();

    let telemetry = Telemetry::open(&path, settings()).await.unwrap();
    telemetry.record(
        event(NOON, "a.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    telemetry.flush().await;
    let overview = telemetry
        .overview(NOON - 1000, NOON + 60_000)
        .await
        .unwrap();
    assert_eq!(overview.forwarded, 1);
}

#[test]
fn days_use_utc() {
    assert_eq!(store::day_of(NOON), "2026-11-03");
    assert_eq!(store::day_start_ms("2026-11-03"), Some(NOON - DAY_MS / 2));
    assert_eq!(store::day_start_ms("not-a-day"), None);
}
