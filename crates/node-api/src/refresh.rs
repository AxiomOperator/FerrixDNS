//! Downloads subscribed lists, on request and on their schedule.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use dns_lists::{Conditional, FetchOutcome, parse_list};
use dns_policy::{ListDef, ListFormat};
use dns_runtime::MutationError;
use dns_storage::ListStatus;
use tracing::{info, warn};
use ulid::Ulid;

use crate::AppState;
use crate::dto::{JobDto, JobState};
use crate::util::now_ms;

const SCHEDULE_INTERVAL: Duration = Duration::from_secs(60);
const RETAINED_JOBS: usize = 100;

/// Recent refresh jobs. Jobs are in memory, because they only matter while someone's watching.
#[derive(Clone, Default)]
pub struct Jobs {
    inner: Arc<Mutex<JobTable>>,
    /// One download at a time, so large lists can't stack up in memory.
    running: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Default)]
struct JobTable {
    jobs: HashMap<String, JobDto>,
    order: VecDeque<String>,
}

impl Jobs {
    fn lock(&self) -> MutexGuard<'_, JobTable> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn start(&self, list_id: &str) -> JobDto {
        let job = JobDto {
            id: Ulid::generate().to_string(),
            list_id: list_id.to_owned(),
            state: JobState::Running,
            message: None,
        };
        let mut table = self.lock();
        table.jobs.insert(job.id.clone(), job.clone());
        table.order.push_back(job.id.clone());
        while table.order.len() > RETAINED_JOBS {
            if let Some(oldest) = table.order.pop_front() {
                table.jobs.remove(&oldest);
            }
        }
        job
    }

    fn finish(&self, id: &str, state: JobState, message: String) {
        if let Some(job) = self.lock().jobs.get_mut(id) {
            job.state = state;
            job.message = Some(message);
        }
    }

    pub fn get(&self, id: &str) -> Option<JobDto> {
        self.lock().jobs.get(id).cloned()
    }
}

/// Starts a refresh in the background and returns its job.
pub fn spawn_refresh(state: &AppState, list_id: &str) -> JobDto {
    let job = state.jobs.start(list_id);
    let state = state.clone();
    let list_id = list_id.to_owned();
    let job_id = job.id.clone();
    tokio::spawn(async move {
        let _running = state.jobs.running.lock().await;
        match refresh_list(&state, &list_id).await {
            Ok(message) => state.jobs.finish(&job_id, JobState::Succeeded, message),
            Err(message) => state.jobs.finish(&job_id, JobState::Failed, message),
        }
    });
    job
}

fn find_list(state: &AppState, list_id: &str) -> Option<ListDef> {
    state
        .manager
        .document()
        .lists
        .into_iter()
        .find(|list| list.id == list_id)
}

/// Downloads one list. Any failure is recorded and leaves the active content in place.
async fn refresh_list(state: &AppState, list_id: &str) -> Result<String, String> {
    let list = find_list(state, list_id).ok_or("the list no longer exists")?;
    let url = list.url.clone().ok_or("this list has no URL")?;
    let format = list.format.unwrap_or(ListFormat::Domains);

    let mut status = state
        .db
        .list_status(list_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| ListStatus {
            list_id: list_id.to_owned(),
            ..ListStatus::default()
        });
    let result = download(state, &list, &url, format, &mut status).await;

    status.last_checked_at_ms = Some(now_ms());
    match &result {
        Ok(_) => {
            status.last_success_at_ms = status.last_checked_at_ms;
            status.last_error = None;
        }
        Err(message) => {
            warn!(list = list_id, error = %message, "list refresh failed");
            status.last_error = Some(message.clone());
        }
    }
    // A deleted list must not leave its status behind.
    if find_list(state, list_id).is_some()
        && let Err(error) = state.db.save_list_status(&status).await
    {
        warn!(%error, "failed to save list status");
    }
    result
}

async fn download(
    state: &AppState,
    list: &ListDef,
    url: &str,
    format: ListFormat,
    status: &mut ListStatus,
) -> Result<String, String> {
    // Validators only apply while the content they describe is still pinned.
    let conditional = if list.artifact_sha256.is_some() {
        Conditional {
            etag: status.etag.clone(),
            last_modified: status.last_modified.clone(),
        }
    } else {
        Conditional::default()
    };
    let outcome = state
        .fetcher
        .fetch(url, &conditional)
        .await
        .map_err(|error| error.to_string())?;

    let (text, etag, last_modified) = match outcome {
        FetchOutcome::NotModified => return Ok("The list hasn't changed".to_owned()),
        FetchOutcome::Body {
            text,
            etag,
            last_modified,
        } => (text, etag, last_modified),
    };

    let store = state
        .manager
        .artifacts()
        .ok_or("list downloads need the node to run with --state-dir")?;
    let manager = Arc::clone(&state.manager);
    let list_id = list.id.clone();
    let unchanged_hash = list.artifact_sha256.clone();

    // Parsing and compiling large lists is CPU-heavy, so it stays off the async workers.
    let (parsed_entries, invalid, sha256) = tokio::task::spawn_blocking(move || {
        let parsed = parse_list(format, &text).map_err(|error| error.to_string())?;
        let sha256 = store
            .put(&parsed.artifact)
            .map_err(|error| error.to_string())?;
        if unchanged_hash.as_deref() != Some(sha256.as_str()) {
            let pinned = sha256.clone();
            manager
                .mutate(|document| {
                    let list = document
                        .lists
                        .iter_mut()
                        .find(|list| list.id == list_id)
                        .ok_or("the list no longer exists")?;
                    list.artifact_sha256 = Some(pinned);
                    Ok::<_, &str>(())
                })
                .map_err(|error: MutationError<&str>| error.to_string())?;
        }
        Ok::<_, String>((parsed.entry_count, parsed.invalid_line_count, sha256))
    })
    .await
    .map_err(|error| error.to_string())??;

    status.etag = etag;
    status.last_modified = last_modified;
    status.entry_count = i64::try_from(parsed_entries).unwrap_or(i64::MAX);
    status.invalid_line_count = i64::try_from(invalid).unwrap_or(i64::MAX);
    info!(list = %list.id, entries = parsed_entries, %sha256, "list refreshed");
    Ok(format!("Loaded {parsed_entries} entries"))
}

/// Refreshes lists when they're due. This runs until it's cancelled.
pub async fn run_schedule(state: AppState) {
    if state.manager.is_read_only() {
        return;
    }
    loop {
        tokio::time::sleep(SCHEDULE_INTERVAL).await;
        let statuses: HashMap<String, ListStatus> = match state.db.list_statuses().await {
            Ok(statuses) => statuses
                .into_iter()
                .map(|status| (status.list_id.clone(), status))
                .collect(),
            Err(error) => {
                warn!(%error, "cannot read list status");
                continue;
            }
        };
        let now = now_ms();
        for list in state.manager.document().lists {
            if !list.enabled || list.url.is_none() {
                continue;
            }
            let last_checked = statuses
                .get(&list.id)
                .and_then(|status| status.last_checked_at_ms)
                .unwrap_or(0);
            let interval =
                i64::try_from(list.refresh_seconds.saturating_mul(1000)).unwrap_or(i64::MAX);
            if now.saturating_sub(last_checked) >= interval {
                spawn_refresh(&state, &list.id);
            }
        }
    }
}
