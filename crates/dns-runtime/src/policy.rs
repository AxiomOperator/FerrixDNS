//! Loads, publishes and persists the active policy.
//!
//! The DNS path reads the active policy without locks. Everything here runs outside that path,
//! and a failed load never replaces the policy already active.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use dns_policy::{CompiledPolicy, PolicyDocument, PolicyError, TelemetryConfig};
use dns_storage::{ArtifactStore, RevisionStore, sha256_hex};
use thiserror::Error;
use tokio::sync::Notify;
use tracing::{error, info, warn};

/// The policy shared with the DNS path.
pub type PolicyHandle = Arc<ArcSwap<CompiledPolicy>>;

/// How often the expiry timer rechecks, in case the system clock jumped.
const EXPIRY_RECHECK: Duration = Duration::from_secs(60);

/// A policy handle holding the empty policy, which allows everything.
pub fn empty_policy() -> PolicyHandle {
    Arc::new(ArcSwap::from_pointee(CompiledPolicy::empty()))
}

/// Why a policy could not be loaded.
#[derive(Debug, Error)]
pub enum PolicyLoadError {
    #[error("cannot read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("policy file isn't valid UTF-8: {path}")]
    NotUtf8 { path: PathBuf },
    #[error(transparent)]
    Invalid(#[from] PolicyError),
    #[error("no policy file is configured to reload")]
    NoSource,
}

/// Why a change to the policy wasn't applied. The active policy is unchanged in every case.
#[derive(Debug, Error)]
pub enum MutationError<E> {
    #[error("the policy is managed by a file, so it can't be changed here")]
    ReadOnly,
    #[error("policy changes need a state directory")]
    NoStateDirectory,
    #[error("{0}")]
    Rejected(E),
    #[error(transparent)]
    Invalid(#[from] PolicyError),
    #[error("cannot store the policy: {0}")]
    Storage(#[from] io::Error),
}

/// A stored policy revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionInfo {
    pub revision: String,
    pub active: bool,
    pub rule_count: usize,
    pub list_count: usize,
    pub client_count: usize,
}

struct State {
    source: Option<PathBuf>,
    store: Option<RevisionStore>,
    artifacts: Option<ArtifactStore>,
    /// The active document, kept so the rule overlay can be rebuilt. `None` for the empty policy.
    document: Option<PolicyDocument>,
}

/// Owns the active policy and every change to it.
pub struct PolicyManager {
    active: PolicyHandle,
    state: Mutex<State>,
    changed: Notify,
}

fn read_source(path: &Path) -> Result<Vec<u8>, PolicyLoadError> {
    fs::read(path).map_err(|source| PolicyLoadError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn parse(path: &Path, content: &[u8]) -> Result<PolicyDocument, PolicyLoadError> {
    let text = std::str::from_utf8(content).map_err(|_| PolicyLoadError::NotUtf8 {
        path: path.to_path_buf(),
    })?;
    Ok(PolicyDocument::parse(text)?)
}

fn log_warnings(document: &PolicyDocument) {
    for warning in document.warnings() {
        warn!("policy: {warning}");
    }
}

impl PolicyManager {
    /// Loads the policy to start with, in this order:
    ///
    /// 1. The policy file, which is stored as the newest revision when valid.
    /// 2. The newest valid stored revision, when the file is missing or invalid.
    /// 3. The empty policy, but only when no policy file was configured.
    ///
    /// A configured policy file that's invalid, with no stored revision to fall back on, is an
    /// error. Serving unfiltered DNS would silently ignore what the operator asked for.
    pub fn start(
        source: Option<PathBuf>,
        state_directory: Option<PathBuf>,
    ) -> Result<Arc<Self>, PolicyLoadError> {
        let artifact_directory = state_directory
            .as_ref()
            .map(|directory| directory.join("lists"));
        let store = state_directory.and_then(|directory| {
            RevisionStore::open(directory.join("policy"))
                .inspect_err(|error| {
                    // DNS must keep working on a read-only or full disk.
                    error!(%error, "cannot open the policy store; changes won't survive a restart");
                })
                .ok()
        });

        let artifacts = store
            .as_ref()
            .and(artifact_directory)
            .and_then(|directory| {
                ArtifactStore::open(directory)
                    .inspect_err(|error| error!(%error, "cannot open the list artifact store"))
                    .ok()
            });

        let mut failure = None;
        let mut loaded = None;
        if let Some(path) = &source {
            match load_file(path, None, artifacts.as_ref()) {
                Ok(file) => {
                    commit(store.as_ref(), &file.content);
                    log_warnings(&file.document);
                    loaded = Some((file.document, file.policy));
                }
                Err(load_error) => failure = Some(load_error),
            }
        }
        if loaded.is_none() {
            if let Some(load_error) = &failure {
                error!(error = %load_error, "the policy file can't be used");
            }
            loaded = last_known_good(store.as_ref(), artifacts.as_ref());
        }

        let (document, policy) = match (loaded, failure) {
            (Some((document, policy)), _) => (Some(document), policy),
            (None, Some(load_error)) => return Err(load_error),
            (None, None) => {
                warn!("no policy is configured, so all queries are allowed");
                (None, CompiledPolicy::empty())
            }
        };
        info!(revision = %short(policy.revision()), "policy active");

        Ok(Arc::new(Self {
            active: Arc::new(ArcSwap::from_pointee(policy)),
            state: Mutex::new(State {
                source,
                store,
                artifacts,
                document,
            }),
            changed: Notify::new(),
        }))
    }

    /// The handle the DNS path reads.
    pub fn handle(&self) -> PolicyHandle {
        Arc::clone(&self.active)
    }

    /// Validates the policy file and makes it active, returning the new revision.
    ///
    /// On any error the active policy keeps serving. This does file I/O and compilation, so call
    /// it off the async runtime.
    pub fn reload(&self) -> Result<String, PolicyLoadError> {
        let mut state = self.lock();
        let path = state.source.clone().ok_or(PolicyLoadError::NoSource)?;
        let current = self.active.load_full();
        let previous = state
            .document
            .as_ref()
            .map(|document| (document, &*current));

        let file = load_file(&path, previous, state.artifacts.as_ref())?;
        log_warnings(&file.document);
        commit(state.store.as_ref(), &file.content);

        let revision = file.policy.revision().to_owned();
        self.active.store(Arc::new(file.policy));
        state.document = Some(file.document);
        drop(state);

        self.changed.notify_one();
        info!(revision = %short(&revision), "policy reloaded");
        Ok(revision)
    }

    /// Whether the policy comes from a file, which makes it read-only through the API.
    pub fn is_read_only(&self) -> bool {
        self.lock().source.is_some()
    }

    /// The active policy document.
    pub fn document(&self) -> PolicyDocument {
        self.lock().document.clone().unwrap_or_default()
    }

    /// The store for downloaded lists, if there's a state directory.
    pub fn artifacts(&self) -> Option<ArtifactStore> {
        self.lock().artifacts.clone()
    }

    /// The current retention and logging settings, read fresh each time.
    pub fn telemetry_settings(&self) -> Arc<dyn Fn() -> TelemetryConfig + Send + Sync> {
        let active = self.handle();
        Arc::new(move || active.load().telemetry())
    }

    /// Applies a change: validates and compiles it, stores it durably, then publishes it.
    ///
    /// If any step fails the active policy is unchanged, and a success means the change is
    /// active on this node. This compiles and does file I/O, so call it off the async runtime.
    pub fn mutate<T, E>(
        &self,
        change: impl FnOnce(&mut PolicyDocument) -> Result<T, E>,
    ) -> Result<(T, String), MutationError<E>> {
        let mut state = self.lock();
        if state.source.is_some() {
            return Err(MutationError::ReadOnly);
        }
        let store = state.store.clone().ok_or(MutationError::NoStateDirectory)?;

        let mut document = state.document.clone().unwrap_or_default();
        let result = change(&mut document).map_err(MutationError::Rejected)?;

        let content = document.to_toml().map_err(MutationError::Invalid)?;
        let revision = sha256_hex(content.as_bytes());
        let current = self.active.load_full();
        let previous = state.document.as_ref().map(|old| (old, &*current));
        let policy = compile_checked(
            &revision,
            &document,
            SystemTime::now(),
            previous,
            &|sha256| load_artifact(state.artifacts.as_ref(), sha256),
        )
        .map_err(MutationError::Invalid)?;

        store
            .commit(content.as_bytes())
            .map_err(MutationError::Storage)?;
        self.active.store(Arc::new(policy));
        state.document = Some(document);
        collect_unused_artifacts(&store, state.artifacts.as_ref());
        drop(state);

        self.changed.notify_one();
        info!(revision = %short(&revision), "policy updated");
        Ok((result, revision))
    }

    /// Stored revisions, newest first.
    pub fn revisions(&self) -> io::Result<Vec<RevisionInfo>> {
        let state = self.lock();
        let Some(store) = &state.store else {
            return Ok(Vec::new());
        };
        let active = self.active.load();
        Ok(store
            .revisions()?
            .into_iter()
            .map(|stored| {
                let document = std::str::from_utf8(&stored.content)
                    .ok()
                    .and_then(|text| PolicyDocument::parse(text).ok());
                let counts = document.as_ref().map_or((0, 0, 0), |document| {
                    (
                        document.rules.len(),
                        document.lists.len(),
                        document.clients.len(),
                    )
                });
                RevisionInfo {
                    active: stored.sha256 == active.revision(),
                    revision: stored.sha256,
                    rule_count: counts.0,
                    list_count: counts.1,
                    client_count: counts.2,
                }
            })
            .collect())
    }

    /// Makes a stored revision active again, as the newest revision.
    pub fn activate(&self, revision: &str) -> Result<(), MutationError<RevisionNotFound>> {
        let mut state = self.lock();
        if state.source.is_some() {
            return Err(MutationError::ReadOnly);
        }
        let store = state.store.clone().ok_or(MutationError::NoStateDirectory)?;
        let stored = store
            .revisions()?
            .into_iter()
            .find(|stored| stored.sha256 == revision)
            .ok_or(MutationError::Rejected(RevisionNotFound))?;
        let text = std::str::from_utf8(&stored.content)
            .map_err(|_| MutationError::Rejected(RevisionNotFound))?;
        let document = PolicyDocument::parse(text).map_err(MutationError::Invalid)?;

        let current = self.active.load_full();
        let previous = state.document.as_ref().map(|old| (old, &*current));
        let policy = compile_checked(
            revision,
            &document,
            SystemTime::now(),
            previous,
            &|sha256| load_artifact(state.artifacts.as_ref(), sha256),
        )
        .map_err(MutationError::Invalid)?;

        store
            .commit(&stored.content)
            .map_err(MutationError::Storage)?;
        self.active.store(Arc::new(policy));
        state.document = Some(document);
        drop(state);

        self.changed.notify_one();
        info!(revision = %short(revision), "policy revision activated");
        Ok(())
    }

    /// Stored revisions and the lists they refer to, for backups.
    pub fn export(&self) -> io::Result<PolicyExport> {
        let state = self.lock();
        let store = state.store.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "this node has no state directory")
        })?;
        let revisions: Vec<(String, Vec<u8>)> = store
            .revisions()?
            .into_iter()
            .map(|stored| (stored.sha256, stored.content))
            .collect();
        let wanted: HashSet<String> = revisions
            .iter()
            .filter_map(|(_, content)| std::str::from_utf8(content).ok())
            .filter_map(|text| PolicyDocument::parse(text).ok())
            .flat_map(|document| document.lists)
            .filter_map(|list| list.artifact_sha256)
            .collect();
        let mut artifacts = Vec::new();
        if let Some(store) = &state.artifacts {
            for sha256 in wanted {
                artifacts.push((sha256.clone(), store.get(&sha256)?));
            }
        }
        Ok(PolicyExport {
            revisions,
            artifacts,
        })
    }

    /// Replaces the policy and its history from a validated backup, publishing the newest.
    ///
    /// `revisions` is newest first. Everything's compiled before anything's stored, and the
    /// previous revisions are kept in history until these push them out.
    pub fn restore(
        &self,
        revisions: &[(String, Vec<u8>)],
        artifacts: &[(String, Vec<u8>)],
    ) -> Result<String, MutationError<RevisionNotFound>> {
        let mut state = self.lock();
        if state.source.is_some() {
            return Err(MutationError::ReadOnly);
        }
        let store = state.store.clone().ok_or(MutationError::NoStateDirectory)?;
        let artifact_store = state
            .artifacts
            .clone()
            .ok_or(MutationError::NoStateDirectory)?;
        let (revision, content) = revisions
            .first()
            .ok_or(MutationError::Rejected(RevisionNotFound))?;
        let text =
            std::str::from_utf8(content).map_err(|_| MutationError::Rejected(RevisionNotFound))?;
        let document = PolicyDocument::parse(text).map_err(MutationError::Invalid)?;

        // Artifacts first, because stored revisions refer to them.
        for (_, artifact) in artifacts {
            artifact_store
                .put(artifact)
                .map_err(MutationError::Storage)?;
        }
        let policy = compile_checked(revision, &document, SystemTime::now(), None, &|sha256| {
            load_artifact(Some(&artifact_store), sha256)
        })
        .map_err(MutationError::Invalid)?;

        // Oldest first, so the newest ends up at the front of the history.
        for (_, content) in revisions.iter().rev() {
            store.commit(content).map_err(MutationError::Storage)?;
        }
        self.active.store(Arc::new(policy));
        state.document = Some(document);
        collect_unused_artifacts(&store, state.artifacts.as_ref());
        let revision = revision.clone();
        drop(state);

        self.changed.notify_one();
        info!(revision = %short(&revision), "policy restored from a backup");
        Ok(revision)
    }

    /// Rebuilds the rule overlay if a rule has expired, keeping the same revision and list layer.
    ///
    /// Returns whether a new policy was published.
    pub fn apply_expiry(&self, now: SystemTime) -> Result<bool, PolicyError> {
        let state = self.lock();
        let current = self.active.load_full();
        let due = current.next_expiry().is_some_and(|expiry| expiry <= now);
        let (true, Some(document)) = (due, state.document.as_ref()) else {
            return Ok(false);
        };
        let rebuilt = compile_checked(
            current.revision(),
            document,
            now,
            Some((document, &*current)),
            &|sha256| load_artifact(state.artifacts.as_ref(), sha256),
        )?;
        self.active.store(Arc::new(rebuilt));
        info!("rule expired; published a new rule overlay");
        Ok(true)
    }

    /// Publishes a new overlay whenever a rule expires. This runs until it's cancelled.
    pub async fn run_expiry_timer(self: Arc<Self>) {
        loop {
            let wait = self
                .active
                .load()
                .next_expiry()
                .map_or(EXPIRY_RECHECK, |expiry| {
                    expiry
                        .duration_since(SystemTime::now())
                        .unwrap_or(Duration::ZERO)
                        .min(EXPIRY_RECHECK)
                });
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.changed.notified() => continue,
            }

            let manager = Arc::clone(&self);
            let result =
                tokio::task::spawn_blocking(move || manager.apply_expiry(SystemTime::now())).await;
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    // The active document compiled before, so this shouldn't happen. Back off
                    // rather than retrying in a tight loop.
                    error!(%error, "failed to rebuild the policy after a rule expired");
                    tokio::time::sleep(EXPIRY_RECHECK).await;
                }
                Err(error) => {
                    error!(%error, "the policy expiry task failed");
                    tokio::time::sleep(EXPIRY_RECHECK).await;
                }
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A node's policy history, for backups.
#[derive(Debug, Default)]
pub struct PolicyExport {
    /// SHA-256 and content, newest first.
    pub revisions: Vec<(String, Vec<u8>)>,
    /// SHA-256 and content of every list the revisions refer to.
    pub artifacts: Vec<(String, Vec<u8>)>,
}

/// The requested revision isn't stored.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("that policy revision isn't stored")]
pub struct RevisionNotFound;

fn load_artifact(store: Option<&ArtifactStore>, sha256: &str) -> Result<Vec<u8>, String> {
    let store = store.ok_or("no list artifact store is available")?;
    store.get(sha256).map_err(|error| error.to_string())
}

/// Removes list downloads that no retained revision refers to.
fn collect_unused_artifacts(store: &RevisionStore, artifacts: Option<&ArtifactStore>) {
    let Some(artifacts) = artifacts else {
        return;
    };
    let Ok(revisions) = store.revisions() else {
        return;
    };
    let keep: HashSet<String> = revisions
        .iter()
        .filter_map(|stored| std::str::from_utf8(&stored.content).ok())
        .filter_map(|text| PolicyDocument::parse(text).ok())
        .flat_map(|document| document.lists)
        .filter_map(|list| list.artifact_sha256)
        .collect();
    if let Err(error) = artifacts.retain(&keep) {
        warn!(%error, "failed to clean up unused list artifacts");
    }
}

struct LoadedFile {
    content: Vec<u8>,
    document: PolicyDocument,
    policy: CompiledPolicy,
}

fn load_file(
    path: &Path,
    previous: Option<(&PolicyDocument, &CompiledPolicy)>,
    artifacts: Option<&ArtifactStore>,
) -> Result<LoadedFile, PolicyLoadError> {
    let content = read_source(path)?;
    let document = parse(path, &content)?;
    let revision = sha256_hex(&content);
    let policy = compile_checked(
        &revision,
        &document,
        SystemTime::now(),
        previous,
        &|sha256| load_artifact(artifacts, sha256),
    )?;
    Ok(LoadedFile {
        content,
        document,
        policy,
    })
}

fn commit(store: Option<&RevisionStore>, content: &[u8]) {
    let Some(store) = store else {
        return;
    };
    if let Err(error) = store.commit(content) {
        error!(%error, "cannot persist the policy; it's active but won't survive a restart");
    }
}

fn last_known_good(
    store: Option<&RevisionStore>,
    artifacts: Option<&ArtifactStore>,
) -> Option<(PolicyDocument, CompiledPolicy)> {
    let revisions = store?
        .revisions()
        .inspect_err(|error| error!(%error, "cannot read stored policy revisions"))
        .ok()?;
    for revision in revisions {
        let compiled = std::str::from_utf8(&revision.content)
            .ok()
            .and_then(|text| PolicyDocument::parse(text).ok())
            .and_then(|document| {
                compile_checked(
                    &revision.sha256,
                    &document,
                    SystemTime::now(),
                    None,
                    &|sha256| load_artifact(artifacts, sha256),
                )
                .ok()
                .map(|policy| (document, policy))
            });
        match compiled {
            Some(found) => {
                warn!(revision = %short(&revision.sha256), "using the last known good policy");
                return Some(found);
            }
            None => warn!(
                revision = %short(&revision.sha256),
                "skipping a stored policy revision that no longer compiles"
            ),
        }
    }
    None
}

fn short(revision: &str) -> &str {
    revision.get(..12).unwrap_or(revision)
}

/// Compiles a document, also checking what only this crate can.
fn compile_checked(
    revision: &str,
    document: &PolicyDocument,
    now: SystemTime,
    previous: Option<(&PolicyDocument, &CompiledPolicy)>,
    artifacts: dns_policy::ArtifactLoader<'_>,
) -> Result<CompiledPolicy, PolicyError> {
    crate::forward::validate_forward_servers(document)?;
    CompiledPolicy::compile_with(revision, document, now, previous, artifacts)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use dns_policy::{DomainName, Verdict};

    use super::*;

    const DENY_A: &str = r#"
schema_version = 1
[[rules]]
id = "r1"
action = "deny"
match = "exact"
pattern = "a.example"
"#;
    const DENY_B: &str = r#"
schema_version = 1
[[rules]]
id = "r1"
action = "deny"
match = "exact"
pattern = "b.example"
"#;

    fn blocks(manager: &PolicyManager, domain: &str) -> bool {
        let source: IpAddr = "127.0.0.1".parse().unwrap();
        let name = DomainName::parse(domain).unwrap();
        matches!(
            manager.handle().load().check_query(source, &name),
            Verdict::Block(_)
        )
    }

    struct Paths {
        _directory: tempfile::TempDir,
        file: PathBuf,
        state: PathBuf,
    }

    fn paths() -> Paths {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("policy.toml");
        let state = directory.path().join("state");
        Paths {
            _directory: directory,
            file,
            state,
        }
    }

    fn start(paths: &Paths) -> Result<Arc<PolicyManager>, PolicyLoadError> {
        PolicyManager::start(Some(paths.file.clone()), Some(paths.state.clone()))
    }

    fn only_state(state: &Path) -> Arc<PolicyManager> {
        PolicyManager::start(None, Some(state.to_path_buf())).unwrap()
    }

    #[test]
    fn with_nothing_configured_everything_is_allowed() {
        let manager = PolicyManager::start(None, None).unwrap();
        assert!(!blocks(&manager, "a.example"));
        assert!(matches!(manager.reload(), Err(PolicyLoadError::NoSource)));
    }

    #[test]
    fn loads_and_persists_the_policy_file() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        let manager = start(&paths).unwrap();
        assert!(blocks(&manager, "a.example"));
        assert_eq!(
            manager.handle().load().revision(),
            sha256_hex(DENY_A.as_bytes())
        );

        // A restart with no policy file still restores it.
        assert!(blocks(&only_state(&paths.state), "a.example"));
    }

    #[test]
    fn an_invalid_file_falls_back_to_the_last_known_good_policy() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        start(&paths).unwrap();

        fs::write(&paths.file, "this isn't a policy").unwrap();
        let manager = start(&paths).unwrap();
        assert!(blocks(&manager, "a.example"));
    }

    #[test]
    fn a_missing_file_falls_back_to_the_last_known_good_policy() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        start(&paths).unwrap();

        fs::remove_file(&paths.file).unwrap();
        assert!(blocks(&start(&paths).unwrap(), "a.example"));
    }

    #[test]
    fn an_invalid_file_with_nothing_stored_is_an_error() {
        let paths = paths();
        fs::write(&paths.file, "this isn't a policy").unwrap();
        assert!(matches!(start(&paths), Err(PolicyLoadError::Invalid(_))));

        fs::remove_file(&paths.file).unwrap();
        assert!(matches!(start(&paths), Err(PolicyLoadError::Read { .. })));
    }

    #[test]
    fn a_corrupt_newest_revision_falls_back_to_the_previous_one() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        start(&paths).unwrap();
        fs::write(&paths.file, DENY_B).unwrap();
        start(&paths).unwrap();

        let newest = paths
            .state
            .join("policy")
            .join(format!("{}.rev", sha256_hex(DENY_B.as_bytes())));
        fs::write(newest, "corrupted").unwrap();

        let manager = only_state(&paths.state);
        assert!(blocks(&manager, "a.example"));
        assert!(!blocks(&manager, "b.example"));
    }

    #[test]
    fn a_stored_revision_that_no_longer_compiles_is_skipped() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        start(&paths).unwrap();
        let store = RevisionStore::open(paths.state.join("policy")).unwrap();
        store.commit(b"schema_version = 99").unwrap();

        assert!(blocks(&only_state(&paths.state), "a.example"));
    }

    #[test]
    fn reload_swaps_the_policy_and_keeps_the_old_one_on_failure() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        let manager = start(&paths).unwrap();

        fs::write(&paths.file, DENY_B).unwrap();
        let revision = manager.reload().unwrap();
        assert_eq!(revision, sha256_hex(DENY_B.as_bytes()));
        assert!(blocks(&manager, "b.example"));
        assert!(!blocks(&manager, "a.example"));

        fs::write(&paths.file, "broken").unwrap();
        assert!(manager.reload().is_err());
        assert!(blocks(&manager, "b.example"));
        assert_eq!(manager.handle().load().revision(), revision);

        // The failed file wasn't persisted, so a restart restores the good revision.
        assert!(blocks(&only_state(&paths.state), "b.example"));
    }

    #[test]
    fn a_read_only_state_directory_does_not_stop_the_policy_loading() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        // A regular file where the state directory belongs makes every store operation fail.
        fs::write(&paths.state, "not a directory").unwrap();
        let manager = start(&paths).unwrap();
        assert!(blocks(&manager, "a.example"));
    }

    fn deny_rule(id: &str, pattern: &str) -> dns_policy::RuleDef {
        dns_policy::RuleDef {
            id: id.into(),
            action: dns_policy::RuleAction::Deny,
            match_type: dns_policy::MatchType::Exact,
            pattern: pattern.into(),
            scope: dns_policy::Scope::Global,
            emergency: false,
            enabled: true,
            expires_at: None,
            reason: None,
            revision: 1,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn mutations_publish_persist_and_survive_a_restart() {
        let paths = paths();
        let manager = only_state(&paths.state);
        assert!(!manager.is_read_only());

        let ((), revision) = manager
            .mutate(|document| {
                document.rules.push(deny_rule("r1", "a.example"));
                Ok::<_, std::convert::Infallible>(())
            })
            .unwrap();
        assert!(blocks(&manager, "a.example"));
        assert_eq!(manager.handle().load().revision(), revision);

        let restarted = only_state(&paths.state);
        assert!(blocks(&restarted, "a.example"));
        assert_eq!(restarted.document().rules.len(), 1);
    }

    #[test]
    fn rejected_and_invalid_mutations_change_nothing() {
        let paths = paths();
        let manager = only_state(&paths.state);
        manager
            .mutate(|document| {
                document.rules.push(deny_rule("r1", "a.example"));
                Ok::<_, std::convert::Infallible>(())
            })
            .unwrap();
        let before = manager.handle().load().revision().to_owned();

        let rejected: Result<((), String), _> = manager.mutate(|document| {
            document.rules.clear();
            Err("no")
        });
        assert!(matches!(rejected, Err(MutationError::Rejected("no"))));

        let invalid = manager.mutate(|document| {
            document.rules.push(deny_rule("r2", "a..b"));
            Ok::<_, std::convert::Infallible>(())
        });
        assert!(matches!(invalid, Err(MutationError::Invalid(_))));

        assert_eq!(manager.handle().load().revision(), before);
        assert_eq!(manager.document().rules.len(), 1);
        assert!(blocks(&manager, "a.example"));
    }

    #[test]
    fn a_policy_file_makes_the_api_read_only() {
        let paths = paths();
        fs::write(&paths.file, DENY_A).unwrap();
        let manager = start(&paths).unwrap();
        assert!(manager.is_read_only());
        let result = manager.mutate(|_| Ok::<_, std::convert::Infallible>(()));
        assert!(matches!(result, Err(MutationError::ReadOnly)));
    }

    #[test]
    fn mutations_need_a_state_directory() {
        let manager = PolicyManager::start(None, None).unwrap();
        let result = manager.mutate(|_| Ok::<_, std::convert::Infallible>(()));
        assert!(matches!(result, Err(MutationError::NoStateDirectory)));
    }

    #[test]
    fn revisions_can_be_listed_and_reactivated() {
        let paths = paths();
        let manager = only_state(&paths.state);
        let add = |pattern: &'static str| {
            manager
                .mutate(move |document| {
                    document.rules = vec![deny_rule("r1", pattern)];
                    Ok::<_, std::convert::Infallible>(())
                })
                .unwrap()
                .1
        };
        let first = add("a.example");
        let second = add("b.example");

        let revisions = manager.revisions().unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].revision, second);
        assert!(revisions[0].active);
        assert!(!revisions[1].active);
        assert_eq!(revisions[1].rule_count, 1);

        manager.activate(&first).unwrap();
        assert!(blocks(&manager, "a.example"));
        assert!(!blocks(&manager, "b.example"));
        assert_eq!(manager.revisions().unwrap()[0].revision, first);
        assert!(matches!(
            manager.activate("0000"),
            Err(MutationError::Rejected(RevisionNotFound))
        ));

        // A rollback survives a restart.
        assert!(blocks(&only_state(&paths.state), "a.example"));
    }

    #[test]
    fn downloaded_lists_load_from_artifacts_and_unused_ones_are_removed() {
        let paths = paths();
        let manager = only_state(&paths.state);
        let store = manager.artifacts().unwrap();
        let put = |name: &str| store.put(format!("e {name}\n").as_bytes()).unwrap();
        let set = |sha256: String| {
            manager
                .mutate(move |document| {
                    document.lists = vec![dns_policy::ListDef {
                        id: "remote".into(),
                        name: None,
                        action: dns_policy::RuleAction::Deny,
                        enabled: true,
                        url: Some("https://lists.example/hosts".into()),
                        format: Some(dns_policy::ListFormat::Domains),
                        refresh_seconds: 3600,
                        artifact_sha256: Some(sha256),
                        groups: vec![],
                        domains: vec![],
                        suffixes: vec![],
                    }];
                    Ok::<_, std::convert::Infallible>(())
                })
                .unwrap();
        };

        let first = put("one.example");
        set(first.clone());
        assert!(blocks(&manager, "one.example"));
        assert!(blocks(&only_state(&paths.state), "one.example"));

        // Four generations pushes the first out of the three retained revisions.
        for name in ["two.example", "three.example", "four.example"] {
            set(put(name));
        }
        assert!(blocks(&manager, "four.example"));
        assert!(!blocks(&manager, "one.example"));
        assert!(
            store.get(&first).is_err(),
            "the unreferenced download is removed"
        );
    }

    #[test]
    fn exported_policy_restores_onto_another_state_directory() {
        let source = paths();
        let manager = only_state(&source.state);
        let store = manager.artifacts().unwrap();
        let sha256 = store.put(b"e listed.example\n").unwrap();
        manager
            .mutate(move |document| {
                document.rules = vec![deny_rule("r1", "a.example")];
                document.lists = vec![dns_policy::ListDef {
                    id: "remote".into(),
                    name: None,
                    action: dns_policy::RuleAction::Deny,
                    enabled: true,
                    url: Some("https://lists.example/hosts".into()),
                    format: Some(dns_policy::ListFormat::Domains),
                    refresh_seconds: 3600,
                    artifact_sha256: Some(sha256),
                    groups: vec![],
                    domains: vec![],
                    suffixes: vec![],
                }];
                Ok::<_, std::convert::Infallible>(())
            })
            .unwrap();
        let export = manager.export().unwrap();
        assert_eq!(export.revisions.len(), 1);
        assert_eq!(export.artifacts.len(), 1);

        let target = paths();
        let restored = only_state(&target.state);
        assert!(!blocks(&restored, "a.example"));
        restored
            .restore(&export.revisions, &export.artifacts)
            .unwrap();
        assert!(blocks(&restored, "a.example"));
        assert!(blocks(&restored, "listed.example"));

        // It's durable, and survives a restart.
        let restarted = only_state(&target.state);
        assert!(blocks(&restarted, "listed.example"));
    }

    #[test]
    fn expiry_publishes_a_new_overlay_with_the_same_revision() {
        let paths = paths();
        fs::write(
            &paths.file,
            r#"
schema_version = 1
[[rules]]
id = "temporary"
action = "deny"
match = "exact"
pattern = "a.example"
expires_at = "2099-01-01T00:00:00Z"
[[lists]]
id = "l1"
action = "deny"
domains = ["list.example"]
"#,
        )
        .unwrap();
        let manager = start(&paths).unwrap();
        assert!(blocks(&manager, "a.example"));

        let before = manager.handle().load_full();
        let expiry = before.next_expiry().unwrap();

        assert!(
            !manager
                .apply_expiry(expiry - Duration::from_secs(1))
                .unwrap()
        );
        assert!(blocks(&manager, "a.example"), "not due yet");

        assert!(manager.apply_expiry(expiry).unwrap());
        let after = manager.handle().load_full();
        assert!(!blocks(&manager, "a.example"));
        assert!(blocks(&manager, "list.example"));
        assert_eq!(after.revision(), before.revision());
        assert_eq!(after.next_expiry(), None);
        assert!(Arc::ptr_eq(
            after.snapshot().lists(),
            before.snapshot().lists()
        ));

        assert!(!manager.apply_expiry(expiry).unwrap(), "nothing left to do");
    }
}
