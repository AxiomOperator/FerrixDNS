//! Loads, publishes and persists the active policy.
//!
//! The DNS path reads the active policy without locks. Everything here runs outside that path,
//! and a failed load never replaces the policy already active.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use dns_policy::{CompiledPolicy, PolicyDocument, PolicyError};
use dns_storage::{RevisionStore, sha256_hex};
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

struct State {
    source: Option<PathBuf>,
    store: Option<RevisionStore>,
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
        let store = state_directory.and_then(|directory| {
            RevisionStore::open(directory.join("policy"))
                .inspect_err(|error| {
                    // DNS must keep working on a read-only or full disk.
                    error!(%error, "cannot open the policy store; changes won't survive a restart");
                })
                .ok()
        });

        let mut failure = None;
        let mut loaded = None;
        if let Some(path) = &source {
            match load_file(path, None) {
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
            loaded = last_known_good(store.as_ref());
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

        let file = load_file(&path, previous)?;
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
        let rebuilt = CompiledPolicy::compile(
            current.revision(),
            document,
            now,
            Some((document, &*current)),
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

struct LoadedFile {
    content: Vec<u8>,
    document: PolicyDocument,
    policy: CompiledPolicy,
}

fn load_file(
    path: &Path,
    previous: Option<(&PolicyDocument, &CompiledPolicy)>,
) -> Result<LoadedFile, PolicyLoadError> {
    let content = read_source(path)?;
    let document = parse(path, &content)?;
    let revision = sha256_hex(&content);
    let policy = CompiledPolicy::compile(&revision, &document, SystemTime::now(), previous)?;
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

fn last_known_good(store: Option<&RevisionStore>) -> Option<(PolicyDocument, CompiledPolicy)> {
    let revisions = store?
        .revisions()
        .inspect_err(|error| error!(%error, "cannot read stored policy revisions"))
        .ok()?;
    for revision in revisions {
        let compiled = std::str::from_utf8(&revision.content)
            .ok()
            .and_then(|text| PolicyDocument::parse(text).ok())
            .and_then(|document| {
                CompiledPolicy::compile(&revision.sha256, &document, SystemTime::now(), None)
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
