//! Durable storage for policy revisions.
//!
//! Each revision is a file named after its SHA-256, and `HISTORY` lists them newest first. Files
//! are written with write, fsync and atomic rename, so a crash leaves either the old state or the
//! new one, and a corrupt revision is detected by its checksum and skipped.

mod artifacts;
mod config_db;

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tracing::warn;

pub use artifacts::ArtifactStore;
pub use config_db::{
    AuditEvent, ConfigDb, ConfigDbError, ListStatus, NetworkDevice, Session, User,
};

/// Revisions kept: the active one plus the previous two known-good revisions.
pub const RETAINED_REVISIONS: usize = 3;

const HISTORY_FILE: &str = "HISTORY";
const REVISION_EXTENSION: &str = "rev";
const TEMP_PREFIX: &str = ".tmp-";

/// A stored revision whose content matched its checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRevision {
    pub sha256: String,
    pub content: Vec<u8>,
}

/// The SHA-256 of `content` in lowercase hexadecimal.
pub fn sha256_hex(content: &[u8]) -> String {
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A directory of policy revisions, ordered from newest to oldest.
#[derive(Clone, Debug)]
pub struct RevisionStore {
    directory: PathBuf,
}

impl RevisionStore {
    /// Opens a store, creating its directory and removing temp files left by a crash.
    pub fn open(directory: impl Into<PathBuf>) -> io::Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(Self { directory })
    }

    /// Durably records `content` as the newest revision and returns its SHA-256.
    ///
    /// Committing content that's already stored moves it to the front of the history.
    pub fn commit(&self, content: &[u8]) -> io::Result<String> {
        let sha256 = sha256_hex(content);
        let path = self.revision_path(&sha256);
        if verified_content(&path, &sha256).is_none() {
            self.write_atomically(&path, content)?;
        }

        let mut history = vec![sha256.clone()];
        history.extend(self.history()?.into_iter().filter(|old| *old != sha256));
        let dropped = history.split_off(history.len().min(RETAINED_REVISIONS));

        let mut listing = history.join("\n");
        listing.push('\n');
        self.write_atomically(&self.directory.join(HISTORY_FILE), listing.as_bytes())?;

        // History no longer references these, so a failure here only wastes disk space.
        for old in dropped {
            if let Err(error) = fs::remove_file(self.revision_path(&old)) {
                warn!(revision = %old, %error, "failed to remove an old policy revision");
            }
        }
        Ok(sha256)
    }

    /// Stored revisions from newest to oldest, skipping any that are missing or corrupt.
    pub fn revisions(&self) -> io::Result<Vec<StoredRevision>> {
        let mut revisions = Vec::new();
        for sha256 in self.history()? {
            match verified_content(&self.revision_path(&sha256), &sha256) {
                Some(content) => revisions.push(StoredRevision { sha256, content }),
                None => warn!(revision = %sha256, "skipping a missing or corrupt policy revision"),
            }
        }
        Ok(revisions)
    }

    fn history(&self) -> io::Result<Vec<String>> {
        let listing = match fs::read_to_string(self.directory.join(HISTORY_FILE)) {
            Ok(listing) => listing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        // Only checksums become paths, so the file can't point outside this directory.
        Ok(listing
            .lines()
            .filter(|line| is_sha256_hex(line))
            .map(ToOwned::to_owned)
            .collect())
    }

    fn revision_path(&self, sha256: &str) -> PathBuf {
        self.directory
            .join(format!("{sha256}.{REVISION_EXTENSION}"))
    }

    fn write_atomically(&self, path: &Path, content: &[u8]) -> io::Result<()> {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let temp = self.directory.join(format!("{TEMP_PREFIX}{name}"));
        let mut file = File::create(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        File::open(&self.directory)?.sync_all()
    }
}

fn verified_content(path: &Path, sha256: &str) -> Option<Vec<u8>> {
    let content = fs::read(path).ok()?;
    (sha256_hex(&content) == sha256).then_some(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, RevisionStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = RevisionStore::open(directory.path().join("policy")).unwrap();
        (directory, store)
    }

    fn contents(store: &RevisionStore) -> Vec<Vec<u8>> {
        store
            .revisions()
            .unwrap()
            .into_iter()
            .map(|revision| revision.content)
            .collect()
    }

    #[test]
    fn an_empty_store_has_no_revisions() {
        let (_directory, store) = store();
        assert!(store.revisions().unwrap().is_empty());
    }

    #[test]
    fn hashes_match_a_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn returns_revisions_newest_first_across_reopens() {
        let (directory, store) = store();
        store.commit(b"one").unwrap();
        let second = store.commit(b"two").unwrap();
        assert_eq!(second, sha256_hex(b"two"));

        let reopened = RevisionStore::open(directory.path().join("policy")).unwrap();
        assert_eq!(contents(&reopened), [b"two".to_vec(), b"one".to_vec()]);
    }

    #[test]
    fn retains_the_active_revision_and_two_previous() {
        let (directory, store) = store();
        for content in [&b"one"[..], b"two", b"three", b"four"] {
            store.commit(content).unwrap();
        }
        assert_eq!(
            contents(&store),
            [b"four".to_vec(), b"three".to_vec(), b"two".to_vec()]
        );
        let oldest = directory
            .path()
            .join("policy")
            .join(format!("{}.rev", sha256_hex(b"one")));
        assert!(!oldest.exists(), "dropped revisions should be deleted");
    }

    #[test]
    fn recommitting_moves_a_revision_to_the_front_without_duplicates() {
        let (_directory, store) = store();
        store.commit(b"one").unwrap();
        store.commit(b"two").unwrap();
        store.commit(b"one").unwrap();
        assert_eq!(contents(&store), [b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn skips_a_corrupt_revision_and_falls_back_to_the_previous_one() {
        let (directory, store) = store();
        store.commit(b"good").unwrap();
        let newest = store.commit(b"newest").unwrap();
        fs::write(
            directory
                .path()
                .join("policy")
                .join(format!("{newest}.rev")),
            b"tampered",
        )
        .unwrap();
        assert_eq!(contents(&store), [b"good".to_vec()]);
    }

    #[test]
    fn recommitting_repairs_a_corrupt_revision() {
        let (directory, store) = store();
        let sha256 = store.commit(b"content").unwrap();
        let path = directory
            .path()
            .join("policy")
            .join(format!("{sha256}.rev"));
        fs::write(&path, b"tampered").unwrap();
        store.commit(b"content").unwrap();
        assert_eq!(contents(&store), [b"content".to_vec()]);
    }

    #[test]
    fn skips_a_missing_revision() {
        let (directory, store) = store();
        store.commit(b"good").unwrap();
        let newest = store.commit(b"newest").unwrap();
        fs::remove_file(
            directory
                .path()
                .join("policy")
                .join(format!("{newest}.rev")),
        )
        .unwrap();
        assert_eq!(contents(&store), [b"good".to_vec()]);
    }

    #[test]
    fn a_crash_before_the_history_update_keeps_the_previous_revision_active() {
        let (directory, store) = store();
        store.commit(b"previous").unwrap();
        // The new revision reached disk, but the crash came before HISTORY was replaced.
        let root = directory.path().join("policy");
        fs::write(root.join(format!("{}.rev", sha256_hex(b"new"))), b"new").unwrap();
        fs::write(root.join(".tmp-HISTORY"), b"partial").unwrap();

        let reopened = RevisionStore::open(&root).unwrap();
        assert_eq!(contents(&reopened), [b"previous".to_vec()]);
        assert!(!root.join(".tmp-HISTORY").exists());
    }

    #[test]
    fn ignores_history_lines_that_are_not_checksums() {
        let (directory, store) = store();
        let sha256 = store.commit(b"good").unwrap();
        let history = format!("../../etc/passwd\n\nnot-a-hash\n{sha256}\n");
        fs::write(directory.path().join("policy").join(HISTORY_FILE), history).unwrap();
        assert_eq!(contents(&store), [b"good".to_vec()]);
    }
}
