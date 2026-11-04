use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tracing::warn;

use crate::sha256_hex;

const EXTENSION: &str = "list";
const TEMP_PREFIX: &str = ".tmp-";

/// Content-addressed storage for normalized list downloads.
#[derive(Clone, Debug)]
pub struct ArtifactStore {
    directory: PathBuf,
}

impl ArtifactStore {
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

    fn path(&self, sha256: &str) -> Option<PathBuf> {
        // Only hashes become paths, so a document can't point outside this directory.
        let valid = sha256.len() == 64
            && sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        valid.then(|| self.directory.join(format!("{sha256}.{EXTENSION}")))
    }

    /// Durably stores content and returns its SHA-256.
    pub fn put(&self, content: &[u8]) -> io::Result<String> {
        let sha256 = sha256_hex(content);
        let path = self
            .path(&sha256)
            .ok_or_else(|| io::Error::other("invalid artifact hash"))?;
        if self.get(&sha256).is_ok() {
            return Ok(sha256);
        }
        let temp = self.directory.join(format!("{TEMP_PREFIX}{sha256}"));
        let mut file = File::create(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, &path)?;
        sync_directory(&self.directory)?;
        Ok(sha256)
    }

    /// Reads an artifact, verifying it against its hash.
    pub fn get(&self, sha256: &str) -> io::Result<Vec<u8>> {
        let path = self
            .path(sha256)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid artifact hash"))?;
        let content = fs::read(path)?;
        if sha256_hex(&content) != sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "list artifact failed its checksum",
            ));
        }
        Ok(content)
    }

    /// Every stored artifact's SHA-256.
    pub fn list(&self) -> io::Result<Vec<String>> {
        let mut hashes = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == EXTENSION)
                && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
            {
                hashes.push(stem.to_owned());
            }
        }
        Ok(hashes)
    }

    /// Removes artifacts not in `keep`.
    pub fn retain(&self, keep: &HashSet<String>) -> io::Result<()> {
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let is_artifact = path
                .extension()
                .is_some_and(|extension| extension == EXTENSION);
            if is_artifact
                && !keep.contains(stem)
                && let Err(error) = fs::remove_file(&path)
            {
                warn!(%error, "failed to remove an unused list artifact");
            }
        }
        Ok(())
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_verifies_content() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(directory.path()).unwrap();
        let sha256 = store.put(b"e ads.example\n").unwrap();
        assert_eq!(store.get(&sha256).unwrap(), b"e ads.example\n");
        assert_eq!(store.put(b"e ads.example\n").unwrap(), sha256);

        fs::write(directory.path().join(format!("{sha256}.list")), b"tampered").unwrap();
        assert_eq!(
            store.get(&sha256).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // Storing the content again repairs it.
        store.put(b"e ads.example\n").unwrap();
        assert!(store.get(&sha256).is_ok());
    }

    #[test]
    fn refuses_hashes_that_would_escape_the_directory() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(directory.path()).unwrap();
        assert_eq!(
            store.get("../../etc/passwd").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn retain_removes_only_unreferenced_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(directory.path()).unwrap();
        let keep = store.put(b"keep").unwrap();
        let remove = store.put(b"remove").unwrap();
        store.retain(&HashSet::from([keep.clone()])).unwrap();
        assert!(store.get(&keep).is_ok());
        assert_eq!(
            store.get(&remove).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
