//! Portable node backups.
//!
//! A backup is a gzipped tar with a manifest of checksums. It holds policy revisions, downloaded
//! lists, list fetch state and the audit log. Query history is left out because it's disposable and
//! sensitive, and sessions are never included. Accounts are only included when encrypted with a
//! passphrase.
//!
//! Restoring reads the archive into memory and validates all of it before anything changes, so a
//! bad backup can't leave a node half restored. Entries are looked up by name and never written to
//! paths taken from the archive, so a malicious archive can't reach outside the state directory.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::time::SystemTime;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dns_policy::{CompiledPolicy, PolicyDocument};
use dns_storage::{AuditEvent, ListStatus, User, sha256_hex};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The format this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;
/// The most data an archive may expand to, which stops a small file using all memory.
pub const MAX_EXPANDED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const MANIFEST: &str = "manifest.json";
const HISTORY: &str = "policy/HISTORY";
const LIST_STATUS: &str = "config/list_status.json";
const AUDIT: &str = "config/audit.json";
const CREDENTIALS: &str = "credentials.enc";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Why a backup couldn't be created or read.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("this isn't a readable backup: {0}")]
    Unreadable(String),
    #[error("this backup uses format {found}, and this build reads format {FORMAT_VERSION}")]
    UnsupportedFormat { found: u32 },
    #[error("the backup has an entry that isn't allowed: {0}")]
    UnexpectedEntry(String),
    #[error("the backup is missing {0}")]
    MissingEntry(String),
    #[error("{0} failed its checksum, so the backup is corrupt or was changed")]
    ChecksumMismatch(String),
    #[error("the backup is larger than the {MAX_EXPANDED_BYTES} byte limit")]
    TooLarge,
    #[error("the backup's policy {revision} can't be used: {reason}")]
    InvalidPolicy { revision: String, reason: String },
    #[error("the backup has no policy revisions")]
    NoPolicy,
    #[error("that passphrase doesn't open this backup's accounts")]
    WrongPassphrase,
    #[error("cannot encrypt the accounts: {0}")]
    Encryption(String),
}

#[derive(Debug, Deserialize, Serialize)]
struct ManifestFile {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    format_version: u32,
    created_at_ms: i64,
    app_version: String,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredUser {
    id: String,
    username: String,
    password_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredStatus {
    list_id: String,
    etag: Option<String>,
    last_modified: Option<String>,
    last_checked_at_ms: Option<i64>,
    last_success_at_ms: Option<i64>,
    last_error: Option<String>,
    entry_count: i64,
    invalid_line_count: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredAudit {
    id: String,
    occurred_at_ms: i64,
    actor: String,
    action: String,
    target: String,
    details_json: String,
}

/// A policy revision from a backup or a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    pub sha256: String,
    pub content: Vec<u8>,
}

/// What goes into a backup.
#[derive(Debug, Default)]
pub struct BackupSource {
    /// Newest first.
    pub revisions: Vec<Revision>,
    /// Downloaded lists, by SHA-256.
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub list_statuses: Vec<ListStatus>,
    pub audit_events: Vec<AuditEvent>,
    /// Accounts, with the passphrase that protects them.
    pub credentials: Option<(Vec<User>, String)>,
    pub app_version: String,
}

/// A backup that has passed every check, ready to restore.
#[derive(Debug)]
pub struct ValidatedBackup {
    /// Newest first.
    pub revisions: Vec<Revision>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub list_statuses: Vec<ListStatus>,
    pub audit_events: Vec<AuditEvent>,
    encrypted_credentials: Option<Vec<u8>>,
    pub summary: BackupSummary,
}

/// What a backup contains, for showing before restoring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSummary {
    pub created_at_ms: i64,
    pub app_version: String,
    pub revision: String,
    pub revision_count: usize,
    pub rule_count: usize,
    pub list_count: usize,
    pub client_count: usize,
    pub local_record_count: usize,
    pub artifact_count: usize,
    pub has_credentials: bool,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], BackupError> {
    let mut key = [0_u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| BackupError::Encryption(error.to_string()))?;
    Ok(key)
}

fn encrypt_credentials(users: &[User], passphrase: &str) -> Result<Vec<u8>, BackupError> {
    let stored: Vec<StoredUser> = users
        .iter()
        .map(|user| StoredUser {
            id: user.id.clone(),
            username: user.username.clone(),
            password_hash: user.password_hash.clone(),
        })
        .collect();
    let plaintext =
        serde_json::to_vec(&stored).map_err(|error| BackupError::Encryption(error.to_string()))?;

    let salt: [u8; SALT_LEN] = rand::random();
    let nonce: [u8; NONCE_LEN] = rand::random();
    let cipher = XChaCha20Poly1305::new((&derive_key(passphrase, &salt)?).into());
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext.as_slice())
        .map_err(|error| BackupError::Encryption(error.to_string()))?;

    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_credentials(data: &[u8], passphrase: &str) -> Result<Vec<User>, BackupError> {
    let (salt, rest) = data
        .split_at_checked(SALT_LEN)
        .ok_or(BackupError::WrongPassphrase)?;
    let (nonce, ciphertext) = rest
        .split_at_checked(NONCE_LEN)
        .ok_or(BackupError::WrongPassphrase)?;
    let cipher = XChaCha20Poly1305::new((&derive_key(passphrase, salt)?).into());
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| BackupError::WrongPassphrase)?;
    let plaintext = cipher
        .decrypt(&XNonce::from(nonce), ciphertext)
        .map_err(|_| BackupError::WrongPassphrase)?;
    let stored: Vec<StoredUser> =
        serde_json::from_slice(&plaintext).map_err(|_| BackupError::WrongPassphrase)?;
    Ok(stored
        .into_iter()
        .map(|user| User {
            id: user.id,
            username: user.username,
            password_hash: user.password_hash,
        })
        .collect())
}

fn json_error(error: serde_json::Error) -> BackupError {
    BackupError::Unreadable(error.to_string())
}

/// Builds a backup archive.
pub fn create_backup(source: &BackupSource) -> Result<Vec<u8>, BackupError> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    let history = source
        .revisions
        .iter()
        .map(|revision| revision.sha256.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    files.push((HISTORY.to_owned(), history.into_bytes()));
    for revision in &source.revisions {
        files.push((
            format!("policy/{}.rev", revision.sha256),
            revision.content.clone(),
        ));
    }
    for (sha256, content) in &source.artifacts {
        files.push((format!("lists/{sha256}.list"), content.clone()));
    }

    let statuses: Vec<StoredStatus> = source
        .list_statuses
        .iter()
        .map(|status| StoredStatus {
            list_id: status.list_id.clone(),
            etag: status.etag.clone(),
            last_modified: status.last_modified.clone(),
            last_checked_at_ms: status.last_checked_at_ms,
            last_success_at_ms: status.last_success_at_ms,
            last_error: status.last_error.clone(),
            entry_count: status.entry_count,
            invalid_line_count: status.invalid_line_count,
        })
        .collect();
    files.push((
        LIST_STATUS.to_owned(),
        serde_json::to_vec(&statuses).map_err(json_error)?,
    ));

    let audit: Vec<StoredAudit> = source
        .audit_events
        .iter()
        .map(|event| StoredAudit {
            id: event.id.clone(),
            occurred_at_ms: event.occurred_at_ms,
            actor: event.actor.clone(),
            action: event.action.clone(),
            target: event.target.clone(),
            details_json: event.details_json.clone(),
        })
        .collect();
    files.push((
        AUDIT.to_owned(),
        serde_json::to_vec(&audit).map_err(json_error)?,
    ));

    if let Some((users, passphrase)) = &source.credentials {
        files.push((
            CREDENTIALS.to_owned(),
            encrypt_credentials(users, passphrase)?,
        ));
    }

    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        created_at_ms: now_ms(),
        app_version: source.app_version.clone(),
        files: files
            .iter()
            .map(|(path, content)| ManifestFile {
                path: path.clone(),
                sha256: sha256_hex(content),
                bytes: content.len() as u64,
            })
            .collect(),
    };

    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut append = |path: &str, content: &[u8]| -> Result<(), BackupError> {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, path, content)
            .map_err(|error| BackupError::Unreadable(error.to_string()))
    };
    append(
        MANIFEST,
        &serde_json::to_vec_pretty(&manifest).map_err(json_error)?,
    )?;
    for (path, content) in &files {
        append(path, content)?;
    }
    let encoder = archive
        .into_inner()
        .map_err(|error| BackupError::Unreadable(error.to_string()))?;
    encoder
        .finish()
        .map_err(|error| BackupError::Unreadable(error.to_string()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a path is one of the fixed names a backup may hold.
fn is_allowed_path(path: &str) -> bool {
    if matches!(path, MANIFEST | HISTORY | LIST_STATUS | AUDIT | CREDENTIALS) {
        return true;
    }
    let hashed = |prefix: &str, suffix: &str| {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(is_sha256)
    };
    hashed("policy/", ".rev") || hashed("lists/", ".list")
}

fn read_entries(
    archive_bytes: &[u8],
    limit: u64,
) -> Result<BTreeMap<String, Vec<u8>>, BackupError> {
    let unreadable = |error: std::io::Error| BackupError::Unreadable(error.to_string());
    // The limit applies to decompressed bytes as they're read, whatever the headers claim.
    let decoder = GzDecoder::new(archive_bytes).take(limit.saturating_add(1024 * 1024));
    let mut archive = tar::Archive::new(decoder);
    let mut entries = BTreeMap::new();
    let mut total = 0_u64;

    for entry in archive.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        let path = entry
            .path()
            .map_err(unreadable)?
            .to_str()
            .ok_or_else(|| BackupError::UnexpectedEntry("a non-text name".to_owned()))?
            .to_owned();
        if !entry.header().entry_type().is_file() || !is_allowed_path(&path) {
            return Err(BackupError::UnexpectedEntry(path));
        }
        let size = entry.size();
        total = total.saturating_add(size);
        if total > limit {
            return Err(BackupError::TooLarge);
        }
        let mut content = Vec::with_capacity(usize::try_from(size).unwrap_or(0).min(1 << 20));
        entry.read_to_end(&mut content).map_err(unreadable)?;
        if entries.insert(path.clone(), content).is_some() {
            return Err(BackupError::UnexpectedEntry(path));
        }
    }
    Ok(entries)
}

/// Reads and fully validates a backup, without changing anything.
pub fn read_backup(archive_bytes: &[u8]) -> Result<ValidatedBackup, BackupError> {
    read_backup_with_limit(archive_bytes, MAX_EXPANDED_BYTES)
}

/// Like [`read_backup`], with a specific limit on the expanded size.
pub fn read_backup_with_limit(
    archive_bytes: &[u8],
    limit: u64,
) -> Result<ValidatedBackup, BackupError> {
    let mut entries = read_entries(archive_bytes, limit)?;
    let manifest_bytes = entries
        .remove(MANIFEST)
        .ok_or_else(|| BackupError::MissingEntry(MANIFEST.to_owned()))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(json_error)?;
    if manifest.format_version != FORMAT_VERSION {
        return Err(BackupError::UnsupportedFormat {
            found: manifest.format_version,
        });
    }

    let listed: HashSet<&str> = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    if let Some(extra) = entries.keys().find(|path| !listed.contains(path.as_str())) {
        return Err(BackupError::UnexpectedEntry(extra.clone()));
    }
    for file in &manifest.files {
        let content = entries
            .get(&file.path)
            .ok_or_else(|| BackupError::MissingEntry(file.path.clone()))?;
        if sha256_hex(content) != file.sha256 || content.len() as u64 != file.bytes {
            return Err(BackupError::ChecksumMismatch(file.path.clone()));
        }
    }

    let history = entries
        .get(HISTORY)
        .ok_or_else(|| BackupError::MissingEntry(HISTORY.to_owned()))?;
    let history = String::from_utf8_lossy(history).into_owned();
    let mut revisions = Vec::new();
    for sha256 in history.lines().filter(|line| !line.is_empty()) {
        let path = format!("policy/{sha256}.rev");
        let content = entries
            .remove(&path)
            .ok_or(BackupError::MissingEntry(path))?;
        // The name is the revision's identity, so it has to match the content.
        if sha256_hex(&content) != sha256 {
            return Err(BackupError::ChecksumMismatch(format!(
                "policy/{sha256}.rev"
            )));
        }
        revisions.push(Revision {
            sha256: sha256.to_owned(),
            content,
        });
    }

    let mut artifacts = BTreeMap::new();
    let artifact_paths: Vec<String> = entries
        .keys()
        .filter(|path| path.starts_with("lists/"))
        .cloned()
        .collect();
    for path in artifact_paths {
        let Some(content) = entries.remove(&path) else {
            continue;
        };
        let sha256 = path
            .strip_prefix("lists/")
            .and_then(|rest| rest.strip_suffix(".list"))
            .unwrap_or_default()
            .to_owned();
        if sha256_hex(&content) != sha256 {
            return Err(BackupError::ChecksumMismatch(path));
        }
        artifacts.insert(sha256, content);
    }

    let newest = revisions.first().ok_or(BackupError::NoPolicy)?;
    let document = validate_policy(newest, &artifacts)?;
    // Older revisions are a rollback path, so they have to work too.
    for revision in revisions.iter().skip(1) {
        validate_policy(revision, &artifacts)?;
    }

    let statuses: Vec<StoredStatus> = match entries.get(LIST_STATUS) {
        Some(bytes) => serde_json::from_slice(bytes).map_err(json_error)?,
        None => Vec::new(),
    };
    let audit: Vec<StoredAudit> = match entries.get(AUDIT) {
        Some(bytes) => serde_json::from_slice(bytes).map_err(json_error)?,
        None => Vec::new(),
    };
    let encrypted_credentials = entries.remove(CREDENTIALS);

    let summary = BackupSummary {
        created_at_ms: manifest.created_at_ms,
        app_version: manifest.app_version,
        revision: newest.sha256.clone(),
        revision_count: revisions.len(),
        rule_count: document.rules.len(),
        list_count: document.lists.len(),
        client_count: document.clients.len(),
        local_record_count: document.local_records.len(),
        artifact_count: artifacts.len(),
        has_credentials: encrypted_credentials.is_some(),
    };
    Ok(ValidatedBackup {
        revisions,
        artifacts,
        list_statuses: statuses
            .into_iter()
            .map(|status| ListStatus {
                list_id: status.list_id,
                etag: status.etag,
                last_modified: status.last_modified,
                last_checked_at_ms: status.last_checked_at_ms,
                last_success_at_ms: status.last_success_at_ms,
                last_error: status.last_error,
                entry_count: status.entry_count,
                invalid_line_count: status.invalid_line_count,
            })
            .collect(),
        audit_events: audit
            .into_iter()
            .map(|event| AuditEvent {
                id: event.id,
                occurred_at_ms: event.occurred_at_ms,
                actor: event.actor,
                action: event.action,
                target: event.target,
                details_json: event.details_json,
            })
            .collect(),
        encrypted_credentials,
        summary,
    })
}

/// A dry run: the policy must parse and compile, with every list it refers to.
fn validate_policy(
    revision: &Revision,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<PolicyDocument, BackupError> {
    let invalid = |reason: String| BackupError::InvalidPolicy {
        revision: revision.sha256.get(..12).unwrap_or_default().to_owned(),
        reason,
    };
    let text = std::str::from_utf8(&revision.content)
        .map_err(|_| invalid("it isn't valid text".to_owned()))?;
    let document = PolicyDocument::parse(text).map_err(|error| invalid(error.to_string()))?;
    CompiledPolicy::compile_with(
        &revision.sha256,
        &document,
        SystemTime::now(),
        None,
        &|sha256| {
            artifacts
                .get(sha256)
                .cloned()
                .ok_or_else(|| "the backup doesn't include this list".to_owned())
        },
    )
    .map_err(|error| invalid(error.to_string()))?;
    Ok(document)
}

impl ValidatedBackup {
    /// Decrypts the backup's accounts.
    pub fn credentials(&self, passphrase: &str) -> Result<Option<Vec<User>>, BackupError> {
        self.encrypted_credentials
            .as_deref()
            .map(|data| decrypt_credentials(data, passphrase))
            .transpose()
    }
}

/// Writes a backup to a file readable only by its owner, replacing it atomically.
pub fn write_private_file(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut temp_name = path.as_os_str().to_owned();
    temp_name.push(".tmp");
    let temp = std::path::PathBuf::from(temp_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(content)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)
}

#[cfg(test)]
mod tests;
