use super::*;

const POLICY: &str = r#"
schema_version = 1
[[rules]]
id = "r1"
action = "deny"
match = "exact"
pattern = "a.example"
[[clients]]
id = "c1"
addresses = ["10.0.0.1"]
"#;

fn revision(content: &str) -> Revision {
    Revision {
        sha256: sha256_hex(content.as_bytes()),
        content: content.as_bytes().to_vec(),
    }
}

fn source() -> BackupSource {
    BackupSource {
        revisions: vec![revision(POLICY), revision("schema_version = 1\n")],
        list_statuses: vec![ListStatus {
            list_id: "l1".into(),
            etag: Some("v1".into()),
            entry_count: 5,
            ..ListStatus::default()
        }],
        audit_events: vec![AuditEvent {
            id: "e1".into(),
            occurred_at_ms: 1,
            actor: "admin".into(),
            action: "rule.create".into(),
            target: "r1".into(),
            details_json: "{}".into(),
        }],
        app_version: "1.2.3".into(),
        ..BackupSource::default()
    }
}

fn user() -> User {
    User {
        id: "u1".into(),
        username: "admin".into(),
        password_hash: "$argon2id$hash".into(),
    }
}

/// Builds a raw archive, for testing what a hostile or damaged one does.
fn raw_archive(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o600);
        header.set_path(path).unwrap();
        header.set_cksum();
        archive.append(&header, content.as_slice()).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap()
}

/// Reads an archive's entries, changes them, and rebuilds it with its original manifest.
fn tampered(change: impl FnOnce(&mut BTreeMap<String, Vec<u8>>)) -> Vec<u8> {
    let mut entries = read_entries(&create_backup(&source()).unwrap(), MAX_EXPANDED_BYTES).unwrap();
    change(&mut entries);
    let refs: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(p, c)| (p.as_str(), c.clone()))
        .collect();
    raw_archive(&refs)
}

#[test]
fn a_backup_round_trips() {
    let archive = create_backup(&source()).unwrap();
    let backup = read_backup(&archive).unwrap();

    assert_eq!(backup.revisions[0].content, POLICY.as_bytes());
    assert_eq!(backup.revisions.len(), 2);
    assert_eq!(backup.list_statuses[0].etag.as_deref(), Some("v1"));
    assert_eq!(backup.audit_events[0].id, "e1");

    let summary = &backup.summary;
    assert_eq!(summary.app_version, "1.2.3");
    assert_eq!(summary.revision, sha256_hex(POLICY.as_bytes()));
    assert_eq!(
        (
            summary.revision_count,
            summary.rule_count,
            summary.client_count
        ),
        (2, 1, 1)
    );
    assert!(!summary.has_credentials);
}

#[test]
fn downloaded_lists_are_included_and_checked() {
    let artifact = b"e ads.example\n".to_vec();
    let sha = sha256_hex(&artifact);
    let policy = format!(
        "schema_version = 1\n[[lists]]\nid = \"l\"\naction = \"deny\"\nartifact_sha256 = \"{sha}\"\n"
    );
    let mut with_list = BackupSource {
        revisions: vec![revision(&policy)],
        ..BackupSource::default()
    };
    with_list.artifacts.insert(sha.clone(), artifact);
    let backup = read_backup(&create_backup(&with_list).unwrap()).unwrap();
    assert_eq!(backup.summary.artifact_count, 1);

    // A revision whose list isn't in the backup can't be restored.
    with_list.artifacts.clear();
    let error = read_backup(&create_backup(&with_list).unwrap()).unwrap_err();
    assert!(
        matches!(error, BackupError::InvalidPolicy { .. }),
        "{error}"
    );
}

#[test]
fn accounts_are_excluded_unless_encrypted() {
    let plain = create_backup(&source()).unwrap();
    assert!(
        read_backup(&plain)
            .unwrap()
            .credentials("any")
            .unwrap()
            .is_none()
    );
    let entries = read_entries(&plain, MAX_EXPANDED_BYTES).unwrap();
    assert!(!entries.contains_key(CREDENTIALS));

    let protected = BackupSource {
        credentials: Some((vec![user()], "correct passphrase".into())),
        ..source()
    };
    let archive = create_backup(&protected).unwrap();
    let backup = read_backup(&archive).unwrap();
    assert!(backup.summary.has_credentials);
    assert_eq!(
        backup.credentials("correct passphrase").unwrap().unwrap(),
        vec![user()]
    );
    assert!(matches!(
        backup.credentials("wrong passphrase"),
        Err(BackupError::WrongPassphrase)
    ));

    // Nothing about the account is readable in the archive.
    let entries = read_entries(&archive, MAX_EXPANDED_BYTES).unwrap();
    let stored = &entries[CREDENTIALS];
    let as_text = String::from_utf8_lossy(stored);
    assert!(!as_text.contains("admin") && !as_text.contains("argon2"));
}

#[test]
fn a_changed_or_missing_file_is_detected() {
    let path = format!("policy/{}.rev", sha256_hex(POLICY.as_bytes()));
    let changed = tampered(|entries| {
        entries.insert(path.clone(), b"schema_version = 1\n# edited\n".to_vec());
    });
    assert!(matches!(
        read_backup(&changed),
        Err(BackupError::ChecksumMismatch(_))
    ));

    let removed = tampered(|entries| {
        entries.remove(&path);
    });
    assert!(matches!(
        read_backup(&removed),
        Err(BackupError::MissingEntry(_))
    ));

    let no_manifest = tampered(|entries| {
        entries.remove(MANIFEST);
    });
    assert!(matches!(
        read_backup(&no_manifest),
        Err(BackupError::MissingEntry(_))
    ));

    let extra_hash = "f".repeat(64);
    let unlisted = tampered(|entries| {
        entries.insert(
            format!("lists/{extra_hash}.list"),
            b"e x.example\n".to_vec(),
        );
    });
    assert!(matches!(
        read_backup(&unlisted),
        Err(BackupError::UnexpectedEntry(_))
    ));
}

#[test]
fn a_revision_must_match_its_name_even_with_a_matching_manifest() {
    let wrong_name = "a".repeat(64);
    let content = POLICY.as_bytes().to_vec();
    let history = wrong_name.clone().into_bytes();
    let rev_path = format!("policy/{wrong_name}.rev");
    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        created_at_ms: 1,
        app_version: "x".into(),
        files: vec![
            ManifestFile {
                path: rev_path.clone(),
                sha256: sha256_hex(&content),
                bytes: content.len() as u64,
            },
            ManifestFile {
                path: HISTORY.into(),
                sha256: sha256_hex(&history),
                bytes: history.len() as u64,
            },
        ],
    };
    let archive = raw_archive(&[
        (MANIFEST, serde_json::to_vec(&manifest).unwrap()),
        (HISTORY, history),
        (&rev_path, content),
    ]);
    assert!(matches!(
        read_backup(&archive),
        Err(BackupError::ChecksumMismatch(_))
    ));
}

#[test]
fn hostile_paths_and_entry_types_are_rejected() {
    for path in [
        "../../etc/passwd",
        "/etc/passwd",
        "policy/../../x",
        "policy/evil.rev",
        "other.txt",
    ] {
        // set_path refuses some of these, so write the raw name into the header directly.
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o600);
        header.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();
        let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        archive.append(&header, &b"x"[..]).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        assert!(
            matches!(read_backup(&bytes), Err(BackupError::UnexpectedEntry(_))),
            "{path}"
        );
    }

    let mut link = tar::Header::new_gnu();
    link.set_size(0);
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_path(MANIFEST).unwrap();
    link.set_link_name("/etc/passwd").unwrap();
    link.set_cksum();
    let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    archive.append(&link, std::io::empty()).unwrap();
    let bytes = archive.into_inner().unwrap().finish().unwrap();
    assert!(matches!(
        read_backup(&bytes),
        Err(BackupError::UnexpectedEntry(_))
    ));
}

#[test]
fn duplicate_entries_are_rejected() {
    let archive = raw_archive(&[(MANIFEST, b"{}".to_vec()), (MANIFEST, b"{}".to_vec())]);
    assert!(matches!(
        read_backup(&archive),
        Err(BackupError::UnexpectedEntry(_))
    ));
}

#[test]
fn archives_that_expand_too_far_are_rejected() {
    let archive = raw_archive(&[(HISTORY, vec![0_u8; 10_000_000])]);
    assert!(archive.len() < 100_000, "this should compress well");
    assert!(matches!(
        read_backup_with_limit(&archive, 1_000_000),
        Err(BackupError::TooLarge)
    ));
}

#[test]
fn other_formats_and_garbage_are_rejected() {
    assert!(matches!(
        read_backup(b"not an archive"),
        Err(BackupError::Unreadable(_))
    ));

    let manifest = Manifest {
        format_version: 99,
        created_at_ms: 1,
        app_version: "x".into(),
        files: vec![],
    };
    let newer = raw_archive(&[(MANIFEST, serde_json::to_vec(&manifest).unwrap())]);
    assert!(matches!(
        read_backup(&newer),
        Err(BackupError::UnsupportedFormat { found: 99 })
    ));
}

#[test]
fn a_backup_with_no_policy_or_a_broken_policy_is_rejected() {
    let empty = BackupSource::default();
    assert!(matches!(
        read_backup(&create_backup(&empty).unwrap()),
        Err(BackupError::NoPolicy)
    ));

    let broken = BackupSource {
        revisions: vec![revision("not a policy")],
        ..BackupSource::default()
    };
    assert!(matches!(
        read_backup(&create_backup(&broken).unwrap()),
        Err(BackupError::InvalidPolicy { .. })
    ));
}

#[test]
fn private_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let directory =
        std::env::temp_dir().join(format!("ferrixdns-backup-test-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("backup.tar.gz");
    write_private_file(&path, b"content").unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(std::fs::read(&path).unwrap(), b"content");
    std::fs::remove_dir_all(&directory).unwrap();
}
