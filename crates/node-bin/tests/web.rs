//! Command-line behavior around the web UI.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Stdio};

fn ferrixdns() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ferrixdns"));
    command.env_remove("RUST_LOG");
    command
}

const SERVE: [&str; 5] = [
    "serve",
    "--listen",
    "127.0.0.1:0",
    "--upstream",
    "127.0.0.1:9",
];

#[test]
fn the_web_ui_needs_a_state_directory() {
    let output = ferrixdns()
        .args(SERVE)
        .args(["--web-listen", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--state-dir"));
}

#[test]
fn plain_http_on_a_network_address_needs_explicit_consent() {
    let directory = tempfile::tempdir().unwrap();
    let output = ferrixdns()
        .args(SERVE)
        .args(["--web-listen", "0.0.0.0:0", "--state-dir"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--web-insecure-remote"), "{stderr}");
}

#[test]
fn health_reports_a_silent_or_missing_node() {
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = silent.local_addr().unwrap().to_string();
    let output = ferrixdns()
        .args(["health", "--address", &address])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no DNS answer"));
}

#[test]
fn settings_can_come_from_the_environment_and_health_checks_a_real_node() {
    use std::io::BufRead;

    let directory = tempfile::tempdir().unwrap();
    let mut child = ferrixdns()
        .arg("serve")
        .env("FERRIXDNS_LISTEN", "127.0.0.1:0")
        .env(
            "FERRIXDNS_UPSTREAM",
            "127.0.0.1:9,tls://dns.example@127.0.0.1:9",
        )
        .env("FERRIXDNS_STATE_DIR", directory.path())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    let address = loop {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "ferrixdns exited early"
        );
        if let Some((_, rest)) = line.split_once("address=") {
            break rest.split_whitespace().next().unwrap().to_owned();
        }
    };
    let output = ferrixdns()
        .args(["health", "--address", &address])
        .output()
        .unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("is answering DNS"));
}

/// Starts a node with a self-signed web UI, returning its URL, fingerprint and setup token.
fn start_tls(state: &std::path::Path) -> (std::process::Child, String, String, Option<String>) {
    use std::io::BufRead;

    let mut child = ferrixdns()
        .args(SERVE)
        .args([
            "--web-listen",
            "127.0.0.1:0",
            "--web-tls-self-signed",
            "--state-dir",
        ])
        .arg(state)
        .env("NO_COLOR", "1")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    let (mut fingerprint, mut url, mut token) = (None, None, None);
    let mut line = String::new();
    while url.is_none() || token.is_none() {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "ferrixdns exited early"
        );
        let value = |key: &str| {
            line.split_once(key)
                .map(|(_, rest)| rest.split_whitespace().next().unwrap().to_owned())
        };
        fingerprint = fingerprint.or_else(|| value("sha256="));
        url = url.or_else(|| value("url="));
        token = token.or_else(|| value("setup_token="));
        // A node with an administrator has no token to wait for.
        if url.is_some() && state.join("config.db").exists() && line.contains("serving the web UI")
        {
            break;
        }
    }
    // Keep reading in the background, so the node never blocks on a full pipe.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while matches!(stderr.read_line(&mut sink), Ok(count) if count > 0) {
            sink.clear();
        }
    });
    (child, url.unwrap(), fingerprint.unwrap(), token)
}

/// Runs curl until the node answers, because `url=` is logged just before it starts serving.
fn curl(args: &[&str], url: &str) -> String {
    let mut last = String::new();
    for _ in 0..50 {
        let output = Command::new("curl")
            .args(["-sk", "-m", "3"])
            .args(args)
            .arg(url)
            .output()
            .expect("these tests need curl");
        last = String::from_utf8_lossy(&output.stdout).into_owned();
        if !last.is_empty() && !last.starts_with("000") {
            return last;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    last
}

#[test]
fn the_web_ui_serves_tls_with_a_self_signed_certificate_and_secure_cookies() {
    let directory = tempfile::tempdir().unwrap();
    let (mut child, url, first_fingerprint, token) = start_tls(directory.path());
    assert!(url.starts_with("https://"), "{url}");

    use std::os::unix::fs::PermissionsExt;
    let key = directory.path().join("tls/self-signed-key.pem");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // HTTP/2 has no Host header, and the DNS rebinding check has to handle that.
    let http2 = curl(
        &[
            "--http2",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{http_version}",
        ],
        &format!("{url}api/v1/health/live"),
    );
    assert_eq!(http2, "200 2");
    let http1 = curl(
        &[
            "--http1.1",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{http_version}",
        ],
        &format!("{url}api/v1/health/live"),
    );
    assert_eq!(http1, "200 1.1");

    let body = format!(
        r#"{{"token":"{}","username":"admin","password":"correct horse battery"}}"#,
        token.unwrap()
    );
    let setup = curl(
        &["-i", "-H", "content-type: application/json", "-d", &body],
        &format!("{url}api/v1/auth/setup"),
    );
    let cookie = setup
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
        .unwrap_or_else(|| panic!("no session cookie in {setup}"));
    assert!(cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(
        !setup
            .to_ascii_lowercase()
            .contains("strict-transport-security"),
        "HSTS would stop people clicking through a self-signed certificate's warning"
    );

    child.kill().unwrap();
    child.wait().unwrap();

    // The certificate stays the same across restarts, so its fingerprint can be trusted once.
    let (mut child, _, second_fingerprint, _) = start_tls(directory.path());
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(first_fingerprint, second_fingerprint);
}

#[test]
fn openapi_prints_the_contract() {
    let output = ferrixdns().arg("openapi").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("\"/api/v1/rules\""));
}

fn reset(state: &std::path::Path, username: &str, password: &str) -> std::process::Output {
    let mut child = ferrixdns()
        .args([
            "admin",
            "reset-password",
            "--username",
            username,
            "--state-dir",
        ])
        .arg(state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{password}").unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn reset_password_rejects_unknown_users_and_short_passwords() {
    let directory = tempfile::tempdir().unwrap();
    let unknown = reset(directory.path(), "nobody", "a long enough password");
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("no administrator named nobody"));

    let short = reset(directory.path(), "nobody", "short");
    assert!(!short.status.success());
    assert!(String::from_utf8_lossy(&short.stderr).contains("at least 10"));
}

mod backup {
    use std::path::Path;
    use std::process::Output;

    use super::*;

    fn run(args: &[&str], state: &Path, extra: &[(&str, &str)]) -> Output {
        let mut command = ferrixdns();
        command.args(args).arg("--state-dir").arg(state);
        for (key, value) in extra {
            command.env(key, value);
        }
        command.env_remove("FERRIXDNS_BACKUP_PASSPHRASE");
        for (key, value) in extra {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    /// Stores a policy with a rule, the way a running node would.
    fn seed(state: &Path) {
        let file = state.with_extension("toml");
        std::fs::write(
            &file,
            "schema_version = 1\n[[rules]]\nid = \"r1\"\naction = \"deny\"\nmatch = \"exact\"\npattern = \"a.example\"\n",
        )
        .unwrap();
        // A brief start with --policy stores it as a revision.
        let mut child = ferrixdns()
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--upstream",
                "127.0.0.1:9",
                "--policy",
            ])
            .arg(&file)
            .arg("--state-dir")
            .arg(state)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(std::io::BufRead::read_line(&mut stderr, &mut line).unwrap() > 0);
            if line.contains("listening for DNS") {
                break;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn create_and_restore_move_a_node_to_a_new_state_directory() {
        let directory = tempfile::tempdir().unwrap();
        let old = directory.path().join("old");
        let new = directory.path().join("new");
        seed(&old);

        let archive = directory.path().join("backup.tar.gz");
        let archive_text = archive.to_str().unwrap();
        let created = run(&["backup", "create", "--output", archive_text], &old, &[]);
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&archive).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "backups can hold sensitive data");

        let dry_run = run(
            &["backup", "restore", "--input", archive_text, "--dry-run"],
            &new,
            &[],
        );
        assert!(dry_run.status.success());
        let stdout = String::from_utf8_lossy(&dry_run.stdout);
        assert!(stdout.contains("1 rules"), "{stdout}");
        assert!(stdout.contains("nothing was changed"), "{stdout}");
        assert!(!new.exists(), "a dry run must not create anything");

        let restored = run(&["backup", "restore", "--input", archive_text], &new, &[]);
        assert!(
            restored.status.success(),
            "{}",
            String::from_utf8_lossy(&restored.stderr)
        );
        let revisions = std::fs::read_dir(new.join("policy")).unwrap().count();
        assert!(revisions >= 2, "expected a revision and its history");
    }

    #[test]
    fn including_accounts_needs_a_strong_passphrase() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        seed(&state);
        let archive = directory.path().join("b.tar.gz");
        let args = [
            "backup",
            "create",
            "--include-credentials",
            "--output",
            archive.to_str().unwrap(),
        ];

        let missing = run(&args, &state, &[]);
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("FERRIXDNS_BACKUP_PASSPHRASE"));

        let short = run(&args, &state, &[("FERRIXDNS_BACKUP_PASSPHRASE", "short")]);
        assert!(!short.status.success());
        assert!(String::from_utf8_lossy(&short.stderr).contains("at least 10"));

        let good = run(
            &args,
            &state,
            &[("FERRIXDNS_BACKUP_PASSPHRASE", "a long passphrase")],
        );
        assert!(
            good.status.success(),
            "{}",
            String::from_utf8_lossy(&good.stderr)
        );

        let target = directory.path().join("target");
        let wrong = run(
            &["backup", "restore", "--input", archive.to_str().unwrap()],
            &target,
            &[("FERRIXDNS_BACKUP_PASSPHRASE", "the wrong passphrase")],
        );
        assert!(!wrong.status.success());
        assert!(String::from_utf8_lossy(&wrong.stderr).contains("passphrase"));
        assert!(
            !target.exists(),
            "a failed restore must not create anything"
        );

        let right = run(
            &["backup", "restore", "--input", archive.to_str().unwrap()],
            &target,
            &[("FERRIXDNS_BACKUP_PASSPHRASE", "a long passphrase")],
        );
        assert!(
            right.status.success(),
            "{}",
            String::from_utf8_lossy(&right.stderr)
        );
        assert!(String::from_utf8_lossy(&right.stdout).contains("accounts"));
    }

    #[test]
    fn a_corrupt_backup_changes_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("bad.tar.gz");
        std::fs::write(&archive, b"garbage").unwrap();
        let target = directory.path().join("target");
        let result = run(
            &["backup", "restore", "--input", archive.to_str().unwrap()],
            &target,
            &[],
        );
        assert!(!result.status.success());
        assert!(!target.exists());
    }
}
