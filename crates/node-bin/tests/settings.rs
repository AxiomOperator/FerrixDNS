//! Changing the node's own settings from the dashboard, on the real binary: restarts, rollback and
//! recovery.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PASSWORD: &str = "correct horse battery";
const SERVFAIL: u8 = 2;

/// A port that's free now, and that no other test in this run has been given.
fn free_port() -> u16 {
    static GIVEN: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut given = GIVEN.lock().unwrap();
        if !given.contains(&port) {
            given.push(port);
            return port;
        }
    }
}

fn free_dns_port() -> u16 {
    loop {
        let port = free_port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A node on known ports, killed when dropped. It keeps its process ID across restarts.
struct Node {
    child: Child,
    dns_port: u16,
    web_port: u16,
    log: Arc<Mutex<String>>,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn start(state: &Path, extra: &[&str]) -> Self {
        let (dns_port, web_port) = (free_dns_port(), free_port());
        Self::start_on(state, dns_port, web_port, extra)
    }

    fn start_on(state: &Path, dns_port: u16, web_port: u16, extra: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrixdns"))
            .args(["serve", "--listen", &format!("127.0.0.1:{dns_port}")])
            .args(["--upstream", "127.0.0.1:9"])
            .args(["--attempt-timeout-ms", "50", "--query-timeout-ms", "100"])
            .args(["--web-listen", &format!("127.0.0.1:{web_port}")])
            .arg("--state-dir")
            .arg(state)
            .args(extra)
            .env("NO_COLOR", "1")
            .env_remove("RUST_LOG")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = BufReader::new(child.stderr.take().unwrap());
        let log = Arc::new(Mutex::new(String::new()));
        let writer = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in stderr.lines().map_while(Result::ok) {
                let mut log = writer.lock().unwrap();
                log.push_str(&line);
                log.push('\n');
            }
        });
        Self {
            child,
            dns_port,
            web_port,
            log,
        }
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}/api/v1", self.web_port)
    }

    fn setup_token(&self) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some((_, rest)) = self.log.lock().unwrap().split_once("setup_token=") {
                return rest.split_whitespace().next().unwrap().to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "no setup token:\n{}",
                self.log.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Sets up the administrator and returns a session.
    fn session(&self, jar: &Path) -> Session {
        let token = self.setup_token();
        let body = format!(r#"{{"token":"{token}","username":"admin","password":"{PASSWORD}"}}"#);
        let reply = wait_for_curl(&[
            "-c",
            jar.to_str().unwrap(),
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &format!("{}/auth/setup", self.base()),
        ]);
        Session {
            csrf: field(&reply, "csrf_token"),
            jar: jar.to_str().unwrap().to_owned(),
        }
    }

    fn rcode(&self, name: &str) -> Option<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(u8::try_from(label.len()).unwrap());
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        socket.send_to(&query, ("127.0.0.1", self.dns_port)).ok()?;
        let mut reply = [0_u8; 512];
        socket.recv_from(&mut reply).ok()?;
        Some(reply[3] & 0x0f)
    }

    fn wait_for_log(&self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.log.lock().unwrap().contains(text) {
            assert!(
                Instant::now() < deadline,
                "never logged {text:?}:\n{}",
                self.log.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn field(json: &str, name: &str) -> String {
    let marker = format!("\"{name}\":\"");
    let (_, rest) = json
        .split_once(&marker)
        .unwrap_or_else(|| panic!("no {name} in {json}"));
    rest.split('"').next().unwrap().to_owned()
}

fn curl(args: &[&str]) -> Option<String> {
    let output = Command::new("curl")
        .args(["-sk", "-m", "3"])
        .args(args)
        .output()
        .expect("these tests need curl");
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn wait_for_curl(args: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(reply) = curl(args) {
            return reply;
        }
        assert!(Instant::now() < deadline, "no answer to {args:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct Session {
    csrf: String,
    jar: String,
}

impl Session {
    fn get(&self, url: &str) -> String {
        wait_for_curl(&["-b", &self.jar, url])
    }

    fn send(&self, method: &str, url: &str, body: &str) -> String {
        wait_for_curl(&[
            "-b",
            &self.jar,
            "-X",
            method,
            "-H",
            &format!("X-CSRF-Token: {}", self.csrf),
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
            url,
        ])
    }

    /// The saved settings as JSON, changed by replacing text.
    fn settings(&self, node: &Node) -> String {
        let view = self.get(&format!("{}/node-settings", node.base()));
        let (_, rest) = view.split_once("\"settings\":").unwrap();
        // The settings object is flat apart from lists, so its first closing brace ends it.
        let end = rest.find('}').unwrap();
        rest[..=end].to_owned()
    }

    fn boot_id(&self, node: &Node) -> String {
        field(
            &self.get(&format!("{}/node-settings", node.base())),
            "boot_id",
        )
    }

    fn wait_for_restart(&self, node: &Node, old_boot_id: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.boot_id(node) == old_boot_id {
            assert!(Instant::now() < deadline, "the node never restarted");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn scripted_upstream(answer_rcode: u8) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 512];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer) {
            let mut reply = buffer[..length].to_vec();
            reply[2] = 0x81;
            reply[3] = 0x80 | answer_rcode;
            let _ = socket.send_to(&reply, peer);
        }
    });
    port
}

#[test]
fn a_saved_setting_restarts_the_node_and_survives_another_restart() {
    const REFUSED_BY_UPSTREAM: u8 = 5;
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let jar = directory.path().join("jar");
    let node = Node::start(&state, &[]);
    let session = node.session(&jar);
    let pid = node.child.id();
    assert_eq!(node.rcode("before.example"), Some(SERVFAIL));

    let upstream = scripted_upstream(REFUSED_BY_UPSTREAM);
    let boot_id = session.boot_id(&node);
    let changed = session.settings(&node).replace(
        "\"upstreams\":[\"127.0.0.1:9\"]",
        &format!("\"upstreams\":[\"127.0.0.1:{upstream}\"]"),
    );
    let reply = session.send("PUT", &format!("{}/node-settings", node.base()), &changed);
    assert!(reply.contains("\"restarting\":true"), "{reply}");
    session.wait_for_restart(&node, &boot_id);
    assert_eq!(node.child.id(), pid, "it restarts in place");
    assert_eq!(node.rcode("after.example"), Some(REFUSED_BY_UPSTREAM));

    // Sessions survive, and only the changed setting is saved.
    let view = session.get(&format!("{}/node-settings", node.base()));
    assert!(view.contains("\"changed\":[\"upstreams\"]"), "{view}");
    assert!(!view.contains("\"pending\":{"), "{view}");
    let saved = std::fs::read_to_string(state.join("node-settings.json")).unwrap();
    assert!(saved.contains(&upstream.to_string()), "{saved}");
    assert!(!saved.contains("cache_mib"), "{saved}");
    assert!(!saved.contains("\"trial\": {"), "{saved}");

    // A fresh start keeps it over the command line, until it's reset.
    let (dns_port, web_port) = (node.dns_port, node.web_port);
    drop(node);
    let node = Node::start_on(&state, dns_port, web_port, &[]);
    node.wait_for_log("using settings saved from the dashboard");
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.rcode("again.example") != Some(REFUSED_BY_UPSTREAM) {
        assert!(Instant::now() < deadline, "the setting didn't survive");
    }
    drop(node);

    let reset = Command::new(env!("CARGO_BIN_EXE_ferrixdns"))
        .args(["admin", "reset-settings", "--state-dir"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(reset.status.success());
    let node = Node::start_on(&state, dns_port, web_port, &[]);
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.rcode("reset.example") != Some(SERVFAIL) {
        assert!(Instant::now() < deadline, "the reset didn't work");
    }
}

#[test]
fn a_taken_port_is_refused_before_anything_changes() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let node = Node::start(&state, &[]);
    let session = node.session(&directory.path().join("jar"));
    let boot_id = session.boot_id(&node);

    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let changed = session.settings(&node).replace(
        &format!("\"listen\":[\"127.0.0.1:{}\"]", node.dns_port),
        &format!("\"listen\":[\"127.0.0.1:{port}\"]"),
    );
    let reply = session.send("PUT", &format!("{}/node-settings", node.base()), &changed);
    assert!(reply.contains("Can't use this DNS address"), "{reply}");
    assert_eq!(session.boot_id(&node), boot_id, "nothing restarted");
    assert_eq!(node.rcode("still.example"), Some(SERVFAIL));
}

/// Saves a change directly, as if the check at save time had passed and the port was taken later.
fn write_trial(state: &Path, changes: &str, confirm_by_ms: &str) {
    std::fs::create_dir_all(state).unwrap();
    std::fs::write(
        state.join("node-settings.json"),
        format!(
            r#"{{"schema_version":1,"changes":{changes},
                "trial":{{"previous":{{}},"confirm_by_ms":{confirm_by_ms}}}}}"#
        ),
    )
    .unwrap();
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

#[test]
fn a_change_the_node_cannot_start_with_is_undone() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    write_trial(
        &state,
        &format!(r#"{{"listen":["127.0.0.1:{port}"]}}"#),
        "null",
    );

    let node = Node::start(&state, &[]);
    node.wait_for_log("restoring the previous ones");
    let deadline = Instant::now() + Duration::from_secs(20);
    while node.rcode("recovered.example") != Some(SERVFAIL) {
        assert!(Instant::now() < deadline, "DNS never came back");
    }
    let saved = std::fs::read_to_string(state.join("node-settings.json")).unwrap();
    assert!(saved.contains("couldn't start with that change"), "{saved}");
    assert!(saved.contains("\"changes\": {}"), "{saved}");
}

#[test]
fn settings_that_worked_before_are_kept_when_an_address_is_missing_at_boot() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let saved = format!(r#"{{"schema_version":1,"changes":{{"listen":["127.0.0.1:{port}"]}}}}"#);
    std::fs::write(state.join("node-settings.json"), &saved).unwrap();

    let mut node = Node::start(&state, &[]);
    let status = node.child.wait().unwrap();
    assert!(!status.success());
    node.wait_for_log("ferrixdns admin reset-settings");
    assert_eq!(
        std::fs::read_to_string(state.join("node-settings.json")).unwrap(),
        saved,
        "a passing problem at boot must not lose saved settings"
    );
}

#[test]
fn a_dashboard_change_nobody_keeps_undoes_itself() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let new_port = free_port();
    write_trial(
        &state,
        &format!(r#"{{"web_listen":"127.0.0.1:{new_port}"}}"#),
        &(unix_ms() + 2_000).to_string(),
    );

    let node = Node::start(&state, &[]);
    // It runs on the new address first, then returns to the old one.
    wait_for_curl(&[&format!("http://127.0.0.1:{new_port}/api/v1/health/live")]);
    wait_for_curl(&[&format!("{}/health/live", node.base())]);
    assert!(
        curl(&[&format!("http://127.0.0.1:{new_port}/api/v1/health/live")]).is_none(),
        "the new address should be gone"
    );
    let saved = std::fs::read_to_string(state.join("node-settings.json")).unwrap();
    assert!(saved.contains("wasn't kept within 2 minutes"), "{saved}");
}

#[test]
fn a_dashboard_change_can_be_kept_or_undone_from_the_new_address() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let node = Node::start(&state, &[]);
    let session = node.session(&directory.path().join("jar"));
    let base = node.base();
    let new_port = free_port();
    let new_base = format!("http://127.0.0.1:{new_port}/api/v1");
    let changed = session.settings(&node).replace(
        &format!("\"web_listen\":\"127.0.0.1:{}\"", node.web_port),
        &format!("\"web_listen\":\"127.0.0.1:{new_port}\""),
    );

    // Undo returns to the old address.
    session.send("PUT", &format!("{base}/node-settings"), &changed);
    let view = session.get(&format!("{new_base}/node-settings"));
    assert!(view.contains("\"seconds_left\":"), "{view}");
    let another = session.send("PUT", &format!("{new_base}/node-settings"), &changed);
    assert!(another.contains("NODE_SETTINGS_PENDING"), "{another}");
    session.send("POST", &format!("{new_base}/node-settings/undo"), "");
    let view = session.get(&format!("{base}/node-settings"));
    assert!(view.contains("\"changed\":[]"), "{view}");

    // Keep stays on the new address, with nothing left to undo.
    session.send("PUT", &format!("{base}/node-settings"), &changed);
    session.get(&format!("{new_base}/node-settings"));
    let kept = session.send("POST", &format!("{new_base}/node-settings/confirm"), "");
    assert!(kept.contains("\"changed\":[\"web_listen\"]"), "{kept}");
    assert!(!kept.contains("\"seconds_left\":"), "{kept}");
    let again = session.send("POST", &format!("{new_base}/node-settings/confirm"), "");
    assert!(again.contains("NODE_SETTINGS_NOT_PENDING"), "{again}");
}

#[test]
fn turning_on_tls_from_the_dashboard_serves_https() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let node = Node::start(&state, &[]);
    let session = node.session(&directory.path().join("jar"));
    let changed = session.settings(&node).replace(
        "\"web_tls_mode\":\"off\"",
        "\"web_tls_mode\":\"self_signed\"",
    );
    session.send("PUT", &format!("{}/node-settings", node.base()), &changed);
    let live = wait_for_curl(&[&format!(
        "https://127.0.0.1:{}/api/v1/health/live",
        node.web_port
    )]);
    assert!(!live.is_empty());
    assert!(state.join("tls/self-signed-cert.pem").exists());
}

#[test]
fn the_data_folder_can_be_moved_and_everything_follows_it() {
    const NXDOMAIN: u8 = 3;
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let moved = directory.path().join("moved");
    let node = Node::start(&state, &[]);
    let session = node.session(&directory.path().join("jar"));
    let rule = session.send(
        "POST",
        &format!("{}/rules", node.base()),
        r#"{"action":"deny","match_type":"exact","pattern":"moved-rule.example","scope":{"kind":"global"}}"#,
    );
    assert!(rule.contains("moved-rule.example"), "{rule}");
    assert_eq!(node.rcode("moved-rule.example"), Some(NXDOMAIN));

    // A folder holding something else is refused.
    let occupied = directory.path().join("occupied");
    std::fs::create_dir_all(&occupied).unwrap();
    std::fs::write(occupied.join("file"), "").unwrap();
    let state_text = state.to_str().unwrap();
    let settings = session.settings(&node);
    let refused = session.send(
        "PUT",
        &format!("{}/node-settings", node.base()),
        &settings.replace(state_text, occupied.to_str().unwrap()),
    );
    assert!(refused.contains("must be empty"), "{refused}");

    let boot_id = session.boot_id(&node);
    session.send(
        "PUT",
        &format!("{}/node-settings", node.base()),
        &settings.replace(state_text, moved.to_str().unwrap()),
    );
    session.wait_for_restart(&node, &boot_id);

    // The session, policy and rule all came along, and the settings stayed where they're looked for.
    assert_eq!(node.rcode("moved-rule.example"), Some(NXDOMAIN));
    assert!(moved.join("config.db").is_file());
    assert!(state.join("node-settings.json").is_file());
    assert!(!moved.join("node-settings.json").exists());
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferrixdns"))
        .args([
            "admin",
            "reset-password",
            "--username",
            "admin",
            "--state-dir",
        ])
        .arg(&state)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"a brand new password\n")
        .unwrap();
    assert!(child.wait().unwrap().success());
    let login = wait_for_curl(&[
        "-H",
        "Content-Type: application/json",
        "-d",
        r#"{"username":"admin","password":"a brand new password"}"#,
        &format!("{}/auth/login", node.base()),
    ]);
    assert!(
        login.contains("csrf_token"),
        "the reset reached the moved data: {login}"
    );
}

#[test]
fn a_certificate_from_files_can_be_turned_on_from_the_dashboard() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let node = Node::start(&state, &[]);
    let session = node.session(&directory.path().join("jar"));

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert, key) = (
        directory.path().join("cert.pem"),
        directory.path().join("key.pem"),
    );
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    let (cert_text, key_text) = (cert.to_str().unwrap(), key.to_str().unwrap());
    let with_files = |key_path: &str| {
        session
            .settings(&node)
            .replace("\"web_tls_mode\":\"off\"", "\"web_tls_mode\":\"files\"")
            .replace(
                "\"web_tls_cert\":null",
                &format!("\"web_tls_cert\":\"{cert_text}\""),
            )
            .replace(
                "\"web_tls_key\":null",
                &format!("\"web_tls_key\":\"{key_path}\""),
            )
    };

    // A key that doesn't match is refused, and the node keeps running.
    let refused = session.send(
        "PUT",
        &format!("{}/node-settings", node.base()),
        &with_files(cert_text),
    );
    assert!(refused.contains("NODE_SETTINGS_INVALID"), "{refused}");

    session.send(
        "PUT",
        &format!("{}/node-settings", node.base()),
        &with_files(key_text),
    );
    let url = format!("https://localhost:{}/api/v1/health/live", node.web_port);
    let live = wait_for_curl(&["--cacert", cert_text, "--fail", &url]);
    assert!(
        !live.is_empty(),
        "the certificate validates against its own file"
    );
}

#[test]
fn the_health_check_follows_a_dns_address_saved_from_the_dashboard() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let dns_port = free_dns_port();
    std::fs::write(
        state.join("node-settings.json"),
        format!(r#"{{"changes":{{"listen":["127.0.0.1:{dns_port}"]}}}}"#),
    )
    .unwrap();
    let node = Node::start(&state, &[]);
    node.wait_for_log("listening for DNS");
    let output = Command::new(env!("CARGO_BIN_EXE_ferrixdns"))
        .arg("health")
        .env("FERRIXDNS_HEALTH_ADDRESS", "127.0.0.1:9")
        .env("FERRIXDNS_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_log_filter_can_be_changed_from_the_dashboard() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let node = Node::start(&state, &[]);
    let session = node.session(&directory.path().join("jar"));
    assert!(!node.log.lock().unwrap().contains(" DEBUG "));
    let boot_id = session.boot_id(&node);
    let changed = session.settings(&node).replace(
        "info,hickory_server=warn",
        "debug,hickory_server=warn,sqlx=warn",
    );
    session.send("PUT", &format!("{}/node-settings", node.base()), &changed);
    session.wait_for_restart(&node, &boot_id);
    node.wait_for_log(" DEBUG ");
}
