//! End-to-end policy behavior of the `ferrixdns` binary: restarts, reloads, expiry and validation.
//!
//! The upstream is unreachable, so an allowed query gets SERVFAIL and a blocked one gets NXDOMAIN
//! without touching the network.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

const SERVFAIL: u8 = 2;
const NXDOMAIN: u8 = 3;

fn deny(domain: &str) -> String {
    format!(
        "schema_version = 1\n[[rules]]\nid = \"r1\"\naction = \"deny\"\nmatch = \"exact\"\npattern = \"{domain}\"\n"
    )
}

/// A running `ferrixdns serve` that's killed when dropped.
struct Node {
    child: Child,
    address: SocketAddr,
    _stderr: BufReader<ChildStderr>,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ferrixdns() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ferrixdns"));
    command.env_remove("RUST_LOG");
    command
}

fn start(policy: Option<&Path>, state: &Path) -> Node {
    let mut command = ferrixdns();
    command
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "127.0.0.1:9",
        ])
        .args(["--attempt-timeout-ms", "50", "--query-timeout-ms", "100"])
        .arg("--state-dir")
        .arg(state)
        .stderr(Stdio::piped());
    if let Some(policy) = policy {
        command.arg("--policy").arg(policy);
    }
    let mut child = command.spawn().unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());

    let mut line = String::new();
    let address = loop {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "ferrixdns exited early"
        );
        if let Some((_, rest)) = line.split_once("address=") {
            break rest.split_whitespace().next().unwrap().parse().unwrap();
        }
    };
    Node {
        child,
        address,
        _stderr: stderr,
    }
}

/// Encodes a type A query for a name.
fn query(domain: &str) -> Vec<u8> {
    let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in domain.split('.') {
        packet.push(u8::try_from(label.len()).unwrap());
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

fn rcode(node: &Node, domain: &str) -> u8 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(&query(domain), node.address).unwrap();
    let mut reply = [0_u8; 512];
    socket.recv_from(&mut reply).unwrap();
    reply[3] & 0x0f
}

fn wait_for_rcode(node: &Node, domain: &str, expected: u8, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        let actual = rcode(node, domain);
        if actual == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{domain} still has rcode {actual}, expected {expected}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn hangup(node: &Node) {
    let status = Command::new("kill")
        .args(["-HUP", &node.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let policy = directory.path().join("policy.toml");
    let state = directory.path().join("state");
    (directory, policy, state)
}

#[test]
fn enforces_the_policy_file() {
    let (_directory, policy, state) = setup();
    fs::write(&policy, deny("blocked.example")).unwrap();
    let node = start(Some(&policy), &state);
    assert_eq!(rcode(&node, "blocked.example"), NXDOMAIN);
    assert_eq!(rcode(&node, "other.example"), SERVFAIL);
}

#[test]
fn a_killed_node_restores_the_last_good_policy_without_its_file() {
    let (_directory, policy, state) = setup();
    fs::write(&policy, deny("blocked.example")).unwrap();
    {
        let mut node = start(Some(&policy), &state);
        assert_eq!(rcode(&node, "blocked.example"), NXDOMAIN);
        // SIGKILL gives the process no chance to save anything on the way out.
        node.child.kill().unwrap();
        node.child.wait().unwrap();
    }

    fs::remove_file(&policy).unwrap();
    let restored = start(Some(&policy), &state);
    assert_eq!(rcode(&restored, "blocked.example"), NXDOMAIN);

    let state_only = start(None, &state);
    assert_eq!(rcode(&state_only, "blocked.example"), NXDOMAIN);
}

#[test]
fn a_restart_with_a_broken_file_keeps_the_last_good_policy() {
    let (_directory, policy, state) = setup();
    fs::write(&policy, deny("blocked.example")).unwrap();
    drop(start(Some(&policy), &state));

    fs::write(&policy, "not valid").unwrap();
    let node = start(Some(&policy), &state);
    assert_eq!(rcode(&node, "blocked.example"), NXDOMAIN);
}

#[test]
fn refuses_to_start_with_a_broken_file_and_no_stored_policy() {
    let (_directory, policy, state) = setup();
    fs::write(&policy, "not valid").unwrap();
    let output = ferrixdns()
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "127.0.0.1:9",
        ])
        .arg("--policy")
        .arg(&policy)
        .arg("--state-dir")
        .arg(&state)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to load the policy"));
}

#[test]
fn sighup_reloads_the_policy_and_a_bad_reload_changes_nothing() {
    let (_directory, policy, state) = setup();
    fs::write(&policy, deny("first.example")).unwrap();
    let node = start(Some(&policy), &state);
    assert_eq!(rcode(&node, "first.example"), NXDOMAIN);

    fs::write(&policy, deny("second.example")).unwrap();
    hangup(&node);
    wait_for_rcode(&node, "second.example", NXDOMAIN, Duration::from_secs(5));
    assert_eq!(rcode(&node, "first.example"), SERVFAIL);

    fs::write(&policy, "not valid").unwrap();
    hangup(&node);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rcode(&node, "second.example"), NXDOMAIN);
    assert_eq!(rcode(&node, "first.example"), SERVFAIL);
}

#[test]
fn a_rule_expires_without_a_restart_or_reload() {
    let (_directory, policy, state) = setup();
    let expiry = SystemTime::now() + Duration::from_secs(2);
    let document = format!(
        "{}expires_at = \"{}\"\n",
        deny("temporary.example"),
        humantime::format_rfc3339_seconds(expiry)
    );
    fs::write(&policy, document).unwrap();

    let node = start(Some(&policy), &state);
    assert_eq!(rcode(&node, "temporary.example"), NXDOMAIN);
    wait_for_rcode(&node, "temporary.example", SERVFAIL, Duration::from_secs(5));
}

#[test]
fn validate_accepts_good_files_and_rejects_bad_ones() {
    let (_directory, policy, _state) = setup();

    fs::write(&policy, deny("a.example")).unwrap();
    let output = ferrixdns()
        .args(["policy", "validate"])
        .arg(&policy)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("is valid: 1 rules"));

    fs::write(&policy, "schema_version = 99").unwrap();
    let output = ferrixdns()
        .args(["policy", "validate"])
        .arg(&policy)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported schema_version"));
}

#[test]
fn the_shipped_example_policy_is_valid() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy.toml");
    let output = ferrixdns()
        .args(["policy", "validate"])
        .arg(&example)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "the example shouldn't produce warnings: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
