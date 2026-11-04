//! End-to-end checks of the `ferrixdns` binary.

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

/// A query for `secretname.example` with type A.
const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
\x0asecretname\x07example\x00\x00\x01\x00\x01";

#[test]
fn serves_dns_without_logging_query_names_by_default() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferrixdns"))
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "127.0.0.1:9",
        ])
        .args(["--attempt-timeout-ms", "50", "--query-timeout-ms", "100"])
        .env_remove("RUST_LOG")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());

    let mut startup = String::new();
    let address: SocketAddr = loop {
        startup.clear();
        assert!(
            stderr.read_line(&mut startup).unwrap() > 0,
            "ferrixdns exited early"
        );
        if let Some((_, rest)) = startup.split_once("address=") {
            break rest.split_whitespace().next().unwrap().parse().unwrap();
        }
    };

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(QUERY, address).unwrap();
    let mut reply = [0_u8; 512];
    let (length, _) = socket.recv_from(&mut reply).unwrap();
    assert!(length >= 12);
    assert_eq!(&reply[..2], &[0x12, 0x34], "the ID must be echoed");
    assert_eq!(
        reply[3] & 0x0f,
        2,
        "an unreachable upstream must give SERVFAIL"
    );

    child.kill().unwrap();
    child.wait().unwrap();
    let mut logs = String::new();
    stderr.read_to_string(&mut logs).unwrap();
    assert!(
        logs.contains("upstream"),
        "upstream failures should be logged: {logs}"
    );
    assert!(
        !logs.contains("secretname"),
        "query names must not be logged: {logs}"
    );
}

#[test]
fn bind_failures_name_the_protocol_and_address() {
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = taken.local_addr().unwrap().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_ferrixdns"))
        .args(["serve", "--listen", &address, "--upstream", "127.0.0.1:9"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("cannot listen on UDP {address}")),
        "{stderr}"
    );
}

#[test]
fn requires_listen_and_upstream_addresses() {
    let output = Command::new(env!("CARGO_BIN_EXE_ferrixdns"))
        .args(["serve", "--listen", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--upstream"));
}
