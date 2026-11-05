//! The central controller and real nodes: joining, deploying, rolling back and failing safely.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use control_plane::{Controller, ControllerConfig};
use dns_cache::{CacheConfig, DnsCache};
use dns_runtime::{DnsServer, PolicyManager, RuntimeConfig, default_allow};
use dns_telemetry::{Outcome, QueryEvent, Telemetry};
use dns_upstreams::PoolConfig;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use integration::{Fixture, ask};
use node_agent::{Agent, AgentConfig};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const PASSWORD: &str = "correct horse battery";

struct Control {
    base: String,
    client: Client,
    cookie: String,
    csrf: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    _directory: tempfile::TempDir,
}

impl Control {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let controller = Controller::new(ControllerConfig {
            state_dir: directory.path().join("control"),
            public_url: base.clone(),
            tls_pin: None,
            hosts: Vec::new(),
            secure_cookies: false,
            hsts: false,
            allow_private_list_urls: true,
        })
        .await
        .unwrap();
        let setup_token = controller.setup_token().unwrap().to_owned();
        let app = controller.router();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async move {
                let _ = stopped.await;
            };
            node_api::serve_plain(app, listener, shutdown)
                .await
                .unwrap();
        });

        let client = Client::new();
        let response = client
            .post(format!("{base}/api/v1/auth/setup"))
            .json(&json!({"token": setup_token, "username": "admin", "password": PASSWORD}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["data"]["role"], "controller");
        Self {
            base,
            client,
            cookie,
            csrf: body["data"]["csrf_token"].as_str().unwrap().to_owned(),
            stop: Some(stop),
            _directory: directory,
        }
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Response {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .header("cookie", &self.cookie)
            .header("x-csrf-token", &self.csrf);
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.unwrap()
    }

    async fn get(&self, path: &str) -> Value {
        let response = self.call(Method::GET, path, None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body: Value = response.json().await.unwrap();
        body["data"].clone()
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        let response = self.call(Method::POST, path, Some(body)).await;
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert!(status.is_success(), "{path}: {status} {body}");
        body["data"].clone()
    }

    async fn site(&self, name: &str) -> String {
        let site = self
            .post("/api/v1/fleet/sites", json!({"name": name}))
            .await;
        site["id"].as_str().unwrap().to_owned()
    }

    async fn deny(&self, site: &str, pattern: &str) -> Value {
        self.post(
            &format!("/api/v1/sites/{site}/rules"),
            json!({"action": "deny", "match_type": "exact", "pattern": pattern, "scope": {"kind": "global"}}),
        )
        .await
    }

    async fn token(&self, site: &str) -> String {
        let created = self
            .post("/api/v1/fleet/enrollment-tokens", json!({"site_id": site}))
            .await;
        created["token"].as_str().unwrap().to_owned()
    }

    async fn deploy(&self, site: &str) -> Value {
        self.post("/api/v1/fleet/deployments", json!({"site_id": site}))
            .await
    }

    async fn deployment(&self, id: &str) -> Value {
        self.get(&format!("/api/v1/fleet/deployments/{id}")).await
    }

    async fn node_named(&self, name: &str) -> Value {
        let nodes = self.get("/api/v1/fleet/nodes").await;
        nodes
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["name"] == name)
            .unwrap_or_else(|| panic!("no node called {name}: {nodes}"))
            .clone()
    }
}

/// A real DNS node, whose agent the test drives one step at a time.
struct TestNode {
    dns: SocketAddr,
    directory: PathBuf,
    agent: Agent,
    manager: Arc<PolicyManager>,
    telemetry: Arc<Telemetry>,
    server: JoinHandle<std::io::Result<()>>,
    _fixture: Fixture,
}

struct NodeOptions<'a> {
    name: &'a str,
    token: Option<String>,
    directory: PathBuf,
    /// Where the agent checks DNS after applying a bundle, in place of the node's own address.
    smoke_test_address: Option<SocketAddr>,
}

impl TestNode {
    async fn start(options: NodeOptions<'_>) -> Result<Self, node_agent::AgentError> {
        let fixture = Fixture::start().await;
        let manager = PolicyManager::start(None, Some(options.directory.clone())).unwrap();
        manager.set_managed();
        let telemetry = Arc::new(
            Telemetry::open(
                options.directory.join("telemetry"),
                manager.telemetry_settings(),
            )
            .await
            .unwrap(),
        );
        let cache = Arc::new(DnsCache::new(CacheConfig::default()));
        let upstreams = PoolConfig {
            servers: vec![fixture.addr.into()],
            load_balance: false,
            attempt_timeout: Duration::from_millis(500),
            total_timeout: Duration::from_millis(1500),
            rounds: 1,
            trust_roots: None,
        };
        let server = DnsServer::bind(RuntimeConfig {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            allow: default_allow(),
            upstreams,
            max_concurrent_requests: 64,
            policy: manager.handle(),
            telemetry: Some(Arc::clone(&telemetry)),
            cache: Some(Arc::clone(&cache)),
            dnssec: None,
            neighbors: dns_runtime::NeighborSource::fixed(Vec::new()),
        })
        .await
        .unwrap();
        let dns = server.local_addrs()[0];
        let agent = Agent::connect(AgentConfig {
            state_dir: options.directory.clone(),
            enroll_token: options.token,
            controller_ca: None,
            name: options.name.to_owned(),
            manager: Arc::clone(&manager),
            telemetry: Some(Arc::clone(&telemetry)),
            cache: Some(cache),
            pool: server.pool(),
            services: server.services(),
            listeners: vec![options.smoke_test_address.unwrap_or(dns)],
            sync_interval: Some(Duration::from_millis(100)),
        })
        .await?;
        let server = tokio::spawn(server.run(std::future::pending()));
        Ok(Self {
            dns,
            directory: options.directory,
            agent,
            manager,
            telemetry,
            server,
            _fixture: fixture,
        })
    }

    async fn join(name: &str, token: String, directory: &tempfile::TempDir) -> Self {
        Self::start(NodeOptions {
            name,
            token: Some(token),
            directory: directory.path().join(name),
            smoke_test_address: None,
        })
        .await
        .unwrap()
    }

    async fn rcode(&self, name: &str) -> ResponseCode {
        ask(self.dns, name, RecordType::A)
            .await
            .metadata
            .response_code
    }
}

async fn serve_once_per_connection(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/list.txt", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0_u8; 2048];
                let _ = socket.read(&mut buffer).await;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    });
    url
}

#[tokio::test]
async fn a_node_joins_gets_policy_and_can_be_rolled_back() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Main office").await;
    control.deny(&site, "a.first.fixture.test").await;

    let sites = control.get("/api/v1/fleet/sites").await;
    assert_eq!(sites[0]["has_undeployed_changes"], true);

    let token = control.token(&site).await;
    let mut node = TestNode::join("dns-1", token, &directory).await;
    node.agent.sync().await.unwrap();
    assert_eq!(
        node.rcode("a.first.fixture.test.").await,
        ResponseCode::NoError,
        "nothing changes until it's deployed"
    );

    let first = control.deploy(&site).await;
    assert_eq!(first["generation"], 1);
    node.agent.sync().await.unwrap();
    assert_eq!(
        node.rcode("a.first.fixture.test.").await,
        ResponseCode::NXDomain
    );

    let progress = control.deployment(first["id"].as_str().unwrap()).await;
    assert_eq!(progress["status"], "succeeded", "{progress}");
    assert_eq!(progress["nodes"][0]["state"], "healthy");
    assert_eq!(progress["nodes"][0]["node_name"], "dns-1");
    let reported = control.node_named("dns-1").await;
    assert_eq!(reported["online"], true);
    assert_eq!(reported["desired_generation"], 1);

    // Applying is reported straight away, and a later report doesn't undo it.
    assert_eq!(control.node_named("dns-1").await["applied_generation"], 1);
    node.agent.sync().await.unwrap();
    assert_eq!(control.node_named("dns-1").await["applied_generation"], 1);

    control.deny(&site, "a.second.fixture.test").await;
    assert_eq!(
        control.get("/api/v1/fleet/sites").await[0]["has_undeployed_changes"],
        true
    );
    let second = control.deploy(&site).await;
    assert_eq!(second["generation"], 2);
    node.agent.sync().await.unwrap();
    assert_eq!(
        node.rcode("a.second.fixture.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        control.get("/api/v1/fleet/sites").await[0]["has_undeployed_changes"],
        false
    );

    // A rollback is a new generation with old contents, and it replaces the newer policy.
    let rollback = control
        .post(
            &format!(
                "/api/v1/fleet/deployments/{}/rollback",
                first["id"].as_str().unwrap()
            ),
            json!({}),
        )
        .await;
    assert_eq!(rollback["generation"], 3);
    assert_eq!(rollback["kind"], "rollback");
    node.agent.sync().await.unwrap();
    assert_eq!(
        node.rcode("a.first.fixture.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        node.rcode("a.second.fixture.test.").await,
        ResponseCode::NoError
    );
    assert_eq!(
        control.get("/api/v1/fleet/sites").await[0]["has_undeployed_changes"],
        true,
        "the policy being edited still has the newer rule"
    );
    assert_eq!(
        control.get("/api/v1/fleet/deployments").await[1]["status"],
        "succeeded",
        "the earlier deployment finished before the rollback"
    );

    let audit = control
        .call(Method::GET, "/api/v1/audit-events", None)
        .await
        .text()
        .await
        .unwrap();
    for action in [
        "site.create",
        "node.enroll",
        "deployment.create",
        "deployment.rollback",
    ] {
        assert!(audit.contains(action), "{action} isn't in {audit}");
    }
}

#[tokio::test]
async fn downloaded_lists_come_from_the_controller_and_nodes_verify_them() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Lists").await;
    let url = serve_once_per_connection("a.from-list.fixture.test\n").await;
    let list = control
        .post(
            &format!("/api/v1/sites/{site}/lists"),
            json!({"name": "Ads", "url": url, "format": "domains", "action": "deny"}),
        )
        .await;
    let id = list["id"].as_str().unwrap();

    // Deploying can't go ahead without the list's content, and doesn't pretend to.
    for _ in 0..100 {
        let list = control
            .get(&format!("/api/v1/sites/{site}/lists/{id}"))
            .await;
        if !list["last_checked_at"].is_null() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let token = control.token(&site).await;
    let mut node = TestNode::join("lists-node", token, &directory).await;
    let deployment = control.deploy(&site).await;
    node.agent.sync().await.unwrap();
    assert_eq!(
        node.rcode("a.from-list.fixture.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        control.deployment(deployment["id"].as_str().unwrap()).await["status"],
        "succeeded"
    );

    // The node never downloads lists itself, and it isn't allowed to refresh them.
    assert!(node.manager.is_managed());
}

#[tokio::test]
async fn a_token_works_once_and_only_while_it_lasts() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Tokens").await;
    let token = control.token(&site).await;
    let first = TestNode::join("first", token.clone(), &directory).await;
    drop(first);

    let second = TestNode::start(NodeOptions {
        name: "second",
        token: Some(token),
        directory: directory.path().join("second"),
        smoke_test_address: None,
    })
    .await;
    let problem = second.err().expect("a used token is refused").to_string();
    assert!(problem.contains("refused"), "{problem}");

    let forged = fleet_contract::EnrollmentToken {
        url: control.base.clone(),
        secret: "made-up".to_owned(),
        controller_key: "x".to_owned(),
        tls_pin: None,
    };
    let third = TestNode::start(NodeOptions {
        name: "third",
        token: Some(forged.encode()),
        directory: directory.path().join("third"),
        smoke_test_address: None,
    })
    .await;
    assert!(third.is_err(), "a made-up token is refused");

    let nodes = control.get("/api/v1/fleet/nodes").await;
    assert_eq!(nodes.as_array().unwrap().len(), 1);

    // A token can be cancelled, and then it's gone.
    let created = control
        .post(
            "/api/v1/fleet/enrollment-tokens",
            json!({"site_id": site, "ttl_minutes": 5}),
        )
        .await;
    let id = created["id"].as_str().unwrap();
    assert_eq!(
        control
            .get("/api/v1/fleet/enrollment-tokens")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let deleted = control
        .call(
            Method::DELETE,
            &format!("/api/v1/fleet/enrollment-tokens/{id}"),
            None,
        )
        .await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let cancelled = TestNode::start(NodeOptions {
        name: "fourth",
        token: created["token"].as_str().map(ToOwned::to_owned),
        directory: directory.path().join("fourth"),
        smoke_test_address: None,
    })
    .await;
    assert!(cancelled.is_err(), "a cancelled token is refused");

    let bad_ttl = control
        .call(
            Method::POST,
            "/api/v1/fleet/enrollment-tokens",
            Some(json!({"site_id": site, "ttl_minutes": 100_000})),
        )
        .await;
    assert_eq!(bad_ttl.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_bundle_signed_by_anyone_else_is_refused_and_the_old_policy_keeps_serving() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Signatures").await;
    control.deny(&site, "a.good.fixture.test").await;
    let token = control.token(&site).await;
    let mut node = TestNode::join("victim", token, &directory).await;
    control.deploy(&site).await;
    node.agent.sync().await.unwrap();
    assert_eq!(
        node.rcode("a.good.fixture.test.").await,
        ResponseCode::NXDomain
    );

    // This node now trusts a different key, as if the controller it's talking to were an impostor.
    let identity_path = node.directory.join("agent/identity.json");
    let mut identity: Value =
        serde_json::from_slice(&std::fs::read(&identity_path).unwrap()).unwrap();
    identity["controller_key"] = json!(
        fleet_contract::SigningKey::generate()
            .unwrap()
            .0
            .public_key()
    );
    std::fs::write(&identity_path, identity.to_string()).unwrap();
    let mut restarted = TestNode::start(NodeOptions {
        name: "victim",
        token: None,
        directory: node.directory.clone(),
        smoke_test_address: None,
    })
    .await
    .unwrap();
    assert_eq!(
        restarted.rcode("a.good.fixture.test.").await,
        ResponseCode::NXDomain
    );

    control.deny(&site, "a.evil-change.fixture.test").await;
    let deployment = control.deploy(&site).await;
    restarted.agent.sync().await.unwrap();
    assert_eq!(
        restarted.rcode("a.evil-change.fixture.test.").await,
        ResponseCode::NoError,
        "the new bundle wasn't applied"
    );
    assert_eq!(
        restarted.rcode("a.good.fixture.test.").await,
        ResponseCode::NXDomain
    );

    let progress = control.deployment(deployment["id"].as_str().unwrap()).await;
    assert_eq!(progress["status"], "failed", "{progress}");
    assert_eq!(progress["nodes"][0]["state"], "failed");
    assert!(
        progress["nodes"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("signature"),
        "{progress}"
    );

    // It isn't tried again.
    restarted.agent.sync().await.unwrap();
    assert_eq!(
        restarted.rcode("a.evil-change.fixture.test.").await,
        ResponseCode::NoError
    );
}

#[tokio::test]
async fn a_canary_goes_first_and_a_failed_one_stops_the_rollout() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Canary").await;

    // This canary's DNS check goes to a closed port, as if the new policy had broken its DNS.
    let closed = {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.local_addr().unwrap()
    };
    let token = control.token(&site).await;
    let mut canary = TestNode::start(NodeOptions {
        name: "canary",
        token: Some(token),
        directory: directory.path().join("canary"),
        smoke_test_address: Some(closed),
    })
    .await
    .unwrap();
    canary.agent.sync().await.unwrap();
    let token = control.token(&site).await;
    let mut other = TestNode::join("other", token, &directory).await;
    other.agent.sync().await.unwrap();

    control.deny(&site, "a.tried.fixture.test").await;
    let deployment = control
        .post(
            "/api/v1/fleet/deployments",
            json!({"site_id": site, "strategy": "canary"}),
        )
        .await;
    assert_eq!(deployment["status"], "canary");
    let id = deployment["id"].as_str().unwrap();

    other.agent.sync().await.unwrap();
    assert_eq!(
        other.rcode("a.tried.fixture.test.").await,
        ResponseCode::NoError,
        "the other node waits for the canary"
    );

    canary.agent.sync().await.unwrap();
    assert_eq!(
        canary.rcode("a.tried.fixture.test.").await,
        ResponseCode::NoError,
        "the canary went back to its previous policy"
    );
    let progress = control.deployment(id).await;
    assert_eq!(progress["status"], "failed", "{progress}");
    let canary_state = progress["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["is_canary"] == true)
        .unwrap();
    assert_eq!(canary_state["state"], "reverted", "{progress}");

    // Going back lasts: a restart doesn't bring the bad bundle back, and it isn't tried again.
    let canary_directory = canary.directory.clone();
    canary.server.abort();
    let _ = (&mut canary.server).await;
    drop(canary);
    let mut canary = TestNode::start(NodeOptions {
        name: "canary",
        token: None,
        directory: canary_directory,
        smoke_test_address: Some(closed),
    })
    .await
    .unwrap();
    assert_eq!(
        canary.rcode("a.tried.fixture.test.").await,
        ResponseCode::NoError
    );
    canary.agent.sync().await.unwrap();
    assert_eq!(
        canary.rcode("a.tried.fixture.test.").await,
        ResponseCode::NoError
    );

    other.agent.sync().await.unwrap();
    assert_eq!(
        other.rcode("a.tried.fixture.test.").await,
        ResponseCode::NoError,
        "a failed canary stops the rollout"
    );

    // The next one can reach the node that was waiting, once its canary is fine.
    let healthy_directory = directory.path().join("other");
    assert!(healthy_directory.exists());
    let next = control
        .post(
            "/api/v1/fleet/deployments",
            json!({"site_id": site, "strategy": "all"}),
        )
        .await;
    other.agent.sync().await.unwrap();
    assert_eq!(
        other.rcode("a.tried.fixture.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        control.deployment(next["id"].as_str().unwrap()).await["nodes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn a_healthy_canary_lets_the_rest_follow() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Healthy canary").await;
    let token = control.token(&site).await;
    let mut first = TestNode::join("first", token, &directory).await;
    first.agent.sync().await.unwrap();
    let token = control.token(&site).await;
    let mut second = TestNode::join("second", token, &directory).await;
    second.agent.sync().await.unwrap();

    control.deny(&site, "a.rolled.fixture.test").await;
    let deployment = control
        .post(
            "/api/v1/fleet/deployments",
            json!({"site_id": site, "strategy": "canary"}),
        )
        .await;
    let id = deployment["id"].as_str().unwrap();
    let nodes = deployment["nodes"].as_array().unwrap();
    let canary_name = nodes.iter().find(|n| n["is_canary"] == true).unwrap()["node_name"].clone();
    let (canary, waiting) = if canary_name == "first" {
        (&mut first, &mut second)
    } else {
        (&mut second, &mut first)
    };

    waiting.agent.sync().await.unwrap();
    assert_eq!(
        waiting.rcode("a.rolled.fixture.test.").await,
        ResponseCode::NoError
    );

    canary.agent.sync().await.unwrap();
    assert_eq!(
        canary.rcode("a.rolled.fixture.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(control.deployment(id).await["status"], "rolling_out");

    waiting.agent.sync().await.unwrap();
    assert_eq!(
        waiting.rcode("a.rolled.fixture.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(control.deployment(id).await["status"], "succeeded");
}

#[tokio::test]
async fn nodes_keep_their_policy_without_the_controller_and_across_restarts() {
    let mut control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Outage").await;
    control.deny(&site, "a.kept.fixture.test").await;
    let token = control.token(&site).await;
    let mut node = TestNode::join("survivor", token, &directory).await;
    control.deploy(&site).await;
    node.agent.sync().await.unwrap();
    assert_eq!(
        node.rcode("a.kept.fixture.test.").await,
        ResponseCode::NXDomain
    );

    drop(control.stop.take());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let start = std::time::Instant::now();
    assert!(node.agent.sync().await.is_err(), "the controller is gone");
    assert!(start.elapsed() < Duration::from_secs(30));
    assert_eq!(
        node.rcode("a.kept.fixture.test.").await,
        ResponseCode::NXDomain,
        "DNS doesn't depend on the controller"
    );
    assert_eq!(node.rcode("a.fixture.test.").await, ResponseCode::NoError);

    // Restarted, with the controller still gone. It needs no token, and it has its policy.
    node.server.abort();
    let _ = (&mut node.server).await;
    let directory_path = node.directory.clone();
    drop(node);
    let restarted = TestNode::start(NodeOptions {
        name: "survivor",
        token: None,
        directory: directory_path,
        smoke_test_address: None,
    })
    .await
    .unwrap();
    assert_eq!(
        restarted.rcode("a.kept.fixture.test.").await,
        ResponseCode::NXDomain
    );
    assert!(
        restarted.manager.mutate(|_| Ok::<_, String>(())).is_err(),
        "only bundles change it"
    );
}

#[tokio::test]
async fn fleet_metrics_come_from_node_reports_and_hold_only_counts() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Metrics").await;
    let token = control.token(&site).await;
    let mut node = TestNode::join("counted", token, &directory).await;

    let now = node_api::now_ms();
    let earlier = now - 180_000;
    for (outcome, count) in [
        (Outcome::Forwarded, 3),
        (Outcome::Cached, 2),
        (Outcome::Stale, 1),
        (Outcome::Blocked, 4),
        (Outcome::Failed, 1),
    ] {
        for _ in 0..count {
            node.telemetry.record(
                QueryEvent {
                    seq: 0,
                    occurred_at_ms: earlier,
                    client_id: None,
                    client_ip: Some("192.0.2.77".to_owned()),
                    qname: Some("private-name.example".to_owned()),
                    matched_name: None,
                    qtype: "A".to_owned(),
                    outcome,
                    rcode: "NOERROR".to_owned(),
                    rule_id: None,
                    source_list_id: None,
                    upstream: None,
                    duration_us: 1000,
                    revision_id: None,
                },
                dns_policy::QueryLogMode::Full,
            );
        }
    }

    let mut overview = Value::Null;
    for _ in 0..60 {
        node.agent.sync().await.unwrap();
        overview = control.get("/api/v1/fleet/overview?hours=1").await;
        if overview["total"] == 11 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(overview["total"], 11, "{overview}");
    assert_eq!(overview["answered"], 6);
    assert_eq!(overview["cached"], 2);
    assert_eq!(overview["stale"], 1);
    assert_eq!(overview["blocked"], 4);
    assert_eq!(overview["failed"], 1);
    assert_eq!(overview["average_latency_us"], 1000);
    assert_eq!(overview["nodes_online"], 1);
    assert_eq!(overview["by_node"][0]["node_name"], "counted");
    assert_eq!(overview["by_node"][0]["total"], 11);
    let text = overview.to_string();
    assert!(
        !text.contains("private-name") && !text.contains("192.0.2.77"),
        "{text}"
    );

    // Reporting again doesn't count anything twice.
    node.agent.sync().await.unwrap();
    node.agent.sync().await.unwrap();
    let again = control.get("/api/v1/fleet/overview?hours=1").await;
    assert_eq!(again["total"], 11, "{again}");
    assert_eq!(control.node_named("counted").await["queries_last_hour"], 11);
}

#[tokio::test]
async fn removing_a_node_cuts_it_off_but_it_keeps_serving() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let site = control.site("Removal").await;
    control.deny(&site, "a.still.fixture.test").await;
    let token = control.token(&site).await;
    let mut node = TestNode::join("removed", token, &directory).await;
    control.deploy(&site).await;
    node.agent.sync().await.unwrap();

    let conflict = control
        .call(Method::DELETE, &format!("/api/v1/fleet/sites/{site}"), None)
        .await;
    assert_eq!(
        conflict.status(),
        StatusCode::CONFLICT,
        "a site with nodes stays"
    );

    let id = control.node_named("removed").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let removed = control
        .call(Method::DELETE, &format!("/api/v1/fleet/nodes/{id}"), None)
        .await;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);

    let failure = node.agent.sync().await.unwrap_err();
    assert!(failure.is_revoked(), "{failure}");
    assert_eq!(
        node.rcode("a.still.fixture.test.").await,
        ResponseCode::NXDomain
    );

    let gone = control
        .call(Method::DELETE, &format!("/api/v1/fleet/sites/{site}"), None)
        .await;
    assert_eq!(gone.status(), StatusCode::NO_CONTENT);
    assert!(
        control
            .get("/api/v1/fleet/sites")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_api_only_exposes_what_a_controller_should_and_requires_a_signed_node() {
    let control = Control::start().await;
    let site = control.site("Boundaries").await;

    // Nobody can reach these without signing in, or from another site's name.
    let anonymous = Client::new();
    for path in [
        "/api/v1/fleet/sites".to_owned(),
        "/api/v1/fleet/nodes".to_owned(),
        "/api/v1/fleet/overview".to_owned(),
        format!("/api/v1/sites/{site}/rules"),
    ] {
        let response = anonymous
            .get(format!("{}{path}", control.base))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }

    // A controller has no DNS of its own, and a site has no query log, backup or node settings.
    for path in [
        "/api/v1/rules".to_owned(),
        "/api/v1/queries".to_owned(),
        "/api/v1/backup".to_owned(),
        "/api/v1/node-settings".to_owned(),
        format!("/api/v1/sites/{site}/queries"),
        format!("/api/v1/sites/{site}/backup"),
        format!("/api/v1/sites/{site}/node-settings"),
        format!("/api/v1/sites/{site}/auth/session"),
        format!("/api/v1/sites/{site}/rulesextra"),
        "/api/v1/sites/no-such-site/rules".to_owned(),
    ] {
        let response = control.call(Method::GET, &path, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }

    // Signing in, and the dashboard's own page, still work.
    assert_eq!(
        control
            .call(Method::GET, "/api/v1/auth/session", None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        control.call(Method::GET, "/", None).await.status(),
        StatusCode::OK
    );

    // Changing a site's policy needs the CSRF token, like every other change.
    let forged = anonymous
        .post(format!("{}/api/v1/sites/{site}/rules", control.base))
        .header("cookie", &control.cookie)
        .json(&json!({"action": "deny", "match_type": "exact", "pattern": "a.example", "scope": {"kind": "global"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);

    // An unknown host name can't reach the dashboard, but nodes may use any name.
    let wrong_host = anonymous
        .get(format!("{}/api/v1/fleet/sites", control.base))
        .header("host", "rebind.example")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), StatusCode::MISDIRECTED_REQUEST);

    // The node API needs a real signature.
    let unsigned = anonymous
        .post(format!("{}/node/v1/heartbeat", control.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    let forged = anonymous
        .get(format!(
            "{}/node/v1/artifacts/{}",
            control.base,
            "a".repeat(64)
        ))
        .header("x-ferrix-node", "nobody")
        .header("x-ferrix-time", node_api::now_ms().to_string())
        .header("x-ferrix-signature", "AAAA")
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn one_sites_node_cannot_read_another_sites_policy() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let ours = control.site("Ours").await;
    let theirs = control.site("Theirs").await;
    control.deny(&theirs, "their-secret.example").await;
    let deployment = control.deploy(&theirs).await;
    let policy = deployment["policy_sha256"].as_str().unwrap().to_owned();

    let token = control.token(&ours).await;
    let node = TestNode::join("nosy", token, &directory).await;
    let id = control.node_named("nosy").await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Signed properly with this node's own key, so only the site check can stop it.
    let key = fleet_contract::SigningKey::from_pkcs8(
        &std::fs::read(node.directory.join("agent/node.key")).unwrap(),
    )
    .unwrap();
    let client = Client::new();
    let path = format!("/node/v1/artifacts/{policy}");
    let time = node_api::now_ms();
    let response = client
        .get(format!("{}{path}", control.base))
        .header("x-ferrix-node", &id)
        .header("x-ferrix-time", time.to_string())
        .header(
            "x-ferrix-signature",
            key.sign_request("GET", &path, time, b""),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // A replay of a signature on a different path doesn't work either.
    let other = format!("/node/v1/bundles/{}", "x".repeat(26));
    let replay = client
        .get(format!("{}{other}", control.base))
        .header("x-ferrix-node", &id)
        .header("x-ferrix-time", time.to_string())
        .header(
            "x-ferrix-signature",
            key.sign_request("GET", &path, time, b""),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    // An old signature doesn't either.
    let old = node_api::now_ms() - 3_600_000;
    let stale = client
        .get(format!("{}{path}", control.base))
        .header("x-ferrix-node", &id)
        .header("x-ferrix-time", old.to_string())
        .header(
            "x-ferrix-signature",
            key.sign_request("GET", &path, old, b""),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_new_site_can_start_from_a_copy_and_blocked_services_reach_nodes() {
    let control = Control::start().await;
    let directory = tempfile::tempdir().unwrap();
    let original = control.site("Original").await;
    let response = control
        .call(
            Method::PUT,
            &format!("/api/v1/sites/{original}/blocked-services/tiktok"),
            Some(json!({"blocked": true})),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let copy = control
        .post(
            "/api/v1/fleet/sites",
            json!({"name": "Copy", "copy_from": original}),
        )
        .await;
    let copy = copy["id"].as_str().unwrap().to_owned();
    let token = control.token(&copy).await;
    let mut node = TestNode::join("copied", token, &directory).await;
    control.deploy(&copy).await;
    node.agent.sync().await.unwrap();
    assert_eq!(node.rcode("www.tiktok.com.").await, ResponseCode::NXDomain);

    let duplicate = control
        .call(
            Method::POST,
            "/api/v1/fleet/sites",
            Some(json!({"name": "copy"})),
        )
        .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_sites_policy_can_be_changed_over_http2() {
    // Browsers use HTTP/2 over TLS, which puts the host name in the request's address instead of a
    // Host header.
    let control = Control::start().await;
    let site = control.site("Over HTTP/2").await;
    let client = Client::builder().http2_prior_knowledge().build().unwrap();
    let response = client
        .post(format!("{}/api/v1/sites/{site}/rules", control.base))
        .header("cookie", &control.cookie)
        .header("x-csrf-token", &control.csrf)
        .json(&json!({"action": "deny", "match_type": "exact", "pattern": "a.example", "scope": {"kind": "global"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "{}",
        response.text().await.unwrap()
    );
}
