#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use dns_lists::{FetchLimits, Fetcher};
use dns_policy::{DomainName, QueryLogMode};
use dns_runtime::PolicyManager;
use dns_storage::ConfigDb;
use dns_telemetry::{Outcome, QueryEvent, Telemetry};
use dns_upstreams::{PoolConfig, UpstreamPool};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{AllowedHosts, Api, ApiConfig};

const PASSWORD: &str = "correct horse battery";

struct Node {
    base: String,
    client: Client,
    setup_token: Option<String>,
    manager: Arc<PolicyManager>,
    telemetry: Arc<Telemetry>,
    state_dir: std::path::PathBuf,
    _directory: tempfile::TempDir,
    cookie: Option<String>,
    csrf: Option<String>,
}

struct Options {
    policy_file: Option<&'static str>,
    allow_private_urls: bool,
    services: dns_runtime::Services,
    stored_devices: Vec<dns_storage::NetworkDevice>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy_file: None,
            allow_private_urls: true,
            services: dns_runtime::Services::detached(vec![]),
            stored_devices: vec![],
        }
    }
}

async fn start_with(options: Options) -> Node {
    let directory = tempfile::tempdir().unwrap();
    let state_dir = directory.path().join("state");
    let source = options.policy_file.map(|content| {
        let path = directory.path().join("policy.toml");
        std::fs::write(&path, content).unwrap();
        path
    });
    let manager = PolicyManager::start(source, Some(state_dir.clone())).unwrap();
    let telemetry = Arc::new(
        Telemetry::open(state_dir.join("telemetry"), manager.telemetry_settings())
            .await
            .unwrap(),
    );
    let db = ConfigDb::open(&state_dir.join("config.db")).await.unwrap();
    db.record_network_devices(&options.stored_devices)
        .await
        .unwrap();
    let pool = Arc::new(
        UpstreamPool::new(PoolConfig {
            servers: vec!["127.0.0.1:9".parse().unwrap()],
            load_balance: false,
            trust_roots: None,
            attempt_timeout: Duration::from_millis(50),
            total_timeout: Duration::from_millis(100),
            rounds: 1,
        })
        .unwrap(),
    );
    let fetcher = Fetcher::new(
        FetchLimits {
            timeout: Duration::from_secs(5),
            ..FetchLimits::default()
        },
        options.allow_private_urls,
    )
    .unwrap();
    let api = Api::new(ApiConfig {
        manager: Arc::clone(&manager),
        telemetry: Some(Arc::clone(&telemetry)),
        db,
        pool,
        cache: Some(Arc::new(dns_cache::DnsCache::new(
            dns_cache::CacheConfig::default(),
        ))),
        fetcher,
        hosts: AllowedHosts::new(["dns.home.arpa".to_owned()]),
        secure_cookies: false,
        dns_listeners: vec!["127.0.0.1:53".parse().unwrap()],
        dnssec_validation: false,
        hsts: false,
        services: options.services.clone(),
        ntp: None,
        node: None,
    })
    .await
    .unwrap();
    let setup_token = api.setup_token().map(ToOwned::to_owned);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(api.serve(listener, std::future::pending()));

    Node {
        base,
        client: Client::new(),
        setup_token,
        manager,
        telemetry,
        state_dir,
        _directory: directory,
        cookie: None,
        csrf: None,
    }
}

async fn start() -> Node {
    start_with(Options::default()).await
}

impl Node {
    async fn send(&self, method: Method, path: &str, body: Option<Value>) -> Response {
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if let Some(cookie) = &self.cookie {
            request = request.header("cookie", cookie);
        }
        if let Some(csrf) = &self.csrf {
            request = request.header("x-csrf-token", csrf);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.unwrap()
    }

    async fn get(&self, path: &str) -> Response {
        self.send(Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> Response {
        self.send(Method::POST, path, Some(body)).await
    }

    async fn adopt_session(&mut self, response: Response) {
        let cookie = response
            .headers()
            .get("set-cookie")
            .expect("a session cookie")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Strict"), "{cookie}");
        self.cookie = Some(cookie.split(';').next().unwrap().to_owned());
        let body: Value = response.json().await.unwrap();
        self.csrf = Some(body["data"]["csrf_token"].as_str().unwrap().to_owned());
    }

    async fn setup(&mut self) {
        let token = self.setup_token.clone().unwrap();
        let response = self
            .post(
                "/api/v1/auth/setup",
                json!({"token": token, "username": "admin", "password": PASSWORD}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        self.adopt_session(response).await;
    }

    async fn create_rule(&self, body: Value) -> Value {
        let response = self.post("/api/v1/rules", body).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body: Value = response.json().await.unwrap();
        body["data"].clone()
    }

    async fn decision(&self, domain: &str) -> Value {
        let response = self
            .post("/api/v1/rules/test", json!({"domain": domain}))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        body["data"].clone()
    }
}

async fn signed_in() -> Node {
    let mut node = start().await;
    node.setup().await;
    node
}

async fn code(response: Response) -> String {
    let body: Value = response.json().await.unwrap();
    assert!(body["error"]["request_id"].is_string(), "{body}");
    body["error"]["code"].as_str().unwrap().to_owned()
}

fn deny(pattern: &str) -> Value {
    json!({"action": "deny", "match_type": "exact", "pattern": pattern, "scope": {"kind": "global"}})
}

/// Serves a canned HTTP response to each connection and counts them.
async fn serve_list(response: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/list", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let response = response.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    url
}

fn http_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn wait_for_list(node: &Node, id: &str) -> Value {
    for _ in 0..100 {
        let body: Value = node
            .get(&format!("/api/v1/lists/{id}"))
            .await
            .json()
            .await
            .unwrap();
        if !body["data"]["last_checked_at"].is_null() {
            return body["data"].clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the list was never checked");
}

#[tokio::test]
async fn health_is_public_and_says_nothing_private() {
    let node = start().await;
    let response = node.get("/api/v1/health/live").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"status": "ok"})
    );
}

#[tokio::test]
async fn setup_needs_the_token_and_only_works_once() {
    let mut node = start().await;
    let status: Value = node.get("/api/v1/auth/status").await.json().await.unwrap();
    assert_eq!(status["setup_required"], true);

    let wrong = node
        .post(
            "/api/v1/auth/setup",
            json!({"token": "wrong", "username": "admin", "password": PASSWORD}),
        )
        .await;
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    assert_eq!(code(wrong).await, "SETUP_TOKEN_INVALID");

    let token = node.setup_token.clone().unwrap();
    let short = node
        .post(
            "/api/v1/auth/setup",
            json!({"token": token, "username": "admin", "password": "short"}),
        )
        .await;
    assert_eq!(short.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(code(short).await, "PASSWORD_TOO_SHORT");

    node.setup().await;
    let status: Value = node.get("/api/v1/auth/status").await.json().await.unwrap();
    assert_eq!(status["setup_required"], false);
    let session = node.get("/api/v1/auth/session").await;
    assert_eq!(session.status(), StatusCode::OK);

    let again = node
        .post(
            "/api/v1/auth/setup",
            json!({"token": token, "username": "other", "password": PASSWORD}),
        )
        .await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn every_protected_endpoint_requires_a_session() {
    let node = start().await;
    let gets = [
        "health/ready",
        "auth/session",
        "overview",
        "queries",
        "queries/stream",
        "rules",
        "rules/x",
        "lists",
        "lists/x",
        "jobs/x",
        "clients",
        "groups",
        "dns/upstreams",
        "config/revisions",
        "settings",
        "system/status",
        "audit-events",
    ];
    for path in gets {
        let response = node.get(&format!("/api/v1/{path}")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let posts = [
        "auth/logout",
        "auth/password",
        "rules",
        "rules/test",
        "lists",
        "lists/x/refresh",
        "clients",
        "groups",
        "dns/upstreams/test",
        "config/activate",
    ];
    for path in posts {
        let response = node.post(&format!("/api/v1/{path}"), json!({})).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn login_logout_and_failed_attempts() {
    let mut node = signed_in().await;
    let logout = node.post("/api/v1/auth/logout", json!({})).await;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        node.get("/api/v1/rules").await.status(),
        StatusCode::UNAUTHORIZED
    );
    node.cookie = None;
    node.csrf = None;

    let wrong = node
        .post(
            "/api/v1/auth/login",
            json!({"username": "admin", "password": "wrong password"}),
        )
        .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(code(wrong).await, "INVALID_CREDENTIALS");
    let unknown = node
        .post(
            "/api/v1/auth/login",
            json!({"username": "nobody", "password": PASSWORD}),
        )
        .await;
    assert_eq!(
        code(unknown).await,
        "INVALID_CREDENTIALS",
        "must not reveal which usernames exist"
    );

    let right = node
        .post(
            "/api/v1/auth/login",
            json!({"username": "admin", "password": PASSWORD}),
        )
        .await;
    assert_eq!(right.status(), StatusCode::OK);
    node.adopt_session(right).await;
    assert_eq!(node.get("/api/v1/rules").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn repeated_failed_logins_are_locked_out() {
    let node = signed_in().await;
    for _ in 0..5 {
        node.post(
            "/api/v1/auth/login",
            json!({"username": "admin", "password": "wrong password"}),
        )
        .await;
    }
    let locked = node
        .post(
            "/api/v1/auth/login",
            json!({"username": "admin", "password": PASSWORD}),
        )
        .await;
    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn changing_the_password_ends_sessions() {
    let mut node = signed_in().await;
    let wrong = node
        .post(
            "/api/v1/auth/password",
            json!({"current_password": "not it at all", "new_password": "a new long password"}),
        )
        .await;
    assert_eq!(wrong.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let changed = node
        .post(
            "/api/v1/auth/password",
            json!({"current_password": PASSWORD, "new_password": "a new long password"}),
        )
        .await;
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        node.get("/api/v1/rules").await.status(),
        StatusCode::UNAUTHORIZED
    );

    node.cookie = None;
    node.csrf = None;
    let login = node
        .post(
            "/api/v1/auth/login",
            json!({"username": "admin", "password": "a new long password"}),
        )
        .await;
    assert_eq!(login.status(), StatusCode::OK);
}

#[tokio::test]
async fn changing_requests_need_the_csrf_token() {
    let mut node = signed_in().await;
    let csrf = node.csrf.take();
    let missing = node.post("/api/v1/rules", deny("a.example")).await;
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    assert_eq!(code(missing).await, "CSRF_TOKEN_INVALID");

    node.csrf = Some("wrong".to_owned());
    let wrong = node.post("/api/v1/rules", deny("a.example")).await;
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

    // Reads don't need it.
    assert_eq!(node.get("/api/v1/rules").await.status(), StatusCode::OK);

    node.csrf = csrf;
    assert_eq!(
        node.post("/api/v1/rules", deny("a.example")).await.status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn requests_from_other_origins_and_hosts_are_rejected() {
    let node = signed_in().await;
    let cross_origin = node
        .client
        .post(format!("{}/api/v1/rules", node.base))
        .header("cookie", node.cookie.clone().unwrap())
        .header("x-csrf-token", node.csrf.clone().unwrap())
        .header("origin", "https://evil.example")
        .json(&deny("a.example"))
        .send()
        .await
        .unwrap();
    assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);
    assert_eq!(code(cross_origin).await, "ORIGIN_NOT_ALLOWED");

    let login = node
        .client
        .post(format!("{}/api/v1/auth/login", node.base))
        .header("origin", "https://evil.example")
        .json(&json!({"username": "admin", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::FORBIDDEN);

    for (host, expected) in [
        ("evil.example", StatusCode::MISDIRECTED_REQUEST),
        ("evil.example:8080", StatusCode::MISDIRECTED_REQUEST),
        ("127.0.0.1.evil.example", StatusCode::MISDIRECTED_REQUEST),
        ("dns.home.arpa", StatusCode::OK),
        ("DNS.HOME.ARPA:8080", StatusCode::OK),
        ("[::1]:8080", StatusCode::OK),
        ("localhost", StatusCode::OK),
    ] {
        let response = node
            .client
            .get(format!("{}/api/v1/health/live", node.base))
            .header("host", host)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{host}");
    }
}

#[tokio::test]
async fn rules_can_be_created_changed_and_deleted_with_immediate_effect() {
    let node = signed_in().await;
    let rule = node
        .create_rule(json!({
            "action": "deny", "match_type": "suffix", "pattern": "ads.example",
            "scope": {"kind": "global"}, "reason": "Testing",
        }))
        .await;
    let id = rule["id"].as_str().unwrap();
    assert_eq!(rule["revision"], 1);
    assert_eq!(rule["reason"], "Testing");

    let decision = node.decision("x.ads.example").await;
    assert_eq!(decision["action"], "deny");
    assert_eq!(decision["tier"], "suffix_deny");
    assert_eq!(decision["scope"], "global");
    assert_eq!(decision["rule_id"], id);
    assert_eq!(decision["rule_pattern"], "ads.example");

    let path = format!("/api/v1/rules/{id}");
    let fetched = node.get(&path).await;
    assert_eq!(fetched.headers().get("etag").unwrap(), "\"1\"");

    let change = |revision: &str| {
        node.client
            .patch(format!("{}{path}", node.base))
            .header("cookie", node.cookie.clone().unwrap())
            .header("x-csrf-token", node.csrf.clone().unwrap())
            .header("if-match", revision)
            .json(&json!({"enabled": false}))
    };
    let unconditional = node
        .send(Method::PATCH, &path, Some(json!({"enabled": false})))
        .await;
    assert_eq!(unconditional.status(), StatusCode::PRECONDITION_REQUIRED);

    let stale = change("\"99\"").send().await.unwrap();
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(code(stale).await, "STALE_WRITE");

    let updated = change("\"1\"").send().await.unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(updated.headers().get("etag").unwrap(), "\"2\"");
    assert_eq!(
        node.decision("x.ads.example").await["tier"],
        "default_allow"
    );

    let delete_stale = node
        .client
        .delete(format!("{}{path}", node.base))
        .header("cookie", node.cookie.clone().unwrap())
        .header("x-csrf-token", node.csrf.clone().unwrap())
        .header("if-match", "\"1\"")
        .send()
        .await
        .unwrap();
    assert_eq!(delete_stale.status(), StatusCode::PRECONDITION_FAILED);
    let delete = node
        .client
        .delete(format!("{}{path}", node.base))
        .header("cookie", node.cookie.clone().unwrap())
        .header("x-csrf-token", node.csrf.clone().unwrap())
        .header("if-match", "\"2\"")
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert_eq!(node.get(&path).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_rules_are_rejected_and_change_nothing() {
    let node = signed_in().await;
    let revision = node.manager.handle().load().revision().to_owned();
    let bad = [
        deny("a..b"),
        deny(""),
        json!({"action": "deny", "match_type": "regex", "pattern": "(", "scope": {"kind": "global"}}),
        json!({"action": "deny", "match_type": "exact", "pattern": "a.example", "scope": {"kind": "group"}}),
        json!({"action": "allow", "match_type": "exact", "pattern": "a.example", "scope": {"kind": "global"}, "emergency": true}),
        json!({"action": "deny", "match_type": "exact", "pattern": "a.example", "scope": {"kind": "global"}, "expires_at": "tomorrow"}),
    ];
    for body in bad {
        let response = node.post("/api/v1/rules", body.clone()).await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}"
        );
    }
    assert_eq!(node.manager.handle().load().revision(), revision);
}

#[tokio::test]
async fn emergency_rules_and_expiry_work_through_the_api() {
    let node = signed_in().await;
    node.create_rule(json!({
        "action": "allow", "match_type": "exact", "pattern": "x.example",
        "scope": {"kind": "global"},
    }))
    .await;
    assert_eq!(node.decision("x.example").await["tier"], "exact_allow");

    let rule = node
        .create_rule(json!({
            "action": "deny", "match_type": "suffix", "pattern": "example",
            "scope": {"kind": "global"}, "emergency": true,
            "expires_at": "2099-01-01T00:00:00.000Z",
        }))
        .await;
    assert_eq!(rule["expires_at"], "2099-01-01T00:00:00Z");
    assert_eq!(node.decision("x.example").await["tier"], "emergency_deny");
}

#[tokio::test]
async fn policy_changes_are_read_only_when_managed_by_a_file() {
    let mut node = start_with(Options {
        policy_file: Some("schema_version = 1\n"),
        ..Options::default()
    })
    .await;
    node.setup().await;

    let session: Value = node.get("/api/v1/auth/session").await.json().await.unwrap();
    assert_eq!(session["data"]["policy_read_only"], true);

    let response = node.post("/api/v1/rules", deny("a.example")).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(code(response).await, "POLICY_READ_ONLY");
}

#[tokio::test]
async fn subscribed_lists_download_apply_and_keep_working_after_failures() {
    let node = signed_in().await;
    let url = serve_list(http_ok(
        "0.0.0.0 ads.example\n0.0.0.0 tracker.example\nbad line\n",
    ))
    .await;
    let created = node
        .post(
            "/api/v1/lists",
            json!({"name": "Test", "url": url, "format": "hosts", "action": "deny"}),
        )
        .await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    let body: Value = created.json().await.unwrap();
    let id = body["data"]["id"].as_str().unwrap().to_owned();

    let list = wait_for_list(&node, &id).await;
    assert_eq!(list["entry_count"], 2);
    assert_eq!(list["invalid_line_count"], 1);
    assert!(list["last_error"].is_null(), "{list}");

    let decision = node.decision("ads.example").await;
    assert_eq!(decision["action"], "deny");
    assert_eq!(decision["tier"], "subscribed_deny");
    assert_eq!(decision["list_name"], "Test");

    // A duplicate is rejected.
    let duplicate = node
        .post(
            "/api/v1/lists",
            json!({"name": "Again", "url": url, "format": "hosts", "action": "deny"}),
        )
        .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);

    // Disabling stops it applying, and enabling restores it from the stored download.
    let disable = node
        .send(
            Method::PATCH,
            &format!("/api/v1/lists/{id}"),
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(disable.status(), StatusCode::OK);
    assert_eq!(node.decision("ads.example").await["action"], "allow");
    node.send(
        Method::PATCH,
        &format!("/api/v1/lists/{id}"),
        Some(json!({"enabled": true})),
    )
    .await;
    assert_eq!(node.decision("ads.example").await["action"], "deny");

    // It survives a restart, restored from the state directory.
    let restarted = PolicyManager::start(None, Some(node.state_dir.clone())).unwrap();
    let source: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let name = dns_policy::DomainName::parse("ads.example").unwrap();
    assert_eq!(
        restarted.handle().load().explain(source, &name).action,
        dns_policy::Action::Deny
    );

    let delete = node
        .send(Method::DELETE, &format!("/api/v1/lists/{id}"), None)
        .await;
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert_eq!(node.decision("ads.example").await["action"], "allow");
}

#[tokio::test]
async fn a_failed_download_is_reported_and_leaves_old_content_active() {
    let node = signed_in().await;
    let good = serve_list(http_ok("ads.example\n")).await;
    let created = node
        .post(
            "/api/v1/lists",
            json!({"name": "Test", "url": good, "format": "domains", "action": "deny"}),
        )
        .await;
    let body: Value = created.json().await.unwrap();
    let id = body["data"]["id"].as_str().unwrap().to_owned();
    wait_for_list(&node, &id).await;
    assert_eq!(node.decision("ads.example").await["action"], "deny");

    // The server starts returning something that isn't a list.
    let url_now_html = serve_list(http_ok("<html>Oops</html>\n")).await;
    node.manager
        .mutate(|document| {
            document.lists[0].url = Some(url_now_html);
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap();

    let job: Value = node
        .post(&format!("/api/v1/lists/{id}/refresh"), json!({}))
        .await
        .json()
        .await
        .unwrap();
    let job_id = job["data"]["id"].as_str().unwrap();
    let mut state = Value::Null;
    for _ in 0..100 {
        let current: Value = node
            .get(&format!("/api/v1/jobs/{job_id}"))
            .await
            .json()
            .await
            .unwrap();
        state = current["data"].clone();
        if state["state"] != "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(state["state"], "failed", "{state}");

    let list: Value = node
        .get(&format!("/api/v1/lists/{id}"))
        .await
        .json()
        .await
        .unwrap();
    assert!(
        list["data"]["last_error"]
            .as_str()
            .unwrap()
            .contains("no valid entries")
    );
    assert_eq!(
        node.decision("ads.example").await["action"],
        "deny",
        "old content stays active"
    );
}

#[tokio::test]
async fn list_urls_to_private_addresses_are_refused_by_default() {
    let mut node = start_with(Options {
        allow_private_urls: false,
        ..Options::default()
    })
    .await;
    node.setup().await;
    for url in [
        "http://127.0.0.1/list",
        "http://169.254.169.254/latest",
        "file:///etc/passwd",
    ] {
        let response = node
            .post(
                "/api/v1/lists",
                json!({"name": "Bad", "url": url, "format": "hosts", "action": "deny"}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{url}");
        assert_eq!(code(response).await, "LIST_URL_INVALID");
    }
}

fn query_event(at: i64, qname: &str, outcome: Outcome) -> QueryEvent {
    QueryEvent {
        seq: 0,
        occurred_at_ms: at,
        client_id: None,
        client_ip: Some("192.168.1.20".into()),
        qname: Some(qname.into()),
        matched_name: None,
        qtype: "A".into(),
        outcome,
        rcode: "NOERROR".into(),
        rule_id: None,
        source_list_id: None,
        upstream: None,
        duration_us: 500,
        revision_id: None,
    }
}

async fn wait_for_queries(node: &Node, count: usize) -> Value {
    for _ in 0..100 {
        let body: Value = node.get("/api/v1/queries").await.json().await.unwrap();
        if body["data"].as_array().unwrap().len() >= count {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("expected {count} queries");
}

#[tokio::test]
async fn overview_and_query_log_report_recorded_queries() {
    let node = signed_in().await;
    let now = crate::util::now_ms();
    node.telemetry.record(
        query_event(now, "a.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );
    let mut blocked = query_event(now, "ads.example", Outcome::Blocked);
    blocked.rule_id = Some("unknown-rule".into());
    node.telemetry.record(blocked, QueryLogMode::Full);

    let log = wait_for_queries(&node, 2).await;
    let newest = &log["data"][0];
    assert_eq!(newest["question"]["name"], "ads.example");
    assert_eq!(newest["question"]["type"], "A");
    assert_eq!(newest["decision"]["action"], "blocked");
    assert_eq!(newest["decision"]["source"], "rule");
    assert_eq!(newest["client"]["address"], "192.168.1.20");
    assert_eq!(log["page"]["has_more"], false);

    let filtered: Value = node
        .get("/api/v1/queries?action=blocked&qname=ADS")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(filtered["data"].as_array().unwrap().len(), 1);

    let paged: Value = node
        .get("/api/v1/queries?limit=1")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(paged["page"]["has_more"], true);
    let cursor = paged["page"]["next_cursor"].as_str().unwrap();
    let next: Value = node
        .get(&format!("/api/v1/queries?limit=1&cursor={cursor}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(next["data"][0]["question"]["name"], "a.example");

    let invalid = node.get("/api/v1/queries?cursor=abc").await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let overview: Value = node.get("/api/v1/overview").await.json().await.unwrap();
    let data = &overview["data"];
    assert_eq!(data["total"], 2);
    assert_eq!(data["blocked"], 1);
    assert_eq!(data["top_clients"][0]["name"], "192.168.1.20");
    assert_eq!(data["top_blocked_domains"][0]["name"], "ads.example");
    assert_eq!(data["query_log_mode"], "full");
    assert!(data["buckets"].as_array().unwrap().len() > 1);

    let backwards = node
        .get("/api/v1/overview?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z")
        .await;
    assert_eq!(backwards.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn the_live_stream_delivers_query_events() {
    use futures_util::StreamExt;

    let node = signed_in().await;
    let response = node.get("/api/v1/queries/stream").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("text/event-stream")
    );

    let telemetry = Arc::clone(&node.telemetry);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        telemetry.record(
            query_event(crate::util::now_ms(), "live.example", Outcome::Forwarded),
            QueryLogMode::Full,
        );
    });

    let mut stream = response.bytes_stream();
    let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("an event should arrive")
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("event: query"), "{text}");
    assert!(text.contains("live.example"), "{text}");
}

#[tokio::test]
async fn clients_merge_named_and_observed_addresses() {
    let node = signed_in().await;
    let now = crate::util::now_ms();
    node.telemetry.record(
        query_event(now, "a.example", Outcome::Forwarded),
        QueryLogMode::Full,
    );

    let body: Value = node.get("/api/v1/clients").await.json().await.unwrap();
    let observed = &body["data"][0];
    assert_eq!(observed["known"], false);
    assert_eq!(observed["id"], "192.168.1.20");
    assert_eq!(observed["query_count"], 1);

    let created = node
        .post(
            "/api/v1/clients",
            json!({"name": "Laptop", "addresses": ["192.168.1.20"], "groups": ["kids"]}),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = created.json().await.unwrap();
    let id = created["data"]["id"].as_str().unwrap().to_owned();

    // The address now belongs to the named client, so it isn't listed separately.
    let body: Value = node.get("/api/v1/clients").await.json().await.unwrap();
    let clients = body["data"].as_array().unwrap();
    assert_eq!(clients.len(), 1, "{clients:?}");
    assert_eq!(clients[0]["name"], "Laptop");
    assert_eq!(clients[0]["known"], true);

    let invalid = node
        .post(
            "/api/v1/clients",
            json!({"name": "Bad", "addresses": ["nope"]}),
        )
        .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let duplicate = node
        .post(
            "/api/v1/clients",
            json!({"name": "Other", "addresses": ["192.168.1.20"]}),
        )
        .await;
    assert_eq!(duplicate.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // A client with rules can't be deleted out from under them.
    node.create_rule(json!({
        "action": "deny", "match_type": "exact", "pattern": "a.example",
        "scope": {"kind": "client", "id": id},
    }))
    .await;
    let in_use = node
        .send(Method::DELETE, &format!("/api/v1/clients/{id}"), None)
        .await;
    assert_eq!(in_use.status(), StatusCode::CONFLICT);

    let updated = node
        .send(
            Method::PATCH,
            &format!("/api/v1/clients/{id}"),
            Some(json!({"name": "New name"})),
        )
        .await;
    assert_eq!(updated.status(), StatusCode::OK);
}

#[tokio::test]
async fn groups_track_usage_and_refuse_deletion_while_used() {
    let node = signed_in().await;
    let created = node
        .post(
            "/api/v1/groups",
            json!({"id": "kids", "description": "Children"}),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        node.post("/api/v1/groups", json!({"id": "kids"}))
            .await
            .status(),
        StatusCode::CONFLICT
    );

    let client: Value = node
        .post(
            "/api/v1/clients",
            json!({"name": "Tablet", "addresses": ["10.0.0.5"], "groups": ["kids"]}),
        )
        .await
        .json()
        .await
        .unwrap();
    let body: Value = node.get("/api/v1/groups").await.json().await.unwrap();
    assert_eq!(body["data"][0]["client_count"], 1);
    assert_eq!(body["data"][0]["description"], "Children");

    let in_use = node.send(Method::DELETE, "/api/v1/groups/kids", None).await;
    assert_eq!(in_use.status(), StatusCode::CONFLICT);
    assert_eq!(code(in_use).await, "GROUP_IN_USE");

    let id = client["data"]["id"].as_str().unwrap();
    node.send(Method::DELETE, &format!("/api/v1/clients/{id}"), None)
        .await;
    let deleted = node.send(Method::DELETE, "/api/v1/groups/kids", None).await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn settings_and_revisions_support_changes_and_rollback() {
    let node = signed_in().await;
    let settings: Value = node.get("/api/v1/settings").await.json().await.unwrap();
    assert_eq!(settings["data"]["query_log_mode"], "full");
    assert_eq!(settings["data"]["query_history_days"], 7);

    let update = json!({
        "block_response": "zero_address", "block_ttl_seconds": 30,
        "query_log_mode": "anonymized", "query_history_days": 3,
        "query_history_max_bytes": 1_073_741_824_u64,
        "rate_limit_queries_per_minute": 600, "rate_limit_exempt": ["192.168.1.1"],
    });
    let changed = node
        .send(Method::PUT, "/api/v1/settings", Some(update))
        .await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert_eq!(
        node.manager.handle().load().telemetry().mode,
        QueryLogMode::Anonymized
    );

    let too_long = node
        .send(
            Method::PUT,
            "/api/v1/settings",
            Some(json!({
                "block_response": "nxdomain", "block_ttl_seconds": 100_000,
                "query_log_mode": "full", "query_history_days": 7,
                "query_history_max_bytes": 1,
                "rate_limit_queries_per_minute": 0, "rate_limit_exempt": [],
            })),
        )
        .await;
    assert_eq!(too_long.status(), StatusCode::UNPROCESSABLE_ENTITY);

    node.create_rule(deny("rollback.example")).await;
    assert_eq!(node.decision("rollback.example").await["action"], "deny");

    let revisions: Value = node
        .get("/api/v1/config/revisions")
        .await
        .json()
        .await
        .unwrap();
    let revisions = revisions["data"].as_array().unwrap();
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0]["active"], true);
    assert_eq!(revisions[0]["rule_count"], 1);
    let previous = revisions[1]["revision"].as_str().unwrap();

    let activate = node
        .post("/api/v1/config/activate", json!({"revision": previous}))
        .await;
    assert_eq!(activate.status(), StatusCode::NO_CONTENT);
    assert_eq!(node.decision("rollback.example").await["action"], "allow");

    let missing = node
        .post("/api/v1/config/activate", json!({"revision": "nope"}))
        .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn system_status_upstreams_and_audit_log_report_state() {
    let node = signed_in().await;
    node.create_rule(deny("a.example")).await;

    let status: Value = node
        .get("/api/v1/system/status")
        .await
        .json()
        .await
        .unwrap();
    let data = &status["data"];
    assert_eq!(data["rule_count"], 1);
    assert_eq!(data["telemetry_available"], true);
    assert_eq!(data["dns_listeners"][0], "127.0.0.1:53");

    let test: Value = node
        .post("/api/v1/dns/upstreams/test", json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(test["data"]["ok"], false);
    let upstreams: Value = node
        .get("/api/v1/dns/upstreams")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(upstreams["data"][0]["server"], "127.0.0.1:9");
    assert_eq!(upstreams["data"][0]["failures"], 1);

    let audit: Value = node.get("/api/v1/audit-events").await.json().await.unwrap();
    let events = audit["data"].as_array().unwrap();
    let actions: Vec<&str> = events
        .iter()
        .map(|event| event["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"rule.create"), "{actions:?}");
    assert!(actions.contains(&"auth.setup"), "{actions:?}");
    assert_eq!(events[0]["actor"], "admin");
}

#[tokio::test]
async fn responses_carry_security_headers_and_unknown_api_paths_are_json() {
    let node = start().await;
    let page = node.get("/some/client/route").await;
    assert_eq!(page.status(), StatusCode::OK);
    let headers = page.headers();
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'self'")
    );
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );

    let api = node.get("/api/v1/does-not-exist").await;
    assert_eq!(api.status(), StatusCode::NOT_FOUND);
    assert_eq!(code(api).await, "NOT_FOUND");
    assert_eq!(
        node.post("/static-path", json!({})).await.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[test]
fn the_openapi_contract_describes_the_api() {
    let spec: Value = serde_json::from_str(&crate::openapi_json().unwrap()).unwrap();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3.1"));
    let paths = spec["paths"].as_object().unwrap();
    for path in [
        "/api/v1/rules",
        "/api/v1/queries",
        "/api/v1/auth/login",
        "/api/v1/rules/{id}",
    ] {
        assert!(paths.contains_key(path), "{path}");
    }
    assert!(spec["components"]["schemas"]["RuleDto"].is_object());
}

#[test]
fn allowed_hosts_ignore_ports_and_case() {
    let hosts = AllowedHosts::new(["DNS.Home.Arpa".to_owned()]);
    for host in [
        "localhost",
        "LOCALHOST:8080",
        "127.0.0.1:80",
        "[::1]",
        "[::1]:80",
        "dns.home.arpa",
    ] {
        assert!(hosts.allows(host), "{host}");
    }
    for host in ["evil.example", "localhost.evil.example", "[::2]", ""] {
        assert!(!hosts.allows(host), "{host}");
    }
}

#[tokio::test]
async fn local_zones_and_records_can_be_managed_with_validation() {
    let node = signed_in().await;
    let record = json!({"name": "nas.home.arpa", "type": "a", "value": "192.168.1.10"});

    let no_zone = node.post("/api/v1/dns/records", record.clone()).await;
    assert_eq!(no_zone.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let zone = node
        .post("/api/v1/dns/zones", json!({"name": "Home.Arpa."}))
        .await;
    assert_eq!(zone.status(), StatusCode::CREATED);
    let duplicate = node
        .post("/api/v1/dns/zones", json!({"name": "home.arpa"}))
        .await;
    assert_eq!(duplicate.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let created = node.post("/api/v1/dns/records", record).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = created.json().await.unwrap();
    assert_eq!(created["data"]["ttl_seconds"], 300);
    let id = created["data"]["id"].as_str().unwrap().to_owned();

    let bad_value = node
        .post(
            "/api/v1/dns/records",
            json!({"name": "x.home.arpa", "type": "a", "value": "nope"}),
        )
        .await;
    assert_eq!(bad_value.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let loop_record = node
        .post(
            "/api/v1/dns/records",
            json!({"name": "c.home.arpa", "type": "cname", "value": "c.home.arpa"}),
        )
        .await;
    assert_eq!(loop_record.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let zones: Value = node.get("/api/v1/dns/zones").await.json().await.unwrap();
    assert_eq!(zones["data"][0]["name"], "home.arpa");
    assert_eq!(zones["data"][0]["record_count"], 1);

    let in_use = node
        .send(Method::DELETE, "/api/v1/dns/zones/home.arpa", None)
        .await;
    assert_eq!(in_use.status(), StatusCode::CONFLICT);

    let updated = node
        .send(
            Method::PATCH,
            &format!("/api/v1/dns/records/{id}"),
            Some(json!({"value": "192.168.1.20"})),
        )
        .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let records: Value = node.get("/api/v1/dns/records").await.json().await.unwrap();
    assert_eq!(records["data"][0]["value"], "192.168.1.20");
    assert_eq!(records["data"][0]["type"], "a");

    assert_eq!(
        node.send(Method::DELETE, &format!("/api/v1/dns/records/{id}"), None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        node.send(Method::DELETE, "/api/v1/dns/zones/home.arpa", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn the_cache_can_be_inspected_and_flushed() {
    let node = signed_in().await;
    let stats: Value = node.get("/api/v1/dns/cache").await.json().await.unwrap();
    assert_eq!(stats["data"]["enabled"], true);
    assert_eq!(stats["data"]["entries"], 0);
    let flush = node.send(Method::DELETE, "/api/v1/dns/cache", None).await;
    assert_eq!(flush.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn backups_download_validate_and_restore_onto_another_node() {
    let node = signed_in().await;
    node.create_rule(deny("backed-up.example")).await;

    let response = node.post("/api/v1/backup", json!({})).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/gzip");
    assert!(
        response.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("ferrixdns-backup-")
    );
    let archive = response.bytes().await.unwrap().to_vec();

    let other = signed_in().await;
    let upload = |dry_run: bool, body: Vec<u8>| {
        let request = other
            .client
            .post(format!(
                "{}/api/v1/backup/restore?dry_run={dry_run}",
                other.base
            ))
            .header("cookie", other.cookie.clone().unwrap())
            .header("x-csrf-token", other.csrf.clone().unwrap())
            .body(body);
        async move { request.send().await.unwrap() }
    };

    // A dry run reports the contents and changes nothing.
    let preview = upload(true, archive.clone()).await;
    assert_eq!(preview.status(), StatusCode::OK);
    let preview: Value = preview.json().await.unwrap();
    assert_eq!(preview["data"]["dry_run"], true);
    assert_eq!(preview["data"]["rule_count"], 1);
    assert_eq!(preview["data"]["has_credentials"], false);
    assert_eq!(other.decision("backed-up.example").await["action"], "allow");

    let garbage = upload(false, b"not a backup".to_vec()).await;
    assert_eq!(garbage.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(code(garbage).await, "BACKUP_INVALID");
    assert_eq!(other.decision("backed-up.example").await["action"], "allow");

    let restored = upload(false, archive).await;
    assert_eq!(restored.status(), StatusCode::OK);
    assert_eq!(other.decision("backed-up.example").await["action"], "deny");

    // The existing account still works, because web restores leave accounts alone.
    assert_eq!(other.get("/api/v1/rules").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn backup_endpoints_need_a_session_and_restore_respects_read_only() {
    let anonymous = start().await;
    assert_eq!(
        anonymous.post("/api/v1/backup", json!({})).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        anonymous
            .post("/api/v1/backup/restore", json!({}))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let source = signed_in().await;
    source.create_rule(deny("a.example")).await;
    let archive = source
        .post("/api/v1/backup", json!({}))
        .await
        .bytes()
        .await
        .unwrap()
        .to_vec();

    let mut read_only = start_with(Options {
        policy_file: Some("schema_version = 1\n"),
        ..Options::default()
    })
    .await;
    read_only.setup().await;
    let response = read_only
        .client
        .post(format!("{}/api/v1/backup/restore", read_only.base))
        .header("cookie", read_only.cookie.clone().unwrap())
        .header("x-csrf-token", read_only.csrf.clone().unwrap())
        .body(archive)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(code(response).await, "POLICY_READ_ONLY");
}

#[tokio::test]
async fn blocking_can_be_paused_for_a_set_time_and_resumed() {
    let services = dns_runtime::Services::detached(vec![]);
    let mut node = start_with(Options {
        services: services.clone(),
        ..Options::default()
    })
    .await;
    assert_eq!(
        node.get("/api/v1/blocking").await.status(),
        StatusCode::UNAUTHORIZED
    );
    node.setup().await;

    let idle: Value = node.get("/api/v1/blocking").await.json().await.unwrap();
    assert_eq!(idle["data"]["paused"], false);
    assert_eq!(idle["data"]["paused_until"], Value::Null);

    for seconds in [0, 86_401] {
        let invalid = node
            .post("/api/v1/blocking/pause", json!({"seconds": seconds}))
            .await;
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(!services.pause.is_active());

    let paused: Value = node
        .post("/api/v1/blocking/pause", json!({"seconds": 300}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(paused["data"]["paused"], true);
    assert_eq!(paused["data"]["remaining_seconds"], 300);
    assert!(paused["data"]["paused_until"].is_string());
    assert!(services.pause.is_active());

    let resumed: Value = node
        .post("/api/v1/blocking/resume", json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(resumed["data"]["paused"], false);
    assert!(!services.pause.is_active());

    let audit: Value = node.get("/api/v1/audit-events").await.json().await.unwrap();
    let text = audit.to_string();
    assert!(text.contains("blocking.pause") && text.contains("blocking.resume"));
}

#[tokio::test]
async fn pausing_works_when_the_policy_comes_from_a_file() {
    let mut node = start_with(Options {
        policy_file: Some("schema_version = 1\n"),
        ..Options::default()
    })
    .await;
    node.setup().await;
    let paused = node
        .post("/api/v1/blocking/pause", json!({"seconds": 60}))
        .await;
    assert_eq!(paused.status(), StatusCode::OK);
}

#[tokio::test]
async fn forward_zones_can_be_managed_with_validation() {
    let node = signed_in().await;
    let create = |zones: Value, servers: Value| {
        let body = json!({"zones": zones, "servers": servers});
        let node = &node;
        async move { node.post("/api/v1/dns/forwarders", body).await }
    };
    for (zones, servers) in [
        (json!([]), json!(["192.168.1.1"])),
        (json!(["lan"]), json!([])),
        (json!(["lan"]), json!(["not a server"])),
        (json!(["192.168.1.0/25"]), json!(["192.168.1.1"])),
        (json!(["localhost"]), json!(["192.168.1.1"])),
    ] {
        let rejected = create(zones, servers).await;
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    let created = create(json!(["lan", "192.168.1.0/24"]), json!(["192.168.1.1"])).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = created.json().await.unwrap();
    let id = created["data"]["id"].as_str().unwrap().to_owned();
    let name = DomainName::parse("nas.lan").unwrap();
    assert!(node.manager.handle().load().forward_route(&name).is_some());

    let path = format!("/api/v1/dns/forwarders/{id}");
    let bad = node
        .send(Method::PATCH, &path, Some(json!({"servers": ["nope"]})))
        .await;
    assert_eq!(bad.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let changed = node
        .send(Method::PATCH, &path, Some(json!({"zones": ["corp"]})))
        .await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert!(node.manager.handle().load().forward_route(&name).is_none());

    let listed: Value = node
        .get("/api/v1/dns/forwarders")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(listed["data"][0]["zones"], json!(["corp"]));

    let removed = node.send(Method::DELETE, &path, None).await;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    let missing = node.send(Method::DELETE, &path, None).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn clients_can_be_identified_by_mac_and_host_name() {
    let node = signed_in().await;
    let empty = node
        .post("/api/v1/clients", json!({"name": "Nothing"}))
        .await;
    assert_eq!(empty.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bad_mac = node
        .post("/api/v1/clients", json!({"name": "Bad", "macs": ["nope"]}))
        .await;
    assert_eq!(bad_mac.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let created = node
        .post(
            "/api/v1/clients",
            json!({"name": "Tablet", "macs": ["AA-BB-CC-00-00-01"], "hostnames": ["tablet"]}),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = created.json().await.unwrap();
    assert_eq!(created["data"]["macs"], json!(["AA-BB-CC-00-00-01"]));
    assert_eq!(created["data"]["addresses"], json!([]));

    let id = created["data"]["id"].as_str().unwrap();
    let cleared = node
        .send(
            Method::PATCH,
            &format!("/api/v1/clients/{id}"),
            Some(json!({"macs": [], "hostnames": []})),
        )
        .await;
    assert_eq!(cleared.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let policy = node.manager.handle().load_full();
    let source = dns_policy::ClientSource {
        address: "192.168.1.2".parse().unwrap(),
        mac: Some("aa:bb:cc:00:00:01".parse().unwrap()),
        hostname: None,
    };
    assert_eq!(policy.identity(source).unwrap().id.as_ref(), id);
}

fn device(address: &str, mac: Option<&str>, hostname: Option<&str>) -> dns_runtime::DeviceInfo {
    dns_runtime::DeviceInfo {
        address: address.parse().unwrap(),
        mac: mac.map(|mac| mac.parse().unwrap()),
        hostname: hostname.map(|name| DomainName::parse(name).unwrap()),
        on_network: mac.is_some(),
        last_active_ms: crate::util::now_ms(),
    }
}

#[tokio::test]
async fn the_network_overview_merges_what_is_known_about_each_device() {
    let now = crate::util::now_ms();
    let services = dns_runtime::Services::detached(vec![
        device("192.168.1.2", Some("aa:bb:cc:00:00:01"), Some("tablet.lan")),
        device("fd00::2", Some("aa:bb:cc:00:00:01"), None),
        device("192.168.1.3", Some("aa:bb:cc:00:00:02"), None),
        device("192.168.1.4", None, None),
    ]);
    let mut node = start_with(Options {
        services,
        stored_devices: vec![
            dns_storage::NetworkDevice {
                mac: "aa:bb:cc:00:00:01".to_owned(),
                addresses: vec!["192.168.1.2".to_owned()],
                hostname: None,
                first_seen_ms: now - 5_000_000,
                last_seen_ms: now - 5_000_000,
            },
            dns_storage::NetworkDevice {
                mac: "aa:bb:cc:00:00:09".to_owned(),
                addresses: vec!["192.168.1.9".to_owned()],
                hostname: Some("old.lan".to_owned()),
                first_seen_ms: now - 9_000_000,
                last_seen_ms: now - 9_000_000,
            },
        ],
        ..Options::default()
    })
    .await;
    assert_eq!(
        node.get("/api/v1/network/devices").await.status(),
        StatusCode::UNAUTHORIZED
    );
    node.setup().await;
    let created = node
        .post(
            "/api/v1/clients",
            json!({"name": "Tablet", "macs": ["aa:bb:cc:00:00:01"], "groups": ["kids"]}),
        )
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let listed: Value = node
        .get("/api/v1/network/devices")
        .await
        .json()
        .await
        .unwrap();
    let rows = listed["data"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "{rows:#?}");
    let row = |id: &str| rows.iter().find(|row| row["id"] == id).unwrap();

    let tablet = row("aa:bb:cc:00:00:01");
    assert_eq!(tablet["addresses"], json!(["192.168.1.2", "fd00::2"]));
    assert_eq!(tablet["hostname"], "tablet.lan");
    assert_eq!(tablet["client_name"], "Tablet");
    assert_eq!(tablet["groups"], json!(["kids"]));
    assert_eq!(tablet["on_network"], true);
    assert!(tablet["first_seen_at"].is_string());

    let unnamed = row("aa:bb:cc:00:00:02");
    assert_eq!(unnamed["client_name"], Value::Null);
    assert_eq!(unnamed["query_count"], 0);

    let without_mac = row("192.168.1.4");
    assert_eq!(without_mac["mac"], Value::Null);
    assert_eq!(without_mac["on_network"], false);

    let remembered = row("aa:bb:cc:00:00:09");
    assert_eq!(remembered["hostname"], "old.lan");
    assert_eq!(remembered["on_network"], false);
    assert_eq!(remembered["query_count"], Value::Null);

    // Anything on the network now sorts above what isn't.
    assert_eq!(rows[0]["on_network"], true);
    assert_eq!(rows[3]["on_network"], false);

    // Once client details aren't kept, counts are unknown rather than zero.
    let settings: Value = node.get("/api/v1/settings").await.json().await.unwrap();
    let mut anonymized = settings["data"].clone();
    anonymized["query_log_mode"] = json!("anonymized");
    let saved = node
        .send(Method::PUT, "/api/v1/settings", Some(anonymized))
        .await;
    assert_eq!(saved.status(), StatusCode::OK);
    let listed: Value = node
        .get("/api/v1/network/devices")
        .await
        .json()
        .await
        .unwrap();
    let unnamed = listed["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "aa:bb:cc:00:00:02")
        .unwrap();
    assert_eq!(unnamed["query_count"], Value::Null);
}

#[tokio::test]
async fn system_status_reports_rate_limiting() {
    let node = signed_in().await;
    let status: Value = node
        .get("/api/v1/system/status")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(status["data"]["rate_limited_queries"], 0);
    assert_eq!(status["data"]["ntp"], Value::Null);
    let settings: Value = node.get("/api/v1/settings").await.json().await.unwrap();
    assert_eq!(settings["data"]["rate_limit_queries_per_minute"], 3000);
    assert_eq!(settings["data"]["rate_limit_exempt"][0], "127.0.0.0/8");
}

#[tokio::test]
async fn node_settings_need_a_session_and_csrf_and_report_when_unavailable() {
    let mut node = start().await;
    let anonymous = node
        .client
        .get(format!("{}/api/v1/node-settings", node.base))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let unprotected = node
        .client
        .put(format!("{}/api/v1/node-settings", node.base))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(unprotected.status(), StatusCode::UNAUTHORIZED);

    node.setup().await;
    let response = node.get("/api/v1/node-settings").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
