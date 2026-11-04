//! Local accounts: first-run setup, Argon2id passwords, cookie sessions and CSRF protection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use axum::extract::FromRequestParts;
use axum::http::header::{COOKIE, ORIGIN};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use dns_storage::{Session, sha256_hex};
use tokio::sync::Semaphore;

use crate::AppState;
use crate::error::ApiError;
use crate::util::now_ms;

pub const SESSION_COOKIE: &str = "ferrixdns_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
pub const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
pub const MIN_PASSWORD_LENGTH: usize = 10;

const MAX_FAILURES_BEFORE_LOCKOUT: u32 = 5;
const BASE_LOCKOUT: Duration = Duration::from_secs(30);
const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Password hashing is deliberately expensive, so only a few can run at once.
const CONCURRENT_HASHES: usize = 2;

/// A random token in lowercase hexadecimal.
pub fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hashes a password with Argon2id.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(ApiError::internal)
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Runs password hashing off the async runtime, limiting how many run at once.
#[derive(Clone)]
pub struct PasswordWorker {
    permits: Arc<Semaphore>,
    /// Verified when a username doesn't exist, so timing doesn't reveal which usernames do.
    decoy_hash: Arc<str>,
}

impl PasswordWorker {
    pub fn new() -> Result<Self, ApiError> {
        Ok(Self {
            permits: Arc::new(Semaphore::new(CONCURRENT_HASHES)),
            decoy_hash: hash_password(&random_token())?.into(),
        })
    }

    pub async fn hash(&self, password: String) -> Result<String, ApiError> {
        let _permit = self.permits.acquire().await.map_err(ApiError::internal)?;
        tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(ApiError::internal)?
    }

    /// Checks a password. With no stored hash this does the same work and returns false.
    pub async fn verify(&self, password: String, hash: Option<String>) -> Result<bool, ApiError> {
        let _permit = self.permits.acquire().await.map_err(ApiError::internal)?;
        let known = hash.is_some();
        let hash = hash.unwrap_or_else(|| self.decoy_hash.to_string());
        let matched = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
            .await
            .map_err(ApiError::internal)?;
        Ok(known && matched)
    }
}

#[derive(Clone, Copy)]
struct Failures {
    count: u32,
    locked_until: Option<Instant>,
}

/// Slows password guessing, per source address.
#[derive(Clone, Default)]
pub struct LoginGuard {
    failures: Arc<Mutex<HashMap<IpAddr, Failures>>>,
}

impl LoginGuard {
    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, Failures>> {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Fails if this source must wait before trying again.
    pub fn check(&self, source: IpAddr) -> Result<(), ApiError> {
        let locked = self
            .lock()
            .get(&source)
            .and_then(|failures| failures.locked_until)
            .and_then(|until| until.checked_duration_since(Instant::now()));
        match locked {
            Some(remaining) => Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "TOO_MANY_ATTEMPTS",
                format!(
                    "Too many failed sign-ins. Try again in {} seconds.",
                    remaining.as_secs() + 1
                ),
            )),
            None => Ok(()),
        }
    }

    pub fn record_failure(&self, source: IpAddr) {
        let mut failures = self.lock();
        // Addresses seen only once don't need keeping forever.
        if failures.len() > 10_000 {
            failures.clear();
        }
        let entry = failures.entry(source).or_insert(Failures {
            count: 0,
            locked_until: None,
        });
        entry.count += 1;
        if entry.count >= MAX_FAILURES_BEFORE_LOCKOUT {
            let doublings = entry.count - MAX_FAILURES_BEFORE_LOCKOUT;
            let lockout = BASE_LOCKOUT
                .saturating_mul(2_u32.saturating_pow(doublings))
                .min(MAX_LOCKOUT);
            entry.locked_until = Some(Instant::now() + lockout);
        }
    }

    pub fn record_success(&self, source: IpAddr) {
        self.lock().remove(&source);
    }
}

pub fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_owned())
}

pub fn session_cookie(token: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{secure}",
        SESSION_LIFETIME.as_secs()
    )
}

pub fn expired_session_cookie(secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}")
}

/// Rejects cross-origin requests where a browser identifies the origin.
pub fn check_origin(headers: &HeaderMap, hosts: &crate::AllowedHosts) -> Result<(), ApiError> {
    let Some(origin) = headers.get(ORIGIN) else {
        return Ok(());
    };
    let host = origin
        .to_str()
        .ok()
        .and_then(|origin| origin.split_once("://"))
        .map(|(_, host)| host);
    match host {
        Some(host) if hosts.allows(host) => Ok(()),
        _ => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "ORIGIN_NOT_ALLOWED",
            "This request came from another site",
        )),
    }
}

/// A signed-in user. Requests that change anything must also carry the CSRF token.
pub struct AuthSession {
    pub session: Session,
    pub token_hash: String,
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = session_token(&parts.headers).ok_or_else(ApiError::unauthenticated)?;
        let token_hash = sha256_hex(token.as_bytes());
        let session = state
            .db
            .find_session(&token_hash, now_ms())
            .await?
            .ok_or_else(ApiError::unauthenticated)?;

        let is_safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        if !is_safe {
            check_origin(&parts.headers, &state.hosts)?;
            let provided = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok());
            if provided != Some(session.csrf_token.as_str()) {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "CSRF_TOKEN_INVALID",
                    "This request is missing its security token. Reload the page and try again.",
                ));
            }
        }
        Ok(Self {
            session,
            token_hash,
        })
    }
}
