//! What nodes and the central controller say to each other, and how it's signed.
//!
//! Nodes always connect out to the controller. Each node signs its requests with a key that never
//! leaves it, and the controller signs each bundle of policy, so a node only applies what its
//! controller issued, whatever happens on the network in between. See ADR-015.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const TOKEN_PREFIX: &str = "fxn1_";
const ENROLL_DOMAIN: &str = "ferrix-enroll-v1";
const REQUEST_DOMAIN: &str = "ferrix-node-request-v1";
const BUNDLE_DOMAIN: &str = "ferrix-bundle-v1";

/// A request's signature is accepted this long either side of its stated time.
pub const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

pub const NODE_HEADER: &str = "x-ferrix-node";
pub const TIME_HEADER: &str = "x-ferrix-time";
pub const SIGNATURE_HEADER: &str = "x-ferrix-signature";

/// Why a key, token or signature couldn't be used.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("this enrollment token isn't valid")]
    InvalidToken,
    #[error("this key isn't valid")]
    InvalidKey,
    #[error("the system's random number generator failed")]
    Random,
}

/// The SHA-256 of some bytes, in lowercase hexadecimal.
pub fn sha256_hex(content: &[u8]) -> String {
    digest::digest(&digest::SHA256, content)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// An Ed25519 key that identifies a node, or that signs a controller's bundles.
pub struct SigningKey {
    pair: Ed25519KeyPair,
}

impl SigningKey {
    /// Generates a key, returning its PKCS#8 form to store.
    pub fn generate() -> Result<(Self, Vec<u8>), ContractError> {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| ContractError::Random)?;
        let bytes = document.as_ref().to_vec();
        Ok((Self::from_pkcs8(&bytes)?, bytes))
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, ContractError> {
        Ok(Self {
            pair: Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| ContractError::InvalidKey)?,
        })
    }

    /// The public half, as base64.
    pub fn public_key(&self) -> String {
        STANDARD.encode(self.pair.public_key().as_ref())
    }

    fn sign(&self, message: &[u8]) -> String {
        STANDARD.encode(self.pair.sign(message).as_ref())
    }

    /// Proves that whoever enrolls with this token holds this key.
    pub fn sign_enrollment(&self, secret: &str) -> String {
        self.sign(&enrollment_message(secret, &self.public_key()))
    }

    /// Signs a request to the controller.
    pub fn sign_request(&self, method: &str, path: &str, time_ms: i64, body: &[u8]) -> String {
        self.sign(&request_message(method, path, time_ms, body))
    }

    /// Signs a bundle's manifest, exactly as stored.
    pub fn sign_manifest(&self, manifest: &str) -> String {
        self.sign(&bundle_message(manifest))
    }
}

fn enrollment_message(secret: &str, public_key: &str) -> Vec<u8> {
    format!("{ENROLL_DOMAIN}\n{secret}\n{public_key}").into_bytes()
}

fn request_message(method: &str, path: &str, time_ms: i64, body: &[u8]) -> Vec<u8> {
    format!(
        "{REQUEST_DOMAIN}\n{method}\n{path}\n{time_ms}\n{}",
        sha256_hex(body)
    )
    .into_bytes()
}

fn bundle_message(manifest: &str) -> Vec<u8> {
    format!("{BUNDLE_DOMAIN}\n{manifest}").into_bytes()
}

fn verify(public_key: &str, message: &[u8], signature: &str) -> bool {
    let (Ok(key), Ok(signature)) = (STANDARD.decode(public_key), STANDARD.decode(signature)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, key)
        .verify(message, &signature)
        .is_ok()
}

/// Checks the proof that an enrolling node holds its key.
pub fn verify_enrollment(public_key: &str, secret: &str, proof: &str) -> bool {
    verify(public_key, &enrollment_message(secret, public_key), proof)
}

/// Checks a node's signature on a request.
pub fn verify_request(
    public_key: &str,
    method: &str,
    path: &str,
    time_ms: i64,
    body: &[u8],
    signature: &str,
) -> bool {
    verify(
        public_key,
        &request_message(method, path, time_ms, body),
        signature,
    )
}

/// Checks the controller's signature on a bundle's manifest.
pub fn verify_manifest(public_key: &str, manifest: &str, signature: &str) -> bool {
    verify(public_key, &bundle_message(manifest), signature)
}

/// Everything a new node needs to join: where the controller is, how to recognize it, and a secret
/// that works once. Trust starts here, so this must reach the node by a safe route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    #[serde(rename = "u")]
    pub url: String,
    #[serde(rename = "s")]
    pub secret: String,
    /// The key the controller signs bundles with.
    #[serde(rename = "k")]
    pub controller_key: String,
    /// The SHA-256 of a self-signed controller's certificate. Without one, the certificate must
    /// chain to a trusted root.
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    pub tls_pin: Option<String>,
}

impl EnrollmentToken {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(token: &str) -> Result<Self, ContractError> {
        let encoded = token
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(ContractError::InvalidToken)?;
        let json = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ContractError::InvalidToken)?;
        serde_json::from_slice(&json).map_err(|_| ContractError::InvalidToken)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub secret: String,
    pub public_key: String,
    pub proof: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub node_id: String,
    pub site_id: String,
}

/// One minute of query counts. No names or addresses leave a node this way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupRow {
    pub bucket_start_ms: i64,
    pub outcome: String,
    pub count: i64,
    pub latency_sum_us: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CacheReport {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub stale_served: u64,
    pub prefetches: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpstreamReport {
    pub server: String,
    pub responses: u64,
    pub failures: u64,
    pub last_latency_us: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Heartbeat {
    pub version: String,
    pub name: String,
    pub uptime_seconds: u64,
    pub listeners: Vec<String>,
    /// The newest generation this node has made active and persisted.
    pub applied_generation: u64,
    pub policy_revision: String,
    pub blocking_paused: bool,
    pub cache: Option<CacheReport>,
    pub upstreams: Vec<UpstreamReport>,
    /// Query counts for recent minutes, which may repeat earlier ones. The newest copy wins.
    pub rollups: Vec<RollupRow>,
}

/// A bundle a node should have.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredBundle {
    pub bundle_id: String,
    pub generation: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub desired: Option<DesiredBundle>,
    /// Query counts up to this time are stored, so they needn't be sent again.
    pub rollups_stored_through_ms: i64,
}

/// A file a bundle pins by hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    pub sha256: String,
    pub size: u64,
}

/// What a bundle contains. The controller signs these exact bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub bundle_id: String,
    pub site_id: String,
    /// Grows with each bundle for a site. A node never goes back to a lower one, so a rollback is
    /// a new, higher generation with older contents.
    pub generation: u64,
    pub policy_schema_version: u32,
    pub policy: ManifestFile,
    pub lists: Vec<ManifestFile>,
    pub created_at_ms: i64,
    /// The signing key's fingerprint.
    pub issuer: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedBundle {
    pub manifest: String,
    pub signature: String,
}

/// How far a node has got with a bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckState {
    Downloading,
    Staged,
    Activating,
    /// It's active, DNS still answers, and it survives a restart.
    Healthy,
    /// It was never made active, and the previous policy kept serving.
    Failed,
    /// It went active, DNS stopped answering, and the node went back. It won't retry this one.
    Reverted,
}

impl AckState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Downloading => "downloading",
            Self::Staged => "staged",
            Self::Activating => "activating",
            Self::Healthy => "healthy",
            Self::Failed => "failed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ack {
    pub generation: u64,
    pub state: AckState,
    pub detail: Option<String>,
    pub policy_revision: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn key() -> SigningKey {
        SigningKey::generate().unwrap().0
    }

    #[test]
    fn keys_survive_being_stored() {
        let (key, stored) = SigningKey::generate().unwrap();
        assert_eq!(
            key.public_key(),
            SigningKey::from_pkcs8(&stored).unwrap().public_key()
        );
        assert!(SigningKey::from_pkcs8(b"nonsense").is_err());
    }

    #[test]
    fn a_request_signature_covers_everything_that_matters() {
        let key = key();
        let public = key.public_key();
        let signature = key.sign_request("POST", "/node/v1/heartbeat", 5, b"body");
        assert!(verify_request(
            &public,
            "POST",
            "/node/v1/heartbeat",
            5,
            b"body",
            &signature
        ));
        assert!(!verify_request(
            &public,
            "GET",
            "/node/v1/heartbeat",
            5,
            b"body",
            &signature
        ));
        assert!(!verify_request(
            &public,
            "POST",
            "/node/v1/other",
            5,
            b"body",
            &signature
        ));
        assert!(!verify_request(
            &public,
            "POST",
            "/node/v1/heartbeat",
            6,
            b"body",
            &signature
        ));
        assert!(!verify_request(
            &public,
            "POST",
            "/node/v1/heartbeat",
            5,
            b"changed",
            &signature
        ));
        let other = self::key().public_key();
        assert!(!verify_request(
            &other,
            "POST",
            "/node/v1/heartbeat",
            5,
            b"body",
            &signature
        ));
        assert!(!verify_request(
            &public,
            "POST",
            "/node/v1/heartbeat",
            5,
            b"body",
            "not base64!"
        ));
    }

    #[test]
    fn a_manifest_signature_is_exact_and_can_not_stand_in_for_anything_else() {
        let key = key();
        let public = key.public_key();
        let signature = key.sign_manifest("{\"generation\":2}");
        assert!(verify_manifest(&public, "{\"generation\":2}", &signature));
        assert!(!verify_manifest(&public, "{\"generation\":3}", &signature));
        assert!(!verify_manifest(&public, "{\"generation\": 2}", &signature));

        let proof = key.sign_enrollment("{\"generation\":2}");
        assert!(!verify_manifest(&public, "{\"generation\":2}", &proof));
    }

    #[test]
    fn enrollment_proves_the_node_holds_its_key() {
        let key = key();
        let proof = key.sign_enrollment("secret");
        assert!(verify_enrollment(&key.public_key(), "secret", &proof));
        assert!(!verify_enrollment(&key.public_key(), "other", &proof));
        assert!(!verify_enrollment(
            &self::key().public_key(),
            "secret",
            &proof
        ));
    }

    #[test]
    fn tokens_round_trip_and_reject_anything_else() {
        let token = EnrollmentToken {
            url: "https://control.example:8444".to_owned(),
            secret: "abc".to_owned(),
            controller_key: "key".to_owned(),
            tls_pin: Some("pin".to_owned()),
        };
        assert_eq!(EnrollmentToken::decode(&token.encode()).unwrap(), token);
        assert_eq!(
            EnrollmentToken::decode(&format!(" {}\n", token.encode())).unwrap(),
            token,
        );
        for bad in ["", "abc", "fxn1_", "fxn1_!!!", "fxn1_e30"] {
            assert_eq!(
                EnrollmentToken::decode(bad),
                Err(ContractError::InvalidToken),
                "{bad}"
            );
        }
    }

    #[test]
    fn hashes_are_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
