//! TLS for the web UI: an operator's certificate, or a self-signed one kept in the state directory.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

const SELF_SIGNED_CERT: &str = "tls/self-signed-cert.pem";
const SELF_SIGNED_KEY: &str = "tls/self-signed-key.pem";

/// Loads an operator's certificate chain and private key.
pub fn from_files(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    node_api::load_tls_files(cert, key).map_err(anyhow::Error::msg)
}

/// Loads the node's self-signed certificate, creating it the first time.
pub fn self_signed(state_dir: &Path, names: &[String]) -> Result<Arc<ServerConfig>> {
    let cert_path = state_dir.join(SELF_SIGNED_CERT);
    let key_path = state_dir.join(SELF_SIGNED_KEY);

    if !cert_path.exists() || !key_path.exists() {
        let mut subject_names: Vec<String> = vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ];
        subject_names.extend(names.iter().map(|name| {
            name.trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned()
        }));
        subject_names.sort_unstable();
        subject_names.dedup();

        let certified = rcgen::generate_simple_self_signed(subject_names)
            .context("cannot create a self-signed certificate")?;
        if let Some(directory) = cert_path.parent() {
            fs::create_dir_all(directory)
                .with_context(|| format!("cannot create {}", directory.display()))?;
        }
        write_private(&key_path, certified.signing_key.serialize_pem().as_bytes())?;
        write_private(&cert_path, certified.cert.pem().as_bytes())?;
    }

    let chain = CertificateDer::pem_file_iter(&cert_path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("cannot read {}", cert_path.display()))?;
    if let Some(certificate) = chain.first() {
        // Browsers will warn about this certificate, so this is how to check it's the right one.
        info!(
            sha256 = %dns_storage::sha256_hex(certificate),
            "using a self-signed certificate for the web UI"
        );
    }
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .with_context(|| format!("cannot read {}", key_path.display()))?;
    node_api::tls_server_config(chain, key).map_err(anyhow::Error::msg)
}

fn write_private(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}
