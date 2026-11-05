//! How a node recognizes its controller's certificate.

use std::sync::Arc;

use fleet_contract::sha256_hex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

/// Accepts exactly one certificate, whichever name it's for. The token that carries the pin came
/// from the controller by a trusted route, so this is stronger than a certificate authority.
#[derive(Debug)]
struct PinnedCertificate {
    sha256: String,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if sha256_hex(end_entity) == self.sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(
                "the controller's certificate isn't the one in the enrollment token".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// TLS settings for reaching a controller: its pinned certificate if it has one, then any private
/// certificate authority given, then the public roots built into this binary.
pub(crate) fn client_config(
    pin: Option<&str>,
    extra_ca_pem: Option<&[u8]>,
) -> Result<ClientConfig, String> {
    let provider: Arc<CryptoProvider> = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?;
    if let Some(pin) = pin {
        let verifier = PinnedCertificate {
            sha256: pin.to_ascii_lowercase(),
            algorithms: provider.signature_verification_algorithms,
        };
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth());
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_ca_pem {
        for certificate in CertificateDer::pem_slice_iter(pem) {
            let certificate =
                certificate.map_err(|error| format!("cannot read the CA file: {error}"))?;
            roots
                .add(certificate)
                .map_err(|error| format!("cannot use the CA file: {error}"))?;
        }
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}
