//! # `mitm::transparent::cert`
//!
//! **Purpose**: Generates per-host TLS server config for transparent TLS interception.
//! **Public API**: module-private certificate helper
//! **Dependencies**: `mitm`, `rcgen`, `tokio-rustls`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 51 / 80

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use tokio_rustls::rustls;

use super::super::RootIssuer;
use crate::error::{EtwardenError, Result};

pub(super) fn server_config_for_host(
    issuer: &RootIssuer,
    host: String,
) -> Result<rustls::ServerConfig> {
    let (cert_der, key_der) = generate_leaf_cert(issuer, host)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .map_err(|e| {
            EtwardenError::MitmProxy(format!("transparent leaf cert config failed: {e}"))
        })?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn generate_leaf_cert(issuer: &RootIssuer, host: String) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::new(vec![host]).map_err(|e| {
        EtwardenError::MitmProxy(format!("transparent leaf cert params failed: {e}"))
    })?;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let key_pair = KeyPair::generate()
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent leaf cert key failed: {e}")))?;
    let cert = params.signed_by(&key_pair, issuer).map_err(|e| {
        EtwardenError::MitmProxy(format!("transparent leaf cert signing failed: {e}"))
    })?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}
