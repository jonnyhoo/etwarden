//! # `mitm::ca`
//!
//! **Purpose**: Loads or creates the local root issuer used by the MITM proxy.
//! **Public API**: `CertificateAuthorityConfig`, `load_or_generate_issuer`
//! **Dependencies**: `rcgen`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 125 / 160

use std::{fs, path::PathBuf, sync::Arc};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, IsCa, KeyPair, KeyUsagePurpose,
};

use crate::error::{EtwardenError, Result};

/// Files backing the generated or imported MITM root issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Loads an existing issuer or creates one on disk.
pub fn load_or_generate_issuer(
    config: &CertificateAuthorityConfig,
) -> Result<Arc<rcgen::Issuer<'static, KeyPair>>> {
    match (config.cert_path.exists(), config.key_path.exists()) {
        (true, true) => load_issuer(config),
        (false, false) => generate_issuer(config),
        (true, false) | (false, true) => Err(EtwardenError::MitmProxy(format!(
            "MITM CA files are incomplete: cert='{}', key='{}'",
            config.cert_path.display(),
            config.key_path.display()
        ))),
    }
}

fn load_issuer(
    config: &CertificateAuthorityConfig,
) -> Result<Arc<rcgen::Issuer<'static, KeyPair>>> {
    let cert_pem = fs::read_to_string(&config.cert_path).map_err(|e| {
        EtwardenError::MitmProxy(format!(
            "failed to read MITM CA cert '{}': {e}",
            config.cert_path.display()
        ))
    })?;
    let key_pem = fs::read_to_string(&config.key_path).map_err(|e| {
        EtwardenError::MitmProxy(format!(
            "failed to read MITM CA key '{}': {e}",
            config.key_path.display()
        ))
    })?;
    let signing_key = KeyPair::from_pem(&key_pem)
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to parse MITM CA key: {e}")))?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&cert_pem, signing_key)
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to parse MITM CA cert: {e}")))?;
    Ok(Arc::new(issuer))
}

fn generate_issuer(
    config: &CertificateAuthorityConfig,
) -> Result<Arc<rcgen::Issuer<'static, KeyPair>>> {
    ensure_parent_dir(&config.cert_path)?;
    ensure_parent_dir(&config.key_path)?;

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("etwarden MITM CA".to_string()),
    );
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let signing_key = KeyPair::generate()
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to generate MITM CA key: {e}")))?;
    let cert = params
        .self_signed(&signing_key)
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to generate MITM CA cert: {e}")))?;

    fs::write(&config.cert_path, cert.pem()).map_err(|e| {
        EtwardenError::MitmProxy(format!(
            "failed to write MITM CA cert '{}': {e}",
            config.cert_path.display()
        ))
    })?;
    fs::write(&config.key_path, signing_key.serialize_pem()).map_err(|e| {
        EtwardenError::MitmProxy(format!(
            "failed to write MITM CA key '{}': {e}",
            config.key_path.display()
        ))
    })?;

    Ok(Arc::new(rcgen::Issuer::new(params, signing_key)))
}

fn ensure_parent_dir(path: &std::path::Path) -> Result<()> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|e| {
        EtwardenError::MitmProxy(format!(
            "failed to create MITM CA directory '{}': {e}",
            parent.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn generates_and_reloads_issuer_files() {
        let dir = tempdir().expect("tempdir");
        let config = CertificateAuthorityConfig {
            cert_path: dir.path().join("ca.crt"),
            key_path: dir.path().join("ca.key"),
        };

        let generated = load_or_generate_issuer(&config).expect("generate issuer");
        let loaded = load_or_generate_issuer(&config).expect("load issuer");

        assert!(config.cert_path.exists());
        assert!(config.key_path.exists());
        assert!(!generated.key().serialize_pem().is_empty());
        assert!(!loaded.key().serialize_pem().is_empty());
    }

    #[test]
    fn incomplete_ca_files_fail_loudly() {
        let dir = tempdir().expect("tempdir");
        let config = CertificateAuthorityConfig {
            cert_path: dir.path().join("ca.crt"),
            key_path: dir.path().join("ca.key"),
        };
        fs::write(&config.cert_path, "cert only").expect("write cert");

        let err = load_or_generate_issuer(&config).expect_err("incomplete files fail");

        assert!(err.to_string().contains("incomplete"));
    }
}
