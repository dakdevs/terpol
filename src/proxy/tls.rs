use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
use hudsucker::rustls::crypto::aws_lc_rs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to generate CA: {0}")]
    Generation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse CA files: {0}")]
    Parse(String),
}

/// Generate a new CA key pair and certificate, saving to the given directory.
pub fn generate_ca(dir: &Path) -> Result<(), TlsError> {
    std::fs::create_dir_all(dir)?;

    let key_pair = KeyPair::generate().map_err(|e| TlsError::Generation(e.to_string()))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "network-latch CA");
        dn.push(DnType::OrganizationName, "network-latch");
        dn
    };
    params.is_ca = hudsucker::rcgen::IsCa::Ca(hudsucker::rcgen::BasicConstraints::Unconstrained);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::Generation(e.to_string()))?;

    std::fs::write(dir.join("ca.pem"), cert.pem())?;
    std::fs::write(dir.join("ca-key.pem"), key_pair.serialize_pem())?;

    Ok(())
}

/// Load an existing CA and create an RcgenAuthority for hudsucker.
pub fn load_ca(dir: &Path) -> Result<RcgenAuthority, TlsError> {
    let cert_pem = std::fs::read_to_string(dir.join("ca.pem"))?;
    let key_pem = std::fs::read_to_string(dir.join("ca-key.pem"))?;

    let key_pair =
        KeyPair::from_pem(&key_pem).map_err(|e| TlsError::Parse(e.to_string()))?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
        .map_err(|e| TlsError::Parse(e.to_string()))?;

    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());
    Ok(ca)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_load_ca() {
        let tmp = TempDir::new().unwrap();
        generate_ca(tmp.path()).unwrap();

        assert!(tmp.path().join("ca.pem").exists());
        assert!(tmp.path().join("ca-key.pem").exists());

        // Should be loadable
        let _ca = load_ca(tmp.path()).unwrap();
    }

    #[test]
    fn test_load_nonexistent_fails() {
        let tmp = TempDir::new().unwrap();
        let result = load_ca(tmp.path());
        assert!(matches!(result, Err(TlsError::Io(_))));
    }
}
