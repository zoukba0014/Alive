use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    SanType,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
}

/// A fleet certificate authority: the CA cert (PEM) plus the key material
/// needed to issue agent leaf certs. Persist `ca_cert_pem` + `ca_key_pem`.
pub struct Ca {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    /// Issuer cert used to sign leaves (same subject+key as `ca_cert_pem`).
    cert: Certificate,
    key: KeyPair,
}

fn ca_params() -> Result<CertificateParams, CaError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Alive Fleet CA");
    params.distinguished_name = dn;
    Ok(params)
}

/// Generate a self-signed CA. Simplified enrollment: the CA issues full leaf
/// keypairs to agents rather than parsing CSRs (documented in WORKSPACE_SPEC).
pub fn generate_ca() -> Result<Ca, CaError> {
    let key = KeyPair::generate()?;
    let cert = ca_params()?.self_signed(&key)?;
    Ok(Ca {
        ca_cert_pem: cert.pem(),
        ca_key_pem: key.serialize_pem(),
        cert,
        key,
    })
}

impl Ca {
    /// Reload a CA from persisted PEM strings. The reconstructed issuer cert
    /// shares the original subject + key, so leaves it signs still chain to
    /// the original `ca_cert_pem` that agents trust.
    pub fn from_pem(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Ca, CaError> {
        let key = KeyPair::from_pem(ca_key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
        let cert = params.self_signed(&key)?;
        Ok(Ca {
            ca_cert_pem: ca_cert_pem.to_string(),
            ca_key_pem: ca_key_pem.to_string(),
            cert,
            key,
        })
    }
}

/// Issue a leaf cert + key for `common_name`, valid for the given SANs
/// (DNS names / IP literals as strings), signed by the CA.
/// Returns `(cert_pem, key_pem)`.
pub fn issue_leaf(
    ca: &Ca,
    common_name: &str,
    sans: &[String],
) -> Result<(String, String), CaError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    for san in sans {
        let entry = match san.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(san.clone().try_into()?),
        };
        params.subject_alt_names.push(entry);
    }
    let cert = params.signed_by(&key, &ca.cert, &ca.key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_issues_leaf() {
        let ca = generate_ca().unwrap();
        assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        let (cert, key) =
            issue_leaf(&ca, "agent-1", &["localhost".into(), "127.0.0.1".into()]).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
    }

    #[test]
    fn ca_reload_round_trips() {
        let ca = generate_ca().unwrap();
        let ca2 = Ca::from_pem(&ca.ca_cert_pem, &ca.ca_key_pem).unwrap();
        assert!(issue_leaf(&ca2, "agent-2", &["localhost".into()]).is_ok());
    }
}
