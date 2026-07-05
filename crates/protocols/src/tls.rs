use std::sync::Arc;
use std::time::Duration;

use alive_core::{Error, Result};
use alive_engine::{TlsCertInfo, TlsClient};
use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

/// TLS runner: handshake (accepting any certificate, like a scanner) and
/// extract certificate facts for `ssl` templates.
pub struct TlsRunner {
    timeout: Duration,
    connector: TlsConnector,
}

impl TlsRunner {
    pub fn new(timeout: Duration) -> Result<Self> {
        let provider = rustls::crypto::ring::default_provider();
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Other(format!("tls config: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny))
            .with_no_client_auth();
        Ok(Self {
            timeout,
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

#[async_trait]
impl TlsClient for TlsRunner {
    async fn connect(&self, addr: &str) -> Result<TlsCertInfo> {
        let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| Error::Other(format!("invalid tls server name: {host}")))?;

        let fut = async {
            let tcp = TcpStream::connect(addr)
                .await
                .map_err(|e| Error::Other(format!("tls connect {addr} failed: {e}")))?;
            let stream = self
                .connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| Error::Other(format!("tls handshake {addr} failed: {e}")))?;

            let (_io, conn) = stream.get_ref();
            let certs = conn
                .peer_certificates()
                .ok_or_else(|| Error::Other("no peer certificate".into()))?;
            let leaf = certs
                .first()
                .ok_or_else(|| Error::Other("empty certificate chain".into()))?;
            parse_cert(leaf)
        };

        match tokio::time::timeout(self.timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(Error::Other(format!("tls timeout talking to {addr}"))),
        }
    }
}

fn parse_cert(der: &CertificateDer<'_>) -> Result<TlsCertInfo> {
    let (_, cert) = parse_x509_certificate(der.as_ref())
        .map_err(|e| Error::Other(format!("x509 parse failed: {e}")))?;

    let mut dns_names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(n) = name {
                dns_names.push(n.to_string());
            }
        }
    }

    Ok(TlsCertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        dns_names,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
    })
}

/// A certificate verifier that accepts everything. Appropriate for a scanner
/// (we inspect certs, we do not trust them); never use in a real client.
#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
